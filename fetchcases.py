#!/usr/bin/env python3
import base64, json, os, queue, re, secrets, socket, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST="app.ecourts.gov.in"; BASE_URL=f"https://{HOST}/services_DC_4.0/"
APP_VERSION="4.0.5"; APP_UID="in.gov.ecourts.eCourtsServices"
LANGUAGE_FLAG="english"; BILINGUAL_FLAG="0"
REQUEST_KEY=bytes.fromhex("4D6251655468576D5A7134743677397A")
RESPONSE_KEY=bytes.fromhex("3273357638782F413F4428472B4B6250")
IV_PREFIXES=["556A586E32723575","34743777217A2543","413F4428472B4B62","48404D635166546A","614E645267556B58","655368566D597133"]

ROOT=Path(__file__).resolve().parent
CNR_FILE=ROOT/"cnr.json"; CASE_DIR=ROOT/"cnr"/"all"; STATE_DIR=ROOT/"state"; LOG_DIR=ROOT/"logs"
COMBINED_FILE=ROOT/"cases.json"; COMPLETED_FILE=STATE_DIR/"completed.json"; PENDING_FILE=STATE_DIR/"pending.json"; FAILED_FILE=STATE_DIR/"failed.json"
IST=ZoneInfo("Asia/Kolkata")
WORKERS=max(1,min(6,int(os.getenv("ECOURTS_WORKERS","3"))))
MAX_CASE_ATTEMPTS=max(1,int(os.getenv("ECOURTS_MAX_ATTEMPTS","8")))
MAX_BOOT_ATTEMPTS=max(1,int(os.getenv("ECOURTS_BOOT_ATTEMPTS","8")))
FORCE_REFRESH=os.getenv("ECOURTS_FORCE_REFRESH","false").lower() in {"1","true","yes","y"}
FALLBACK_IPS=[x.strip() for x in os.getenv("ECOURTS_FALLBACK_IPS","103.195.217.42").split(",") if x.strip()]
THROTTLE_HTTP={405,408,425,429,500,502,503,504}

PRINT_LOCK=threading.Lock(); PAUSE_LOCK=threading.Lock(); SESSION_POOL=queue.Queue()
pause_until=0.0; pause_reason=""; throttle_events=0

def log(message=""):
    with PRINT_LOCK: print(f"[{datetime.now(IST).strftime('%H:%M:%S')}] {message}",flush=True)
def now_iso(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def today_ist(): return datetime.now(IST).strftime("%Y-%m-%d")

def atomic_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True); tmp=Path(str(path)+".tmp")
    tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); os.replace(tmp,path)
def read_json(path,default=None):
    try: return json.loads(path.read_text(encoding="utf-8"))
    except Exception: return default

def load_cnrs():
    raw=read_json(CNR_FILE)
    if isinstance(raw,dict): raw=raw.get("cnrs")
    if not isinstance(raw,list): raise ValueError("cnr.json must contain a JSON array of CNR numbers")
    valid=[]; invalid=[]; seen=set()
    for value in raw:
        cnr=str(value).strip().upper()
        if not cnr: continue
        if not re.fullmatch(r"[A-Z0-9]{16}",cnr): invalid.append(cnr); continue
        if cnr not in seen: seen.add(cnr); valid.append(cnr)
    return valid,invalid

def encrypt_params(data):
    i=secrets.randbelow(len(IV_PREFIXES)); rnd=secrets.token_hex(8); iv=bytes.fromhex(IV_PREFIXES[i]+rnd)
    raw=json.dumps(data,ensure_ascii=False,separators=(",",":")).encode("utf-8")
    enc=AES.new(REQUEST_KEY,AES.MODE_CBC,iv).encrypt(pad(raw,AES.block_size))
    return rnd+str(i)+base64.b64encode(enc).decode("ascii")

def decrypt_response(body):
    body=(body or "").strip()
    if not body: return None
    if body.startswith(("{","[")):
        try: return json.loads(body)
        except Exception: pass
    try:
        iv=bytes.fromhex(body[:32]); enc=base64.b64decode(body[32:])
        plain=unpad(AES.new(RESPONSE_KEY,AES.MODE_CBC,iv).decrypt(enc),AES.block_size).decode("utf-8")
        try: return json.loads(plain)
        except Exception: return plain
    except Exception as exc: return {"_decode_error":str(exc),"_raw":body[:1000]}

def ipv4_routes():
    discovered=[]
    try:
        for info in socket.getaddrinfo(HOST,443,socket.AF_INET,socket.SOCK_STREAM):
            ip=info[4][0]
            if ip not in discovered: discovered.append(ip)
    except Exception as exc: log(f"DNS warning: {exc}")
    routes=[None]
    for ip in discovered+FALLBACK_IPS:
        if ip and ip not in routes: routes.append(ip)
    return routes

def curl_once(url,blob,token=None,force_ip=None):
    cmd=["curl","-4","--http1.1","-sS","--connect-timeout","10","--max-time","40","--retry","1","--retry-delay","1","--retry-all-errors",
         "--get","--data-urlencode",f"params={blob}","-H","Accept: application/json, text/plain, */*",
         "-w","\n__ECOURTS_META__:%{http_code}|%{remote_ip}|%{time_connect}|%{time_total}",url]
    if token: cmd[1:1]=["-H",f"Authorization: Bearer {token}"]
    if force_ip: cmd[1:1]=["--resolve",f"{HOST}:443:{force_ip}"]
    try:
        p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=50)
    except subprocess.TimeoutExpired as exc:
        return {"status":0,"body":"","data":None,"remote":"","connect":"","total":"","error":f"curl timeout: {exc}"}
    o=p.stdout or ""; body=o; status=0; remote=""; connect=""; total=""; marker="\n__ECOURTS_META__:"
    if marker in o:
        body,meta=o.rsplit(marker,1); z=meta.strip().split("|")
        try: status=int(z[0])
        except Exception: status=0
        remote=z[1] if len(z)>1 else ""; connect=z[2] if len(z)>2 else ""; total=z[3] if len(z)>3 else ""
    return {"status":status,"body":body.strip(),"data":decrypt_response(body),"remote":remote,"connect":connect,"total":total,"error":(p.stderr or "").strip()}

def ecourts_request(endpoint,params,token=None):
    payload=dict(params); payload["uid"]=APP_UID; blob=encrypt_params(payload); last=None
    for route in ipv4_routes():
        r=curl_once(BASE_URL+endpoint,blob,token=token,force_ip=route); last=r
        if r["status"]: r["route"]=route or "DNS"; return r
    return last or {"status":0,"data":None,"error":"No route attempted"}

def set_global_pause(seconds,reason):
    global pause_until,pause_reason,throttle_events
    with PAUSE_LOCK:
        deadline=time.monotonic()+seconds
        if deadline>pause_until:
            pause_until=deadline; pause_reason=reason; throttle_events+=1; log(f"PAUSE {seconds}s | {reason}")

def wait_for_global_pause():
    while True:
        with PAUSE_LOCK: left=pause_until-time.monotonic()
        if left<=0: return
        time.sleep(min(1.0,left))

def bootstrap(label="session"):
    last="unknown"
    for attempt in range(1,MAX_BOOT_ATTEMPTS+1):
        wait_for_global_pause(); r=ecourts_request("appReleaseWebService.php",{"version":APP_VERSION}); s=r["status"]; d=r["data"]
        if s==200 and isinstance(d,dict) and isinstance(d.get("token"),str) and d["token"].strip():
            log(f"{label}: ready | route={r.get('route','?')} remote={r.get('remote') or '?'} total={r.get('total') or '?'}s")
            return d["token"].strip()
        last=f"HTTP {s}: {r.get('error','')[:250]}"
        if s==0:
            delay=min(30,4+attempt*3); log(f"{label}: HTTP 000/network failure {attempt}/{MAX_BOOT_ATTEMPTS}"); set_global_pause(delay,"eCourts network unavailable")
        elif s in THROTTLE_HTTP:
            delay=min(60,10+attempt*5); log(f"{label}: HTTP {s} {attempt}/{MAX_BOOT_ATTEMPTS}"); set_global_pause(delay,f"eCourts throttle HTTP {s}")
        else:
            delay=min(15,attempt*2); log(f"{label}: {last}; retry in {delay}s"); time.sleep(delay)
    raise RuntimeError(f"{label} bootstrap failed: {last}")

def case_file(cnr): return CASE_DIR/f"{cnr}.json"

def normalize_case_record(data,cnr):
    if not isinstance(data,dict): return None
    response=data.get("response")
    if isinstance(response,dict) and isinstance(response.get("history"),dict) and str(response["history"].get("cino","")).upper()==cnr: return data
    if isinstance(data.get("history"),dict) and str(data["history"].get("cino","")).upper()==cnr:
        return {"cnr":cnr,"fetched_at":data.get("fetched_at"),"http_status":200,"response":{k:v for k,v in data.items() if k!="token"}}
    case=data.get("case")
    if isinstance(case,dict) and isinstance(case.get("history"),dict) and str(case["history"].get("cino","")).upper()==cnr:
        return {"cnr":cnr,"fetched_at":data.get("fetched_at"),"http_status":data.get("http_status",200),"response":{k:v for k,v in case.items() if k!="token"}}
    return None

def saved_case(cnr):
    p=case_file(cnr)
    return normalize_case_record(read_json(p),cnr) if p.exists() else None

def snapshot(response):
    h=response.get("history",{}) if isinstance(response,dict) else {}
    pet=h.get("pet_name") or h.get("petparty_name") or "-"; res=h.get("res_name") or h.get("resparty_name") or "-"
    st="DISPOSED" if h.get("date_of_decision") else "PENDING"
    return f"{st} | {h.get('type_name','-')}/{h.get('reg_no','-')}/{h.get('reg_year','-')} | {pet} vs {res} | Next {h.get('date_next_list') or '-'}"

def build_state(master,invalid,errors=None):
    completed=[c for c in master if saved_case(c)]; done=set(completed); pending=[c for c in master if c not in done]; errors=errors or {}
    atomic_json(COMPLETED_FILE,{"updated_at":now_iso(),"master_total":len(master),"total_completed":len(completed),"completed":completed})
    atomic_json(PENDING_FILE,{"updated_at":now_iso(),"master_total":len(master),"total_pending":len(pending),"pending":pending,"invalid_cnrs":invalid})
    atomic_json(FAILED_FILE,{"updated_at":now_iso(),"total_failed":len([c for c in pending if c in errors]),"failed":[{"cnr":c,"error":errors[c]} for c in pending if c in errors]})
    return completed,pending

def build_combined(master):
    cases=[]; missing=[]
    for c in master:
        d=saved_case(c)
        (cases if d else missing).append(d if d else c)
    atomic_json(COMBINED_FILE,{"generated_at":now_iso(),"source":"eCourts Services 4.0.5","total_requested":len(master),"total_success":len(cases),"total_missing":len(missing),"complete":not missing,"cases":cases,"missing_cnrs":missing})
    return cases,missing

def append_daily_log(run):
    path=LOG_DIR/f"{today_ist()}.json"; data=read_json(path,{})
    runs=data.get("runs",[]) if isinstance(data,dict) else []
    if not isinstance(runs,list): runs=[]
    runs.append(run)
    atomic_json(path,{"date":today_ist(),"timezone":"Asia/Kolkata","runs":runs,"latest":run})

def create_session_pool():
    created=0
    for i in range(1,WORKERS+1):
        try: SESSION_POOL.put(bootstrap(f"session {i}/{WORKERS}")); created+=1; time.sleep(.25)
        except Exception as exc: log(f"session {i}/{WORKERS}: unavailable: {exc}"); break
    return created

def fetch_one(cnr):
    started=time.time(); last="unknown"
    for attempt in range(1,MAX_CASE_ATTEMPTS+1):
        wait_for_global_pause(); token=SESSION_POOL.get()
        try:
            r=ecourts_request("caseHistoryWebService.php",{"cino":cnr,"bilingual_flag":BILINGUAL_FLAG,"language_flag":LANGUAGE_FLAG},token=token)
            s=r["status"]; d=r["data"]
            if s==200 and isinstance(d,dict) and isinstance(d.get("history"),dict):
                returned=str(d["history"].get("cino","")).upper()
                if returned!=cnr: raise RuntimeError(f"CNR mismatch: {returned or 'blank'}")
                rotated=d.get("token")
                if isinstance(rotated,str) and rotated.strip(): token=rotated.strip()
                return {"ok":True,"cnr":cnr,"status":200,"response":{k:v for k,v in d.items() if k!="token"},"elapsed":time.time()-started}
            api_status=str(d.get("status_code","")) if isinstance(d,dict) else ""
            if s==401 or api_status=="401":
                log(f"{cnr}: session expired; replacing token"); token=None
                try: SESSION_POOL.put(bootstrap("replacement session"))
                except Exception as exc: last=f"session refresh failed: {exc}"
                continue
            if s==0:
                last=r.get("error") or "HTTP 000 / no connection"; delay=min(35,6+attempt*3)
                log(f"{cnr}: HTTP 000/network failure | attempt {attempt}/{MAX_CASE_ATTEMPTS}"); set_global_pause(delay,"eCourts network unavailable"); continue
            if s in THROTTLE_HTTP:
                last=f"HTTP {s}"; delay=min(75,12+throttle_events*8)
                log(f"{cnr}: HTTP {s} | attempt {attempt}/{MAX_CASE_ATTEMPTS}"); set_global_pause(delay,f"server throttle HTTP {s}"); continue
            if s in {400,404,422}: return {"ok":False,"cnr":cnr,"error":f"HTTP {s}: {str(d)[:500]}","elapsed":time.time()-started}
            last=f"HTTP {s}: {str(d)[:500]}"
            if attempt<MAX_CASE_ATTEMPTS: time.sleep(min(8,attempt*2))
        except Exception as exc:
            last=str(exc)
            if attempt<MAX_CASE_ATTEMPTS: time.sleep(min(8,attempt*2))
        finally:
            if token is not None: SESSION_POOL.put(token)
    return {"ok":False,"cnr":cnr,"error":last,"elapsed":time.time()-started}

def main():
    started_at=now_iso(); run_started=time.time(); CASE_DIR.mkdir(parents=True,exist_ok=True); STATE_DIR.mkdir(parents=True,exist_ok=True); LOG_DIR.mkdir(parents=True,exist_ok=True)
    cnrs,invalid=load_cnrs(); errors={}; completed,pending=build_state(cnrs,invalid); already=len(completed); todo=list(cnrs if FORCE_REFRESH else pending)
    log("="*88); log(f"MASTER={len(cnrs)} | COMPLETE={already} | TODO={len(todo)} | INVALID={len(invalid)} | WORKERS={WORKERS}"); log("cnr.json is permanent master; validated state/case files define next-run queue"); log("="*88)
    successes=[]
    if todo:
        created=create_session_pool()
        if created==0:
            common="Could not create any eCourts session from this runner"; log(common)
            for c in todo: errors[c]=common
            completed,pending=build_state(cnrs,invalid,errors); cases,missing=build_combined(cnrs)
            append_daily_log({"started_at":started_at,"finished_at":now_iso(),"status":"network_unavailable","master_total":len(cnrs),"already_complete_at_start":already,"attempted":0,"success_this_run":0,"failed_this_run":0,"total_complete":len(completed),"total_pending":len(pending),"successes":[],"failures":[{"cnr":c,"error":errors[c]} for c in todo],"duration_seconds":round(time.time()-run_started,2)})
            return
        if created<WORKERS: log(f"Starting with {created} working session(s), not {WORKERS}")
        canary=todo.pop(0); log(f"CANARY {canary}"); result=fetch_one(canary)
        if result["ok"]:
            atomic_json(case_file(canary),{"cnr":canary,"fetched_at":now_iso(),"http_status":result["status"],"response":result["response"]}); successes.append(canary); log(f"OK {canary} | {snapshot(result['response'])} | {result['elapsed']:.2f}s")
        else:
            errors[canary]=result["error"]; log(f"FAIL {canary} | {result['error']}"); todo.insert(0,canary)
        if successes and todo:
            active=min(created,WORKERS); log(f"CANARY OK -> parallel fetch with {active} worker(s)")
            with ThreadPoolExecutor(max_workers=active) as ex:
                fs={ex.submit(fetch_one,c):c for c in todo}
                for f in as_completed(fs):
                    c=fs[f]
                    try: result=f.result()
                    except Exception as exc: result={"ok":False,"cnr":c,"error":str(exc),"elapsed":0}
                    if result["ok"]:
                        atomic_json(case_file(c),{"cnr":c,"fetched_at":now_iso(),"http_status":result["status"],"response":result["response"]}); successes.append(c); errors.pop(c,None); log(f"OK {len(successes)} new | {c} | {snapshot(result['response'])} | {result['elapsed']:.2f}s")
                    else: errors[c]=result["error"]; log(f"FAIL {c} | {result['error']}")
                    completed,pending=build_state(cnrs,invalid,errors); log(f"PROGRESS complete={len(completed)}/{len(cnrs)} pending={len(pending)} new={len(successes)}")
    completed,pending=build_state(cnrs,invalid,errors); cases,missing=build_combined(cnrs)
    run={"started_at":started_at,"finished_at":now_iso(),"status":"complete" if not pending else "partial","master_total":len(cnrs),"already_complete_at_start":already,"attempted":len(successes)+len(errors),"success_this_run":len(successes),"failed_this_run":len(errors),"total_complete":len(completed),"total_pending":len(pending),"successes":successes,"failures":[{"cnr":c,"error":errors[c]} for c in errors],"duration_seconds":round(time.time()-run_started,2)}
    append_daily_log(run)
    log("="*88); log(f"DONE | COMPLETE={len(completed)}/{len(cnrs)} | PENDING={len(pending)} | NEW={len(successes)}"); log(f"cases.json contains {len(cases)} saved case(s); complete={not missing}"); log(f"daily log: logs/{today_ist()}.json"); log("="*88)

if __name__=="__main__": main()
