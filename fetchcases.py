#!/usr/bin/env python3
import base64
import json
import os
import re
import secrets
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = "app.ecourts.gov.in"
BASE_URL = f"https://{HOST}/services_DC_4.0/"
APP_VERSION = "4.0.5"
APP_UID = "in.gov.ecourts.eCourtsServices"
LANGUAGE_FLAG = "english"
BILINGUAL_FLAG = "0"

REQUEST_KEY = bytes.fromhex("4D6251655468576D5A7134743677397A")
RESPONSE_KEY = bytes.fromhex("3273357638782F413F4428472B4B6250")
IV_PREFIXES = [
    "556A586E32723575",
    "34743777217A2543",
    "413F4428472B4B62",
    "48404D635166546A",
    "614E645267556B58",
    "655368566D597133",
]

ROOT = Path(__file__).resolve().parent
CNR_FILE = ROOT / "cnr.json"
CASE_DIR = ROOT / "cnr" / "all"
COMBINED_FILE = ROOT / "cases.json"
FAILED_FILE = ROOT / "failed.json"

DELAY = max(0.0, float(os.getenv("ECOURTS_DELAY", "1.5")))
MAX_ATTEMPTS = max(1, int(os.getenv("ECOURTS_MAX_ATTEMPTS", "6")))
FORCE_REFRESH = os.getenv("ECOURTS_FORCE_REFRESH", "false").strip().lower() in {
    "1", "true", "yes", "y"
}
VERBOSE_JSON = os.getenv("ECOURTS_VERBOSE_JSON", "false").strip().lower() in {
    "1", "true", "yes", "y"
}

RETRYABLE_HTTP = {408, 425, 429, 500, 502, 503, 504}


class EcourtsHTTPError(RuntimeError):
    def __init__(self, status, decoded):
        self.status = int(status)
        self.decoded = decoded
        super().__init__(
            f"HTTP {self.status}: " + json.dumps(decoded, ensure_ascii=False)[:1200]
        )


def log(message=""):
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temp.replace(path)


def load_cnrs():
    if not CNR_FILE.exists():
        raise FileNotFoundError("cnr.json not found in repository root")

    raw = json.loads(CNR_FILE.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("cnrs")
    if not isinstance(raw, list):
        raise ValueError(
            'cnr.json must be a JSON array, e.g. ["PBFZC00032292025"]'
        )

    seen = set()
    valid = []
    invalid = []
    for item in raw:
        cnr = str(item).strip().upper()
        if not cnr:
            continue
        if not re.fullmatch(r"[A-Z0-9]{16}", cnr):
            invalid.append(cnr)
            continue
        if cnr not in seen:
            seen.add(cnr)
            valid.append(cnr)
    return valid, invalid


def encrypt_params(data: dict) -> str:
    index = secrets.randbelow(len(IV_PREFIXES))
    random_low = secrets.token_hex(8)
    iv = bytes.fromhex(IV_PREFIXES[index] + random_low)
    plain = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher = AES.new(REQUEST_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plain, AES.block_size))
    return random_low + str(index) + base64.b64encode(encrypted).decode("ascii")


def decrypt_response(body: str):
    body = body.strip()
    if not body:
        return None

    if body.startswith("{") or body.startswith("["):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            pass

    if len(body) < 33:
        return {"_raw": body, "_note": "Response too short for encrypted eCourts format"}

    try:
        iv = bytes.fromhex(body[:32])
        encrypted = base64.b64decode(body[32:])
        cipher = AES.new(RESPONSE_KEY, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(encrypted), AES.block_size).decode("utf-8")
        try:
            return json.loads(plain)
        except json.JSONDecodeError:
            return plain
    except Exception as exc:
        return {"_decode_error": str(exc), "_raw": body[:2000]}


def get_ipv4s():
    ips = []
    try:
        infos = socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as exc:
        log(f"DNS warning: {exc}")
    return ips


def curl_once(url, blob, token=None, force_ip=None):
    cmd = [
        "curl", "-4", "--http1.1", "-sS",
        "--connect-timeout", "12",
        "--max-time", "55",
        "--retry", "2",
        "--retry-delay", "2",
        "--retry-all-errors",
        "--get",
        "--data-urlencode", f"params={blob}",
        "-H", "Accept: application/json, text/plain, */*",
        "-w", "\n__ECOURTS_META__:%{http_code}|%{remote_ip}|%{time_connect}|%{time_total}",
        url,
    ]
    if token:
        cmd[1:1] = ["-H", f"Authorization: Bearer {token}"]
    if force_ip:
        cmd[1:1] = ["--resolve", f"{HOST}:443:{force_ip}"]

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=70,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "exit": 124, "status": 0, "body": "", "stderr": f"curl subprocess timeout: {exc}",
            "remote_ip": "", "connect_time": "", "total_time": "",
        }

    output = proc.stdout or ""
    marker = "\n__ECOURTS_META__:"
    status = 0
    body = output
    remote_ip = ""
    connect_time = ""
    total_time = ""

    if marker in output:
        body, meta = output.rsplit(marker, 1)
        parts = meta.strip().split("|")
        try:
            status = int(parts[0]) if parts else 0
        except ValueError:
            status = 0
        remote_ip = parts[1] if len(parts) > 1 else ""
        connect_time = parts[2] if len(parts) > 2 else ""
        total_time = parts[3] if len(parts) > 3 else ""

    return {
        "exit": proc.returncode,
        "status": status,
        "body": body.strip(),
        "stderr": (proc.stderr or "").strip(),
        "remote_ip": remote_ip,
        "connect_time": connect_time,
        "total_time": total_time,
    }


def ecourts_request(endpoint, params, token=None, label="request"):
    payload = dict(params)
    payload["uid"] = APP_UID
    blob = encrypt_params(payload)
    url = BASE_URL + endpoint

    ips = get_ipv4s()
    targets = [None] + ips
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]

    log(f"{label}: endpoint={endpoint} | IPv4={','.join(ips) if ips else 'DNS/default'}")

    network_errors = []
    retryable_http_error = None

    for route_no, target in enumerate(targets, 1):
        route = target or "normal-DNS"
        log(f"{label}: connecting route {route_no}/{len(targets)} via {route}")
        result = curl_once(url, blob, token=token, force_ip=target)
        status = int(result.get("status") or 0)

        if status:
            remote_ip = result.get("remote_ip") or route
            total = result.get("total_time") or "?"
            connect = result.get("connect_time") or "?"
            log(f"{label}: HTTP {status} | remote={remote_ip} | connect={connect}s | total={total}s")
            decoded = decrypt_response(result.get("body", ""))

            if status == 200:
                return decoded

            error = EcourtsHTTPError(status, decoded)
            if status in RETRYABLE_HTTP:
                log(f"{label}: retryable HTTP {status}; trying next route/attempt")
                retryable_http_error = error
                continue
            raise error

        message = result.get("stderr") or "no HTTP response"
        log(f"{label}: NETWORK ERROR via {route}: {message[:500]}")
        network_errors.append(f"{route}: {message}")

    if retryable_http_error is not None:
        raise retryable_http_error

    raise ConnectionError(
        "Could not establish HTTPS connection to " + HOST + ". " + " | ".join(network_errors[-4:])
    )


def retry_wait(attempt):
    return min(30.0, (2 ** max(0, attempt - 1)) + secrets.randbelow(1000) / 1000)


def bootstrap():
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            log(f"SESSION: bootstrap attempt {attempt}/{MAX_ATTEMPTS}")
            data = ecourts_request(
                "appReleaseWebService.php",
                {"version": APP_VERSION},
                label="SESSION",
            )
            if not isinstance(data, dict):
                raise RuntimeError("Bootstrap returned a non-object response")
            token = data.get("token")
            if not isinstance(token, str) or not token.strip():
                raise RuntimeError(
                    "Bootstrap returned no token: " + json.dumps(data, ensure_ascii=False)[:1200]
                )
            compat = data.get("version_compatible", "?")
            release = (data.get("appReleaseObj") or {}).get("version_no", "?") if isinstance(data.get("appReleaseObj"), dict) else "?"
            log(f"SESSION: ready | server release={release} | compatibility={compat} | token=received (hidden)")
            return token.strip()
        except Exception as exc:
            last_error = exc
            log(f"SESSION: attempt {attempt}/{MAX_ATTEMPTS} FAILED: {exc}")
            if attempt >= MAX_ATTEMPTS:
                break
            wait = retry_wait(attempt)
            log(f"SESSION: retrying in {wait:.1f}s")
            time.sleep(wait)
    raise RuntimeError(f"Bootstrap failed: {last_error}")


def saved_case(cnr):
    path = CASE_DIR / f"{cnr}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        history = data.get("history") if isinstance(data, dict) else None
        if isinstance(history, dict) and str(history.get("cino", "")).upper() == cnr:
            return data
    except Exception:
        return None
    return None


def response_without_token(data):
    if not isinstance(data, dict):
        return data
    return {key: value for key, value in data.items() if key != "token"}


def clean(value):
    if value is None:
        return "-"
    text = str(value).strip()
    return text if text else "-"


def print_case_snapshot(cnr, data, prefix="CASE"):
    history = data.get("history", {}) if isinstance(data, dict) else {}
    if not isinstance(history, dict):
        history = {}

    petitioner = clean(history.get("petparty_name") or history.get("pet_name"))
    respondent = clean(history.get("resparty_name") or history.get("res_name"))
    case_type = clean(history.get("type_name"))
    reg_no = clean(history.get("reg_no"))
    reg_year = clean(history.get("reg_year"))
    case_label = f"{case_type}/{reg_no}/{reg_year}"
    status = "Disposed" if history.get("date_of_decision") else "Pending"
    next_date = clean(history.get("date_next_list"))
    decision = clean(history.get("date_of_decision"))
    last_date = clean(history.get("date_last_list"))
    purpose = clean(history.get("purpose_name"))
    court = clean(history.get("court_name"))
    judge = clean(history.get("desgname"))
    fir = clean(history.get("fir_details"))
    pet_adv = clean(history.get("pet_adv") or history.get("petAdv"))
    res_adv = clean(history.get("res_adv") or history.get("resAdv"))
    hearings = history.get("historyOfCaseHearing") or []
    interim = history.get("interimOrder") or []
    processes = history.get("processes") or []
    ia = history.get("iaFiling") or []
    final_order = history.get("finalOrder")
    last_order = history.get("last_order") or {}
    last_order_date = clean(last_order.get("order_date1") if isinstance(last_order, dict) else None)

    log(f"{prefix} {cnr}: {petitioner} vs {respondent}")
    log(f"{prefix} {cnr}: {case_label} | STATUS={status} | next={next_date} | decision={decision}")
    log(f"{prefix} {cnr}: purpose={purpose} | last-hearing={last_date} | last-order={last_order_date}")
    log(f"{prefix} {cnr}: court={court} | judge={judge}")
    log(f"{prefix} {cnr}: FIR={fir} | advocates: petitioner={pet_adv} | respondent={res_adv}")
    log(
        f"{prefix} {cnr}: hearings={len(hearings) if isinstance(hearings, list) else 0} | "
        f"interim-orders={len(interim) if isinstance(interim, list) else 0} | "
        f"final-order={'yes' if final_order else 'no'} | "
        f"processes={len(processes) if isinstance(processes, list) else 0} | "
        f"IA={len(ia) if isinstance(ia, list) else 0}"
    )


def fetch_case(cnr, token):
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            log(f"CNR {cnr}: fetch attempt {attempt}/{MAX_ATTEMPTS}")
            data = ecourts_request(
                "caseHistoryWebService.php",
                {
                    "cino": cnr,
                    "bilingual_flag": BILINGUAL_FLAG,
                    "language_flag": LANGUAGE_FLAG,
                },
                token=token,
                label=f"CNR {cnr}",
            )

            if not isinstance(data, dict):
                raise RuntimeError(f"Unexpected case response: {str(data)[:1200]}")

            refreshed = data.get("token")
            if isinstance(refreshed, str) and refreshed.strip():
                token = refreshed.strip()
                log(f"CNR {cnr}: session token refreshed by server (hidden)")

            if str(data.get("status_code", "")) == "401":
                log(f"CNR {cnr}: application status 401; refreshing session")
                token = bootstrap()
                raise RuntimeError("Session expired; token refreshed")

            history = data.get("history")
            if isinstance(history, dict) and history:
                safe_data = response_without_token(data)
                print_case_snapshot(cnr, safe_data)
                if VERBOSE_JSON:
                    log(f"CNR {cnr}: FULL DECRYPTED JSON follows")
                    print(json.dumps(safe_data, ensure_ascii=False, indent=2), flush=True)
                return safe_data, token

            raise RuntimeError(
                "No history in response: " + json.dumps(data, ensure_ascii=False)[:1200]
            )

        except EcourtsHTTPError as exc:
            last_error = exc
            if exc.status == 401:
                log(f"CNR {cnr}: HTTP 401; refreshing session")
                try:
                    token = bootstrap()
                    last_error = RuntimeError("HTTP 401; token refreshed")
                except Exception as refresh_exc:
                    last_error = refresh_exc
        except Exception as exc:
            last_error = exc

        log(f"CNR {cnr}: attempt {attempt}/{MAX_ATTEMPTS} FAILED: {last_error}")
        if attempt >= MAX_ATTEMPTS:
            break
        wait = retry_wait(attempt)
        log(f"CNR {cnr}: retrying in {wait:.1f}s")
        time.sleep(wait)

    raise RuntimeError(str(last_error))


def build_combined(cnrs):
    cases = []
    missing = []
    for cnr in cnrs:
        data = saved_case(cnr)
        if data is None:
            missing.append(cnr)
        else:
            cases.append(data)
    if missing:
        return None, missing
    return {
        "generated_at": now_iso(),
        "source": "eCourts Services 4.0.5",
        "total": len(cases),
        "cases": cases,
    }, []


def write_step_summary(total, cached, fetched_ok, failures):
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        "## eCourts Fetch Summary",
        "",
        f"- Total valid CNRs: **{total}**",
        f"- Cached/skipped: **{cached}**",
        f"- Fetched successfully this run: **{fetched_ok}**",
        f"- Failed/incomplete: **{len(failures)}**",
        "",
    ]
    if failures:
        lines += ["### Failures", "", "| CNR | Error |", "|---|---|"]
        for item in failures[:100]:
            err = str(item.get("error", "")).replace("|", "\\|").replace("\n", " ")[:300]
            lines.append(f"| `{item.get('cnr')}` | {err} |")
    Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    cnrs, invalid = load_cnrs()

    log("=" * 76)
    log("eCourts Services 4.0.5 bulk fetch — LIVE STATUS MODE")
    log("Transport: curl IPv4 + HTTP/1.1 + retries + per-IP fallback")
    log(f"Input: {len(cnrs)} valid CNR(s), {len(invalid)} invalid | delay={DELAY}s | attempts={MAX_ATTEMPTS}")
    log(f"Mode: {'FORCE REFRESH' if FORCE_REFRESH else 'RESUME / SKIP VALID CACHE'} | full-json-log={VERBOSE_JSON}")
    log("=" * 76)

    failures = [{"cnr": cnr, "error": "Invalid CNR format"} for cnr in invalid]
    if invalid:
        for cnr in invalid:
            log(f"INVALID {cnr}: rejected before network request")

    todo = []
    cached = 0
    for pos, cnr in enumerate(cnrs, 1):
        existing = None if FORCE_REFRESH else saved_case(cnr)
        if existing is not None:
            cached += 1
            log(f"[{pos}/{len(cnrs)}] CACHE HIT {cnr}: valid file already exists; skipping network")
            print_case_snapshot(cnr, existing, prefix="CACHE")
        else:
            todo.append(cnr)

    log(f"Queue ready: cached={cached} | to-fetch={len(todo)} | invalid={len(invalid)}")

    token = None
    if todo:
        token = bootstrap()

    fetched_ok = 0
    fetched_fail = 0

    for index, cnr in enumerate(todo, 1):
        overall_done_before = cached + fetched_ok + fetched_fail
        log("")
        log("-" * 76)
        log(
            f"START CNR {cnr} | fetch {index}/{len(todo)} | "
            f"overall completed={overall_done_before}/{len(cnrs)}"
        )
        started = time.monotonic()

        try:
            case_data, token = fetch_case(cnr, token)
            out = CASE_DIR / f"{cnr}.json"
            atomic_json(out, case_data)
            fetched_ok += 1
            elapsed = time.monotonic() - started
            log(f"SUCCESS {cnr}: saved {out.relative_to(ROOT)} | elapsed={elapsed:.1f}s")
        except Exception as exc:
            fetched_fail += 1
            failures.append({"cnr": cnr, "error": str(exc)})
            elapsed = time.monotonic() - started
            log(f"FAILED {cnr}: {exc} | elapsed={elapsed:.1f}s")

        completed = cached + fetched_ok + fetched_fail
        log(
            f"PROGRESS: {completed}/{len(cnrs)} processed | "
            f"cached={cached} | fetched-ok={fetched_ok} | fetched-failed={fetched_fail} | remaining={len(todo)-index}"
        )
        log("-" * 76)

        if index < len(todo):
            log(f"Pacing: sleeping {DELAY:.1f}s before next CNR")
            time.sleep(DELAY)

    combined, missing = build_combined(cnrs)
    known_failed = {item["cnr"] for item in failures}
    for cnr in missing:
        if cnr not in known_failed:
            failures.append({"cnr": cnr, "error": "Case file missing or invalid"})

    write_step_summary(len(cnrs), cached, fetched_ok, failures)

    log("")
    log("=" * 76)
    if failures:
        atomic_json(
            FAILED_FILE,
            {"generated_at": now_iso(), "total_failed": len(failures), "failed": failures},
        )
        log(f"RUN INCOMPLETE: {len(failures)} failure(s)")
        log(f"Successful files kept in cnr/all/ for resume; failure report={FAILED_FILE.name}")
        for item in failures:
            log(f"FAILED LIST: {item['cnr']} -> {item['error']}")
    else:
        if FAILED_FILE.exists():
            FAILED_FILE.unlink()
        atomic_json(COMBINED_FILE, combined)
        log(f"RUN COMPLETE: {len(cnrs)}/{len(cnrs)} cases available")
        log(f"Combined JSON: {COMBINED_FILE.name}")
        log("Individual JSON: cnr/all/<CNR>.json")
    log("=" * 76)


if __name__ == "__main__":
    main()
