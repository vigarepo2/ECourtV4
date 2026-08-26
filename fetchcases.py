#!/usr/bin/env python3
import base64
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BASE_URL = "https://app.ecourts.gov.in/services_DC_4.0/"
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
FORCE_REFRESH = os.getenv("ECOURTS_FORCE_REFRESH", "false").strip().lower() in {"1", "true", "yes", "y"}


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def load_cnrs():
    if not CNR_FILE.exists():
        raise FileNotFoundError("cnr.json not found in repository root")

    raw = json.loads(CNR_FILE.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("cnrs")
    if not isinstance(raw, list):
        raise ValueError('cnr.json must be a JSON array, e.g. ["PBFZC00032292025"]')

    seen = set()
    valid = []
    invalid = []
    for item in raw:
        cnr = str(item).strip().upper()
        if not cnr:
            continue
        # Current eCourts CNRs are 16 alphanumeric characters. This accepts valid
        # forms such as PBFZC00032292025 instead of assuming exactly four letters.
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
    plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher = AES.new(REQUEST_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return random_low + str(index) + base64.b64encode(ciphertext).decode("ascii")


def decrypt_response(body: str):
    body = body.strip()
    if not body:
        return None

    if body[0] in "{[":
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            pass

    if len(body) < 33:
        raise ValueError(f"Unexpected eCourts response: {body[:200]!r}")

    iv = bytes.fromhex(body[:32])
    encrypted = base64.b64decode(body[32:])
    cipher = AES.new(RESPONSE_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(encrypted), AES.block_size).decode("utf-8")
    return json.loads(plaintext)


def make_session():
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "Accept": "application/json, text/plain, */*",
        "Connection": "keep-alive",
    })
    return session


def ecourts_request(session, endpoint, params, token=None):
    payload = dict(params)
    payload["uid"] = APP_UID
    blob = encrypt_params(payload)

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = session.get(
        BASE_URL + endpoint,
        params={"params": blob},
        headers=headers,
        timeout=(20, 60),
    )

    body = response.text.strip()
    try:
        decoded = decrypt_response(body)
    except Exception as exc:
        decoded = {"_decode_error": str(exc), "_raw": body[:1000]}

    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}: {json.dumps(decoded, ensure_ascii=False)}")

    return decoded


def bootstrap(session):
    data = ecourts_request(session, "appReleaseWebService.php", {"version": APP_VERSION})
    if not isinstance(data, dict):
        raise RuntimeError("Bootstrap returned a non-object response")
    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError(f"Bootstrap returned no token: {json.dumps(data, ensure_ascii=False)}")
    return token.strip()


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


def fetch_case(session, cnr, token):
    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            data = ecourts_request(
                session,
                "caseHistoryWebService.php",
                {
                    "cino": cnr,
                    "bilingual_flag": BILINGUAL_FLAG,
                    "language_flag": LANGUAGE_FLAG,
                },
                token=token,
            )

            if isinstance(data, dict):
                refreshed = data.get("token")
                if isinstance(refreshed, str) and refreshed.strip():
                    token = refreshed.strip()

                status_code = str(data.get("status_code", ""))
                if status_code == "401":
                    token = bootstrap(session)
                    raise RuntimeError("Session expired; token refreshed")

                history = data.get("history")
                if isinstance(history, dict) and history:
                    # Persist case data only. The JWT is session data, not case data,
                    # and must never be written into this public repository.
                    return {"history": history}, token

            raise RuntimeError(f"No history in response: {json.dumps(data, ensure_ascii=False)[:1200]}")

        except Exception as exc:
            last_error = exc
            if attempt >= MAX_ATTEMPTS:
                break
            wait = min(30.0, (2 ** (attempt - 1)) + secrets.randbelow(1000) / 1000)
            print(f"    attempt {attempt}/{MAX_ATTEMPTS} failed: {exc}")
            print(f"    retrying in {wait:.1f}s")
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


def main():
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    cnrs, invalid = load_cnrs()

    print(f"CNRs: {len(cnrs)} valid, {len(invalid)} invalid")
    print(f"Mode: {'force refresh' if FORCE_REFRESH else 'resume / skip cached'}")

    failures = [{"cnr": cnr, "error": "Invalid CNR format"} for cnr in invalid]
    todo = [cnr for cnr in cnrs if FORCE_REFRESH or saved_case(cnr) is None]
    cached = len(cnrs) - len(todo)

    if cached:
        print(f"Cached valid case files: {cached}")
    print(f"Cases to fetch: {len(todo)}")

    session = make_session()
    token = None

    if todo:
        print("Creating eCourts session...")
        token = bootstrap(session)
        print("Session token received.")

    for index, cnr in enumerate(todo, 1):
        print(f"[{index}/{len(todo)}] {cnr}")
        try:
            case_data, token = fetch_case(session, cnr, token)
            atomic_json(CASE_DIR / f"{cnr}.json", case_data)
            print("    OK")
        except Exception as exc:
            failures.append({"cnr": cnr, "error": str(exc)})
            print(f"    FAILED: {exc}")

        if index < len(todo):
            time.sleep(DELAY)

    session.close()

    combined, missing = build_combined(cnrs)
    known_failed = {item["cnr"] for item in failures}
    for cnr in missing:
        if cnr not in known_failed:
            failures.append({"cnr": cnr, "error": "Case file missing or invalid"})

    if failures:
        atomic_json(FAILED_FILE, {
            "generated_at": now_iso(),
            "total_failed": len(failures),
            "failed": failures,
        })
        print(f"Incomplete: {len(failures)} failure(s). Partial case files were kept for resume.")
        print(f"Failure report: {FAILED_FILE.name}")
        return

    if FAILED_FILE.exists():
        FAILED_FILE.unlink()

    atomic_json(COMBINED_FILE, combined)
    print(f"Complete: {len(cnrs)}/{len(cnrs)} cases available.")
    print(f"Combined JSON: {COMBINED_FILE.name}")
    print(f"Individual JSON: cnr/all/<CNR>.json")


if __name__ == "__main__":
    main()
