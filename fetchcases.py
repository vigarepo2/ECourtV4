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

RETRYABLE_HTTP = {408, 425, 429, 500, 502, 503, 504}


class EcourtsHTTPError(RuntimeError):
    def __init__(self, status, decoded):
        self.status = int(status)
        self.decoded = decoded
        super().__init__(
            f"HTTP {self.status}: "
            + json.dumps(decoded, ensure_ascii=False)[:1200]
        )


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

    plain = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

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
        return {
            "_raw": body,
            "_note": "Response too short for encrypted eCourts format",
        }

    try:
        iv = bytes.fromhex(body[:32])
        encrypted = base64.b64decode(body[32:])
        cipher = AES.new(RESPONSE_KEY, AES.MODE_CBC, iv)
        plain = unpad(
            cipher.decrypt(encrypted),
            AES.block_size,
        ).decode("utf-8")

        try:
            return json.loads(plain)
        except json.JSONDecodeError:
            return plain

    except Exception as exc:
        return {
            "_decode_error": str(exc),
            "_raw": body[:2000],
        }


def get_ipv4s():
    ips = []
    try:
        infos = socket.getaddrinfo(
            HOST,
            443,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as exc:
        print(f"    DNS warning: {exc}")
    return ips


def curl_once(url, blob, token=None, force_ip=None):
    cmd = [
        "curl",
        "-4",
        "--http1.1",
        "-sS",
        "--connect-timeout", "12",
        "--max-time", "55",
        "--retry", "2",
        "--retry-delay", "2",
        "--retry-all-errors",
        "--get",
        "--data-urlencode", f"params={blob}",
        "-H", "Accept: application/json, text/plain, */*",
        "-w", "\n__ECOURTS_HTTP__:%{http_code}",
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
            "exit": 124,
            "status": 0,
            "body": "",
            "stderr": f"curl subprocess timeout: {exc}",
        }

    output = proc.stdout or ""
    marker = "\n__ECOURTS_HTTP__:"

    if marker in output:
        body, status_text = output.rsplit(marker, 1)
        try:
            status = int(status_text.strip())
        except ValueError:
            status = 0
    else:
        body = output
        status = 0

    return {
        "exit": proc.returncode,
        "status": status,
        "body": body.strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def ecourts_request(endpoint, params, token=None):
    payload = dict(params)
    payload["uid"] = APP_UID
    blob = encrypt_params(payload)
    url = BASE_URL + endpoint

    ips = get_ipv4s()
    targets = [None] + ips

    seen = set()
    targets = [
        target for target in targets
        if not (target in seen or seen.add(target))
    ]

    network_errors = []
    retryable_http_error = None

    for target in targets:
        result = curl_once(
            url,
            blob,
            token=token,
            force_ip=target,
        )

        status = int(result.get("status") or 0)

        if status:
            decoded = decrypt_response(result.get("body", ""))

            if status == 200:
                return decoded

            error = EcourtsHTTPError(status, decoded)
            if status in RETRYABLE_HTTP:
                retryable_http_error = error
                continue
            raise error

        route = target or "normal DNS"
        message = result.get("stderr") or "no HTTP response"
        network_errors.append(f"{route}: {message}")

    if retryable_http_error is not None:
        raise retryable_http_error

    raise ConnectionError(
        "Could not establish HTTPS connection to "
        + HOST
        + ". "
        + " | ".join(network_errors[-4:])
    )


def retry_wait(attempt):
    return min(
        30.0,
        (2 ** max(0, attempt - 1)) + secrets.randbelow(1000) / 1000,
    )


def bootstrap():
    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            data = ecourts_request(
                "appReleaseWebService.php",
                {"version": APP_VERSION},
            )

            if not isinstance(data, dict):
                raise RuntimeError("Bootstrap returned a non-object response")

            token = data.get("token")
            if not isinstance(token, str) or not token.strip():
                raise RuntimeError(
                    "Bootstrap returned no token: "
                    + json.dumps(data, ensure_ascii=False)[:1200]
                )

            return token.strip()

        except Exception as exc:
            last_error = exc
            if attempt >= MAX_ATTEMPTS:
                break
            wait = retry_wait(attempt)
            print(f"    bootstrap attempt {attempt}/{MAX_ATTEMPTS} failed: {exc}")
            print(f"    retrying bootstrap in {wait:.1f}s")
            time.sleep(wait)

    raise RuntimeError(f"Bootstrap failed: {last_error}")


def saved_case(cnr):
    path = CASE_DIR / f"{cnr}.json"
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        history = data.get("history") if isinstance(data, dict) else None
        if (
            isinstance(history, dict)
            and str(history.get("cino", "")).upper() == cnr
        ):
            return data
    except Exception:
        return None

    return None


def response_without_token(data):
    if not isinstance(data, dict):
        return data
    return {key: value for key, value in data.items() if key != "token"}


def fetch_case(cnr, token):
    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            data = ecourts_request(
                "caseHistoryWebService.php",
                {
                    "cino": cnr,
                    "bilingual_flag": BILINGUAL_FLAG,
                    "language_flag": LANGUAGE_FLAG,
                },
                token=token,
            )

            if not isinstance(data, dict):
                raise RuntimeError(
                    f"Unexpected case response: {str(data)[:1200]}"
                )

            refreshed = data.get("token")
            if isinstance(refreshed, str) and refreshed.strip():
                token = refreshed.strip()

            status_code = str(data.get("status_code", ""))
            if status_code == "401":
                token = bootstrap()
                raise RuntimeError("Session expired; token refreshed")

            history = data.get("history")
            if isinstance(history, dict) and history:
                return response_without_token(data), token

            raise RuntimeError(
                "No history in response: "
                + json.dumps(data, ensure_ascii=False)[:1200]
            )

        except EcourtsHTTPError as exc:
            last_error = exc
            if exc.status == 401:
                try:
                    token = bootstrap()
                    last_error = RuntimeError("HTTP 401; token refreshed")
                except Exception as refresh_exc:
                    last_error = refresh_exc

        except Exception as exc:
            last_error = exc

        if attempt >= MAX_ATTEMPTS:
            break

        wait = retry_wait(attempt)
        print(f"    attempt {attempt}/{MAX_ATTEMPTS} failed: {last_error}")
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

    print("=" * 68)
    print("eCourts Services 4.0.5 bulk fetch")
    print("Transport: curl IPv4 + HTTP/1.1 + per-IP fallback")
    print("=" * 68)
    print(f"CNRs: {len(cnrs)} valid, {len(invalid)} invalid")
    print(f"Mode: {'force refresh' if FORCE_REFRESH else 'resume / skip cached'}")

    failures = [
        {"cnr": cnr, "error": "Invalid CNR format"}
        for cnr in invalid
    ]

    todo = [
        cnr for cnr in cnrs
        if FORCE_REFRESH or saved_case(cnr) is None
    ]
    cached = len(cnrs) - len(todo)

    if cached:
        print(f"Cached valid case files: {cached}")
    print(f"Cases to fetch: {len(todo)}")

    token = None

    if todo:
        print("Creating eCourts session...")
        token = bootstrap()
        print("Session token received.")

    for index, cnr in enumerate(todo, 1):
        print(f"[{index}/{len(todo)}] {cnr}")

        try:
            case_data, token = fetch_case(cnr, token)
            atomic_json(CASE_DIR / f"{cnr}.json", case_data)
            print("    OK")
        except Exception as exc:
            failures.append({"cnr": cnr, "error": str(exc)})
            print(f"    FAILED: {exc}")

        if index < len(todo):
            time.sleep(DELAY)

    combined, missing = build_combined(cnrs)

    known_failed = {item["cnr"] for item in failures}
    for cnr in missing:
        if cnr not in known_failed:
            failures.append({
                "cnr": cnr,
                "error": "Case file missing or invalid",
            })

    if failures:
        atomic_json(
            FAILED_FILE,
            {
                "generated_at": now_iso(),
                "total_failed": len(failures),
                "failed": failures,
            },
        )
        print(
            f"Incomplete: {len(failures)} failure(s). "
            "Successful case files were kept for resume."
        )
        print(f"Failure report: {FAILED_FILE.name}")
        return

    if FAILED_FILE.exists():
        FAILED_FILE.unlink()

    atomic_json(COMBINED_FILE, combined)
    print(f"Complete: {len(cnrs)}/{len(cnrs)} cases available.")
    print(f"Combined JSON: {COMBINED_FILE.name}")
    print("Individual JSON: cnr/all/<CNR>.json")


if __name__ == "__main__":
    main()
