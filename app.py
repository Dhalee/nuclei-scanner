"""Nuclei teaching scanner. Serve locally; scan only allowed origins."""
import json
import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, render_template, request

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "nuclei-templates" / "http-missing-security-headers.yaml"
RESULTS = ROOT / "results"
DEFAULT_ORIGINS = "http://127.0.0.1:8000,http://localhost:8000"
# The four headers checked by the bundled template (matcher names in the YAML).
CHECKED_HEADERS = [
    "x-content-type-options",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
]
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096


def origin(value):
    if not value or len(value) > 2048 or any(c.isspace() or c == "\\" for c in value):
        raise ValueError("Use one HTTP(S) URL without spaces or backslashes.")
    try:
        u = urlsplit(value)
        if (u.scheme not in ("http", "https") or not u.hostname
                or u.username is not None or u.password is not None
                or u.fragment or "%" in u.netloc or u.hostname.endswith(".")):
            raise ValueError("Invalid HTTP(S) URL, credentials, or fragment.")
        return u.scheme, u.hostname.lower(), u.port or (443 if u.scheme == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid HTTP(S) target URL or port.") from exc


def validate_target(target):
    candidate = origin(target)
    allowed = set()
    entries = os.environ.get("ALLOWED_ORIGINS", DEFAULT_ORIGINS)
    for item in entries.split(","):
        item = item.strip()
        if not item:
            continue
        u = urlsplit(item)
        if u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("ALLOWED_ORIGINS must contain exact origins, not paths.")
        allowed.add(origin(item))
    if candidate not in allowed:
        raise ValueError("Target not authorized. Only scan explicitly allowed laboratory origins.")
    return target


def scan_target(target):
    if not TEMPLATE.is_file():
        raise RuntimeError("Bundled Nuclei template is missing.")
    RESULTS.mkdir(parents=True, exist_ok=True)
    scan_id = uuid.uuid4().hex
    output = RESULTS / ("scan_" + scan_id + ".jsonl")
    # Nuclei exits 0 even when the target is unreachable, so request errors
    # are written to a separate log and checked after the scan.
    error_log = RESULTS / ("scan_" + scan_id + ".errors.jsonl")
    cmd = [
        os.environ.get("NUCLEI_BIN", "nuclei"), "-u", target,
        "-t", str(TEMPLATE), "-jsonl", "-o", str(output), "-elog", str(error_log),
        "-c", "1", "-rl", "1", "-timeout", "10", "-retries", "0",
        "-silent", "-duc", "-ni", "-no-color", "-dr", "-no-stdin",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=45)
    except FileNotFoundError as exc:
        raise RuntimeError("Nuclei not found. Check PATH or NUCLEI_BIN.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nuclei exceeded the 45-second scan limit.") from exc
    except OSError as exc:
        raise RuntimeError("Cannot start Nuclei: " + str(exc)) from exc

    message = (proc.stderr or "").strip()[:3000]
    if proc.returncode:
        raise RuntimeError("Nuclei failed (exit " + str(proc.returncode) + "): " + message)
    request_errors = read_error_log(error_log)
    if request_errors:
        raise RuntimeError("Nuclei could not check the target: " + "; ".join(request_errors)
                           + ". Is the practice website running?")
    findings = []
    if output.is_file():
        try:
            with output.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        finding = json.loads(line)
                        if not isinstance(finding, dict):
                            raise ValueError("JSONL item is not an object")
                        findings.append(finding)
        except (OSError, ValueError) as exc:
            raise RuntimeError("Invalid Nuclei JSONL output: " + str(exc)) from exc
    return findings, message


def read_error_log(path):
    """Return the request error messages Nuclei logged (empty list if none)."""
    if not path.is_file():
        return []
    errors = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    text = item.get("error", "") if isinstance(item, dict) else ""
                except ValueError:
                    text = line.strip()
                errors.append(str(text or "unknown request error")[:300])
    except OSError as exc:
        return ["cannot read Nuclei error log: " + str(exc)]
    return list(dict.fromkeys(errors))[:5]


def summarize_headers(findings):
    """Return one row per checked header: Missing if Nuclei reported it, else Present.

    Only called after a successful scan, so "Present" means the template ran
    and its matcher for that header did not fire.
    """
    missing = {str(f.get("matcher-name", "")).lower() for f in findings}
    rows = [{"header": h, "status": "Missing" if h in missing else "Present"}
            for h in CHECKED_HEADERS]
    missing_count = sum(1 for r in rows if r["status"] == "Missing")
    return {"rows": rows, "missing": missing_count, "total": len(CHECKED_HEADERS)}


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/scan")
def scan():
    target = request.form.get("target", "").strip()
    try:
        validate_target(target)
    except ValueError as exc:
        return render_template("index.html", target=target, error=str(exc)), 400
    try:
        findings, stderr = scan_target(target)
    except RuntimeError as exc:
        return render_template("index.html", target=target, error=str(exc)), 502
    return render_template("index.html", target=target, findings=findings,
                           summary=summarize_headers(findings),
                           stderr=stderr, completed=True)


if __name__ == "__main__":
    from waitress import serve
    serve(app, host="127.0.0.1", port=int(os.environ.get("PORT", "10000")))
