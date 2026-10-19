import os
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# المعلومات لي طالعة عندك فـ التصويرة
SIA_USERNAME = os.getenv("SIA_USERNAME", "mtrmdgrl@75848703")
SIA_PASSWORD = os.getenv("SIA_PASSWORD", "حط_هنا_كلمة_السر_ديال_الحساب")

def get_auth_token():
    """تسجيل الدخول وجلب الـ Bearer Token"""
    login_url = "https://api.spamhaus.org/api/v1/login"
    payload = {
        "username": SIA_USERNAME,
        "password": SIA_PASSWORD,
        "realm": "intel"
    }
    try:
        r = requests.post(login_url, json=payload, timeout=10)
        if r.status_code == 200:
            return r.json().get("token")
        else:
            print("Login Failed:", r.text)
            return None
    except Exception as e:
        print("Login Exception:", e)
        return None

def fetch_domain_data(domain):
    token = get_auth_token()
    if not token:
        return {"error": "Authentication Failed. Check password!"}

    # الرابط الرسمي للاستعلام عن الدومين
    url = f"https://api.spamhaus.org/api/intel/v1/byobject/domain/{domain}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {"error": f"API returned status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    raw_domains = data.get('domains', '')
    mode = data.get('mode', 'general')

    domains = [d.strip() for d in raw_domains.split('\n') if d.strip()]
    results = []

    for domain in domains:
        clean = domain.replace("https://", "").replace("http://", "").split("/")[0]
        sia_data = fetch_domain_data(clean)

        # إذا كانت الداتا جاية مباشرة من Spamhaus
        if "error" not in sia_data:
            results.append({
                "domain": clean,
                "last_seen": sia_data.get("last_seen", "N/A"),
                "tags": sia_data.get("tags", []),
                "abused": sia_data.get("abused", False),
                "whois": sia_data.get("whois", {}),
                "score": sia_data.get("score", 0),
                "clusters": sia_data.get("clusters", {}).get("auth", "N/A")
            })
        else:
            # إذا وقع مشكل فكلمة السر
            results.append({
                "domain": clean,
                "last_seen": "Error",
                "tags": ["auth_error"],
                "abused": False,
                "whois": {"created": "N/A", "expires": "N/A", "registrar": sia_data["error"]},
                "score": 0,
                "clusters": "N/A"
            })

    return jsonify({"mode": mode, "data": results})

if __name__ == '__main__':
    app.run(debug=True)
