import os
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SIA_USERNAME = os.getenv("SIA_USERNAME", "mtrmdgrl@75848703")
SIA_PASSWORD = os.getenv("SIA_PASSWORD", "q7QmIbkYzVN/Vw=p")

def format_ts(ts):
    """تحويل Unix Timestamp لتاريخ عادي بحال التصويرة"""
    if not ts or ts == "N/A":
        return "N/A"
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)

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
        print("Login failed:", r.status_code, r.text)
        return None
    except Exception as e:
        print("Login error:", e)
        return None

def fetch_domain_data(domain):
    token = get_auth_token()
    if not token:
        return {"status": "auth_error", "message": "Check SIA Username / Password in Render"}

    # الرابط الصحيح الرسمي v2 للدومينات
    url = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)
        
        # إذا لقا المعطيات
        if r.status_code == 200:
            return {"status": "success", "data": r.json()}
        
        # إذا كان الدومين ما مسجلش فـ قاعدة بيانات السبام ديالهم (Clean)
        elif r.status_code == 404:
            return {"status": "clean", "data": {
                "domain": domain,
                "last-seen": None,
                "tags": ["clean", "not_listed"],
                "abused": False,
                "score": 0,
                "whois": {"registrar": "Not in Spamhaus DB / Clean"},
                "clusters": {"auth": "N/A"}
            }}
        else:
            return {"status": "error", "message": f"API error code {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
        res = fetch_domain_data(clean)

        if res["status"] in ["success", "clean"]:
            d = res["data"]
            whois_info = d.get("whois") or {}
            
            # استخراج المعطيات بنفس أسماء حقول Spamhaus الرسمية
            results.append({
                "domain": clean,
                "last_seen": format_ts(d.get("last-seen")),
                "tags": d.get("tags", []),
                "abused": d.get("abused", False),
                "whois": {
                    "created": format_ts(whois_info.get("created")),
                    "expires": format_ts(whois_info.get("expires")),
                    "registrar": whois_info.get("registrar", "N/A")
                },
                "score": d.get("score", 0),
                "clusters": (d.get("clusters") or {}).get("auth", "N/A")
            })
        else:
            results.append({
                "domain": clean,
                "last_seen": "Error",
                "tags": ["error"],
                "abused": False,
                "whois": {"created": "N/A", "expires": "N/A", "registrar": res["message"]},
                "score": 0,
                "clusters": "N/A"
            })

    return jsonify({"mode": mode, "data": results})

if __name__ == '__main__':
    app.run(debug=True)
