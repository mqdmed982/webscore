import os
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SIA_USERNAME = os.getenv("SIA_USERNAME", "mtrmdgrl@75848703")
SIA_PASSWORD = os.getenv("SIA_PASSWORD", "")

def format_ts(ts):
    if not ts or ts == "N/A":
        return "N/A"
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)

def get_auth_token():
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
        return None
    except Exception:
        return None

def fetch_domain_senders(domain, token):
    """جلب قائمة الـ Senders الخاصة بالدومين من Spamhaus SIA"""
    url = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain}/senders"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json() # قائمة بـ IP, HELO, last-seen, score
        return []
    except Exception:
        return []

def fetch_domain_general(domain, token):
    url = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    raw_domains = data.get('domains', '')
    mode = data.get('mode', 'general')

    domains = [d.strip() for d in raw_domains.split('\n') if d.strip()]
    token = get_auth_token()
    results = []

    for domain in domains:
        clean = domain.replace("https://", "").replace("http://", "").split("/")[0]

        # 1. إذا اختار المستخدم "Domain Senders"
        if mode == 'domain_senders':
            senders = fetch_domain_senders(clean, token) if token else []
            if senders:
                for s in senders:
                    results.append({
                        "domain": clean,
                        "ip": s.get("ip", "N/A"),
                        "helo": s.get("helo") or "None",
                        "last_seen": format_ts(s.get("last-seen")),
                        "score": s.get("score", 0)
                    })
            else:
                # إذا كان الدومين ما عندوش Senders مسجلين
                results.append({
                    "domain": clean,
                    "ip": "No Senders Observed",
                    "helo": "None",
                    "last_seen": "N/A",
                    "score": 0
                })

        # 2. إذا اختار "General Overview"
        elif mode == 'general':
            d = fetch_domain_general(clean, token) if token else {}
            if d:
                whois_info = d.get("whois") or {}
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
                    "last_seen": "Clean / Not Observed",
                    "tags": ["clean"],
                    "abused": False,
                    "whois": {"created": "N/A", "expires": "N/A", "registrar": "N/A"},
                    "score": 0,
                    "clusters": "N/A"
                })

        # باقي الأزرار
        else:
            results.append({
                "domain": clean,
                "ip": "127.0.0.1",
                "helo": clean,
                "last_seen": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                "score": 0
            })

    return jsonify({"mode": mode, "data": results})

if __name__ == '__main__':
    app.run(debug=True)
