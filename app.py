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
        r = requests.post(login_url, json=payload, timeout=8)
        if r.status_code == 200:
            return r.json().get("token")
        return None
    except Exception:
        return None

def fetch_sia(endpoint, token):
    if not token:
        return None
    url = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{endpoint}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

def fetch_ip_history(ip, token):
    """جلب تاريخ البلاك ليست (History) الخاص بالـ IP من Spamhaus"""
    if not token:
        return []
    # الرابط الرسمي لـ IP History عبر جميع قوائم Spamhaus
    url = f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/ALL/listed/history/{ip}?limit=50"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            return r.json()
        return []
    except Exception:
        return []

@app.route('/')
def index():
    return render_template('index.html')

# فحص الدومينات
@app.route('/scan', methods=['POST'])
def scan_domains():
    data = request.get_json() or {}
    raw_domains = data.get('domains', '')
    mode = data.get('mode', 'general')

    domains = [d.strip() for d in raw_domains.split('\n') if d.strip()]
    token = get_auth_token()
    results = []

    for domain in domains:
        clean = domain.replace("https://", "").replace("http://", "").split("/")[0]

        if mode == 'general':
            res = fetch_sia(f"{clean}", token) or {}
            whois_info = res.get("whois") or {}
            results.append({
                "domain": clean,
                "last_seen": format_ts(res.get("last-seen")),
                "tags": res.get("tags") or ["clean"],
                "abused": res.get("abused", False),
                "whois": {
                    "created": format_ts(whois_info.get("created")),
                    "expires": format_ts(whois_info.get("expires")),
                    "registrar": whois_info.get("registrar", "Not Listed / Clean")
                },
                "score": res.get("score", 0),
                "clusters": (res.get("clusters") or {}).get("auth", "N/A")
            })

        elif mode == 'reputation_dim':
            res = fetch_sia(f"{clean}", token) or {}
            score = res.get("score", 0)
            threat = "High" if score > 70 else ("Medium" if score > 30 else "Low")
            results.append({
                "domain": clean,
                "score": score,
                "email_threat": "Listed" if res.get("abused") else threat,
                "web_threat": "Suspicious" if "suspicious" in (res.get("tags") or []) else "Clean",
                "phishing": "Malicious" if "phishing" in (res.get("tags") or []) else "Clean",
                "malware": "Malicious" if "malware" in (res.get("tags") or []) else "Clean"
            })

        elif mode == 'domain_senders':
            senders = fetch_sia(f"{clean}/senders", token)
            if isinstance(senders, list) and len(senders) > 0:
                for s in senders:
                    results.append({
                        "domain": clean,
                        "ip": s.get("ip", "N/A"),
                        "helo": s.get("helo") or "None",
                        "last_seen": format_ts(s.get("last-seen")),
                        "score": s.get("score", 0)
                    })
            else:
                results.append({
                    "domain": clean,
                    "ip": "No Senders Observed",
                    "helo": "None",
                    "last_seen": "N/A",
                    "score": 0
                })

        else:
            # معالجة افتراضية لباقي الأزرار
            res = fetch_sia(f"{clean}", token) or {}
            results.append({
                "domain": clean,
                "last_seen": format_ts(res.get("last-seen")),
                "tags": res.get("tags") or ["clean"],
                "abused": res.get("abused", False),
                "whois": {"created": "N/A", "expires": "N/A", "registrar": "N/A"},
                "score": res.get("score", 0),
                "clusters": "N/A"
            })

    return jsonify({"mode": mode, "data": results})

# فحص الـ IPs و الـ History
@app.route('/scan_ip', methods=['POST'])
def scan_ips():
    data = request.get_json() or {}
    raw_ips = data.get('ips', '')
    mode = data.get('mode', 'history')

    ips = [i.strip() for i in raw_ips.split('\n') if i.strip()]
    token = get_auth_token()
    results = []

    for ip in ips:
        clean_ip = ip.strip()
        history_records = fetch_ip_history(clean_ip, token) if token else []

        if history_records and isinstance(history_records, list):
            for rec in history_records:
                results.append({
                    "ip": clean_ip,
                    "dataset": rec.get("dataset", "XBL/SBL"),
                    "first_seen": format_ts(rec.get("first-seen") or rec.get("timestamp")),
                    "last_seen": format_ts(rec.get("last-seen")),
                    "status": "Listed" if rec.get("active") else "Expired (Clean)",
                    "code": rec.get("return-code", "127.0.0.2"),
                    "threat": rec.get("threat-type", "Spam / Botnet Activity")
                })
        else:
            # إذا ما كاينش History مسجل لداك الـ IP
            results.append({
                "ip": clean_ip,
                "dataset": "ALL (Clean)",
                "first_seen": "N/A",
                "last_seen": "Not Observed",
                "status": "Clean",
                "code": "None",
                "threat": "No Historical Listings"
            })

    return jsonify({"data": results})

if __name__ == '__main__':
    app.run(debug=True)
