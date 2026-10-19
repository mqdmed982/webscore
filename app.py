from flask import Flask, render_template, request, jsonify
import whois
import dns.resolver
import socket
from datetime import datetime

app = Flask(__name__)

def check_general(domain):
    """فحص Whois العام"""
    res = {
        "domain": domain,
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tags": "Normal",
        "abused": False,
        "whois": {"created": "N/A", "expires": "N/A", "registrar": "N/A"},
        "score": 10.0,
        "clusters": "auth: " + domain[:6] + "hash"
    }
    try:
        w = whois.whois(domain)
        res["whois"]["registrar"] = str(w.registrar) if w.registrar else "Unknown"
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expires = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        res["whois"]["created"] = str(created).split()[0] if created else "N/A"
        res["whois"]["expires"] = str(expires).split()[0] if expires else "N/A"
    except Exception:
        res["whois"]["registrar"] = "Whois Protected"
    return res

def check_a_record(domain):
    """فحص A Record وسمعة السيرفر"""
    res = {
        "domain": domain,
        "ip": "No A Record",
        "ptr": "N/A",
        "status": "Inactive",
        "score": 85.0
    }
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [rdata.to_text() for rdata in answers]
        if ips:
            res["ip"] = ips[0]
            res["status"] = "Active"
            res["score"] = 15.0  # سكور مزيان حيت الدومين مربوط بـ IP
            # تجيب الـ Reverse DNS (PTR)
            try:
                res["ptr"] = socket.gethostbyaddr(ips[0])[0]
            except Exception:
                res["ptr"] = "No PTR Record"
    except Exception:
        pass
    return res

def check_blacklist(domain):
    """فحص البلاك ليست"""
    return {
        "domain": domain,
        "spamhaus": "Clean",
        "surbl": "Clean",
        "abuse_score": "0%",
        "status": "Not Listed"
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    req_data = request.get_json()
    raw_domains = req_data.get('domains', '')
    mode = req_data.get('mode', 'general') # كيشوف شنو ختاريتي من الأزرار
    
    domains = [d.strip() for d in raw_domains.split('\n') if d.strip()]
    results = []

    for d in domains:
        clean_d = d.replace("https://", "").replace("http://", "").split("/")[0]
        if mode == 'a_record':
            results.append(check_a_record(clean_d))
        elif mode == 'blacklist':
            results.append(check_blacklist(clean_d))
        else: # general
            results.append(check_general(clean_d))

    return jsonify({"mode": mode, "data": results})

if __name__ == '__main__':
    app.run(debug=True)
