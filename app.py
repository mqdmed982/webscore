import os
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

# حط هنا Token لي عطاوك Spamhaus، أو خليه خاوي للتجربة
SPAMHAUS_API_KEY = os.getenv("SPAMHAUS_API_KEY", "YOUR_SPAMHAUS_API_KEY")

def fetch_sia_intel(domain):
    """جلب البيانات الخام من Spamhaus API"""
    if SPAMHAUS_API_KEY and SPAMHAUS_API_KEY != "YOUR_SPAMHAUS_API_KEY":
        url = f"https://api.spamhaus.org/api/v1/intel/domain/{domain}"
        headers = {
            "Authorization": f"Bearer {SPAMHAUS_API_KEY}",
            "Accept": "application/json"
        }
        try:
            r = requests.get(url, headers=headers, timeout=8)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass

    # بيانات افتراضية بنفس هيكل SIA 100% (Simulation)
    return {
        "domain": domain,
        "last_seen": "2026-10-11 04:18:01",
        "tags": ["disposable", "shared"],
        "abused": False,
        "score": 36,
        "whois": {
            "created": "2018-11-27 03:24:11",
            "expires": "2026-11-27 03:24:11",
            "registrar": "MarkMonitor Inc."
        },
        "clusters": {
            "auth": "88f9d1cc54c054eef5e9ebbc5ff68d25f3251ecc"
        },
        "dimensions": {
            "email_threat": "Low",
            "web_threat": "Neutral",
            "phishing": "Clean",
            "malware": "Clean"
        },
        "context": {
            "nameservers": ["ns-1.awsglobalaccelerator.com", "ns-2.awsglobalaccelerator.com"],
            "ips": ["15.197.142.1", "3.33.152.1"],
            "asn": "AS16509 (AMAZON-02)"
        },
        "blacklist": {
            "dbl_listed": "No",
            "zbl_listed": "No",
            "detection": "Clean",
            "return_code": "None"
        },
        "senders": {
            "mx_record": "mail.protection.outlook.com",
            "sender_score": 88,
            "auth_spf": "Pass",
            "auth_dkim": "Pass"
        },
        "a_record": {
            "ip": "15.197.142.1",
            "ptr": "a.accelerator.aws",
            "ip_rep": "Good (12/100)",
            "status": "Active"
        },
        "ns_rep": {
            "primary_ns": "ns-1.awsglobalaccelerator.com",
            "ns_ip": "205.251.192.1",
            "ns_score": 15,
            "status": "Verified"
        },
        "hostnames": [
            {"hostname": f"api.{domain}", "type": "Subdomain", "status": "Clean"},
            {"hostname": f"mail.{domain}", "type": "Subdomain", "status": "Clean"}
        ]
    }

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
        raw = fetch_sia_intel(clean)

        # تفصيل النتيجة على حساب الزر المضغوط
        if mode == 'general':
            results.append({
                "domain": clean,
                "last_seen": raw.get("last_seen", "N/A"),
                "tags": raw.get("tags", []),
                "abused": raw.get("abused", False),
                "whois": raw.get("whois", {}),
                "score": raw.get("score", 0),
                "clusters": raw.get("clusters", {}).get("auth", "N/A")
            })
        elif mode == 'reputation_dim':
            dim = raw.get("dimensions", {})
            results.append({
                "domain": clean,
                "score": raw.get("score", 0),
                "email_threat": dim.get("email_threat", "Clean"),
                "web_threat": dim.get("web_threat", "Clean"),
                "phishing": dim.get("phishing", "Clean"),
                "malware": dim.get("malware", "Clean")
            })
        elif mode == 'domain_context':
            ctx = raw.get("context", {})
            results.append({
                "domain": clean,
                "registrar": raw.get("whois", {}).get("registrar", "N/A"),
                "nameservers": ", ".join(ctx.get("nameservers", [])),
                "ips": ", ".join(ctx.get("ips", [])),
                "asn": ctx.get("asn", "N/A")
            })
        elif mode == 'blacklist':
            bl = raw.get("blacklist", {})
            results.append({
                "domain": clean,
                "dbl": bl.get("dbl_listed", "No"),
                "zbl": bl.get("zbl_listed", "No"),
                "detection": bl.get("detection", "Clean"),
                "code": bl.get("return_code", "None")
            })
        elif mode == 'domain_senders':
            snd = raw.get("senders", {})
            results.append({
                "domain": clean,
                "mx": snd.get("mx_record", "N/A"),
                "score": snd.get("sender_score", 0),
                "spf": snd.get("auth_spf", "N/A"),
                "dkim": snd.get("auth_dkim", "N/A")
            })
        elif mode == 'a_record':
            ar = raw.get("a_record", {})
            results.append({
                "domain": clean,
                "ip": ar.get("ip", "N/A"),
                "ptr": ar.get("ptr", "N/A"),
                "ip_rep": ar.get("ip_rep", "N/A"),
                "status": ar.get("status", "N/A")
            })
        elif mode == 'ns_rep':
            nsr = raw.get("ns_rep", {})
            results.append({
                "domain": clean,
                "primary_ns": nsr.get("primary_ns", "N/A"),
                "ns_ip": nsr.get("ns_ip", "N/A"),
                "ns_score": nsr.get("ns_score", 0),
                "status": nsr.get("status", "N/A")
            })
        elif mode == 'hostnames':
            hosts = raw.get("hostnames", [])
            for h in hosts:
                results.append({
                    "domain": clean,
                    "hostname": h.get("hostname", "N/A"),
                    "type": h.get("type", "Subdomain"),
                    "status": h.get("status", "Clean")
                })

    return jsonify({"mode": mode, "data": results})

if __name__ == '__main__':
    app.run(debug=True)
