from flask import Flask, render_template, request, jsonify
import whois
import dns.resolver
from datetime import datetime

app = Flask(__name__)

def get_domain_info(domain):
    data = {
        "domain": domain,
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tags": "Normal",
        "abused": False,
        "whois": {"created": "N/A", "expires": "N/A", "registrar": "N/A"},
        "score": 10.0,
        "cluster_auth": "N/A"
    }
    
    # 1. Whois Check
    try:
        w = whois.whois(domain)
        data["whois"]["registrar"] = str(w.registrar) if w.registrar else "Unknown"
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expires = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        data["whois"]["created"] = str(created) if created else "N/A"
        data["whois"]["expires"] = str(expires) if expires else "N/A"
    except Exception:
        data["whois"]["registrar"] = "Whois Protected / Error"

    # 2. DNS Check (A Record)
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [rdata.to_text() for rdata in answers]
        data["cluster_auth"] = ips[0] if ips else "N/A"
    except Exception:
        data["cluster_auth"] = "No A Record"
        data["score"] = 50.0  # كيطلع الشك إلا ما كانش عندو DNS

    return data

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    req_data = request.get_json()
    raw_domains = req_data.get('domains', '')
    
    # تفريق الدومينات بسطر بسطر
    domains = [d.strip() for d in raw_domains.split('\n') if d.strip()]
    results = []
    
    for d in domains:
        # مسح https:// و / إلا كانو زايدين
        clean_d = d.replace("https://", "").replace("http://", "").split("/")[0]
        results.append(get_domain_info(clean_d))
        
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
