import socket
import re

def fetch_ip_history(ip, token):
    """جلب تاريخ البلوك من Spamhaus SIA بدقة"""
    if not token:
        return []
    
    # الرابط الرسمي لـ IP History
    url = f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/ALL/listed/history/{ip}?limit=50"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # Spamhaus كترد results وسط Object
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            elif isinstance(data, list):
                return data
        return []
    except Exception as e:
        print("Error fetching IP history:", e)
        return []

@app.route('/scan_ip', methods=['POST'])
def scan_ips():
    data = request.get_json() or {}
    raw_ips = data.get('ips', '')

    items = [i.strip() for i in raw_ips.split('\n') if i.strip()]
    token = get_auth_token()
    results = []

    for item in items:
        clean = item.replace("https://", "").replace("http://", "").split("/")[0]

        # إذا دخل المستخدم دومين، كنجبدو الـ IP ديالو أوتوماتيك
        target_ip = clean
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean):
            try:
                target_ip = socket.gethostbyname(clean)
            except Exception:
                target_ip = None

        if not target_ip:
            results.append({
                "ip": clean,
                "dataset": "DNS Resolution Failed",
                "first_seen": "N/A",
                "last_seen": "N/A",
                "status": "Could not resolve IP",
                "threat": "Invalid Domain / Host"
            })
            continue

        history_records = fetch_ip_history(target_ip, token) if token else []

        if history_records:
            now_ts = datetime.utcnow().timestamp()
            for rec in history_records:
                # Spamhaus fields: listed, seen, valid_until
                valid_until = rec.get("valid_until", 0)
                is_active = (valid_until and valid_until > now_ts) or rec.get("active", False)

                results.append({
                    "ip": target_ip,
                    "dataset": rec.get("dataset", "XBL/SBL"),
                    "first_seen": format_ts(rec.get("listed") or rec.get("first-seen") or rec.get("timestamp")),
                    "last_seen": format_ts(rec.get("seen") or rec.get("last-seen")),
                    "status": "Active (Listed)" if is_active else "Expired (Clean)",
                    "threat": f"Listed in {rec.get('dataset', 'Spamhaus')} (ASN: {rec.get('asn', 'N/A')})"
                })
        else:
            # إذا ما كاين حتى سطر فـ آخر 12 شهر
            results.append({
                "ip": target_ip,
                "dataset": "ALL",
                "first_seen": "N/A",
                "last_seen": "Not Observed",
                "status": "Clean",
                "threat": "No Historical Listings in past 12 months"
            })

    return jsonify({"data": results})
