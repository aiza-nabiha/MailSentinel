import requests

def check_reputation(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(url, headers=headers, params=params)
    data = resp.json().get("data", {})
    return {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "risk_flag": data.get("abuseConfidenceScore", 0) > 50
    }