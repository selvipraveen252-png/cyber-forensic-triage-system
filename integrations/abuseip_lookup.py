import requests
import config

def check_ip_abuse(ip_address):
    """Check AbuseIPDB for IP reputation."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': config.ABUSEIPDB_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"AbuseIPDB API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
