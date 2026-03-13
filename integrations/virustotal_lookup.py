import requests
import config

def check_file_reputation(file_hash):
    """Check VirusTotal for file hash reputation."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Hash not found in VirusTotal"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_url_reputation(target_url):
    """Check VirusTotal for URL reputation."""
    # We need to encode the URL to base64 for the V3 API
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal URL API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
