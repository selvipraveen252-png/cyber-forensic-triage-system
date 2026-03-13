import requests
import config

def get_ip_details(ip_address):
    """Fetch IP intelligence from IPinfo."""
    url = f"https://ipinfo.io/{ip_address}/json"
    params = {
        'token': config.IPINFO_API_KEY
    }
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"IPinfo API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
