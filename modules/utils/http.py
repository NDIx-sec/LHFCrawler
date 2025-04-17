# http.py
import requests

def is_live(domain):
    try:
        for proto in ('https://', 'http://'):
            url = proto + domain
            r = requests.get(url, timeout=5)
            if r.status_code in (200, 301, 302):
                return url
    except Exception:
        return None
    return None
