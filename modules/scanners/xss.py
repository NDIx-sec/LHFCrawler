# xss.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def scan_xss(url, payloads, no_check_cert=False):
    verify_ssl = not no_check_cert
    parsed = urlparse(url)
    original_qs = parse_qs(parsed.query)
    if not original_qs:
        return None

    for payload in payloads:
        injected_qs = {k: [payload] for k in original_qs}
        new_query = urlencode(injected_qs, doseq=True)
        injected_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        try:
            r = requests.get(injected_url, timeout=6, verify=verify_ssl)
            if payload in r.text:
                return {"vulnerable_url": injected_url, "payload": payload}
        except requests.exceptions.RequestException:
            # fallback HTTPS
            if injected_url.startswith("http://"):
                sec = injected_url.replace("http://", "https://", 1)
                try:
                    r2 = requests.get(sec, timeout=6, verify=verify_ssl)
                    if payload in r2.text:
                        return {"vulnerable_url": sec, "payload": payload}
                except Exception:
                    pass
    return None
