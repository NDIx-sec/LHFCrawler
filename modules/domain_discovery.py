# domain_discovery.py
import json
import time
from pathlib import Path
import requests
from config.settings import CACHE_DIR_NAME

# A cache könyvtár létrehozása, ha nincs
CACHE_DIR = Path(CACHE_DIR_NAME)
CACHE_DIR.mkdir(exist_ok=True)

def get_crtsh_domains(domain_tld="hu", limit=100, max_retries=3, use_cache=False):
    cache_file = CACHE_DIR / f"crtsh_{domain_tld}.json"

    # 1) Ha cache-t kérünk és létezik a fájl, onnan töltünk
    if use_cache and cache_file.exists():
        print(f"[*] Loading cache file: {cache_file}")
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return data[:limit]
        except Exception as e:
            print(f"[!] Failed reading cache: {e}")

    # 2) Egyébként lekérdezzük a crt.sh-t
    print(f"[*] Querying crt.sh for: {domain_tld} targets")
    query = "*" if domain_tld.lower() == "all" else f"%25.{domain_tld}"
    url = f"https://crt.sh/?q={query}&output=json"
    retries = 0

    while retries < max_retries:
        try:
            r = requests.get(url, timeout=30)
            if r.status_code != 200 or not r.text.strip().startswith(("[", "{")):
                retries += 1
                time.sleep(5 * retries)
                continue

            data = json.loads(r.text)
            domains = set()
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    if domain_tld.lower() == "all" or name.endswith(f".{domain_tld}"):
                        domains.add(name.strip())
                        if len(domains) >= limit:
                            break
            domain_list = list(domains)[:limit]

            # 3) Cache mentése
            try:
                cache_file.write_text(json.dumps(domain_list, indent=2), encoding="utf-8")
                print(f"[+] Cache saved: {cache_file}")
            except Exception as e:
                print(f"[!] Failed to save cache: {e}")

            return domain_list

        except Exception as e:
            print(f"[!] crt.sh request error: {e}")
            retries += 1
            time.sleep(5 * retries)

    print(f"[X] crt.sh request error after {max_retries} retries.")
    return []
