# url_collector.py
import subprocess

def run_gau(domain):
    try:
        result = subprocess.run(["gau", domain], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return list(set(result.stdout.decode().splitlines()))
    except Exception as e:
        print(f"[!] GAU error for {domain}: {e}")
        return []

def run_waybackurls(domain):
    try:
        result = subprocess.run(["waybackurls", domain], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return list(set(result.stdout.decode().splitlines()))
    except Exception as e:
        print(f"[!] waybackurls error for {domain}: {e}")
        return []

def run_hakrawler(domain):
    try:
        result = subprocess.run(["hakrawler", "-url", f"https://{domain}", "-depth", "2"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return list(set(result.stdout.decode().splitlines()))
    except Exception as e:
        print(f"[!] hakrawler error for {domain}: {e}")
        return []
