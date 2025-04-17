# pipeline.py
import json
import threading
import logging
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.domain_discovery import get_crtsh_domains
from modules.url_collector import run_gau, run_waybackurls, run_hakrawler
from modules.scanners.xss import scan_xss
from modules.utils.helpers import filter_query_urls
from core.reporting import save_reports

logger = logging.getLogger(__name__)

def collect_urls(domain):
    """URL-ek gyűjtése több forrásból és szűrése."""
    urls = []
    urls.extend(run_gau(domain))
    urls.extend(run_waybackurls(domain))
    urls.extend(run_hakrawler(domain))
    return filter_query_urls(urls, domain)


def process_xss_scan(domain, urls, payloads, no_check_cert, max_errors, max_findings, workers=5, print_func=None):
    """Egy domain URL-jeinek XSS tesztelése párhuzamosan."""
    findings = []
    lock = threading.Lock()
    error_count = 0
    hit_count = 0
    stop_event = threading.Event()

    def test_url(url):
        nonlocal error_count, hit_count
        if stop_event.is_set():
            return
        try:
            finding = scan_xss(url, payloads, no_check_cert)
        except Exception:
            with lock:
                error_count += 1
                if error_count >= max_errors:
                    stop_event.set()
            return
        if finding:
            finding["domain"] = domain
            with lock:
                if max_findings is None or hit_count < max_findings:
                    findings.append(finding)
                    hit_count += 1
                    if print_func:
                        print_func(f"[!!!] {domain} VULN: {finding['vulnerable_url']}")
                    if max_findings is not None and hit_count >= max_findings:
                        stop_event.set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(test_url, url): url for url in urls}
        for future in as_completed(futures):
            if stop_event.is_set():
                break
    return findings if findings else None


def make_status_table(scan_status, status_lock):
    """Rich táblázat összeállítása a domain státuszokról."""
    from rich.table import Table
    from rich.text import Text

    table = Table(title="XSS Testing Status", expand=False)
    table.add_column("Domain", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta", no_wrap=True)
    with status_lock:
        for domain, status in scan_status.items():
            if status == "WAITING":
                status_text = Text("⏳ WAITING")
            elif status == "IN PROGRESS":
                status_text = Text("🔄 IN PROGRESS")
            elif status == "DONE":
                status_text = Text("✅ DONE")
            else:
                status_text = Text(status)
            table.add_row(domain, status_text)
    return table


def run_pipeline(domains, threads=10, out_file="report.json", no_check_cert=False, max_errors=5, payloads=None, html_report=None, max_findings=None):
    """Fő munkafolyamat: CRT lekérdezés, URL gyűjtés párhuzamosan, XSS teszt és riport mentés."""
    #  CRT lekérdezés
    domains = get_crtsh_domains(
        domain_tld=domains if isinstance(domains, str) else None,
        limit=len(domains) if isinstance(domains, list) else None,
        use_cache=False
    ) if not isinstance(domains, list) else domains

    logger.info(f"[*] Querying crt.sh for: {domains if isinstance(domains, str) else 'multiple'} targets")
    logger.info(f"[*] {len(domains)} Processing Domains using {threads} threads...\n")

    # 1) URL gyűjtés párhuzamosan
    domain_url_map = {}

    def collect_task(domain):
        # Kiírjuk, hogy elindult az URL-gyűjtés
        print(f"[*] URL collection: {domain}")
        urls = collect_urls(domain)
        # Kiírjuk, hogy hány endpoint jött vissza
        print(f"[*] {domain}: {len(urls)} endpoint found")
        return domain, urls

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {executor.submit(collect_task, d): d for d in domains}
        for future in as_completed(future_to_domain):
            domain, urls = future.result()
            domain_url_map[domain] = urls

    # 2) Státuszok inicializálása
    status_lock = Lock()
    scan_status = {d: "WAITING" for d in domain_url_map}
    findings = []

    # 3) Rich Live támogatása
    try:
        from rich.live import Live
        live_enabled = True
    except ImportError:
        live_enabled = False

    # 4) XSS tesztelés
    if live_enabled:
            shutdown_requested = False
            executor = ThreadPoolExecutor(max_workers=threads)
            try:
                with Live(make_status_table(scan_status, status_lock), refresh_per_second=4) as live:
                    future_to_domain = {}
                    # indítjuk a XSS scan munkákat
                    for domain, urls in domain_url_map.items():
                        with status_lock:
                            scan_status[domain] = "IN PROGRESS"
                        live.update(make_status_table(scan_status, status_lock))
                        future = executor.submit(
                            process_xss_scan,
                            domain, urls, payloads,
                            no_check_cert, max_errors,
                            max_findings, threads,
                            live.console.print
                        )
                        future_to_domain[future] = domain

                    # gyűjtjük és frissítjük a státuszokat
                    for future in as_completed(future_to_domain):
                        domain = future_to_domain[future]
                        try:
                            result = future.result()
                            if result:
                                findings.extend(result)
                        except Exception:
                            pass
                        with status_lock:
                            scan_status[domain] = "DONE"
                        live.update(make_status_table(scan_status, status_lock))
            except KeyboardInterrupt:
                # csak jelöljük, ne itt nyomtassuk
                shutdown_requested = True
                executor.shutdown(wait=False, cancel_futures=True)
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

            # Live blokk után, a tábla lezárása után írjuk ki
            if shutdown_requested:
                print("[*] Shutdown requested (Ctrl+C). Exiting gracefully...")
                return
    else:
        executor = ThreadPoolExecutor(max_workers=threads)
        future_to_domain = {
            executor.submit(
                process_xss_scan,
                domain, urls, payloads,
                no_check_cert, max_errors,
                max_findings, threads,
                print
            ): domain
            for domain, urls in domain_url_map.items()
        }
        try:
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                result = future.result()
                if result:
                    for f in result:
                        findings.append(f)
        except KeyboardInterrupt:
            print("[*] Shutdown requested (Ctrl+C). Exiting gracefully...")
            executor.shutdown(wait=False, cancel_futures=True)
            return
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    # 5) Összesítés és riport mentése
    total = len(findings)
    logger.info(f"[*] Total findings: {total}")
    if findings:
        counts = {}
        for f in findings:
            counts[f["domain"]] = counts.get(f["domain"], 0) + 1
        for domain, count in counts.items():
            logger.info(f"  - {domain}: {count} findings")

    save_reports(findings, out_file, html_report)