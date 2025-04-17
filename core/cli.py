# cli.py
import argparse
import logging
import shutil

# Importált konstans a payload útvonalhoz
from config.settings import DEFAULT_XSS_PAYLOAD_PATH

logger = logging.getLogger(__name__)

def parse_args():
    epilog_text = """
Pipeline operation:
  1. Queries domains from the crt.sh certificate log.
  2. Checks whether the domains are live (HTTP response: 200/301/302).
  3. Gathers URLs from live domains:
     - gau (GetAllUrls)
     - waybackurls (Internet Archive)
     - hakrawler (JS & link crawler).
  4. Sends XSS payloads to each URL and checks if they are reflected.
  5. Saves the results in JSON format.

The search scans crt.sh logs using wildcard characters (%.tld).

Required tools (Go needed):
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/hakluke/hakrawler@latest
  export PATH=$PATH:$(go env GOPATH)/bin

Example run:
  python3 pipeline_v2.py --target uniqa.hu --payloads payloads/XSS/blind.txt --no-check-cert
  python3 pipeline_v2.py --tld hu --limit 10 --max-errors 6
"""
    parser = argparse.ArgumentParser(
        description="🔥 domain Recon + XSS pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text
    )
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for the scanner (default: 10)")
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of domains to process (default: 50)")
    parser.add_argument("--out", type=str, default="hu_report.json", help="JSON report filename (default: hu_report.json)")
    parser.add_argument("--tld", type=str, default="hu", help="Domain TLD (e.g. hu, com, xyz, dev, all). Any value allowed.")
    parser.add_argument("--tools-check", action="store_true", help="Check if required Go tools are installed (gau, waybackurls, hakrawler, rich)")
    parser.add_argument("--no-check-cert", action="store_true", help="Do not verify SSL certificates")
    parser.add_argument("--use-cache", action="store_true", help="Use cached crt.sh response (if available)")
    parser.add_argument("--target", type=str, help="Target a specific domain (e.g. uniqa.hu)")
    parser.add_argument(
        "--payloads",
        type=str,
        default=str(DEFAULT_XSS_PAYLOAD_PATH),
        help=f"Path to XSS payload file (default: {DEFAULT_XSS_PAYLOAD_PATH})"
    )
    parser.add_argument("--max-errors", type=int, default=5, help="Max errors per domain before skipping (default: 5)")
    parser.add_argument("--max-hits", type=int, default=None, help="Maximum number of XSS findings per domain (default: unlimited)")
    parser.add_argument(
        "--html-report",
        nargs="?",
        const="auto",
        default=None,
        help=(
            "Generate HTML report from the findings (only if any found).\n"
            "If used without value: auto-names the report (e.g. output/YYYYMMDD_report.html).\n"
            "If you provide a filename: saves the HTML report there.\n"
            "Example: --html-report or --html-report custom_report.html"
        )
    )
    return parser.parse_args()

def check_required_tools():
    print("[*] Checking required tools in PATH...\n")
    tools = ["gau", "waybackurls", "hakrawler"]
    all_ok = True
    for tool in tools:
        path = shutil.which(tool)
        if path:
            print(f"✅ {tool} found: {path}")
        else:
            print(f"❌ {tool} NOT installed or not in PATH!")
            all_ok = False

    print("\n[*] Checking Python modules...\n")
    try:
        import rich
        print("✅ rich module installed")
    except ImportError:
        print("❌ The 'rich' module is NOT installed!")
        print("👉 To install: pip install rich")
        all_ok = False

    if not all_ok:
        print("\n[!] At least one required component is missing.")
        print("👉 To install, use the following commands:\n")
        print("  go install github.com/lc/gau/v2/cmd/gau@latest")
        print("  go install github.com/tomnomnom/waybackurls@latest")
        print("  go install github.com/hakluke/hakrawler@latest")
        print("  export PATH=$PATH:$(go env GOPATH)/bin")
        print("  pip install rich\n")
    else:
        print("\n🎉 All required tools and modules are available, ready to start the scan!\n")