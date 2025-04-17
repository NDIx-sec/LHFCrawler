# LHFCrawler.py
#!/usr/bin/env python3
import logging
import warnings

from core.cli import parse_args, check_required_tools
from config.payloads import load_payloads
from modules.domain_discovery import get_crtsh_domains
from core.pipeline import run_pipeline

def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    if args.tools_check:
        check_required_tools()
        return

    if args.no_check_cert:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    payloads = load_payloads(args.payloads)

    if args.target:
        domains = [args.target]
    else:
        domains = get_crtsh_domains(
            domain_tld=args.tld,
            limit=args.limit,
            use_cache=args.use_cache
        )

    run_pipeline(
        domains=domains,
        threads=args.threads,
        out_file=args.out,
        no_check_cert=args.no_check_cert,
        max_errors=args.max_errors,
        payloads=payloads,
        html_report=args.html_report,
        max_findings=args.max_hits
    )

if __name__ == "__main__":
    main()
