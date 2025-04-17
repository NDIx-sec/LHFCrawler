# LHFCrawler (Low Hanging Fruit Crawler)

## Overview

LHFCrawler is a Python-based pipeline for automated domain reconnaissance and reflected XSS vulnerability testing. It queries public certificate transparency logs (crt.sh), gathers URLs from discovered domains using multiple open-source tools, and scans those URLs for reflected XSS vulnerabilities using custom payloads.

In addition to automatic domain and URL discovery, LHFCrawler also supports manually defined individual domains for targeted and automated domain reconnaissance and reflected XSS vulnerability testing.

## Key Features

- Collects domains from crt.sh using wildcard patterns
- Detects live domains via HTTP/HTTPS status code checks
- Collects URLs via:
  - `gau` (GetAllUrls)
  - `waybackurls` (Internet Archive)
  - `hakrawler` (JavaScript-aware crawler)
- Injects XSS payloads into URL parameters
- Detects reflections of payloads in responses
- Multithreaded for high performance
- JSON and HTML report generation
- CLI-friendly with detailed argument options

## Installation

### Prerequisites

- Python 3.7 or newer
- Go (required for URL collection tools)

### Installation Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/NDIX-sec/LFHCrawler.git
   cd LHFCrawler
   ```

2. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Install Go-based tools:

   ```bash
   go install github.com/lc/gau/v2/cmd/gau@latest
   go install github.com/tomnomnom/waybackurls@latest
   go install github.com/hakluke/hakrawler@latest
   export PATH=$PATH:$(go env GOPATH)/bin
   ```

## Usage

### Test Specific URLs

You can test custom URLs directly by providing a domain with a `--target` flag or pointing the tool to a local file or custom URL feed source.

This is useful for:

- Retesting URLs found in a previous scan
- Manually collected or known vulnerable endpoints

_Example usage will depend on the specific integration or customization — plugin support for this is part of future plans._

### Basic Usage

```bash
python3 LHFCrawler.py --tld hu --limit 20
```

### Scan a Specific Domain

```bash
python3 LHFCrawler.py --target example.com --payloads payloads/XSS/blind.txt
```

### Generate HTML Report Automatically

```bash
python3 LHFCrawler.py --tld com --html-report
```

### Disable SSL Certificate Checks

```bash
python3 LHFCrawler.py --tld xyz --no-check-cert
```

### Check if Tools Are Installed

```bash
python3 LHFCrawler.py --tools-check
```

## Options

```bash
--threads        Number of threads (default: 10)
--limit          Maximum number of domains to process (default: 50)
--out            Output JSON report file name
--tld            Domain suffix to scan (e.g. hu, com, xyz, all)
--tools-check    Checks if required tools (gau, hakrawler, etc.) are installed
--no-check-cert  Skip SSL certificate verification
--use-cache      Use cached crt.sh responses
--target         Target a specific domain
--payloads       File containing XSS payloads
--max-errors     Max errors per domain before skipping (default: 5)
--max-hits       Max XSS hits per domain (default: unlimited)
--html-report    Generate HTML report (auto or custom filename)
```

## Output

Reports are saved in the `output/` directory. Examples:

- `20250416_report.json`
- `20250416_report.html`

## Payload Format

XSS payloads are loaded from a simple text file:

```txt
"><script>alert(1)</script>
<svg/onload=alert(1)>
```

## Performance Tips

- Increase `--threads` for faster scanning on multi-core systems
- Use `--limit` to avoid scanning too many domains
- Use caching (`--use-cache`) for faster repeat runs

## Future Plans

### HTML Report Enhancements

- Interactive filtering: show only selected domain/payload
- CSV / Excel export alongside `report.json` and `report.html`

### Modular Scanner Architecture

- `--scan xss,sqli`: run only selected modules
- `--plugins-dir plugins/`: load custom PoC plugins dynamically

### Performance Options

- `--timeout 5`: request timeout in seconds
- `--delay 0.1`: delay in seconds between each request
- `--rate-limit 100`: limit requests per second

### Authentication / Session Support

- `--cookie "PHPSESSID=abc"`: session cookie injection
- `--headers "User-Agent: xyz"`: full header override
- `--login-script login.py`: use custom login script for auth

### Vulnerability Proof Modes

- `--proofmode alert`: use `alert(1)` as proof
- `--proofmode beacon`: send beacon to custom endpoint (e.g. `https://xss.ndix.local/log.php`)

## License

MIT License

## Author

Developed by NDIx
