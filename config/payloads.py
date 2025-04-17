# payloads.py
import logging
from pathlib import Path

from config.settings import DEFAULT_XSS_PAYLOAD_PATH

logger = logging.getLogger(__name__)

def load_payloads(path: Path = DEFAULT_XSS_PAYLOAD_PATH):
    payload_file = Path(path)
    try:
        if not payload_file.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")
        with payload_file.open(encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        logger.info(f"[+] {len(payloads)} XSS payload(s) loaded from: {path}")
        return payloads
    except Exception as e:
        logger.warning(f"[!] Failed to load payloads: {e}")
        logger.warning("[!] Using default payloads instead.")
        return [
            "<script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>"
        ]
