#settings.py
from pathlib import Path

# Default payload fájl-útvonalak
DEFAULT_XSS_PAYLOAD_PATH = Path("payloads/XSS/reflected.txt")
DEFAULT_LFI_PAYLOAD_PATH = Path("payloads/LFI/traversal.txt")
DEFAULT_SQLI_PAYLOAD_PATH = Path("payloads/SQLI/basic.txt")
DEFAULT_SSRF_PAYLOAD_PATH = Path("payloads/SSRF/basic.txt")

# Alapértelmezett mappák
OUTPUT_DIR = Path("output")
CACHE_DIR_NAME = "cache"