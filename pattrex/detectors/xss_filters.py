
"""
XSS detector rules and helper utilities.
"""
from typing import Set, Iterable
import regex
import os


def load_payload_hints(filepath: str) -> list:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except Exception as e:
        print(f"Error loading XSS payload hints from {filepath}: {e}")
        return []

# Default payload path is in the same directory as this script
DEFAULT_PAYLOAD_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "payload.txt"
)

PAYLOAD_HINTS_PATH = os.environ.get("XSS_PAYLOAD_HINTS_PATH", DEFAULT_PAYLOAD_PATH)
PAYLOAD_HINTS = load_payload_hints(PAYLOAD_HINTS_PATH)

try:
    if PAYLOAD_HINTS:
        COMBINED = regex.compile("|".join(regex.escape(p) for p in PAYLOAD_HINTS))
    else:
        COMBINED = regex.compile("$^")  # matches nothing
except Exception as e:
    print(f"Error compiling XSS regex: {e}")
    COMBINED = regex.compile("$^")  # matches

def detect_xss(lines: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for line in lines:
        if isinstance(line, str) and COMBINED.search(line):
            out.add(line.strip())
    return out
