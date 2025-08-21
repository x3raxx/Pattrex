"""
patterns.py

This module provides a collection of precompiled regular expressions for extracting and detecting
common patterns in log files, security data, and text streams. Patterns include usernames, IP addresses,
URLs, emails, hashes, file paths, HTTP methods, SQL injection attempts, credentials, and more.

Usage:
    - Import the `ALL` or `feature_map` dictionary to access all patterns and their descriptions.
    - Each entry in `ALL` maps a string key to a tuple: (compiled_regex, description).
    - Example:
        from patterns import ALL
        ipv4_pattern, desc = ALL["ipv4"]
        matches = ipv4_pattern.findall(some_text)

Exports:
    - ALL: Main mapping of pattern names to (compiled_regex, description).
    - feature_map: Alias for ALL.
"""

import regex
from typing import Dict, Tuple, Pattern

# ----- Core building blocks -----
# Username (common log styles: sshd, web, app)
USERNAME = regex.compile(
    r"""(?ix)
    (?:
        user(?:name)?\s*[=:]\s* | # key=value style
        for\s+ | by\s+ | login\s+from\s+ | account\s+
    )
    (?P<username>[a-z0-9_.-]{2,64})
    """
)

# IPv4 precise (0-255 segments), extracted with word boundaries
IPV4 = regex.compile(r"""
    (?<!\d)
    (?:25[0-5]|2[0-4]\d|1?\d?\d)
    (?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}
    (?!\d)
""", regex.VERBOSE)

# IPv6 (simplified but robust)
IPV6 = regex.compile(r"""
    (?xi)
    \b
    (?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|
    (?:[0-9a-f]{1,4}:){1,7}:|
    (?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|
    (?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|
    (?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|
    (?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|
    (?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|
    [0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|
    :(?:(?::[0-9a-f]{1,4}){1,7}|:)|
    fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-z]+|
    ::(ffff(:0{1,4}){0,1}:){0,1}
    (?:(25[0-5]|(2[0-4]|1{0,1}\d){0,1}\d)\.){3,3}
    (25[0-5]|(2[0-4]|1{0,1}\d){0,1}\d)|
    (?:[0-9a-f]{1,4}:){1,4}:
    (?:(25[0-5]|(2[0-4]|1{0,1}\d){0,1}\d)\.){3,3}
    (25[0-5]|(2[0-4]|1{0,1}\d){0,1}\d)
    \b
""")

# URLs (split by scheme flags)
URL = regex.compile(r"""(?xi)
    \bhttps?://[^\s"'<>()\[\]{}]+
""")

HTTP_ONLY = regex.compile(r"""(?xi)\bhttp://[^\s"'<>()\[\]{}]+""")
HTTPS_ONLY = regex.compile(r"""(?xi)\bhttps://[^\s"'<>()\[\]{}]+""")

# Emails (fixed extractor)
EMAIL = regex.compile(r"""
    (?ix)
    <?"?                      # optional < or "
    [a-z0-9._%+\-]+           # local part
    @
    [a-z0-9.-]+               # domain name
    \. [a-z]{2,}               # TLD
    >"?                       # optional > or "
""")

# Hashes (MD5/SHA1/SHA256)
MD5  = regex.compile(r"(?i)\b[a-f0-9]{32}\b")
SHA1 = regex.compile(r"(?i)\b[a-f0-9]{40}\b")
SHA256 = regex.compile(r"(?i)\b[a-f0-9]{64}\b")

# Base64 blobs (conservative; 16+ chars)
BASE64_BLOB = regex.compile(r"(?i)\b(?:[A-Za-z0-9+/]{16,}={0,2})\b")

# File paths (Windows & Linux)
WIN_PATH = regex.compile(r"""(?x)
    \b
    (?:[a-zA-Z]:\\\\|\\\\\\\\)[^\s:*?"<>|]+
""")
LINUX_PATH = regex.compile(r"""(?x)
    (?<!\w)/(?:[^\s'"]+/?)+
""")

# HTTP methods (GET|POST|PUT|HEAD|DELETE) using group alternation
HTTP_METHOD = regex.compile(r"""(?i)\b(GET|POST|PUT|HEAD|DELETE)\b""")

# SQLi attempt (case-insensitive)
SQLI = regex.compile(r"""(?i)\b(?:union\s+select|or\s+1=1|sleep\(\d+\)|database\(\))\b""")

# Credentials key=value
CREDENTIALS = regex.compile(r"""(?i)\bpassword\s*=\s*[^;&\s]+""")

# Malicious file extensions
MALICIOUS_EXT = regex.compile(r"""(?i)\b[^\s]+?\.(?:exe|php|jsp|aspx|ps1|vbs|bat|scr)\b""")

# Alternation demo (cat|dog)
CAT_DOG = regex.compile(r"\b(cat|dog)\b", regex.I)
HTTP_METHOD_GROUP = HTTP_METHOD  # alias

# Lookarounds examples
LOOKAHEAD_EX = regex.compile(r"""(?ix)\badmin(?=\s*[:=])""")
NEG_LOOKAHEAD_EX = regex.compile(r"""(?ix)\bpassword(?!\s*masked)""")
LOOKBEHIND_EX = regex.compile(r"""(?ix)(?<=\buser=)[^&\s]+""")

# HTML method tokens (GET|POST)
HTTP_VERB_IN_LINE = HTTP_METHOD

# JavaScript XSS filters
XSS = regex.compile(r"""(?ix)
    (?:
        (?:(?:&lt;|%3c|<)\s*/?\s*script(?:&gt;|%3e|>)) |
        (?:(?:&lt;|%3c|<)\s*img[^>]+onerror\s*=\s*) |
        (?:onerror\s*=\s*) |
        (?:onload\s*=\s*)
    )
    |
    (?:
        j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:
        |
        (?:j%[0-9a-f]{2}){4,}:%?
    )
    |
    (?:
        on\w+\s*=\s*(?:alert|prompt|confirm)\s*\(
    )
    |
    (?:
        (?:(?<=<)|(?<=&lt;))\s*svg[^>]+on\w+\s*=
    )
""")

# Public map
ALL: Dict[str, Tuple[Pattern, str]] = {
    "username": (USERNAME, "Extract usernames from logs (e.g., user=alice, by bob)"),
    "ipv4": (IPV4, "Match IPv4 addresses (e.g., 192.168.1.1)"),
    "ipv6": (IPV6, "Match IPv6 addresses (e.g., fe80::1)"),
    "url": (URL, "Match all HTTP/HTTPS URLs"),
    "http": (HTTP_ONLY, "Match HTTP URLs only (http://...)"),
    "https": (HTTPS_ONLY, "Match HTTPS URLs only (https://...)"),
    "email": (EMAIL, "Extract email addresses"),
    "md5": (MD5, "Match MD5 hashes (32 hex characters)"),
    "sha1": (SHA1, "Match SHA1 hashes (40 hex characters)"),
    "sha256": (SHA256, "Match SHA256 hashes (64 hex characters)"),
    "base64": (BASE64_BLOB, "Extract Base64 blobs (16+ chars)"),
    "winpath": (WIN_PATH, "Detect Windows file paths (e.g., C:\\path\\file.txt)"),
    "linuxpath": (LINUX_PATH, "Detect Linux/Unix file paths (e.g., /var/log/syslog)"),
    "http_method": (HTTP_METHOD, "Match HTTP request methods (GET, POST, etc.)"),
    "sqli": (SQLI, "Detect common SQL injection attempts"),
    "creds": (CREDENTIALS, "Detect password assignments (e.g., password=secret)"),
    "malicious_ext": (MALICIOUS_EXT, "Detect files with potentially malicious extensions"),
    "cat_dog": (CAT_DOG, "Match the words 'cat' or 'dog' (case-insensitive)"),
    "lookahead_ex": (LOOKAHEAD_EX, "Match 'admin' only if followed by ':' or '='"),
    "neg_lookahead_ex": (NEG_LOOKAHEAD_EX, "Match 'password' not followed by 'masked'"),
    "lookbehind_ex": (LOOKBEHIND_EX, "Extract value after 'user='"),
    "xss": (XSS, "Detect JavaScript/XSS payloads and obfuscations"),
}

feature_map: Dict[str, Tuple[Pattern, str]] = ALL

def _selftest() -> None:
    for key, (pat, desc) in ALL.items():
        assert hasattr(pat, "search") and callable(pat.search), f"{key} is not a compiled regex"
        assert isinstance(desc, str) and desc, f"{key} description missing"

__all__ = ["ALL", "feature_map"]
