from __future__ import annotations
from typing import Dict, List, Any, Optional
import regex as re


def build_selected(feature_keys):
    """
    Given feature keys, return dict of {key: compiled_regex}.
    """
    from pattrex.patterns import feature_map
    compiled: Dict[str, re.Pattern] = {}

    for k in feature_keys:
        pat, _desc = feature_map[k]   # feature_map[k] = (pattern, description)

        if isinstance(pat, re.Pattern):
            compiled[k] = pat
        else:
            compiled[k] = re.compile(str(pat))

    return compiled


def collect_matches(
    text: str,
    compiled: Dict[str, re.Pattern],
    want_groups: bool = False
) -> Dict[str, List[Any]]:
    """
    Run all compiled extractors on the given text and return matches.

    - If want_groups=False → return simple list of matches
    - If want_groups=True  → return list of group dictionaries per match
    """
    results: Dict[str, List[Any]] = {}

    for key, regex_obj in compiled.items():
        if want_groups and regex_obj.groupindex:  
            # return dictionaries of named groups
            matches = [m.groupdict() for m in regex_obj.finditer(text)]
        else:
            # return full matches (avoid findall group issue)
            matches = [m.group(0) for m in regex_obj.finditer(text)]

        if matches:
            results[key] = matches

    return results



def post_filter_ips(ips: List[str], mode: Optional[str] = None) -> List[str]:
    """
    Filter out invalid IP addresses.
    If mode == "internal" → keep only private ranges.
    If mode == "external" → keep only public ranges.
    """
    valid_ips: List[str] = []
    for ip in ips:
        try:
            parts = ip.split(".")
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                if mode == "internal":
                    if (ip.startswith("10.") or
                        ip.startswith("192.168.") or
                        ip.startswith("172.")):
                        valid_ips.append(ip)
                elif mode == "external":
                    if not (ip.startswith("10.") or
                            ip.startswith("192.168.") or
                            ip.startswith("172.")):
                        valid_ips.append(ip)
                else:
                    valid_ips.append(ip)
        except ValueError:
            continue
    return valid_ips
