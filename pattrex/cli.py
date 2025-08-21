#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Set, Dict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from .fileio import read_text_safely
from .extractors import build_selected, collect_matches, post_filter_ips
from . import patterns
from pattrex.patterns import feature_map


APP_THEME = Theme({
    "primary": "#cd853f",
    "bg": "#faf4f2",
    "ok": "green",
    "warn": "yellow",
    "err": "red",
})

console = Console(theme=APP_THEME)

FEATURE_KEYS = {
    "email": "email",
    "ips": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "urls": "url",
    "http": "http",
    "https": "https",
    "hashes": None,
    "base64": "base64",
    "malware": "malicious_ext",
    "httpmethods": "http_method",
    "sqli": "sqli",
    "creds": "creds",
    "winpath": "winpath",
    "linuxpath": "linuxpath",
    "username": "username",
    "xss": "xss",
    "catdog": "cat_dog",
    "lookahead": "lookahead_ex",
    "neglookahead": "neg_lookahead_ex",
    "lookbehind": "lookbehind_ex",
}

HASH_KEYS = ["md5", "sha1", "sha256"]


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="pattrex"
    )
    p.add_argument("file", help="Input log file to scan")
    p.add_argument("-o", "--out", help="Write results to this file (and also print when --tee or --stream)")
    # feature flags
    for flag in FEATURE_KEYS:
        p.add_argument(f"--{flag}", action="store_true", help=f"Extract {flag}")
    p.add_argument("--all", action="store_true", help="Run all extractors")
    p.add_argument("--ips-and-users", dest="ips_and_users", action="store_true", help="Extract IPs and Usernames together (printed in separate sections)")
    # output style
    p.add_argument("--tee", action="store_true", help="Print results AND write to file (if -o given)")
    p.add_argument("--stream", action="store_true", help="Stream matches line-by-line while scanning (also writes when -o given)")
    p.add_argument("--external-ips", action="store_true", help="Only external (public) IPv4/IPv6")
    p.add_argument("--internal-ips", action="store_true", help="Only internal (private) IPv4/IPv6")
    return p.parse_args(argv)


def gather_features(ns, feature_map):
    feature_keys = []
    if ns.all:
        return list(feature_map.keys())

    for cli_flag, fmap_key in FEATURE_KEYS.items():
        if getattr(ns, cli_flag.replace("-", "_"), False):
            if fmap_key:
                feature_keys.append(fmap_key)
    return feature_keys


def write_output_always(outpath: str | None, content: str, also_print: bool) -> None:
    if outpath:
        Path(outpath).write_text(content, encoding="utf-8")
        console.print(f"[ok]Saved output to[/ok] [primary]{outpath}[/primary]")
    if also_print or not outpath:
        console.print(content)


def format_section(title, items):
    if not items:
        return ""
    body = "\n".join(sorted(set(map(str, items))))
    return f"\n{title}:\n{body}"



def stream_scan(text: str, feature_keys: List[str], outpath: str | None) -> int:
    # Simple streaming scan (single-process) for immediate feedback
    pats: Dict[str, object] = {}
    for k in feature_keys:
        pat, _desc = feature_map[k]
        if isinstance(pat, patterns.re.Pattern):
            pats[k] = pat
        else:
            pats[k] = patterns.re.compile(str(pat))

    count_map: Dict[str, int] = {k: 0 for k in feature_keys}
    out_lines = []
    for line in text.splitlines():
        for k, pat in pats.items():
            for m in pat.finditer(line):
                val = m.groupdict().get("username") if (k == "username" and m.groupdict()) else m.group(0)
                count_map[k] += 1
                msg = f"[primary]{k}[/primary]: {val}"
                console.print(msg)
                out_lines.append(val)
                if outpath:
                    with open(outpath, "a", encoding="utf-8") as f:
                        f.write(val + "\n")
    # summary
    table = Table(title="Pattrex Stream Summary", show_lines=True, border_style="primary")
    table.add_column("Extractor", style="primary")
    table.add_column("Count", style="ok")
    for k in feature_keys:
        table.add_row(k, str(count_map[k]))
    console.print(table)
    return 0


def main(argv: List[str] | None = None) -> int:
    ns = parse_args(argv or sys.argv[1:])
    infile = ns.file
    try:
        text = read_text_safely(infile, return_encoding=False)
    except Exception as e:
        console.print(Panel.fit(f"[err]Error reading file:[/err] {e}", border_style="err"))
        return 2

    feature_keys = gather_features(ns, feature_map)

    if not feature_keys:
        console.print(Panel.fit("[warn]No extractors selected. Use flags like --email, --ipv4, --urls, or --all[/warn]", border_style="warn"))
        return 2

    want_groups = "username" in feature_keys

    console.print(Panel.fit(f"Pattrex scanning [primary]{infile}[/primary] with {len(feature_keys)} extractor(s)...",
                            style="bg"))

    if ns.stream:
        return stream_scan(text, feature_keys, ns.out)

    try:
        compiled = build_selected(feature_keys)
    except KeyError as e:
        console.print(Panel.fit(f"[err]{e}[/err]", border_style="err"))
        return 2

    matches = collect_matches(text, compiled, want_groups=want_groups)

    # Post-filters for IPs
    for key in ["ipv4", "ipv6"]:
        if key in matches and (ns.external_ips or ns.internal_ips):
            mode = "external" if ns.external_ips else "internal"
            matches[key] = post_filter_ips(matches[key], mode)

    # Special combo: --ips-and-users
    if ns.ips_and_users:
        ipv4s = matches.get("ipv4", [])
        users = matches.get("username", [])
        content = format_section("IPv4", ipv4s) + format_section("Usernames", users)
        write_output_always(ns.out, content, also_print=True)
        return 0

    # Summary table
    table = Table(title="Pattrex Results", show_lines=True, border_style="primary")
    table.add_column("Extractor", style="primary")
    table.add_column("Count", style="ok")
    for k in feature_keys:
        table.add_row(k, str(len(matches.get(k, []))))
    console.print(table)

    # Build sectioned output
    content_parts = []
    for k in feature_keys:
        items = matches.get(k, [])
        if not items:
            continue
        content_parts.append(format_section(k.upper(), items))
    out_text = "\n".join(content_parts) if content_parts else "No matches found."

    write_output_always(ns.out, out_text, also_print=ns.tee)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
