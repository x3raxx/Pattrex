# Pattrex — blazing-fast log pattern extractor (CLI)

Color palette: **primary** `#cd853f`, **background** `#faf4f2`. Uses [rich] to render them.

## Features

- Extract: emails, IPv4, IPv6, URLs (http/https), MD5/SHA1/SHA256, Base64 blobs, usernames, suspicious file extensions (.exe/.php/…), Windows/Linux paths.
- Filters: internal vs external IPs.
- Detectors: SQLi attempts, credentials (`password=...`), JavaScript XSS indicators (raw/HTML/percent-encoded), HTTP methods (GET|POST|PUT|HEAD|DELETE).
- Regex power-ups: lookaheads, lookbehinds, alternation, groups; all implemented with the `regex` module.
- Speed: multiprocessing across CPU cores; compiled patterns; streaming-friendly.
- UX: colorized table summary and sectioned output; output to stdout or `-o` file.
- Error handling: robust reads with encoding auto-detect.

## Install

### Linux / macOS / Windows (Python 3.9+)
```bash
pip install -r requirements.txt
cd pattrex
sudo ln -s $(pwd)/pattrex.py /usr/local/bin/pattrex
sudo chmod +x /usr/local/bin/pattrex

```

> If you want a global command:
```bash
python pattrex.py --help
# or
python -m pattrex.cli --help
```

## Usage

Examples:
```bash
# Emails -> file
python pattrex.py --email logs.txt -o logs_emails.txt

# URLs and hashes
python pattrex.py --urls --hashes logs.txt -o urls_and_hashes.txt

# External IPv4 only
python pattrex.py --ipv4 --external-ips logs.txt

# HTTP vs HTTPS
python pattrex.py --http logs.txt
python pattrex.py --https logs.txt

# IPv4 + Usernames in one go (separate sections)
python pattrex.py --ips-and-users --ipv4 --username logs.txt -o ips_users.txt

# Detect XSS & SQLi
python pattrex.py --xss --sqli web_access.log -o attacks.txt

# Everything
python pattrex.py --all huge.log -o everything.txt
```

## Add new extractors (future-proof design)

Open `pattrex/patterns.py` and add your compiled regex to the `ALL` map:
```python
MY_NEW = regex.compile(r"...")
ALL["my_new"] = MY_NEW
```
Then expose a CLI flag in `pattrex/cli.py` by adding to `FEATURE_KEYS`:
```python
"mynew": "my_new"
```
That's it — auto-wired into the multiprocessing scanner.

## Notes on Internal vs External IPs

- Internal IPv4: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16.
- Internal IPv6: fc00::/7, fe80::/10, ::1.

## XSS detection

We match raw and encoded payloads (`<script>`, `onerror=`, `javascript:`), `%3cscript`, `&lt;script`, `svg on*=` etc., with lookarounds to reduce false positives.

## Error Handling

- Input file missing → friendly message, exit code 2
- Unknown feature flag → message showing the invalid key
- Encoding detection fallback (UTF-8→Latin-1) to avoid crashes

## License
MIT (adjust if you prefer).


---

## 🧷 Tee (print + save) and Live Streaming
- **Default tee:** When you pass `-o/--out`, Pattrex now **prints to terminal** and **saves to file**.
- **Live streaming:** print matches as they are found (single-process):
```bash
python pattrex.py --email --xss web.log --stream -o hits.txt
```
This streams matches in a live table and writes the final deduped sections to `hits.txt`.


## View + Save at the same time

- Print to terminal **and** save to a file:
```bash
python pattrex.py --email logs.txt -o emails.txt --tee
```

## Live Streaming Mode
- Print matches **as they are found** (line-by-line). Also appends to `-o` if provided:
```bash
python pattrex.py --all logs.txt --stream -o live_out.txt
```
