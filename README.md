# LFI / Path Traversal Scanner

A Python-based automated scanner for detecting Local File Inclusion (LFI) and Path Traversal vulnerabilities in web applications. Built for use in authorized bug bounty programs and penetration testing engagements.

> ⚠️ **Legal Disclaimer**: This tool is intended for use **only** on systems you own or have explicit written permission to test. Unauthorized use against systems you do not own is illegal. The author assumes no liability for misuse.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setup — Wordlists](#setup--wordlists)
- [Usage](#usage)
- [Arguments](#arguments)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [Output](#output)
- [Detection Logic](#detection-logic)
- [Project Structure](#project-structure)
- [Bug Bounty Notes](#bug-bounty-notes)

---

## Features

- Automatically identifies path-traversal-prone parameters from a URL list
- Injects payloads into GET parameters and tests each combination
- **Early stop per param** — stops fuzzing a parameter the moment a vulnerability is confirmed, saving time and reducing noise
- **Response intelligence** — classifies findings by severity (CRITICAL / HIGH / MEDIUM / LOW) with labeled indicators
- **Baseline comparison** — compares response size before and after injection to catch anomalies without a known indicator match
- **Structured JSON output** — every finding logged as a JSON object with full context
- **Rate limiting with jitter** — randomized delay between requests to avoid detection and respect target infrastructure
- **Custom User-Agent** — pass any UA string via CLI, required by most bug bounty programs
- **Threading** — concurrent requests via `ThreadPoolExecutor` for faster scans
- Cross-platform — works on Windows, Linux, and macOS

---

## Requirements

- Python 3.10+
- `requests` library

Install dependencies:

```bash
pip install requests
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourhandle/path-traversal-scanner.git
cd path-traversal-scanner
```

---

## Setup — Wordlists

This repository does **not** bundle wordlists to respect third-party licenses and keep the repo lightweight. Download your payload list manually and place it in the project directory.

**Recommended sources:**

- [payloadbox/rfi-lfi-payload-list](https://github.com/payloadbox/rfi-lfi-payload-list)
- [danielmiessler/SecLists — LFI](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)

**Quick download:**

```bash
# Linux / macOS
curl -o path_injec.txt https://raw.githubusercontent.com/payloadbox/rfi-lfi-payload-list/master/RFI-LFI-payload-list.txt
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/payloadbox/rfi-lfi-payload-list/master/RFI-LFI-payload-list.txt" -OutFile "path_injec.txt"
```

---

## Usage

### Basic

```bash
python path_traversal.py <urls_file> <payloads_file>
```

### With custom User-Agent (required by most bug bounty programs)

```bash
python path_traversal.py urls.txt path_injec.txt --user-agent "bugbounty-yourhandle/1.0"
```

### Short flag

```bash
python path_traversal.py urls.txt path_injec.txt -ua "bugbounty-yourhandle/1.0"
```

### Examples

```bash
# Windows
python path_traversal.py C:\recon\urls.txt C:\recon\path_injec.txt -ua "myhandle-bugbounty/1.0"

# Linux
python path_traversal.py ~/recon/urls.txt ~/recon/path_injec.txt -ua "myhandle-bugbounty/1.0"
```

---

## Arguments

| Argument | Required | Description |
|---|---|---|
| `urls` | ✅ | Path to a `.txt` file containing one URL per line |
| `payloads` | ✅ | Path to a `.txt` file containing one payload per line |
| `--user-agent` / `-ua` | ❌ | Custom User-Agent string. Defaults to a Chrome UA if not provided |

---

## Configuration

You can tune the following constants at the top of `path_traversal.py`:

| Constant | Default | Description |
|---|---|---|
| `THREADS` | `10` | Number of concurrent worker threads |
| `DELAY_MIN` | `1.0` | Minimum seconds between requests per thread |
| `JITTER` | `1.0` | Max random extra seconds added on top of `DELAY_MIN` |
| `VULN_JSON` | `confirmed_vulns.json` | Output file for structured findings |

**Effective request rate:**

With `DELAY_MIN=1.0` and `JITTER=1.0`, each thread waits 1–2 seconds between requests. With `THREADS=10` this gives a maximum of roughly 5–10 requests per second — conservative enough for most targets.

To slow down further (e.g. very sensitive targets):

```python
DELAY_MIN = 2.0
JITTER    = 2.0
THREADS   = 5
```

---

## How It Works

```
urls.txt
   │
   ▼
Parse query string
   │
   ▼
Filter params matching KEYWORDS list  ──► no matching params → skip URL
   │
   ▼
GET baseline response (original URL)
   │
   ▼
For each matching param:
   │
   ├── Already confirmed vulnerable? ──► SKIP (early stop)
   │
   └── For each payload:
         │
         ├── Already confirmed by another thread? ──► BREAK
         │
         ├── Inject payload into param
         │
         ├── Send GET request (with throttle + jitter)
         │
         └── Analyze response:
               ├── Indicator matched?   ──► VULN  → log + write JSON + mark confirmed
               ├── Size anomaly >500B?  ──► SIZE? → log + write JSON
               └── Nothing             ──► OK    → log only
```

---

## Output

### Console + Log file (`lfi_scan.log`)

```
2026-03-24 01:45:01 [INFO]    Loaded 120 URLs and 87 payloads.
2026-03-24 01:45:01 [INFO]    User-Agent: bugbounty-handle/1.0
2026-03-24 01:45:01 [INFO]    Rate limit: 1.0s + up to 1.0s jitter between requests.
2026-03-24 01:45:03 [INFO]    [OK]              200 | param='page' | payload='../etc/passwd' | size_diff=0 | url=...
2026-03-24 01:45:05 [INFO]    [VULN [CRITICAL]] 200 | param='file' | payload='../../../../etc/passwd' | size_diff=1423 | url=...
2026-03-24 01:45:05 [WARNING] [!!!] CRITICAL — ETC_PASSWD | evidence='root:x:' | https://target.com/view?file=../../../../etc/passwd
2026-03-24 01:45:05 [INFO]    [SKIP] Already confirmed vuln: param='file' | https://target.com/view?file=index.php
```

### Findings file (`confirmed_vulns.json`)

One JSON object per line (JSONL format):

```json
{
  "timestamp": "2026-03-24T01:45:05Z",
  "url": "https://target.com/view?file=../../../../etc/passwd",
  "original_url": "https://target.com/view?file=index.php",
  "param": "file",
  "payload": "../../../../etc/passwd",
  "evidence": "root:x:",
  "label": "ETC_PASSWD",
  "severity": "CRITICAL",
  "status_code": 200,
  "size_change": 1423,
  "snippet": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1..."
}
```

**Filter findings with `jq`:**

```bash
# Only CRITICAL
jq 'select(.severity == "CRITICAL")' confirmed_vulns.json

# All confirmed params
jq '{url, param, payload, severity}' confirmed_vulns.json

# Unique vulnerable URLs
jq -r '.original_url' confirmed_vulns.json | sort -u
```

---

## Detection Logic

The scanner classifies responses using a layered approach:

### Indicator matching

| Label | Severity | Triggers on |
|---|---|---|
| `ETC_PASSWD` | CRITICAL | `root:x:`, `daemon:x:`, `bin/bash`, `bin/sh` |
| `BOOT_INI` | CRITICAL | `[boot loader]` |
| `WIN_INI` | CRITICAL | `for 16-bit app`, `[fonts]` |
| `WIN_PATH_LEAK` | CRITICAL / HIGH | `\windows\system32`, `\windows\`, `c:\` |
| `UNIX_PATH_LEAK` | HIGH / MEDIUM | `/home/`, `/etc/`, `/var/` |
| `PHP_INCLUDE_ERROR` | HIGH | `failed to open stream`, `Warning: include`, `Warning: require` |
| `PHP_BASEDIR` | MEDIUM | `open_basedir restriction` |
| `FILE_NOT_FOUND` | MEDIUM | `No such file` |

### Size anomaly

If no indicator is matched but the response length differs by more than 500 bytes from the baseline, the finding is flagged as `SIZE_ANOMALY` with severity `LOW` — useful for catching cases where the app leaks data without standard error strings.

---

## Project Structure

```
path-traversal-scanner/
├── path_traversal.py     # Main scanner
├── urls.txt              # Your target URLs (one per line, gitignored)
├── path_injec.txt        # Payload wordlist (one per line, gitignored)
├── lfi_scan.log          # Full scan log (generated at runtime)
├── confirmed_vulns.json  # Structured findings (generated at runtime)
└── README.md
```

**`.gitignore` (recommended):**

```
*.txt
*.log
*.json
!README.md
```

---

## Bug Bounty Notes

- Always pass a custom `--user-agent` matching the format required by the program's policy
- Only run this tool against in-scope targets
- Keep `DELAY_MIN` and `JITTER` at a reasonable level — DoSing a target is out of scope in every program
- `confirmed_vulns.json` gives you a clean, copy-pasteable report format for submissions
- Double-check SIZE_ANOMALY findings manually before reporting — they are lower confidence
