import copy
import json
import logging
import argparse
import time
import random
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ── Logging: file + console ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("lfi_scan.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ── Keywords ──────────────────────────────────────────────────────────────────
KEYWORDS = [
    "file", "filename", "filepath", "file_path", "file_name",
    "path", "pathname", "dir", "directory", "folder", "location",
    "url", "page", "doc", "document", "docs", "load", "read",
    "download", "open", "fetch", "get", "retrieve", "view", "show",
    "display", "content", "data", "src", "source", "include",
    "require", "import", "template", "layout", "theme", "style",
    "skin", "lang", "language", "locale", "resource", "res",
    "asset", "lib", "conf", "config", "cfg", "ini", "log", "logs",
    "report", "img", "image", "pdf", "csv", "xml", "json", "module",
    "plugin", "component", "widget", "action", "cat", "category",
    "name", "base", "base_path", "root", "home", "prefix", "suffix",
    "ext", "type", "format", "ref", "href", "link", "redirect",
    "return", "next", "target", "dest", "destination", "goto",
    "forward", "back", "returnurl", "return_url", "redirect_url",
    "next_url", "inc", "section", "dispatch", "handler",
    "virtualpath", "static", "attachment", "tmpl", "option",
]

# ── Detection signatures ──────────────────────────────────────────────────────
# Each entry: (indicator_string, label, severity)
INDICATORS = [
    # Linux / Unix
    ("root:x:",                 "ETC_PASSWD",        "CRITICAL"),
    ("daemon:x:",               "ETC_PASSWD",        "CRITICAL"),
    ("bin/bash",                "ETC_PASSWD",        "CRITICAL"),
    ("bin/sh",                  "ETC_PASSWD",        "CRITICAL"),
    ("/home/",                  "UNIX_PATH_LEAK",    "HIGH"),
    # Windows
    ("[boot loader]",           "BOOT_INI",          "CRITICAL"),
    ("for 16-bit app",          "WIN_INI",           "CRITICAL"),
    ("\\windows\\system32",     "WIN_PATH_LEAK",     "CRITICAL"),
    ("\\windows\\",             "WIN_PATH_LEAK",     "HIGH"),
    ("[fonts]",                 "WIN_INI",           "HIGH"),
    # App / framework errors
    ("failed to open stream",   "PHP_INCLUDE_ERROR", "HIGH"),
    ("warning: include",        "PHP_INCLUDE_ERROR", "HIGH"),
    ("warning: require",        "PHP_INCLUDE_ERROR", "HIGH"),
    ("no such file",            "FILE_NOT_FOUND",    "MEDIUM"),
    ("open_basedir restriction","PHP_BASEDIR",        "MEDIUM"),
    # Generic path leaks
    ("c:\\",                    "WIN_PATH_LEAK",     "MEDIUM"),
    ("/etc/",                   "UNIX_PATH_LEAK",    "MEDIUM"),
    ("/var/",                   "UNIX_PATH_LEAK",    "MEDIUM"),
]

# ── Config ────────────────────────────────────────────────────────────────────
VULN_JSON = "confirmed_vulns.json"
THREADS   = 10
DELAY_MIN = 1.0   # minimum seconds between requests per thread
JITTER    = 1.0   # max random extra on top

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ── Shared state for early stop ───────────────────────────────────────────────
confirmed    = set()
confirmed_lk = Lock()

# ── Thread-safe JSON writer ───────────────────────────────────────────────────
results_lk = Lock()


def write_result(entry: dict) -> None:
    """Append a structured finding to the JSON output file."""
    with results_lk:
        try:
            with open(VULN_JSON, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            log.error(f"Failed to write result: {e}")


# ── Rate limiting ─────────────────────────────────────────────────────────────
def throttle() -> None:
    time.sleep(DELAY_MIN + random.uniform(0, JITTER))


# ── File readers ──────────────────────────────────────────────────────────────
def read_urls(path: str) -> list[str]:
    urls = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    urls.append(line)
    except FileNotFoundError:
        log.error(f"URLs file not found: '{path}'")
    except Exception as e:
        log.error(f"Error reading URLs: {e}")
    return urls


def load_injections(path: str) -> list[str]:
    payloads = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    payloads.append(line)
    except FileNotFoundError:
        log.error(f"Payloads file not found: '{path}'")
    except Exception as e:
        log.error(f"Error reading payloads: {e}")
    return payloads


# ── Baseline ──────────────────────────────────────────────────────────────────
def get_baseline(session: requests.Session, url: str) -> int:
    """GET the original URL and return response length as baseline."""
    try:
        throttle()
        r = session.get(url, timeout=10, allow_redirects=True)
        return len(r.text)
    except Exception:
        return -1


# ── Response intelligence ─────────────────────────────────────────────────────
def analyze_response(r: requests.Response, baseline_length: int) -> dict:
    """
    Returns a dict with:
      - detected    : bool — indicator matched
      - evidence    : str  — matched indicator string
      - label       : str  — indicator category
      - severity    : str  — CRITICAL / HIGH / MEDIUM
      - size_change : int  — absolute diff from baseline
      - suspicious  : bool — size change > 500 with no indicator match
      - snippet     : str  — first 300 chars of response body
    """
    body     = r.text.lower()
    evidence = None
    label    = None
    severity = None

    for indicator, ind_label, ind_severity in INDICATORS:
        if indicator.lower() in body:
            evidence = indicator
            label    = ind_label
            severity = ind_severity
            break  # first match is enough

    size_change = abs(len(r.text) - baseline_length) if baseline_length != -1 else 0

    return {
        "detected":   evidence is not None,
        "evidence":   evidence,
        "label":      label,
        "severity":   severity,
        "size_change": size_change,
        "suspicious": size_change > 500 and evidence is None,
        "snippet":    r.text[:300],
    }


# ── URL generator ─────────────────────────────────────────────────────────────
def generate_injected_urls(parsed, qs: dict, payloads: list[str], original_url: str):
    """
    Yields (injected_url, param_key, payload).
    Skips (original_url, param) pairs already confirmed — EARLY STOP.
    """
    candidate_keys = [
        key for key in qs
        if any(kw.lower() in key.lower() for kw in KEYWORDS)
    ]

    for key in candidate_keys:
        # Pre-loop early stop (no lock needed for a read on a set — worst case
        # we send one extra request, lock is enforced inside send_request)
        if (original_url, key) in confirmed:
            log.info(f"[SKIP] Already confirmed: param={key!r} | {original_url}")
            continue

        for payload in payloads:
            # Re-check inside payload loop — another thread may have just confirmed it
            with confirmed_lk:
                if (original_url, key) in confirmed:
                    break  # stop remaining payloads for this key

            injected_qs = copy.deepcopy(qs)
            injected_qs[key] = [payload]
            new_query = urlencode(injected_qs, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment,
            ))
            yield new_url, key, payload


# ── Request sender ────────────────────────────────────────────────────────────
def send_request(
    session: requests.Session,
    original_url: str,        # full original URL (with original query string)
    injected_url: str,        # URL with payload injected
    key: str,
    payload: str,
    baseline_length: int = -1,
) -> None:
    # Early stop: another thread may have confirmed this pair while this
    # task was sitting in the executor queue
    with confirmed_lk:
        if (original_url, key) in confirmed:
            return

    try:
        throttle()
        r = session.get(injected_url, timeout=10, allow_redirects=True)
        intel = analyze_response(r, baseline_length)

        if intel["detected"]:
            status = f"VULN [{intel['severity']}]"
        elif intel["suspicious"]:
            status = "SIZE?"
        else:
            status = "OK"

        log.info(
            f"[{status}] {r.status_code} | "
            f"param={key!r} | "
            f"payload={payload!r} | "
            f"size_diff={intel['size_change']} | "
            f"url={injected_url}"
        )

        if intel["detected"]:
            with confirmed_lk:
                confirmed.add((original_url, key))

            log.warning(
                f"[!!!] {intel['severity']} — {intel['label']} "
                f"| evidence={intel['evidence']!r} | {injected_url}"
            )

            write_result({
                "timestamp":    datetime.utcnow().isoformat() + "Z",
                "url":          injected_url,
                "original_url": original_url,
                "param":        key,
                "payload":      payload,
                "evidence":     intel["evidence"],
                "label":        intel["label"],
                "severity":     intel["severity"],
                "status_code":  r.status_code,
                "size_change":  intel["size_change"],
                "snippet":      intel["snippet"],
            })

        elif intel["suspicious"]:
            log.warning(
                f"[SIZE CHANGE +{intel['size_change']}] "
                f"suspicious response — param={key!r} | {injected_url}"
            )
            write_result({
                "timestamp":    datetime.utcnow().isoformat() + "Z",
                "url":          injected_url,
                "original_url": original_url,
                "param":        key,
                "payload":      payload,
                "evidence":     None,
                "label":        "SIZE_ANOMALY",
                "severity":     "LOW",
                "status_code":  r.status_code,
                "size_change":  intel["size_change"],
                "snippet":      intel["snippet"],
            })

    except requests.exceptions.Timeout:
        log.warning(f"[TIMEOUT]    {injected_url}")
    except requests.exceptions.ConnectionError:
        log.warning(f"[CONN ERROR] {injected_url}")
    except requests.exceptions.RequestException as e:
        log.error(f"[FAILED]     {injected_url} — {e}")


# ── Entry point ───────────────────────────────────────────────────────────────
def injection(path_url: str, path_injec: str, user_agent: str) -> None:
    urls     = read_urls(path_url)
    payloads = load_injections(path_injec)

    if not urls:
        log.error("No URLs loaded. Aborting.")
        return
    if not payloads:
        log.error("No payloads loaded. Aborting.")
        return

    log.info(f"Loaded {len(urls)} URLs and {len(payloads)} payloads.")
    log.info(f"User-Agent: {user_agent}")
    log.info(f"Rate limit: {DELAY_MIN}s + up to {JITTER}s jitter between requests.")
    log.info(f"Output: {VULN_JSON}")

    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    # FIX: tasks now carries original_url explicitly as first element
    # so send_request always has the correct full original URL
    tasks: list[tuple[str, str, str, str, int]] = []
    baselines: dict[str, int] = {}

    for original_url in urls:
        parsed = urlparse(original_url)
        if not parsed.query:
            continue
        qs = parse_qs(parsed.query)

        if original_url not in baselines:
            baselines[original_url] = get_baseline(session, original_url)

        for injected_url, key, payload in generate_injected_urls(
            parsed, qs, payloads, original_url
        ):
            # (original_url, injected_url, key, payload, baseline)
            tasks.append((original_url, injected_url, key, payload, baselines[original_url]))

    log.info(f"Total requests queued: {len(tasks)}")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        # FIX: clean unpack — no nested list comprehension, original_url passed directly
        futures = {
            executor.submit(
                send_request,
                session,
                original_url,   # full original URL with original query string
                injected_url,   # URL with payload injected
                key,
                payload,
                baseline,
            ): (original_url, injected_url, key, payload)
            for original_url, injected_url, key, payload, baseline in tasks
        }

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log.error(f"Thread error: {e}")

    log.info(f"Scan complete. Results saved to {VULN_JSON}")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Path Traversal / LFI Scanner",
        usage="python path_traversal.py <urls_file> <payloads_file> [--user-agent UA]",
    )
    parser.add_argument("urls",     help="Path to the URLs file")
    parser.add_argument("payloads", help="Path to the payloads file")
    parser.add_argument(
        "--user-agent", "-ua",
        default=DEFAULT_UA,
        help=(
            "Custom User-Agent string. "
            "Many bug bounty programs require this to identify your traffic. "
            f'Default: "{DEFAULT_UA}"'
        ),
    )
    args = parser.parse_args()
    injection(args.urls, args.payloads, args.user_agent)
