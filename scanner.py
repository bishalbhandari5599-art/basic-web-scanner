#!/usr/bin/env python3
"""
Basic Web Vulnerability Scanner
===============================

A small, dependency-free Python tool that checks a website you own - or a
deliberately vulnerable practice target such as the Web Security Testing Lab -
for a handful of simple, common security issues.

It is deliberately BASIC. It is not a replacement for Burp Suite, ZAP, nikto or
nmap, and it will not "hack" anything: it makes a few polite GET requests and
tells you what it noticed.

Checks it performs
------------------
  1. Security headers        (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy)
  2. Cookie flags            (HttpOnly, Secure, SameSite)
  3. Transport / TLS         (HTTP vs HTTPS, certificate, protocol version)
  4. Exposed sensitive paths (/robots.txt, /.git/HEAD, /.env, /debug, backups...)
  5. Information disclosure  (server banner, version numbers, SQL error text)
  6. Reflected input         (a safe marker echoed back unescaped -> possible XSS)
  7. SQL error probing       (a single quote -> possible SQL injection)
  8. Password forms          (credentials posted over plain HTTP)

Safety built in
---------------
  * GET requests only. Nothing is ever submitted, changed or deleted.
  * Refuses to run against a non-local, non-private host unless you pass
    --i-have-written-permission and mean it.
  * Rate limited (--delay, default 0.25s) and capped (--max-paths) so it can
    never turn into a flood.
  * No exploitation, no brute forcing, no fuzzing, no payload that attacks a
    real user. Findings are "things to look at", written up with a fix.

Usage
-----
    python scanner.py http://127.0.0.1:8000                 # scan a local target
    python scanner.py http://127.0.0.1:8000 --json r.json -o r.md
    python scanner.py https://staging.example.com --i-have-written-permission
    python scanner.py --selftest                            # demo/self check

Requires Python 3.8+. No third-party packages.
"""

from __future__ import annotations

import argparse
import concurrent.futures  # noqa: F401  (kept for future parallel checks)
import datetime
import html
import http.server
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple

__version__ = "1.0.0"
USER_AGENT = "BasicWebScanner/%s (+authorized testing only)" % __version__


def utcnow() -> datetime.datetime:
    """Timezone-aware UTC now (datetime.utcnow() is deprecated)."""
    return datetime.datetime.now(datetime.timezone.utc)

# ---------------------------------------------------------------------------
# Severity handling
# ---------------------------------------------------------------------------
HIGH, MEDIUM, LOW, INFO, OK = "HIGH", "MEDIUM", "LOW", "INFO", "OK"
SEVERITY_ORDER = [HIGH, MEDIUM, LOW, INFO, OK]
MAX_BODY = 300_000  # never read more than ~300 KB of a page


@dataclass
class Finding:
    """One thing the scanner noticed."""

    severity: str
    check_id: str
    title: str
    target: str
    detail: str = ""
    evidence: str = ""
    fix: str = ""

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: str
    final_url: str
    set_cookies: List[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------
class Palette:
    COLOURS = {
        HIGH: "\033[91m", MEDIUM: "\033[93m", LOW: "\033[96m",
        INFO: "\033[90m", OK: "\033[92m", "head": "\033[1m", "reset": "\033[0m",
    }

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, kind: str) -> str:
        if not self.enabled:
            return text
        return "%s%s%s" % (self.COLOURS.get(kind, ""), text, self.COLOURS["reset"])


# ---------------------------------------------------------------------------
# What to look for
# ---------------------------------------------------------------------------
# path -> (severity, title, signature). The signature is what makes us confident
# the 200 we got back is the real thing and not a friendly "not found" page.
SENSITIVE_PATHS: List[Tuple[str, str, str, Callable[[Response], bool]]] = [
    ("/.git/HEAD", HIGH, "Exposed Git metadata",
     lambda r: r.body.strip().startswith("ref:") or "refs/heads" in r.body),
    ("/.env", HIGH, "Exposed environment file",
     lambda r: bool(re.search(r"^\s*[A-Z0-9_]{3,}\s*=", r.body, re.M))),
    ("/config.php.bak", HIGH, "Exposed configuration backup",
     lambda r: "<?php" in r.body or "password" in r.body.lower()),
    ("/db.sql", HIGH, "Exposed database dump",
     lambda r: "INSERT INTO" in r.body.upper() or "CREATE TABLE" in r.body.upper()),
    ("/backup.zip", HIGH, "Exposed backup archive", lambda r: r.body[:2] == "PK"),
    ("/.svn/entries", HIGH, "Exposed Subversion metadata", lambda r: len(r.body) > 0),
    ("/debug", HIGH, "Debug / diagnostics endpoint",
     lambda r: r.body.strip().startswith("{") or "debug" in r.body.lower()),
    ("/phpinfo.php", MEDIUM, "phpinfo() disclosure",
     lambda r: "phpinfo()" in r.body or "PHP Version" in r.body),
    ("/server-status", MEDIUM, "Apache server-status page",
     lambda r: "Apache Server Status" in r.body),
    ("/actuator/env", MEDIUM, "Spring Boot actuator", lambda r: "propertySources" in r.body),
    ("/admin", LOW, "Admin interface reachable", lambda r: r.status == 200),
    ("/static/backup/db_backup.txt", HIGH, "Backup file left in the web root",
     lambda r: "backup" in r.body.lower() or "password" in r.body.lower()),
    ("/console", LOW, "Debug console exposed", lambda r: "console" in r.body.lower()),
    ("/wp-login.php", LOW, "WordPress login page", lambda r: "wp-login" in r.body.lower()),
]

# Text that means "a database complained about your quote character".
SQL_ERROR_PATTERNS = [
    "SQL syntax", "sqlite3.", "sqlite error", "mysql_fetch", "mysql_query",
    "You have an error in your SQL", "PostgreSQL", "pg_query", "ORA-0",
    "Unclosed quotation mark", "quoted string not properly terminated",
    "SQL error", "sqlalchemy.exc", "SequelizeDatabaseError", "SQLSTATE",
]

# Cookie values that the server should never be sending.
HEADER_CHECKS = [
    ("content-security-policy", MEDIUM, "Missing Content-Security-Policy",
     "A CSP is the strongest defence-in-depth against XSS. Start with "
     "default-src 'self' and tighten from there."),
    ("x-frame-options", MEDIUM, "Missing X-Frame-Options",
     "Without it the site can be framed by anyone (clickjacking). Set DENY, or "
     "use CSP frame-ancestors 'none'."),
    ("x-content-type-options", LOW, "Missing X-Content-Type-Options",
     "Set it to 'nosniff' so browsers stop guessing content types."),
    ("referrer-policy", LOW, "Missing Referrer-Policy",
     "Use strict-origin-when-cross-origin to avoid leaking full URLs to other sites."),
    ("permissions-policy", INFO, "Missing Permissions-Policy",
     "Optional, but it is how you switch off camera/microphone/geolocation that "
     "the site does not use."),
    ("strict-transport-security", MEDIUM, "Missing Strict-Transport-Security (HSTS)",
     "Only meaningful over HTTPS: it stops downgrade and cookie-stealing on "
     "plain HTTP. Use max-age=31536000; includeSubDomains."),
]

SKIP_PARAMS = {"csrf", "csrf_token", "_token", "authenticity_token", "submit",
               "password", "passwd", "pwd", "logout", "delete", "action"}


# ---------------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------------
def is_local_or_private(host: str) -> bool:
    """True for loopback, private ranges and obvious local hostnames."""
    host = host.split(":")[0].strip("[]").lower()
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    if host.endswith((".localhost", ".local", ".test", ".internal", ".lan", ".home.arpa")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False   # a real domain name: require the permission flag


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, target: str, timeout: float = 8.0, delay: float = 0.25,
                 cookie: str = "", max_paths: int = 25, extra_paths: Optional[List[str]] = None,
                 verbose: bool = False):
        self.target = target.rstrip("/")
        parsed = urllib.parse.urlparse(self.target)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc
        self.origin = "%s://%s" % (parsed.scheme, parsed.netloc)
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.max_paths = max_paths
        self.extra_paths = extra_paths or []
        self.request_count = 0
        self.cookie_jar: List[Tuple[str, str]] = []   # (url, raw Set-Cookie header)
        self.skipped: List[str] = []
        self.notes: List[str] = []
        self.findings: List[Finding] = []

        self.opener = urllib.request.build_opener()
        self.headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*"}
        if cookie:
            self.headers["Cookie"] = cookie

    # -- plumbing ----------------------------------------------------------
    def _log(self, msg: str) -> None:
        if self.verbose:
            print("    ... %s" % msg)

    def get(self, url: str) -> Optional[Response]:
        """One polite GET request."""
        if self.request_count:
            time.sleep(self.delay)
        self.request_count += 1
        self._log("GET %s" % url)
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                body = r.read(MAX_BODY).decode("utf-8", "replace")
                cookies = r.headers.get_all("Set-Cookie") or []
                self._remember_cookies(r.geturl(), cookies)
                return Response(r.status, dict(r.headers), body, r.geturl(), cookies)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(MAX_BODY).decode("utf-8", "replace")
            except Exception:
                pass
            cookies = e.headers.get_all("Set-Cookie") or [] if e.headers else []
            self._remember_cookies(url, cookies)
            return Response(e.code, dict(e.headers or {}), body, e.geturl() or url, cookies)
        except ssl.SSLCertVerificationError as e:
            return Response(0, {}, "", url, []) if self._ssl_warn(e) else None
        except Exception as e:  # noqa: BLE001 - a scanner must never crash
            self._log("request failed: %s" % e)
            return None

    def _ssl_warn(self, exc: Exception) -> bool:
        self.notes.append("TLS verification failed: %s" % exc)
        return False

    def _remember_cookies(self, url: str, cookies: List[str]) -> None:
        for raw in cookies:
            if (url, raw) not in self.cookie_jar:
                self.cookie_jar.append((url, raw))

    def add(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))

    # -- checks ------------------------------------------------------------
    def run(self) -> List[Finding]:
        root = self.get(self.target)
        if root is None:
            print("Could not reach %s - nothing scanned." % self.target)
            return []
        self.notes.append("Root: HTTP %s (%d bytes)" % (root.status, len(root.body)))

        self.check_headers(root)
        self.check_forms(root)
        self.check_transport(root)
        protected = self.check_paths(root)
        self.check_injection(root, protected)
        self.check_cookies()          # last: by now we have seen every Set-Cookie
        return self.findings

    # 1. security headers ---------------------------------------------------
    def check_headers(self, root: Response) -> None:
        self._log("checking security headers")
        if self.scheme != "https":
            self.add(LOW, "headers.http", "Traffic is not encrypted (plain HTTP)",
                     self.target,
                     "The site answered over http://, so every request, cookie and "
                     "password travels in clear text.",
                     "Target: %s" % self.target,
                     "Serve everything over HTTPS and redirect HTTP to it. (For a "
                     "local practice target this is expected - just never deploy "
                     "it that way.)")
        for name, severity, title, fix in HEADER_CHECKS:
            if name == "strict-transport-security" and self.scheme != "https":
                continue
            if not root.header(name):
                self.add(severity, "headers." + name, title, self.target,
                         "Response headers for %s did not include %s."
                         % (self.target, name.title()),
                         "Checked response had no %s header." % name.title(), fix)
        # Version/banner disclosure
        for hdr in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = root.header(hdr)
            if value and re.search(r"\d+\.\d+", value):
                self.add(INFO, "banner." + hdr.lower(), "Software version disclosed (%s)" % hdr,
                         self.target, "The banner advertises an exact version to attackers.",
                         "%s: %s" % (hdr, value),
                         "Trim or genericise version strings, and keep the software patched.")

    # 2. cookies -----------------------------------------------------------
    def check_cookies(self) -> None:
        """Flag cookies that are missing HttpOnly / Secure / SameSite.

        Cookies are collected from every response, because plenty of sites only
        set their session cookie on the page that creates the session.
        """
        self._log("checking cookie flags")
        already: set = set()
        for url, raw in self.cookie_jar:
            name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            if not name:
                continue
            if "httponly" not in low and (name, "httponly") not in already:
                already.add((name, "httponly"))
                self.add(MEDIUM, "cookie.httponly.%s" % name,
                         "Cookie '%s' is readable by JavaScript (no HttpOnly)" % name,
                         url,
                         "Script injected into any page can read this cookie with "
                         "document.cookie - the classic XSS cookie theft.",
                         "Set-Cookie: %s" % raw.strip(),
                         "Add the HttpOnly flag (and SameSite=Lax or Strict) to "
                         "session and sensitive cookies.")
            if self.scheme == "https" and "secure" not in low and (name, "secure") not in already:
                already.add((name, "secure"))
                self.add(MEDIUM, "cookie.secure.%s" % name,
                         "Cookie '%s' will be sent over plain HTTP (no Secure)" % name,
                         url, "Without Secure the cookie can leak on any "
                         "http:// request to this host.",
                         "Set-Cookie: %s" % raw.strip(),
                         "Add the Secure flag.")
            if "samesite" not in low and (name, "samesite") not in already:
                already.add((name, "samesite"))
                self.add(LOW, "cookie.samesite.%s" % name,
                         "Cookie '%s' has no SameSite attribute" % name,
                         url,
                         "Together with a state-changing request this is how CSRF "
                         "gets a foothold.",
                         "Set-Cookie: %s" % raw.strip(),
                         "Add SameSite=Lax (or Strict for high-value cookies).")

    # 3. forms over http ---------------------------------------------------
    def check_forms(self, root: Response) -> None:
        self._log("checking forms")
        if self.scheme == "https":
            return
        for action, method, fields in extract_forms(root.body):
            if any("password" in (t or "").lower() for _, t in fields) and \
                    (method or "get").lower() == "post":
                self.add(MEDIUM, "form.password.http",
                         "Login form submits a password over plain HTTP",
                         urllib.parse.urljoin(self.target, action or "/"),
                         "Credentials typed into this form go over the wire "
                         "unencrypted and can be read by anyone on the path.",
                         "Form action=%s method=%s" % (action or "(self)", method),
                         "Serve the form over HTTPS only; redirect http:// to "
                         "https:// and set HSTS.")
                break

    # 4. transport / TLS ----------------------------------------------------
    def check_transport(self, root: Response) -> None:
        self._log("checking transport")
        if root.final_url.startswith("https://") and self.scheme == "http":
            self.add(INFO, "transport.redirect", "HTTP redirects to HTTPS", self.target,
                     "Good: the plain-HTTP request was redirected to the encrypted "
                     "version.", "%s -> %s" % (self.target, root.final_url),
                     "Keep it, and add HSTS so the first request is protected too.")
        if self.scheme != "https":
            self.skipped.append("TLS certificate check (target is not HTTPS)")
            return
        host = urllib.parse.urlparse(self.target).hostname
        port = urllib.parse.urlparse(self.target).port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
        except ssl.SSLCertVerificationError as exc:
            self.add(MEDIUM, "tls.verify", "TLS certificate does not validate", self.target,
                     "The certificate could not be verified, so users cannot tell "
                     "this site from an impostor.", str(exc)[:160],
                     "Install a valid certificate (Let's Encrypt is free) and renew "
                     "it automatically.")
            return
        except Exception as exc:  # noqa: BLE001
            self.notes.append("TLS probe failed: %s" % exc)
            return
        if version and version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
            self.add(HIGH, "tls.version", "Obsolete TLS version (%s)" % version, self.target,
                     "Old protocol versions have known weaknesses.",
                     "Negotiated protocol: %s" % version,
                     "Disable TLS 1.0/1.1 and SSL entirely; allow TLS 1.2+.")
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (expiry - utcnow().replace(tzinfo=None)).days
                if days < 0:
                    self.add(HIGH, "tls.expired", "TLS certificate has expired", self.target,
                             "Browsers show a full-page warning and security-conscious "
                             "users leave.", "Expired: %s" % not_after,
                             "Renew the certificate and enable auto-renewal.")
                elif days < 21:
                    self.add(MEDIUM, "tls.expiring", "TLS certificate expires soon", self.target,
                             "The certificate expires in %d day(s)." % days,
                             "notAfter: %s" % not_after, "Renew before it does.")
                else:
                    self.notes.append("TLS certificate valid for %d more days" % days)
            except ValueError:
                pass

    # 5. sensitive paths ----------------------------------------------------
    def check_paths(self, root: Response) -> List[str]:
        """Probe a short list of well-known paths. Returns paths we must not inject into."""
        self._log("probing well-known paths")
        baseline = self.get(urllib.parse.urljoin(self.origin, "/wvs-missing-%s" %
                                                 random.randint(10000, 99999)))
        soft_404 = bool(baseline and baseline.status == 200)
        if soft_404:
            self.notes.append("Site returns 200 for unknown paths (soft 404): only "
                              "strong signatures will be reported.")

        # robots.txt is a hint file, so read it first and follow what it hides.
        robots = self.get(urllib.parse.urljoin(self.origin, "/robots.txt"))
        probe_list = list(self.extra_paths)
        if robots and robots.status == 200 and "user-agent" in robots.body.lower():
            disallowed = re.findall(r"(?im)^\s*disallow:\s*(\S+)", robots.body)
            self.add(INFO, "path./robots.txt", "robots.txt found", self.origin + "/robots.txt",
                     "robots.txt is a crawling convention, not an access control - it "
                     "often lists exactly the paths someone wanted to hide.",
                     "Disallow entries: %s" % (", ".join(disallowed) or "(none)"),
                     "Use authentication for sensitive areas, not robots.txt.")
            probe_list += [d for d in disallowed if d not in ("/", "")]
        probe_list += [p for p, _, _, _ in SENSITIVE_PATHS]
        seen, queue = set(), []
        for path in probe_list:
            if path not in seen:
                seen.add(path)
                queue.append(path)
        if len(queue) > self.max_paths:
            self.notes.append("Path list capped at %d by --max-paths." % self.max_paths)
            queue = queue[:self.max_paths]

        protected: List[str] = []
        for path in queue:
            url = urllib.parse.urljoin(self.origin, path)
            resp = self.get(url)
            if resp is None:
                continue
            if resp.status == 200:
                sig = next((s for p, _, _, s in SENSITIVE_PATHS if p == path), None)
                looks_real = (not soft_404) or (sig is not None and sig(resp))
                if sig is not None and not sig(resp) and not soft_404:
                    looks_real = False
                if looks_real:
                    severity, title = "INFO", "Reachable path"
                    for p, sev, ttl, _ in SENSITIVE_PATHS:
                        if p == path:
                            severity, title = sev, ttl
                    if path not in [p for p, _, _, _ in SENSITIVE_PATHS] and path != "/robots.txt":
                        severity, title = MEDIUM, "Hidden path from robots.txt is reachable"
                    self.add(severity, "path." + path, "%s: %s" % (title, path), url,
                             "This path returned HTTP 200 with content that looks like a "
                             "real page.",
                             first_lines(resp.body, 2),
                             "Remove the file/endpoint from production, or put it behind "
                             "authentication. Verify by hand before acting on this.")
                    protected.append(path)
            elif resp.status in (401, 403) and path in ("/admin", "/.git/HEAD", "/.env"):
                self.add(INFO, "path.%s.locked" % path, "Path exists but is protected: %s" % path,
                         url, "A %d here means the path exists - the server refused it. "
                              "That is information, not a hole." % resp.status,
                         "HTTP %d" % resp.status, "No action needed unless it should not exist.")
            if resp.status == 200 and "Index of /" in resp.body:
                self.add(MEDIUM, "path.dirlisting", "Directory listing enabled: %s" % path, url,
                         "The server is listing file names to anyone who asks.",
                         "<title>Index of /</title>",
                         "Turn directory listing off (Options -Indexes) and keep files "
                         "that are not meant to be public outside the web root.")
        return protected

    # 6 & 7. reflection + SQL errors ---------------------------------------
    def check_injection(self, root: Response, protected: List[str]) -> None:
        params = discover_params(root.body, self.target, self.netloc)
        params = [p for p in params if p[0] not in protected][:6]
        if not params:
            self.skipped.append("Input probing (no query parameters found on the home page)")
            return
        marker = "wvs" + "".join(random.choice(string.hexdigits.lower()[:16]) for _ in range(6))
        payload = marker + '<b>'
        for path, param, original in params:
            base = urllib.parse.urljoin(self.origin, path)

            # -- reflection (possible XSS): does our markup come back alive? --
            url = "%s?%s" % (base, urllib.parse.urlencode({param: payload}))
            resp = self.get(url)
            if resp and payload in resp.body:
                self.add(HIGH, "xss.reflected.%s" % param,
                         "Possible reflected XSS in parameter '%s'" % param, url,
                         "A marker containing HTML markup was sent in '%s' and came back "
                         "in the page unescaped. If a browser executes that markup, an "
                         "attacker who controls the link controls the page." % param,
                         context_snippet(resp.body, payload),
                         "Encode the value for its output context (html.escape for HTML "
                         "body/attributes) and never render user input as markup. "
                         "Confirm by hand in a browser before reporting it.")
            elif resp and marker in resp.body:
                self.add(INFO, "xss.escaped.%s" % param,
                         "Input reflected but escaped in '%s'" % param, url,
                         "Your marker came back HTML-escaped, which is the correct "
                         "behaviour.", context_snippet(resp.body, marker),
                         "No action needed - this is what good output encoding looks like.")

            # -- SQL errors: does a lone quote upset the database? ------------
            value = (original or "1") + "'"
            url = "%s?%s" % (base, urllib.parse.urlencode({param: value}))
            resp = self.get(url)
            if resp:
                hit = next((p for p in SQL_ERROR_PATTERNS if p.lower() in resp.body.lower()), None)
                if hit:
                    self.add(HIGH, "sqli.error.%s" % param,
                             "Possible SQL injection in parameter '%s'" % param, url,
                             "A single quote in '%s' produced a database error in the "
                             "response. That usually means the value is being glued into "
                             "a SQL string." % param,
                             context_snippet(resp.body, hit),
                             "Use parameterised queries (placeholders), never string "
                             "formatting, and hide database errors from users. Confirm "
                             "with your own testing before reporting.")
                elif resp.status >= 500:
                    self.add(MEDIUM, "error.500.%s" % param,
                             "Server error (HTTP %d) caused by that parameter" % resp.status,
                             url, "A crafted value made the page fail with an internal "
                                  "error - often the first sign of a crash or injection bug.",
                             "HTTP %s for %s" % (resp.status, url),
                             "Return clean errors and never leak stack traces to users.")

    # -- text summary -------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Small parsing helpers
# ---------------------------------------------------------------------------
def first_lines(text: str, n: int) -> str:
    lines = [l.strip() for l in text.splitlines() if l.strip()][:n]
    return " / ".join(lines)[:200]


def context_snippet(body: str, needle: str, width: int = 90) -> str:
    """Show what the matched text looked like in context."""
    i = body.lower().find(needle.lower())
    if i < 0:
        return needle
    start = max(0, i - width)
    snippet = body[start:i + len(needle) + width]
    return " ".join(snippet.split())[:240]


def discover_params(html_body: str, target: str, netloc: str) -> List[Tuple[str, str, str]]:
    """Find (path, parameter, example value) triples worth testing, same host only."""
    found: List[Tuple[str, str, str]] = []

    def add(url: str, method: str = "get") -> None:
        full = urllib.parse.urljoin(target, url)
        parsed = urllib.parse.urlparse(full)
        if parsed.netloc != netloc or method.lower() != "get":
            return
        for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
            if key.lower() in SKIP_PARAMS:
                continue
            found.append((parsed.path or "/", key, values[0] if values else "1"))

    for m in re.finditer(r'(?:href|action)\s*=\s*["\']([^"\']+)["\']', html_body, re.I):
        url = m.group(1)
        if url.startswith(("mailto:", "javascript:", "#")):
            continue
        add(url)

    # GET forms whose action has no query string: use the input names.
    for action, method, fields in extract_forms(html_body):
        if (method or "get").lower() != "get":
            continue
        full = urllib.parse.urljoin(target, action or "/")
        parsed = urllib.parse.urlparse(full)
        if parsed.netloc != netloc:
            continue
        for name, _type in fields:
            if name and name.lower() not in SKIP_PARAMS:
                found.append((parsed.path or "/", name, "1"))

    deduped: List[Tuple[str, str, str]] = []
    for triple in found:
        if triple not in deduped:
            deduped.append(triple)
    return deduped


def extract_forms(html_body: str) -> List[Tuple[str, str, List[Tuple[str, str]]]]:
    """Very small <form> parser: [(action, method, [(input_name, input_type)])]."""
    forms = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html_body, re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        action = (re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I) or [None, ""])[1]
        method = (re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.I) or [None, "get"])[1]
        fields = [(i[0], i[1]) for i in re.findall(
            r'<input\b[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*?(?:type\s*=\s*["\']([^"\']+)["\'])?',
            inner, re.I)]
        fields += [(n, "text") for n in re.findall(
            r'<textarea\b[^>]*name\s*=\s*["\']([^"\']+)["\']', inner, re.I)]
        forms.append((action, method, fields))
    return forms


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(scanner: Scanner, colour: Palette, elapsed: float) -> None:
    c = colour
    line = "=" * 66
    print()
    print(c(line, "head"))
    print(c(" Basic Web Vulnerability Scanner v%s" % __version__, "head"))
    print(c(line, "head"))
    print("  Target    : %s" % scanner.target)
    print("  Requests  : %d   (GET only, %.2fs apart)" % (scanner.request_count, scanner.delay))
    print("  Duration  : %.1fs" % elapsed)
    print("  Finished  : %s UTC" % utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    print()

    counts = scanner.summary()
    print("  Summary   : " + "  ".join(
        c("%s %d" % (sev, counts[sev]), sev) for sev in SEVERITY_ORDER[:-1]))
    print()

    by_sev = {s: [f for f in scanner.findings if f.severity == s] for s in SEVERITY_ORDER}
    i = 0
    for sev in SEVERITY_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue
        print(c("  %s (%d)" % (sev, len(group)), sev))
        for f in group:
            i += 1
            print("   %2d. %s" % (i, f.title))
            print("       where : %s" % f.target)
            if f.detail:
                print("       what  : %s" % wrap(f.detail, 8, 90))
            if f.evidence:
                print("       proof : %s" % wrap(f.evidence, 8, 90))
            if f.fix and sev not in (INFO, OK):
                print("       fix   : %s" % wrap(f.fix, 8, 90))
            print()

    if scanner.skipped:
        print(c("  Skipped", "head"))
        for s in scanner.skipped:
            print("   - %s" % s)
        print()
    if scanner.notes:
        print(c("  Notes", "head"))
        for n in scanner.notes[:8]:
            print("   - %s" % n)
        print()

    print(c("-" * 66, "INFO"))
    print("  Findings are heuristics, not proof. Verify by hand before reporting,")
    print("  and only ever scan systems you own or have written permission to test.")
    print()


def wrap(text: str, indent: int, width: int) -> str:
    words, lines, current = text.split(), [], ""
    for w in words:
        if len(current) + len(w) + 1 > width:
            lines.append(current)
            current = w
        else:
            current = (current + " " + w).strip()
    if current:
        lines.append(current)
    pad = " " * indent
    return ("\n" + pad).join(lines) if len(lines) > 1 else lines[0]


def write_json(scanner: Scanner, path: str, elapsed: float) -> None:
    payload = {
        "scanner": "basic-web-vulnerability-scanner",
        "version": __version__,
        "target": scanner.target,
        "scanned_at": utcnow().isoformat() + "Z",
        "duration_seconds": round(elapsed, 2),
        "requests": scanner.request_count,
        "summary": scanner.summary(),
        "skipped": scanner.skipped,
        "notes": scanner.notes,
        "findings": [f.to_dict() for f in scanner.findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_markdown(scanner: Scanner, path: str, elapsed: float) -> None:
    counts = scanner.summary()
    out = ["# Web vulnerability scan report", "",
           "| | |", "|---|---|",
           "| **Target** | `%s` |" % scanner.target,
           "| **Scanned** | %s UTC |" % utcnow().strftime("%Y-%m-%d %H:%M"),
           "| **Requests** | %d (GET only) |" % scanner.request_count,
           "| **Duration** | %.1fs |" % elapsed, "",
           "| Severity | Count |", "|---|---|"]
    out += ["| %s | %d |" % (sev, counts[sev]) for sev in SEVERITY_ORDER[:-1]]
    out += ["", "---", "", "## Findings", ""]
    if not scanner.findings:
        out += ["Nothing detected. That is not the same as 'secure' - this scanner "
                "only checks a handful of basics.", ""]
    for i, f in enumerate(scanner.findings, 1):
        out += ["### %d. [%s] %s" % (i, f.severity, f.title), "",
                "* **Where:** `%s`" % f.target]
        if f.detail:
            out += ["* **What:** %s" % f.detail]
        if f.evidence:
            out += ["* **Evidence:** `%s`" % f.evidence.replace("`", "'")]
        if f.fix:
            out += ["* **Fix:** %s" % f.fix]
        out += [""]
    if scanner.skipped:
        out += ["## Checks skipped", ""] + ["* %s" % s for s in scanner.skipped] + [""]
    out += ["---", "",
            "*Generated by Basic Web Vulnerability Scanner v%s. Findings are "
            "heuristics: verify before reporting, and only scan systems you own or "
            "have written permission to test.*" % __version__]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


# ---------------------------------------------------------------------------
# --selftest : a tiny deliberately-bad server, so the tool can prove itself
# ---------------------------------------------------------------------------
class _SelfTestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the demo output clean
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        body, status, extra = "", 200, {}
        if parsed.path == "/":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            body = ("<html><head><title>Self test</title></head><body>"
                    "<h1>Self test</h1>"
                    "<a href='/search?q=hello'>search</a>"
                    "<div>Results for: %s</div>"
                    "<form action='/login' method='post'>"
                    "<input name='username' type='text'>"
                    "<input name='password' type='password'></form>"
                    "</body></html>") % q          # reflected, unescaped: on purpose
            extra["Set-Cookie"] = "session=abc123; Path=/"   # no HttpOnly/SameSite
        elif parsed.path == "/search":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            body = "<html><body>Results for: %s</body></html>" % q
        elif parsed.path == "/debug":
            body = '{"debug": true, "secret_key": "not-a-real-key"}'
        elif parsed.path == "/.env":
            body = "APP_KEY=abc\nDB_PASSWORD=hunter2\n"
        elif parsed.path == "/robots.txt":
            body = "User-agent: *\nDisallow: /debug\nDisallow: /.env\n"
        else:
            status = 404
            body = "<html><body>404 not found</body></html>"
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)


def selftest() -> int:
    """Start a deliberately bad local server, scan it, print the report."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SelfTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("Self-test server running on http://127.0.0.1:%d" % port)
    print("This target is a throwaway in-memory server that is bad on purpose.\n")
    try:
        scanner = Scanner("http://127.0.0.1:%d" % port, delay=0.05)
        start = time.time()
        scanner.run()
        print_report(scanner, Palette(sys.stdout.isatty()), time.time() - start)
        highs = [f for f in scanner.findings if f.severity == HIGH]
        if not highs:
            print("SELFTEST FAILED: expected at least one HIGH finding.")
            return 2
        print("SELFTEST OK: %d HIGH, %d findings total."
              % (len(highs), len(scanner.findings)))
        return 0
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description="Basic Web Vulnerability Scanner - checks a site you own (or a "
                    "local practice target) for simple, common security issues.",
        epilog="Example: python scanner.py http://127.0.0.1:8000 --json out.json",
    )
    p.add_argument("target", nargs="?", help="Base URL, e.g. http://127.0.0.1:8000")
    p.add_argument("--selftest", action="store_true",
                   help="start a deliberately bad local server and scan it (demo)")
    p.add_argument("--json", metavar="FILE", help="write machine-readable results")
    p.add_argument("-o", "--md", metavar="FILE", help="write a markdown report")
    p.add_argument("--cookie", default="", metavar="NAME=VALUE",
                   help="send a session cookie (lets you scan pages behind a login)")
    p.add_argument("--paths", metavar="FILE",
                   help="extra wordlist of paths to probe, one per line")
    p.add_argument("--max-paths", type=int, default=25,
                   help="maximum number of paths to probe (default 25)")
    p.add_argument("--delay", type=float, default=0.25,
                   help="seconds between requests, be polite (default 0.25)")
    p.add_argument("--timeout", type=float, default=8.0, help="request timeout (default 8s)")
    p.add_argument("--no-color", action="store_true", help="plain text output")
    p.add_argument("-v", "--verbose", action="store_true", help="show every request")
    p.add_argument("--i-have-written-permission", action="store_true", dest="authorised",
                   help="required to scan a host that is not on your own machine")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    colour = Palette(False if args.no_color else sys.stdout.isatty())

    if args.selftest:
        return selftest()

    if not args.target:
        build_parser().print_help()
        return 1
    if not args.target.startswith(("http://", "https://")):
        args.target = "http://" + args.target

    host = urllib.parse.urlparse(args.target).hostname or ""
    local = is_local_or_private(host)
    print(colour("Basic Web Vulnerability Scanner v%s" % __version__, "head"))
    print("Target: %s" % args.target)

    if not local and not args.authorised:
        print()
        print(colour("REFUSING TO SCAN.", HIGH))
        print("'%s' is not a local or private address." % host)
        print("Only scan systems you own or have explicit written permission to test.")
        print("If you do have that permission, re-run with ")
        print("    --i-have-written-permission")
        return 3
    if not local:
        print(colour("Permission asserted by --i-have-written-permission. "
                     "You are responsible for that claim.", MEDIUM))
    else:
        print(colour("Local/private target: safe to test.", "INFO"))

    extra = []
    if args.paths and os.path.isfile(args.paths):
        with open(args.paths, encoding="utf-8") as fh:
            extra = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        print("Loaded %d extra paths from %s" % (len(extra), args.paths))

    scanner = Scanner(args.target, timeout=args.timeout, delay=args.delay,
                      cookie=args.cookie, max_paths=args.max_paths,
                      extra_paths=extra, verbose=args.verbose)
    start = time.time()
    scanner.run()
    elapsed = time.time() - start
    print_report(scanner, colour, elapsed)

    if args.json:
        write_json(scanner, args.json, elapsed)
        print("JSON report written to %s" % args.json)
    if args.md:
        write_markdown(scanner, args.md, elapsed)
        print("Markdown report written to %s" % args.md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
