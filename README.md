
# Basic Web Vulnerability Scanner

**A small, dependency-free Python tool that checks a website you own — or a deliberately vulnerable practice target — for simple, common security issues.**

[![License: MIT](https://img.shields.io/badge/License-MIT-3fb950.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776ab.svg)](https://www.python.org/)
[![Dependencies: none](https://img.shields.io/badge/dependencies-none-58a6ff.svg)](#-quick-start)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-f0883e.svg)](#-contributing)

---

> [!WARNING]
> **Only scan systems you own or have explicit written permission to test.**
> Scanning someone else's website without authorisation is a criminal offence in
> most countries, even if you "just look". This tool refuses to run against
> anything that is not a local or private address unless you pass
> `--i-have-written-permission` and mean it.


## ⚡ Quick start

```bash
git clone https://github.com/bishalbhandari-art/basic-web-scanner.git
cd basic-web-scanner

# no install step — it is stdlib only
python scanner.py --selftest                 # demo: scans a throwaway bad server
python scanner.py http://127.0.0.1:8000      # scan your own local target
```


### Scanning a page behind a login

Grab a session cookie once (any way you like — DevTools, `curl`, a browser
extension) and pass it in:

```bash
curl -s -c - -o /dev/null -d "username=alice&password=alice123" \
     http://127.0.0.1:8000/login | grep session

python scanner.py http://127.0.0.1:8000 --cookie "session=<paste-value>"
```

Authenticated scanning matters: on the practice lab, one injection point is only
reachable after logging in, and the scanner finds it as soon as you hand it a
session.

## 🎛 Usage

```text
python scanner.py <target-url> [options]

  --selftest                     start a bad local server and scan it (demo / self check)
  --cookie NAME=VALUE            send this cookie with every request
  --paths FILE                   extra wordlist of paths to probe, one per line
  --max-paths N                  cap the number of path probes (default 25)
  --delay SECONDS                pause between requests (default 0.25 — be polite)
  --timeout SECONDS              per-request timeout (default 8)
  --json FILE                    also write machine-readable results
  -o, --md FILE                  also write a markdown report
  --no-color                     plain output for logs and CI
  -v, --verbose                  show every request
  --i-have-written-permission    required for anything that is not local/private
  --version                      print the version
```

**Exit codes:** `0` scan finished · `1` no target given · `2` self-test failed ·
`3` refused to scan (non-local target without the permission flag). Handy for CI:

```bash
python scanner.py http://127.0.0.1:8000 --no-color --json scan.json -o scan.md
```

## 📊 Sample output

Real run against the companion lab (`python app.py` on `127.0.0.1:8000`), with a
session cookie supplied:

```text
==================================================================
 Basic Web Vulnerability Scanner v1.0.0
==================================================================
  Target    : http://127.0.0.1:8000
  Requests  : 24   (GET only, 0.25s apart)
  Duration  : 5.9s

  Summary   : HIGH 4  MEDIUM 3  LOW 4  INFO 6

  HIGH (4)
    1. Debug / diagnostics endpoint: /debug
       where : http://127.0.0.1:8000/debug
       proof : {"app":"web-security-testing-lab","backups":"/static/backup/...
       fix   : Remove the file/endpoint from production, or put it behind
               authentication. Verify by hand before acting on this.

    2. Backup file left in the web root: /static/backup/db_backup.txt
       where : http://127.0.0.1:8000/static/backup/db_backup.txt
       fix   : Remove the file/endpoint from production ...

    3. Possible reflected XSS in parameter 'q'
       where : http://127.0.0.1:8000/search?q=wvs9fb916%3Cb%3E
       what  : A marker containing HTML markup was sent in 'q' and came back
               in the page unescaped.
       fix   : Encode the value for its output context (html.escape ...)

    4. Possible SQL injection in parameter 'id'
       where : http://127.0.0.1:8000/profile?id=1%27
       proof : SQL error: unrecognized token: "&#34;&#39;&#34;"
       fix   : Use parameterised queries (placeholders), never string formatting ...

  MEDIUM (3)
    5. Missing Content-Security-Policy
    6. Missing X-Frame-Options
    7. Cookie 'lab_xss_flag' is readable by JavaScript (no HttpOnly)

  LOW (4)
    8. Traffic is not encrypted (plain HTTP)
    9. Missing X-Content-Type-Options
   10. Missing Referrer-Policy
   11. Cookie 'session' has no SameSite attribute

  INFO (6)
   12. Missing Permissions-Policy
   13. Software version disclosed (Server)
   14. robots.txt found                     -> Disallow: /admin, /debug, /static/backup/
   15. Reachable path: /robots.txt
   16. Path exists but is protected: /admin
   17. Input reflected but escaped in 'id'      <- correctly escaped, no finding
------------------------------------------------------------------
  Findings are heuristics, not proof. Verify by hand before reporting,
  and only ever scan systems you own or have written permission to test.
```

Note finding 17: the scanner reports when input comes back **escaped** too. That
is how you tell "this parameter may be vulnerable" from "this parameter is
handled correctly" — and it is the check you point at a fix to prove it worked.

## 🛡 Safety built in (read this part)

The tool is designed so that a beginner cannot accidentally do damage:

| Guardrail | Why |
|-----------|-----|
| **GET only** | Nothing is ever submitted, created, edited or deleted. Probing is limited to reading. |
| **Local/private by default** | `localhost`, `127.0.0.0/8`, `::1`, RFC1918 ranges and `*.local`/`.test`/`.internal` are allowed. Anything else needs `--i-have-written-permission`. |
| **Rate limited** | ~4 requests/second by default (`--delay`), with a hard cap on how many paths are probed. |
| **No payload weapons** | The XSS probe is `wvs<random><b>` — it proves a point without attacking anyone. There is no data exfiltration, no brute force, no session theft. |
| **Reads a bounded amount** | Never reads more than 300 KB per response, and never follows links off the target host. |
| **Honest reporting** | Every finding says "possible" and asks you to verify. Heuristics are labelled as heuristics. |

## 🧠 What it will *not* do

Knowing the limits is half of being useful. This tool **cannot** find:

- **Blind or stored injection** — a quote that does not print an error is
  invisible to it. It only notices *reflected* output and *error-based* SQL.
- **Anything behind JavaScript** — it does not run a browser, so single-page
  apps, client-side routing and DOM XSS are largely invisible to it.
- **Logic and access-control bugs** — IDOR, privilege escalation, payment
  tampering. These need a human who understands what the app is *supposed* to
  do. (The companion lab has a flag sitting behind exactly this kind of bug.)
- **Concurrency or timing issues** — it is single-threaded and slow on purpose.
- **Anything needing authentication it does not have** — pass a `--cookie` if
  you have one.
- **A clean bill of health.** "No findings" means "the handful of checks this
  scanner performs did not fire", not "the site is secure". That distinction is
  the whole reason this tool prints it in the report.

## 🔧 Adding a check

Everything lives in `scanner.py`; a check is a method on `Scanner` that appends
`Finding` objects. The two easiest extension points:

```python
# 1. another path to probe
SENSITIVE_PATHS.append((
    "/.htaccess", HIGH, "Exposed .htaccess file",
    lambda r: "RewriteEngine" in r.body or "AuthType" in r.body,
))

# 2. another response signature (inside a check)
if "stack trace" in resp.body.lower():
    self.add(MEDIUM, "error.stacktrace", "Stack trace leaked", url, ...,
             first_lines(resp.body, 2), "Log errors server-side; show users nothing.")
```

Please keep the style: severity, evidence, and a fix in every finding. A finding
without a fix is just noise.

## 🤝 Contributing

Ideas welcome — more checks (CSRF on state-changing GETs, CORS misconfig,
weak `Set-Cookie` scoping, open redirects), better heuristics, output formats.
Rules: standard library only, GET only, no exploitation, and keep the safety
guardrails intact. Open an issue describing the check before sending a big PR.

```bash
python scanner.py --selftest      # must print "SELFTEST OK"
```

## 📄 License

[MIT](LICENSE) — use it, fork it, teach with it, ship it.

## ⚠️ Disclaimer

This tool is provided for **defensive, authorised security testing and
education only**. It performs a handful of non-intrusive checks against a target
you nominate. You are responsible for having permission to test that target.
The authors accept no liability for misuse or for damage caused by running this
tool against systems you do not own.

*Found a bug in the scanner? Open an issue. Found a bug with the scanner? That's the point.* ⭐
