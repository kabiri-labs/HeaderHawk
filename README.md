# HeaderHawk

[![Version](https://img.shields.io/badge/version-2.13.2-brightgreen.svg)](headerhawk.py)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-565%20passing-brightgreen.svg)](tests)
[![GitHub Stars](https://img.shields.io/github/stars/kabiri-labs/HeaderHawk.svg?style=social&label=Star)](https://github.com/kabiri-labs/HeaderHawk)

**Evidence that your HTTP headers are safe — in a form an auditor will accept.**

HeaderHawk assesses both sides of the HTTP exchange: the **request headers an attacker manipulates** (`Host`, `X-Forwarded-*`, `Forwarded`, client-IP and URL-override headers) and the **response headers your product is supposed to send** (HSTS, CSP, cookie attributes, framing). It confirms what it finds with a second probe, maps every finding to the published requirement it fails, and — the part that matters most — **tells you what it could not assess instead of counting it as a pass**.

```bash
python headerhawk.py https://app.example.com/ --discover \
       --evidence compliance.md --output findings.sarif --fail-on any
```

Three artefacts, one run: a requirement-by-requirement compliance report, a SARIF file for your security dashboard, and an exit code your pipeline can gate on.

---

## Contents

- [The problem this solves](#the-problem-this-solves)
- [What you get](#what-you-get)
- [How it decides something is true](#how-it-decides-something-is-true)
- [Coverage](#coverage)
- [Where HeaderHawk fits](#where-headerhawk-fits)
- [Scanning what you actually ship](#scanning-what-you-actually-ship)
- [In your pipeline](#in-your-pipeline)
- [Installation](#installation)
- [Options](#options)
- [Contributing](#contributing)
- [License, disclaimer, contact](#license)

---

## The problem this solves

Header security is where three uncomfortable facts meet.

**Nobody owns it.** `Host` handling belongs to the load balancer, `X-Forwarded-*` to the CDN, HSTS to the platform team, cookie flags to the application. Each group assumes another one has it covered. Nothing is coordinated because nothing forces it to be.

**A clean scan and an unreachable target look identical.** Every scanner reports findings. When there are none, the natural reading is "compliant". But a scan that never got a valid response also reports none — and so does a scan of an authenticated product that only ever saw the login page. Automated evidence that cannot tell those apart is worse than no evidence, because it is confidently wrong.

**The findings arrive in the wrong shape.** An assessor asks *"show me that requirement 4.1.3 is met."* A scanner answers with a list of URLs and header names. Somebody then rebuilds the crosswalk by hand in a spreadsheet, once per audit, and it goes stale immediately.

Add the noise problem — header checks that fire on every route, every run, forever — and the predictable outcome is that the gate gets switched off and the control silently stops working.

HeaderHawk is built around those four failures: **assessed-vs-not-assessed as a first-class result**, **requirement-keyed output**, **confirmation before reporting**, and **a baseline so the gate fails on regressions rather than permanently**.

---

## What you get

### A report keyed by requirement, not by finding

`--evidence report.md` (or `.json`) answers the question an assessor actually asks. Real output:

```markdown
# HeaderHawk Compliance Evidence

- **Tool:** HeaderHawk 2.13.2
- **Target(s):** https://app.example.com/
- **Scan mode:** unauthenticated
- **Requests:** 604/604 succeeded (0 failed)

## Summary

| Status | Controls |
| --- | --- |
| Fail | 12 |
| Not assessed | 1 |
| Pass | 13 |

> This scan was not confirmed to be running as a logged-in user, so these results
> describe whatever the target serves anonymously. For an authenticated product
> that is the login page, not the application behind it.
```

Every control is then listed with its framework, the requirement text transcribed from the standard, a link to the source chapter, and its evidence:

```markdown
### ASVS-5.0:13.4.6 — FAIL

- **Requirement:** The application does not expose detailed version information of backend components.
- **Source:** https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md
- **Assessed by:** Response Header Posture
- **Evidence:** 1 finding(s)
  - **[Low] Version Disclosure** — https://app.example.com/
    - Response header field(s) expose a component version: Server: nginx/1.18.0
    - Reproduce: `curl -s -i 'https://app.example.com/'`

### ASVS-5.0:1.2.1 — PASS

- **Requirement:** Output encoding for an HTTP response is relevant for the context required,
  including for HTTP header fields, so that untrusted data cannot change the structure of the message.
- **Assessed by:** CRLF Injection
- **Evidence:** assessed, no finding.

### PCI-DSS-4.0.1:11.6.1 — NOT ASSESSED

- **Requirement:** A change- and tamper-detection mechanism alerts on unauthorised modification
  of the security-impacting HTTP headers and script content of payment pages.
- **Not assessed because:**
  - baseline comparison: no baseline was supplied, so no change detection was
    performed (pass --baseline <previous.json>)
```

**A control only passes when a check that covers it actually completed.** That single rule is what makes the document worth putting in front of an assessor. Everything else is reported as *not assessed*, with the reason — and a finding type that maps to no catalogued requirement is listed at the end rather than quietly dropped.

### Findings you can act on

```
[!] Host Header Injection Finding! [Medium]
URL: https://app.example.com/
Method: GET
Header: X-Forwarded-Host
Payload: 297aa83e0c90.example-collab.com
Status Code: 200
Analysis: Injected host reflected in 'Location' header: https://297aa83e0c90.example-collab.com/next
Reproduce: curl -s -i -H 'X-Forwarded-Host: 297aa83e0c90.example-collab.com' 'https://app.example.com/'
```

Every finding carries a severity, the requirements it is evidence against, and a **copy-paste command that reproduces it** — `curl` for header and parameter issues, a `printf | ncat` or `openssl s_client` wire-level command for the raw-socket bypasses that curl cannot express.

The run ends with a summary that always states coverage and reachability, so a quiet result can be read correctly:

```
========== Test Summary ==========
Targets scanned: 1/1
Scan mode: unauthenticated
Requests: 604/604 succeeded (0 failed).
Total findings: 14 (5 vulnerability, 9 posture)
```

### Reports in the format your tooling already reads

`--output` picks the format from the extension: **`.json`** for pipelines, **`.md`** for humans, **`.sarif`** for GitHub code scanning and security dashboards — with per-rule `security-severity` scores, stable fingerprints so alerts do not churn, and the mapped requirement in the rule help text.

---

## How it decides something is true

A header scanner earns its place by what it refuses to report. These are the rules HeaderHawk applies.

### Confirmed, not inferred

| Class | What counts as proof |
| ----- | -------------------- |
| **Host header injection** | A unique per-request marker comes back in the body, in `Location`, or in any response header. A guessable value would not distinguish reflection from coincidence. |
| **Web cache poisoning** | The poisoning request is sent through an unkeyed header, then the same URL is requested **without it**. Only a marker that survives into the second response — served from cache — is reported, with `X-Cache` / `Age` / `CF-Cache-Status` context. |
| **Web cache deception** | A page still served under a `.css` suffix is half of it. The same URL is then requested by a session carrying **no cookies and no authorization**; content only the logged-in session should have seen, coming back to an anonymous one, is a shared cache handing one user's page to another. A response that already says `no-store` or `private` is not reported at all — that control is working. |
| **CRLF injection** | The injected header field is *named* after a unique per-scan marker, so a field carrying it cannot have come from anywhere else. A value merely echoed into `Location` is not reported. |
| **CORS** | A per-scan origin that cannot exist is sent; only the server echoing it back counts. Severity follows `Access-Control-Allow-Credentials`, because a permissive allowlist that also allows credentials lets an attacker's page read authenticated responses. A bare `*` without credentials — correct for a public endpoint — produces nothing. |
| **Virtual host discovery** | The default vhost is sampled repeatedly to learn its natural page-to-page variance; a candidate is reported only when a status, length or title difference survives a second probe. |
| **SSRF** | Response-time deviation, internal-target indicators and header anomalies are combined behind a weighted threshold. Anomalies are measured only against headers proven stable across baseline samples, so request ids, tracing headers, `CF-RAY` and nonces are learned as volatile and ignored. |
| **Request smuggling** | A hang is reported only after two consecutive probes agree **and** a well-formed request in between still returns normally — which is what separates a desync from a target that merely became slow. |

### Honest about the limits of its own evidence

Timing is evidence, not proof. Every smuggling finding carries a `Confirming this` note stating exactly that, what to run for certainty, and what that costs — printed to the console and included in every report format. Confirming a desync for real is **intrusive**: `--enable-desync` plants a smuggled prefix that can attach to another user's request. It is opt-in, and the warning says why.

The same applies elsewhere: an unconfirmed cache-deception finding tells you it needs an authenticated session to prove, and which flags supply one.

### One defect, one finding

Five static-looking suffixes that all work are one defect with one fix, so they are one finding that names all five. A server that reflects *any* origin is reported once as reflection, not five times over as each narrower bypass. One CRLF hole is reported once, not once per encoding that reaches it.

### Findings split by class, so the gate stays useful

Proven **vulnerabilities** and missing **posture** controls are counted separately, and `--fail-on` decides which gate the exit code. Turning on posture reporting does not turn an existing pipeline red.

---

## Coverage

**14 check modules, 35 finding types, 26 catalogued requirements.**

### Request side — what an attacker manipulates

| Attack class | Vectors exercised |
| ------------ | ----------------- |
| **Host header injection** | 19 routing headers — `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-Host`, `X-HTTP-Host-Override`, `Forwarded`, `Base-Url` and more — with marker reflection checked in body, `Location` and every response header |
| **Host validation bypass** | Duplicate `Host` headers, absolute-URI request lines, line-folded headers, host overrides — sent verbatim by a purpose-built raw HTTP/1.1 client, because `requests` would normalise them away |
| **Unkeyed input discovery** | **91 intermediary-set header fields** searched by bisection — `X-Forwarded-Scheme`, `CDN-Loop`, `X-Envoy-Original-Path`, `X-Wap-Profile`, … Ruling out the whole list costs **one request**; isolating one header among ninety costs about a dozen |
| **Web cache poisoning** | Unkeyed headers plus a cache-buster and a clean re-request that proves the poisoned response is served back |
| **Web cache deception** | Static-looking suffixes (`.css`, `/nonexistent.js`, `;.css`, …) a router ignores but a CDN keys on |
| **Access-control bypass** | Internal `Host` / `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` values against 401/403 endpoints, plus the `X-Original-URL` / `X-Rewrite-URL` path-override family |
| **SSRF via routing headers** | Routing headers pointed at internal hosts and cloud metadata endpoints |
| **Blind SSRF (out-of-band)** | Per-scan correlation id in payloads, confirmed by polling your listener — interactsh, webhook.site, RequestBin, Burp Collaborator exports, custom sinks. An interaction is attributed to the payload hostname that caused it, so one visit is one finding; an export naming only the scan id is reported once, as an interaction whose vector could not be identified |
| **URL-parameter SSRF** | `url`, `next`, `redirect`, `dest`, `uri`, `path`, … against internal targets, with baseline differencing |
| **Open redirect** | `Host`-driven redirects whose `Location` host matches the injected value |
| **CRLF injection / response splitting** | Percent-encoded, double-encoded and overlong-UTF-8 `CR`/`LF` in parameters, path and decoded headers |
| **HTTP request smuggling** | CL.TE and TE.CL front-end/back-end disagreement, detected by timing |
| **Virtual host discovery** | `Host` brute force over 44 built-in names or your own wordlist, two-probe confirmed |

### Response side — what your product is supposed to send

| Area | Assessed |
| ---- | -------- |
| **Transport & framing** | `Strict-Transport-Security` (including `max-age` and `includeSubDomains`), `frame-ancestors` / `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy` |
| **CSP, read the way a browser reads it** | `'unsafe-inline'` is **not** reported when a nonce or hash is also present, because a browser ignores it there; `'strict-dynamic'` suppresses host and scheme allowlist findings for the same reason; `object-src` accepts a `default-src` fallback while `base-uri`, which has none, must be explicit; `*.example.com` is treated as an allowlist, not an open door |
| **Cookies, per `Set-Cookie` field** | `Secure`, `SameSite`, `__Secure-` / `__Host-` prefixes and the 4096-byte limit — parsed individually, including several folded into one header, without tearing apart the comma inside an `Expires` date. `HttpOnly` is reported only for cookies whose name suggests a session or sensitive value, since an analytics cookie legitimately needs script access |
| **Information exposure** | Version banners in `Server`, `X-Powered-By` and friends |

### Requirements catalogued

**OWASP ASVS 5.0** — 25 requirements across encoding (1.2.1), cookies (3.3.1–3.3.5), browser controls (3.4.1–3.4.8), redirects (3.7.2), intermediary headers (4.1.3), message boundaries (4.2.1–4.2.2), authorization (8.3.1), SSRF allowlists (13.2.4–13.2.5), exposure (13.4.5–13.4.6) and caching (14.2.2, 14.2.5).

**PCI DSS 4.0.1** — requirement 11.6.1, satisfied by running with `--baseline`. See [In your pipeline](#in-your-pipeline).

Control ids are transcribed from the published standard and each links to the chapter it came from. **A finding type with no genuinely matching requirement is reported as unmapped rather than attached to an approximate one** — an id that does not hold up under review is worse than an empty column. `Permissions-Policy` is the current example: ASVS 5.0 has no requirement for it, so it is reported without one.

---

## Where HeaderHawk fits

It is a narrow tool, deliberately. Here is where it sits next to the things you probably already run.

| Tool | Strongest at | What HeaderHawk adds |
| ---- | ------------ | -------------------- |
| **Burp Suite Pro** (+ Param Miner, HTTP Request Smuggler) | The deepest interactive research on exactly these classes — this is where much of the technique originated | Headless, repeatable, unattended. Same classes without an operator driving the GUI, and the output is requirement-keyed evidence rather than an issue list |
| **Nuclei** | Enormous community template breadth across every vulnerability class | Templates largely match on presence and absence. HeaderHawk confirms with a second probe, searches 91 headers by bisection rather than testing a fixed list, and reports what it could not assess |
| **OWASP ZAP** | Full DAST across the whole application surface | Depth on header-specific classes that a general crawler treats shallowly — unkeyed input discovery, cache deception, desync timing — plus the compliance report |
| **securityheaders.com**, **Mozilla Observatory** | Instant response-header grade for a single URL | The request side, which those do not test at all; many endpoints per run; CI gating; and evidence rather than a letter grade |
| **testssl.sh** | The model: one focused layer, exhaustively, honestly, CI-friendly | The same idea one layer up — headers instead of TLS |

### What HeaderHawk is not

- **Not a full DAST.** No SQL injection, no XSS body scanning, no business-logic or authorization-model testing. Run it alongside ZAP or Burp, not instead of them.
- **Not HTTP/2 or HTTP/3 aware.** All traffic is HTTP/1.1, so HTTP/2-specific downgrade desync is out of scope — and reported as not assessed rather than passed.
- **Not a runtime control.** It tells you a header is missing; it does not add one.
- **Not a substitute for a human on the classes it flags as timing-only.** It says so in the finding.

---

## Scanning what you actually ship

The default is one URL, anonymous. Real products are neither.

### Drive the scan from a request you captured

The request worth testing carries a session cookie, a bearer token, a CSRF token, a content type and a JSON body. Save it from your browser's dev tools or an intercepting proxy and hand the file over:

```bash
python headerhawk.py --request order.txt
```

```http
POST /api/v2/orders?page=2 HTTP/1.1
Host: shop.example
Content-Type: application/json
Cookie: session=abc123; theme=dark
Authorization: Bearer t0ken
X-Csrf-Token: csrf-9f2
Content-Length: 17

{"quantity": 100}
```

The file supplies the URL, the method and the body, so the positional URL and `--methods` become optional. Give an explicit URL to replay the same request against staging or another region.

**The file is a starting point, not a fixed request.** Every check still sets the header it is testing: where the file already carries that header the check's value **replaces** it, and where it does not the check **adds** it. That holds down to the raw-socket probes, so a Host bypass is tested as the authenticated request it really is.

Four things are deliberately not carried over. `Host` decides the target rather than travelling as a header — pinning it would neutralise every Host-manipulation check. `Content-Length` and `Transfer-Encoding` are the smuggling probes' own subject. The connection-management fields describe one hop that is not the one being made. And the body is replayed only on the method the file used, bounded by the declared `Content-Length`.

Credentials from the file **never reach a report**: their values are redacted from both the stored wire request and the reproduction command, which then says what to add back and where to find it.

### Log in first

```bash
export HH_LOGIN='user=admin&pass=s3cret'
python headerhawk.py https://app.example.com/dashboard \
       --auth-login-url https://app.example.com/login \
       --auth-login-data env:HH_LOGIN \
       --auth-verify-text 'Sign out'
```

Credentials can be a cookie (`--auth-cookie 'sid=…'`) or a form login; either accepts `env:NAME` to stay out of the command line and shell history.

**The session is checked, not assumed.** If you said what a logged-in page contains and it is not there, the scan **stops** rather than assess the logged-out pages and present them as the product's. With no expectation given, the authenticated response is compared with an anonymous one, and a session that changes nothing is reported as such. And because a scan that walks a site can log itself out partway through, the session is re-verified at the end — if it was valid at the start and not at the end, the results are reported as inconclusive.

The scan mode — `authenticated`, `authentication unverified` or `unauthenticated` — appears in the summary and in the evidence report, never suppressed, because whether the scan saw the product or its login page decides what every other line means.

### Cover more than one route

```bash
python headerhawk.py https://app.example.com/ --discover --max-endpoints 20
```

`--discover` reads what the target already publishes about itself: an **OpenAPI/Swagger** description, **sitemap.xml** (following a sitemap index one level), **robots.txt**, and the **same-origin links on the page**. Nothing is guessed or brute-forced — a scan that invents paths spends its budget on 404s.

URLs that are the same endpoint collapse: `/order/1041`, `/order/1042` and `/order/1043` are three URLs, one endpoint, one set of headers and one place a fix would go. Identifier-looking path segments become placeholders and a query string reduces to its parameter names. Without that, a paginated site spends the whole budget on one route. The URL you asked for always comes first and is never displaced, and when more endpoints are found than the limit allows, the run says so rather than implying the product was that small.

Some checks belong to the host rather than the route — a front-end that mis-parses `Host`, or desyncs from its back-end, does so for every route at once:

| Scope | Checks |
| ----- | ------ |
| Endpoint | response header posture, CSP, cookies, Host header injection, cache poisoning, unkeyed inputs, cache deception, CORS, CRLF injection, access-control bypass, URL-parameter SSRF, open redirect |
| Host | virtual host discovery, Host validation bypass, SSRF via routing headers, request smuggling |

Running those per endpoint would issue identical requests and file identical findings, so they run against the requested target only.

### Scan a whole estate

```bash
python headerhawk.py --list targets.txt -o report.json
```

One run, one aggregated report, one summary, one exit code.

---

## In your pipeline

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed, nothing gated on was found |
| `1` | Findings in the classes selected by `--fail-on` |
| `2` | The scan could not run, or could not finish — bad input, an unreachable target, an interrupt, or an unexpected error |

**An unreachable host exits `2`, never `0`.** A pipeline that treats "no findings" as success must not be handed a silent failure. For the same reason an unexpected error never exits `1`: that code means findings were reported, and a crash is not a finding.

A single check that fails unexpectedly does not end the run. It is recorded as a check that did not assess its controls — so the requirements it covers read *not assessed*, with the reason — the remaining checks still run, and both report files are still written.

### Fail on regressions, not forever

```bash
# Accept today's state
python headerhawk.py https://app.example.com -o baseline.json

# From now on, fail only on what is new
python headerhawk.py https://app.example.com --baseline baseline.json \
       --fail-on any --fail-on-new
```

`--baseline` reports `N new, N fixed, N unchanged`. `--fail-on-new` narrows the gate to the new ones, so a team that has accepted its current findings gets a pipeline that fails on a **regression** instead of failing permanently — which is the difference between a gate that stays on and one that gets deleted.

A finding keeps the same identity between runs even though several checks put a fresh random marker in every payload: marker-shaped tokens are folded out before matching. Without that, every finding would look new on every run.

### PCI DSS 4.0.1 requirement 11.6.1

11.6.1 asks for a change- and tamper-detection mechanism that alerts on unauthorised modification of the security-impacting HTTP headers of payment pages, evaluated at least weekly (or at the frequency set by a targeted risk analysis). Running the baseline comparison on a schedule **is** that mechanism:

```bash
python headerhawk.py https://shop.example/checkout \
       --baseline last-week.json --fail-on-new \
       --evidence pci-11.6.1.md -o this-week.json
```

The evidence report marks 11.6.1 as assessed when a baseline was supplied and as **not assessed** when one was not. Detecting a change is the mechanism working, not the control failing.

### GitHub code scanning

```bash
python headerhawk.py https://app.example.com -o headerhawk.sarif --fail-on vuln
```

Upload the SARIF with `github/codeql-action/upload-sarif`. Alerts carry the severity, the mapped requirement and a stable fingerprint, so they deduplicate across runs instead of reopening.

### Staying under the radar

`--rate 5` caps the entire scan — all threads plus the raw client — at a fixed requests-per-second budget, which is usually what it takes to survive a WAF. `--proxy http://127.0.0.1:8080` routes everything through an intercepting proxy including the raw bypass traffic, tunnelled with `CONNECT` so the malformed requests reach the target intact. `--insecure` genuinely disables TLS verification even when the environment sets `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE`, which otherwise silently override it.

---

## Installation

Python **3.8+**, four dependencies, no services and no database.

```bash
git clone https://github.com/kabiri-labs/HeaderHawk.git
cd HeaderHawk
pip install -r requirements.txt
python headerhawk.py https://example.com
```

`requests`, `urllib3`, `tqdm`, `colorama`. The test suite is fully offline — no network access required.

---

## Options

### Target

| Option | Purpose |
| ------ | ------- |
| `<target_url>` | The URL to scan. Required unless `--list` or `--request` is given |
| `--list`, `-l` `<file>` | Scan every URL in a file, one per line (`#` comments ignored) |
| `--request`, `-r` `<file>` | Drive the scan from a raw HTTP request saved from a browser or proxy |
| `--request-scheme {http,https}` | Scheme for `--request` when the file has no absolute URL. Defaults to the scheme implied by a `:80`/`:443` port in `Host`, otherwise `https` |
| `--discover` | Scan the endpoints the target publishes about itself |
| `--max-endpoints <n>` | Cap for `--discover` (default 20) |
| `--openapi <url>` | OpenAPI/Swagger description not at a standard path. Requires `--discover` |
| `--methods <list>` | Comma-separated methods (default `GET`, or the method in `--request`) |
| `--header`, `-H` `"Name: Value"` | Extra request header. Repeatable, and wins over `--request` |

### Authentication

| Option | Purpose |
| ------ | ------- |
| `--auth-cookie <cookies>` | Scan with these cookies, as `'a=1; b=2'`. Accepts `env:NAME` |
| `--auth-login-url <url>` | Log in by submitting a form before scanning |
| `--auth-login-data <body>` | Form body for the login. Accepts `env:NAME` |
| `--auth-login-method <method>` | Method for the login request (default `POST`) |
| `--auth-verify-text <text>` | Text that appears only when logged in — the scan stops if it is absent |
| `--auth-verify-absent <text>` | Text that appears only when logged out. The inverse of the above |

### Output and gating

| Option | Purpose |
| ------ | ------- |
| `--output`, `-o` `<file>` | Report file; format from the extension (`.json`, `.md`, `.sarif`) |
| `--evidence <file>` | Per-requirement compliance report (`.md` or `.json`) |
| `--baseline <file>` | A previous scan's JSON; findings reported as new, fixed or unchanged |
| `--fail-on-new` | Gate the exit code on findings absent from `--baseline`. Requires `--baseline` |
| `--fail-on {vuln,posture,any,none}` | Which classes make the process exit `1` (default `vuln`) |
| `--verbose {1,2}` | Level 2 also records non-findings for the report |
| `--quiet`, `-q` | Strip progress bars and colour. Auto-enabled when stdout is not a TTY |

### Network

| Option | Purpose |
| ------ | ------- |
| `--threads <n>` | Concurrent threads, 1–20 (default 5) |
| `--rate <n>` | Cap the whole scan at N requests/second (0 = unlimited) |
| `--timeout <s>` | Per-request timeout (default 10) |
| `--proxy <url>` | Upstream/intercepting proxy, raw traffic included. Supports `user:pass@` |
| `--insecure`, `-k` | Disable TLS certificate verification |

### Specialised

| Option | Purpose |
| ------ | ------- |
| `--oob <domain>` | OOB/collaborator domain embedded in payloads for blind SSRF |
| `--oob-poll-url <url>` | Listener export URL polled afterwards to confirm interactions |
| `--wordlist`, `-w` `<file>` | Custom virtual-host wordlist |
| `--enable-desync` | Confirm a suspected desync by planting a smuggled prefix. **Intrusive** — the prefix can attach to another user's request and corrupt or misroute live traffic. Without it, smuggling is reported from timing alone |

`Ctrl+C` stops a run gracefully; results collected so far are still written to `--output` and `--evidence`.

---

## Contributing

### Project layout

The scanner is a package; `headerhawk.py` at the repository root is a thin entry point so `python headerhawk.py <target>` keeps working from a checkout.

```
headerhawk/
├── cli.py                 # argument parsing and scan orchestration
├── _meta.py               # tool name, version, project URL
├── compliance/            # control catalogue and finding -> control mapping
├── core/                  # engine: session, pacing, stats, severity, OOB, request files
├── net/raw.py             # raw HTTP/1.1 client, with timed byte-exact sends
├── discovery/             # endpoint sources and URL-shape collapsing
├── posture/               # response-side assessment
│   ├── facts.py           # the response view a rule is given
│   ├── rules.py           # header and CSP rules
│   └── cookies.py         # Set-Cookie parsing and cookie rules
├── checks/                # one module per class of weakness
│   ├── base.py            # shared scaffolding (requests, thread pool, findings)
│   ├── wordlists.py       # header and virtual-host name lists
│   └── registry.py        # ordered list of checks the CLI runs
└── report/                # JSON, SARIF and Markdown rendering
```

### Adding a detection module

Subclass `BaseTest` in a new `checks/` module, give it a `test_type`, add that type to `SEVERITY_BY_TEST` in `core/severity.py`, and register the class in `checks/registry.py`. Also give it an entry in `compliance/mapping.py` — an empty tuple is a valid answer, but **the decision may not be skipped**; a test enforces it.

### House rules

Two of them carry most of the weight:

1. **Every change ships with a test.** `python -m unittest discover -s tests` must pass — 565 tests, fully offline.
2. **A check must be able to say it could not judge.** Call `skip(reason)` rather than returning silently; the evidence report prints that reason next to the requirements consequently left unassessed. A check that quietly returns nothing turns an unreachable target into a clean bill of health.

Fork, branch (`feat/…` or `fix/…`), keep the suite green, open a pull request.

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

HeaderHawk is intended for authorised testing only. Some checks send deliberately malformed requests, and `--enable-desync` can affect other users' traffic. Using it against systems you do not have explicit permission to test is illegal. The authors accept no liability for misuse.

## Contact

- **Email:** [certification.kabiri@gmail.com](mailto:certification.kabiri@gmail.com)
- **Issues:** [github.com/kabiri-labs/HeaderHawk/issues](https://github.com/kabiri-labs/HeaderHawk/issues)
