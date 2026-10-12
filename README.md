# HeaderHawk

[![Version](https://img.shields.io/badge/version-2.21.0-brightgreen.svg)](headerhawk.py)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-787%20passing-brightgreen.svg)](tests)
[![GitHub Stars](https://img.shields.io/github/stars/kabiri-labs/HeaderHawk.svg?style=social&label=Star)](https://github.com/kabiri-labs/HeaderHawk)

**An HTTP header scanner that produces evidence an auditor will accept.**

HeaderHawk tests both sides of the exchange — the **request headers an attacker manipulates** (`Host`, `X-Forwarded-*`, `Forwarded`, client-IP and URL-override headers) and the **response headers your product is supposed to send** (HSTS, CSP, cookie attributes, framing). **14 check modules, 36 finding types, 26 catalogued requirements.**

```bash
python headerhawk.py https://app.example.com/ --discover \
       --evidence compliance.md --output findings.sarif --fail-on any
```

Three artefacts, one run: a requirement-by-requirement compliance report, a SARIF file for your dashboard, and an exit code your pipeline can gate on.

Three things set it apart from a header checklist:

- **It confirms before it reports.** A finding has to survive a second probe, or it is filed as the single observation it is. [How it decides](#why-its-findings-hold-up)
- **It tells you what it could not assess, instead of counting it as a pass.** An unreachable target, a login page mistaken for the product, a cache that hides the answer — each is reported as a gap with a reason, never as compliance. [The report](#what-it-produces)
- **Its claims are checked against real servers**, not only against mocks that reply with whatever a test told them to. [The lab](#verified-against-real-servers)

---

## Contents

- [What it detects](#what-it-detects)
- [What it produces](#what-it-produces)
- [Quickstart](#quickstart)
- [Worked examples](#worked-examples)
- [Why its findings hold up](#why-its-findings-hold-up)
- [Compared with the tools you already run](#compared-with-the-tools-you-already-run)
- [Scanning what you actually ship](#scanning-what-you-actually-ship)
- [In your pipeline](#in-your-pipeline)
- [Options](#options)
- [Verified against real servers](#verified-against-real-servers)
- [Limits](#limits)
- [Contributing](#contributing)
- [License, disclaimer, contact](#license)

---

## What it detects

### Request side — what an attacker manipulates

| Attack class | Vectors exercised |
| ------------ | ----------------- |
| **Host header injection** | 19 routing headers — `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-Host`, `X-HTTP-Host-Override`, `Forwarded`, `Base-Url` and more — each probed with the shapes two parsers disagree about: the host plain, as a prefix (`target.marker`), as userinfo (`target@marker`), appended to a list (`target, marker`), with an explicit port and with a trailing dot; `Forwarded` with RFC 7239 parameter syntax; a URL-valued header with an absolute URL. Reflection is checked in the body, `Location` and every response header |
| **Host validation bypass** | Six wire shapes a header mapping cannot express: duplicate `Host` headers **both ways round** (which of the two wins is a choice each implementation makes for itself), the obsolete fold with a space **and** with a tab (a middlebox that strips one does not always strip the other), whitespace before the colon (RFC 7230 says a server must reject it; one that reads it anyway, behind one that rejected nothing, is the bug) and absolute-URI request lines — all sent verbatim by a purpose-built raw HTTP/1.1 client, because `requests` would normalise them away. **A bypass is a refusal that was got past**, so a baseline establishes the refusal first: one well-formed request carrying the target's own host and one carrying a host minted for the scan. An ordinary `Host` header is that baseline, not a technique — where an unknown host is refused it *is* the refusal, and where it is not, there was nothing to bypass |
| **Unkeyed input discovery** | **91 intermediary-set header fields** searched by bisection — `X-Forwarded-Scheme`, `CDN-Loop`, `X-Envoy-Original-Path`, `X-Wap-Profile`, … Ruling out the whole list costs **one request**; isolating one header among ninety costs about a dozen. Each one carries a value of the shape it really holds: a scheme header gets a scheme — **the one the target does not already have**, because offering a target its own scheme asks it nothing — a port header gets a port it is not already on, an address header gets an address from the documentation range. **46 of the 91** mean nothing as a hostname, and a hostname is what they all used to be sent |
| **Web cache poisoning** | Unkeyed headers plus a cache-buster and a clean re-request that proves the poisoned response is served back |
| **Web cache deception** | Static-looking suffixes (`.css`, `/nonexistent.js`, `;.css`, …) a router ignores but a CDN keys on |
| **Access-control bypass** | Internal `Host` / `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` values against 401/403 endpoints, plus the `X-Original-URL` / `X-Rewrite-URL` path-override family |
| **SSRF via routing headers** | Routing headers pointed at internal hosts and cloud metadata endpoints |
| **Blind SSRF (out-of-band)** | Per-scan correlation id in payloads, confirmed by polling your listener — interactsh, webhook.site, RequestBin, Burp Collaborator exports, custom sinks. An interaction is attributed to the payload hostname that caused it, so one visit is one finding; an export naming only the scan id is reported once, as an interaction whose vector could not be identified |
| **URL-parameter SSRF** | `url`, `next`, `redirect`, `dest`, `uri`, `path`, … against internal targets, with baseline differencing |
| **Open redirect** | `Host`-driven redirects whose `Location` host matches the injected value, on a status a browser follows, on a second probe as well, and for a host minted for this scan. Well-known hostnames are sent too — an application that resolves a destination before redirecting takes one of those where a marker fails — but on their own they are reported as the weaker evidence they are. One finding, naming every host that held |
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

**PCI DSS 4.0.1** — requirement 11.6.1, satisfied by running with `--baseline` on a schedule. See [PCI DSS 11.6.1](#pci-dss-401-requirement-1161).

Control ids are transcribed from the published standard and each links to the chapter it came from. **A finding type with no genuinely matching requirement is reported as unmapped rather than attached to an approximate one** — an id that does not hold up under review is worse than an empty column. There are two examples. `Permissions-Policy`, because ASVS 5.0 has no requirement for it, reported at `Info` and so below the default reporting threshold. And **`Host Header Poisoning`**: 4.1.3 is about a field *set by an intermediary layer* that the end user must not be able to override, and the client sets `Host` by definition of HTTP/1.1 — so poisoning a link or a reset email through it has no catalogued requirement, and citing 4.1.3 would be the stretch this rule exists to prevent. The same marker reflected in `X-Forwarded-Host` and its family, which an intermediary really does set, is reported as `Host Header Injection` against 4.1.3. When the poisoning takes the shape of a redirect it also fails 3.7.2, which the open-redirect check reports under that id.

---

## What it produces

### A report keyed by requirement, not by finding

`--evidence report.md` (or `.json`) answers the question an assessor actually asks: *show me that requirement 4.1.3 is met.* Every control is listed with its framework, the requirement text transcribed from the standard, a link to the source chapter, and its evidence.

```markdown
## Summary

| Status | Controls |
| --- | --- |
| Fail | 12 |
| Not assessed | 1 |
| Partly assessed | 1 |
| Pass | 12 |

### ASVS-5.0:13.4.6 — FAIL

- **Requirement:** The application does not expose detailed version information of backend components.
- **Source:** https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md
- **Assessed by:** Response Header Posture
- **Evidence:** 1 finding(s)
  - **[Low, confirmed] Version Disclosure** — https://app.example.com/
    - Response header field(s) expose a component version: Server: nginx/1.18.0
    - Reproduce: `curl -s -i 'https://app.example.com/'`

### ASVS-5.0:4.1.3 — PARTLY ASSESSED

- **Requirement:** An HTTP header field set by an intermediary layer cannot be overridden
  by the end user.
- **Assessed by:** Auth Bypass, Host Header Bypass, Host Header Injection, Web Cache Poisoning
- **Evidence:** assessed by the above, no finding - but not everything covering this
  control could look, so this is not a pass.
- **Not looked at by:**
  - Unkeyed Input: the cache answered a URL this scan had just invented, so the
    query string is not part of its key
```

**A control only passes when everything that covers it actually looked.** That single rule is what makes the document worth putting in front of an assessor, and it has four answers rather than three. The report lists them worst first, in this order:

| Status | Meaning |
| ------ | ------- |
| **Fail** | A finding is evidence against this requirement |
| **Not assessed** | Nothing could assess it, with the reason |
| **Partly assessed** | Some checks judged it; another recorded that it could not look. Signing it off on the strength of the ones that happened to run would drop the check whose silence could be hiding the failure |
| **Pass** | Everything covering it could judge it, and found nothing |

The distinction between the middle two is whether a check *could not look* or had *nothing to look at*. A cache that answers every URL the scan invents from one stored response blinds the unkeyed search, and the requirement cannot be signed off without it. A JSON reply simply has no document for a framing or CSP requirement to act on, so where another check did judge that control, nothing is missing. The first costs a control its pass; the second does not. A finding type that maps to no catalogued requirement is listed at the end rather than quietly dropped.

### Findings you can act on

```
[!] Host Header Injection Finding! [Medium, confirmed]
URL: https://app.example.com/
Method: GET
Header: X-Forwarded-Host
Payload: hh297aa83e0c90.example-collab.com
Status Code: 302
Analysis: 'X-Forwarded-Host' decides a host this response points a browser at: the
marker came back as the host of a URL (hh297aa83e0c90.example-collab.com) in the
'Location' header, and the same probe produced it again on a second request. Shape(s)
reflected: appended to a list, plain, target as userinfo.
Reproduce: curl -s -i -H 'X-Forwarded-Host: hh297aa83e0c90.example-collab.com' 'https://app.example.com/'
```

Every finding carries a severity, how well it is evidenced, the requirements it is evidence against, and a **copy-paste command that reproduces it** — `curl` for header and parameter issues, a `printf | ncat` or `openssl s_client` wire-level command for the raw-socket bypasses that curl cannot express.

The run ends with a summary that always states coverage and reachability, so a quiet result can be read correctly:

```
========== Test Summary ==========
Targets scanned: 1/1
Scan mode: unauthenticated
Requests: 604/604 succeeded (0 failed).
Total findings: 14 (5 vulnerability, 9 posture)
Evidence: 6 confirmed, 8 suspected
Not shown: 4 posture finding(s) below --min-severity medium (the compliance evidence report lists every one)
```

### Formats your tooling already reads

`--output` picks the format from the extension: **`.json`** for pipelines, **`.md`** for humans, **`.sarif`** for GitHub code scanning and security dashboards — with per-rule `security-severity` scores, the confidence the finding carries, fingerprints that survive the per-scan marker so alerts deduplicate instead of reopening, and the mapped requirement in the rule help text.

---

## Quickstart

Python **3.8+**, four dependencies, no services and no database.

```bash
git clone https://github.com/kabiri-labs/HeaderHawk.git
cd HeaderHawk
pip install -r requirements.txt
python headerhawk.py https://example.com
```

`requests`, `urllib3`, `tqdm`, `colorama`. The test suite is fully offline — no network access required.

---

## Worked examples

From the first run to a captured authenticated request driving a whole estate. Each step adds one idea to the one before it.

### 1. The first scan

```bash
python headerhawk.py https://app.example.com/
```

One URL, anonymous, `GET`, findings on the console. Nothing is written to disk. This is the right first command against any target: it tells you whether the target answers at all, how many requests the scan costs, and whether there is anything obvious before you decide what else to ask for.

### 2. Keep the evidence

```bash
python headerhawk.py https://app.example.com/ \
       --evidence compliance.md -o findings.json
```

Two artefacts that answer different questions. `--evidence` is the per-requirement document — every catalogued control, its status and why. `-o findings.json` is the finding list, and it is also the file `--baseline` reads back later, so this is the run worth keeping.

### 3. More than one route

```bash
python headerhawk.py https://app.example.com/ --discover --max-endpoints 20
```

Reads the target's own OpenAPI description, `sitemap.xml`, `robots.txt` and same-origin links; guesses nothing. Endpoint-scoped checks run per route, host-scoped checks once. Raise `--max-endpoints` when the run reports it found more than the cap allowed.

### 4. Behind a login

```bash
# A cookie you already have
python headerhawk.py https://app.example.com/dashboard \
       --auth-cookie 'session=abc123' \
       --auth-verify-text 'Sign out'

# Or let it log in
export HH_LOGIN='user=admin&pass=s3cret'
python headerhawk.py https://app.example.com/dashboard \
       --auth-login-url https://app.example.com/login \
       --auth-login-data env:HH_LOGIN \
       --auth-verify-text 'Sign out'
```

Always pass `--auth-verify-text`. Without it the scan cannot tell the product from its login page, and an authenticated scan that silently ran logged out is the most expensive kind of wrong answer. With it, the scan stops instead.

### 5. From a captured request

This is the mode that tests what you actually ship. A real request carries a session, a CSRF token, a content type and a body — and the endpoint behaves differently without them.

**Capture it.** In Burp or ZAP, right-click the request → *Copy to file*. In browser dev tools, *Copy as cURL* and paste the parts into a file. Either way you want the raw request, headers and body:

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

**Run it.** No URL and no `--methods` needed — the file supplies both:

```bash
python headerhawk.py --request order.txt --evidence compliance.md
```

```
Request file: order.txt (POST https://shop.example/api/v2/orders?page=2, 4 header(s), 17-byte body)
Targets: 1
Methods: POST
```

Four headers, not six: `Host` became the target and `Content-Length` belongs to the body, so neither travels as a header.

Every check now tests that endpoint **as the authenticated `POST` it really is**: the session cookie and bearer token ride on every probe, the JSON body is replayed on `POST`, and each check still sets the header it is testing — replacing the file's value where it already carries one. The raw-socket `Host` bypasses included, so they are tested as the real request rather than as an anonymous `GET`.

**Replay it elsewhere.** Give an explicit URL and the file's headers and body come along to a different environment:

```bash
python headerhawk.py https://staging.shop.example/api/v2/orders --request order.txt
```

**A file with no absolute URL** takes its scheme from the `:80`/`:443` port in `Host`, or `https` otherwise. Override it when the capture was plain HTTP:

```bash
python headerhawk.py --request order.txt --request-scheme http
```

**Add or override a header** for this run only — `-H` wins over the file:

```bash
python headerhawk.py --request order.txt -H 'X-Debug: 1'
```

Credentials in the file never reach a report: their values are redacted from the stored wire request and from the reproduction command, which says what to add back instead. What the file does *not* pin, and why, is in [Drive the scan from a request you captured](#drive-the-scan-from-a-request-you-captured).

### 6. The captured session across many endpoints

The captured request's headers go onto the session, so they apply to whatever targets you give it. This is the fullest use of the tool:

```bash
# That session, against every route the product publishes
python headerhawk.py --request order.txt --discover --max-endpoints 30 \
       --evidence compliance.md -o findings.json

# Or against a list of endpoints you chose yourself
python headerhawk.py --list endpoints.txt --request order.txt -o findings.json
```

With `--list` the targets come from the file of URLs and the captured request supplies the session, headers and body. One run, one aggregated report, one exit code.

### 7. In CI, gating on regressions

```bash
# Once: accept today's state
python headerhawk.py https://app.example.com/ -o baseline.json

# Every build after that
python headerhawk.py https://app.example.com/ \
       --baseline baseline.json --fail-on any --fail-on-new \
       -o headerhawk.sarif --evidence compliance.md
```

Exit `1` only for findings that are **new** against the baseline, exit `2` if the scan could not run. Upload `headerhawk.sarif` with `github/codeql-action/upload-sarif`. Non-TTY output is detected, so `--quiet` is already on in a pipeline.

### 8. Awkward targets

```bash
# Survive a WAF: cap the whole scan, raw client included
python headerhawk.py https://app.example.com/ --rate 5 --threads 3

# Watch every request, malformed ones included, through a proxy
python headerhawk.py https://app.example.com/ --proxy http://127.0.0.1:8080

# A test environment with a self-signed certificate
python headerhawk.py https://staging.internal/ --insecure

# Confirm blind SSRF against your own listener
python headerhawk.py https://app.example.com/ \
       --oob abc123.oast.fun --oob-poll-url https://…/export

# Everything: the real request, every route, full evidence, gated
python headerhawk.py --request order.txt --discover --max-endpoints 30 \
       --baseline baseline.json --fail-on any --fail-on-new \
       --rate 5 --evidence compliance.md -o headerhawk.sarif
```

---

## Why its findings hold up

A header scanner earns its place by what it refuses to report.

### Confirmed, not inferred

| Class | What counts as proof |
| ----- | -------------------- |
| **Host header injection** | A unique per-request marker comes back as **the host of a URL the response points a browser at** — a `Location` on a redirect status, a `Link` or `Refresh` header, or an `href`, `src`, `action` or `url=` in the body — and does so again when the same probe is repeated. That is a link- and redirect-poisoning primitive: a browser handed that response goes to a host the attacker chose. Three things deliberately do not count, because a browser does not act on any of them: a URL *printed* as text (`Requested https://marker/` in a diagnostic page, a field in a JSON error), a `Location` beside a non-redirect status, and a marker in the userinfo of a URL whose host is the target (`https://target@marker/`). Each is still reported, as `suspected`, which is what an echoed header is. |
| **Web cache poisoning** | The poisoning request is sent through an unkeyed header, then the same URL is requested **without it**. Only a response that comes back poisoned is reported, with `X-Cache` / `Age` / `CF-Cache-Status` context — proved by a marker that survives into it where the header's value can carry one — a value minted for this scan cannot arrive from anywhere but a store — and otherwise by the clean request being answered with the poisoned response **while a request for a different key, made at the same moment, is not**. Without that control a page that changed globally part way through the scan would read as a cache replaying a poisoned copy. |
| **Unkeyed input** | A candidate is reported when the response changes in a way a cache key built from the method, host, path and query does not capture, and the change survives a second probe. What is compared is a canonical artefact — the body with the page's own noise masked, its status, and the response headers a cache or a browser acts on — because a cache gadget changes a URL in the page, not the page's weight. The masking generalises, and only so far. A page carrying a timestamp shows three values while it is sampled and a fourth on the next request, so what is learned is the **place** it moved in — the text just before it and which occurrence of that text it was — and anything of that shape, or anything that looks generated, is masked *there*. A timestamp in a footer does not teach that every number on the page is noise; an asset hash that a header changes is a finding and not noise; and a timestamp moving in one table row does not mask the account id in the next. What moves is learned from everything the artefact covers, headers included. A page that will not reproduce itself even then falls back to its own measured variance, and says so in the finding. |
| **Web cache deception** | There has to be a page first: the gadget hands the next requester what the victim was served, so the bar is a **`2xx` and nothing else**. A front-end answering every URL with the same `403` is ignoring the suffix, but an identical refusal served to everyone is not a victim's page, and a redirect carries no page either — below the bar the route is reported as *not assessed* with the status, rather than as a pass. A page still served under a `.css` suffix is then half of it. The same URL is requested again by a session carrying **no cookies and no authorization**; content only the logged-in session should have seen, coming back to an anonymous one, is a shared cache handing one user's page to another. A response that already says `no-store` or `private` is not reported at all — that control is working. |
| **CRLF injection** | The injected header field is *named* after a unique per-scan marker, so a field carrying it cannot have come from anywhere else. A value merely echoed into `Location` is not reported. |
| **CORS** | A per-scan origin that cannot exist is sent; only the server echoing it back counts. Severity follows `Access-Control-Allow-Credentials`, because a permissive allowlist that also allows credentials lets an attacker's page read authenticated responses. A bare `*` without credentials — correct for a public endpoint — produces nothing. |
| **Open redirect** | The status has to be a redirect a browser follows, the host in `Location` has to be the host that was sent, an identical second probe has to redirect the same way, **and the host that was sent has to be one minted for this scan**. A fixed hostname cannot tell "the destination follows the header" from "this is where the site always redirects": a site whose canonical destination is one of the probe hostnames matches every probe for reasons that have nothing to do with the header. When the target redirects to the same place whatever the header says, nothing is reported at all. |
| **Virtual host discovery** | The default vhost is sampled repeatedly to learn its natural page-to-page variance; a candidate is reported only when a status, length or title difference survives a second probe. |
| **SSRF** | Content only an internal target would return — `ami-id`, an IAM credentials path, `root:x:0:0:` — or an interaction at your own out-of-band listener. **A slow response is never reported as SSRF**, and neither is a slow response plus a changed header: a target under load looks exactly like that. An internal error string is reported as `suspected`, with the flags that would settle it. Header anomalies are measured only against headers proven stable across baseline samples, so request ids, tracing headers, `CF-RAY` and nonces are learned as volatile and ignored. |
| **Request smuggling** | A hang is reported only after two consecutive probes agree **and** a well-formed request in between still returns normally — which is what separates a desync from a target that merely became slow. |

### Every finding says how well it is evidenced

Each finding carries a confidence: **`confirmed`** when the scanner reproduced it, **`suspected`** when one observation supports it and nothing re-tested it, and **`informational`** for context worth printing and never worth failing a build over. It appears on the console, in every report format and beside the severity in the evidence report, so a reader can tell proof from observation without reading the analysis. `informational` never gates the exit code.

Timing is evidence, not proof. Every smuggling finding carries a `Confirming this` note stating exactly that, what to run for certainty, and what that costs — confirming a desync for real is **intrusive**, so `--enable-desync` is opt-in and the warning says why. An unconfirmed cache-deception finding likewise tells you it needs an authenticated session to prove, and which flags supply one.

### Assessed only where the control can act

A JSON API reply has no document for a browser to frame, no referrer to withhold, no script to constrain and no opener to isolate. Failing it for a missing `Content-Security-Policy` is noise; **passing** it would be worse. So the document controls — CSP, framing, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`, CSP reporting — are assessed only on a response a browser renders as a document, and on anything else they are reported as *not assessed* naming the media type returned instead. Transport security, MIME sniffing, cookie attributes and a leaked version banner apply to every response and are assessed everywhere.

An SVG counts as a document — navigated to rather than drawn by an `<img>`, script inside it runs and a policy applies to it — and so does a response that declares no media type at all, because a browser may sniff one. `text/plain` does not: no links to send a referrer from, no script for a policy to constrain. Nor does XML, which is what a great many APIs answer with. This is per control, not per check: one HTML page in the scan is enough to have assessed the document controls, and the API endpoints alongside it no longer file a finding each for them.

### One defect, one finding

Five static-looking suffixes that all work are one defect with one fix, so they are one finding that names all five. A server that reflects *any* origin is reported once as reflection, not five times over as each narrower bypass. One CRLF hole is reported once, not once per encoding that reaches it. One routing header that echoes the marker is one finding naming every shape that worked — six shapes of one echoed header are one defect with one place to fix it. Every hostname a `Host`-driven redirect accepts is one finding naming all of them, and only the ones that held on their own second probe.

### Quiet enough to keep reading

Response-header posture has a long tail of controls that almost no site sets and that almost no site is meaningfully worse off for not setting. Reported on every route, every run, they are how a report stops being read. So `--min-severity` (default **`medium`**) decides the quietest posture finding the console, the Markdown report, the SARIF and the exit code take account of — and the run says how many it is not showing, so it is never silent about its own silence.

The threshold applies to posture only. A proven vulnerability is reported at any band: a confirmed internal hostname is filed as `Low`, and an operator who asked for less noise did not ask for that. Three bands are calibrated to their real stakes rather than their appearance — a missing `Referrer-Policy` (every current browser already withholds the path and query cross-origin), a missing `Permissions-Policy` (no catalogued requirement covers it), and framing restricted only by `X-Frame-Options` (honoured by every browser still in support). Each is still reported and each still fails its requirement in the evidence report; none reads as something to fix today.

Two artefacts are records rather than views and always carry every finding whatever band it is: the **compliance evidence report**, because a requirement that is unmet has to appear in the document an assessor reads, and **`-o <file>.json`**, because that is the file `--baseline` reads back. A baseline missing the findings the next scan still collects would report every one of them as new, run after run.

Proven **vulnerabilities** and missing **posture** controls are also counted separately, and `--fail-on` decides which gate the exit code — so turning on posture reporting does not turn an existing pipeline red.

---

## Compared with the tools you already run

HeaderHawk is narrow on purpose. On the header classes it covers, here is how it actually compares — wins and losses in the same table.

| | HeaderHawk | Burp Pro + Param Miner | Nuclei | ZAP | securityheaders.com |
| --- | --- | --- | --- | --- | --- |
| **Unkeyed header discovery** | 91 fields by bisection; **one request** rules out the whole list. Each field gets a value of its real type, not a hostname | The technique's origin, and deeper interactively. Operator-driven | A fixed list per template | Not a focus | — |
| **Second-probe confirmation** | Required across every class; a single observation is filed as `suspected`, not as a finding | Param Miner re-tests its own candidates; elsewhere it is the operator's call | Templates largely match on presence and absence | Varies by rule | — |
| **Raw-wire `Host` bypass shapes** | 6 shapes an HTTP library normalises away, sent byte-exact by its own client, after establishing that a refusal existed to get past | Yes, by hand in Repeater | Limited — templates go through an HTTP library | No | — |
| **Reports what it could not assess** | A first-class status with a reason, per requirement, per check | An empty issue list | An empty result set | An empty result set | A letter grade |
| **Requirement-keyed output** | Every finding mapped to ASVS 5.0 / PCI DSS 4.0.1, with the requirement text and a link to the chapter | Issue list | Issue list | Issue list | Grade and header list |
| **Unattended in CI** | Headless, exit code by finding class, SARIF with stable fingerprints | GUI; CI needs the Enterprise product | Yes | Yes | — |
| **Response-header posture** | CSP read the way a browser reads it, per-`Set-Cookie` parsing | Yes | Template-level | Yes | Its whole purpose, and excellent at it |
| **Breadth beyond headers** | **None.** No SQLi, no XSS, no business logic | Everything | Everything, by template | Full DAST | — |
| **Crawling** | Reads what the target publishes (OpenAPI, sitemap, robots, links). **Guesses nothing** | Full crawler | — | Full crawler | Single URL |

**Where the others win, plainly.** Burp Pro is where much of this technique originated and remains far deeper for interactive research; a human in Repeater will out-think any scanner on a specific target. Nuclei's community template breadth across every vulnerability class is something HeaderHawk will never approach. ZAP crawls and tests the whole application surface, which HeaderHawk deliberately does not. securityheaders.com and Mozilla Observatory give an instant response-header grade for a single URL with nothing to install. If you need one tool, none of these is HeaderHawk.

**Where HeaderHawk wins.** Unattended, repeatable depth on the request side — the half those response-header graders do not test at all — with a confirmation step before anything is reported, and output shaped like the requirement it answers rather than like an issue list. The combination is the point: a scanner that reports only what it proved, says so when it could not look, and hands you the document instead of the spreadsheet you would otherwise rebuild by hand once per audit.

*`testssl.sh` is the model rather than a competitor: one focused layer, exhaustively, honestly, CI-friendly. This is the same idea one layer up.*

---

## Scanning what you actually ship

The default is one URL, anonymous. Real products are neither.

### Drive the scan from a request you captured

[Example 5](#5-from-a-captured-request) shows the commands. What matters about the semantics is this:

**The file is a starting point, not a fixed request.** Every check still sets the header it is testing: where the file already carries that header the check's value **replaces** it, and where it does not the check **adds** it. That holds down to the raw-socket probes, so a Host bypass is tested as the authenticated request it really is.

Four things are deliberately not carried over. `Host` decides the target rather than travelling as a header — pinning it would neutralise every Host-manipulation check. `Content-Length` and `Transfer-Encoding` are the smuggling probes' own subject. The connection-management fields describe one hop that is not the one being made. And the body is replayed only on the method the file used, bounded by the declared `Content-Length`.

A malformed file **stops the scan** rather than being skipped. Continuing would silently test a bare URL, dropping the session cookie and the body that were the reason for supplying a request in the first place.

Credentials from the file **never reach a report**: their values are redacted from both the stored wire request and the reproduction command, which then says what to add back and where to find it.

### Log in first

Credentials can be a cookie (`--auth-cookie 'sid=…'`) or a form login ([example 4](#4-behind-a-login)); either accepts `env:NAME` to stay out of the command line and shell history.

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

`--list targets.txt` scans every URL in a file — one run, one aggregated report, one summary, one exit code. It combines with `--request`, which then supplies the session every target is scanned with ([example 6](#6-the-captured-session-across-many-endpoints)).

**Host-scoped checks run against the first URL in the list only**, on the same reasoning as under `--discover`: they describe the host rather than the route. If your list spans several different hosts and you want virtual-host discovery, `Host` validation bypass, routing-header SSRF and smuggling tested on each of them, run one scan per host rather than one list across all of them.

---

## In your pipeline

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed, nothing gated on was found |
| `1` | Findings in the classes selected by `--fail-on` |
| `2` | The scan could not run, or could not finish — bad input, an unreachable target, an interrupt, or an unexpected error |

**An unreachable host exits `2`, never `0`.** A pipeline that treats "no findings" as success must not be handed a silent failure. For the same reason an unexpected error never exits `1`: that code means findings were reported, and a crash is not a finding.

A single check that fails unexpectedly does not end the run. It is recorded as a check that could not assess its controls, and the requirements it covers say so with the reason — *not assessed* where nothing else covered them, *partly assessed* where something did, never a pass. The remaining checks still run, and both report files are still written.

### Fail on regressions, not forever

```bash
# Accept today's state
python headerhawk.py https://app.example.com -o baseline.json

# From now on, fail only on what is new
python headerhawk.py https://app.example.com --baseline baseline.json \
       --fail-on any --fail-on-new
```

`--baseline` reports `N new, N fixed, N unchanged`. `--fail-on-new` narrows the gate to the new ones, so a team that has accepted its current findings gets a pipeline that fails on a **regression** instead of failing permanently — which is the difference between a gate that stays on and one that gets deleted.

A finding keeps the same identity between runs even though several checks put a fresh random marker in every payload: the scanner's own tokens are folded out before matching. Without that, every finding would look new on every run. The SARIF fingerprint is that same identity, so an alert `--baseline` calls unchanged is not a fresh alert on the dashboard.

**Only the scanner's own tokens.** Every marker it mints carries a short prefix that says who made it, and that is the only shape folded out. A hexadecimal value that means something — a virtual host named in hex, an identifier in a path — is kept, so two findings that differ only in one stay two findings. Markers minted before 2.15.1 carried no prefix, so a baseline taken with an older version needs taking again; the run says so when it sees one rather than leaving it to be worked out.

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
| `--min-severity {info,low,medium,high,critical}` | Quietest posture finding the console, the Markdown report, the SARIF and the exit code take account of (default `medium`). The evidence report and `.json` output always carry every one; proven vulnerabilities are reported at any severity |
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

## Verified against real servers

The offline suite answers one kind of question: given this response, does the check draw the right conclusion? It cannot answer the other kind, because a mock replies with whatever the test told it to — so an assumption about what a real server does that is wrong is wrong in the test too, and the test passes.

`lab/` is a Docker lab that answers the other kind. Five containers: the application under test with a vulnerable route and a secure twin for each weakness, an nginx front-end that refuses an unknown host and owns the forwarding headers, Varnish with the cache key it ships with, the same Varnish with the header added to the key, and a cache whose key leaves the query string out. One command brings it up, scans every scenario with this CLI and these defaults, compares, and tears it down:

```bash
python lab/lab.py
```

What each scenario expects is written down in [`lab/scenarios.json`](lab/scenarios.json) before anything runs, and a scenario is **exhaustive** by default: every finding the scanner would show a user at the default threshold has to be one the scenario asked for, so an undeclared finding is a false positive rather than noise the lab tolerates. Absence is read from the per-control evidence report rather than guessed from an empty findings file, because a scan that found nothing and a scan that could not look produce the same file and the difference is the whole point.

The current run — [`lab/report.md`](lab/report.md), 17 scenarios against HeaderHawk 2.21.0:

| | |
| --- | --- |
| Declared findings produced as declared | 36 |
| Declared absences that held | 39 |
| Declared and not produced | 0 |
| Reported to a user and declared by nothing | 0 |

Nothing is reported that no scenario declared, and nothing declared goes unproduced. The lab found three defects on its first runs — two over-claims and one silent gap in the evidence report — and each was closed by its own change, with its own test and the scenario that reproduced it. None was fixed by editing the lab: a lab that edits the scanner to make its own scenarios pass is not evidence of anything. [`lab/README.md`](lab/README.md) records what it found and how each one closed.

---

## Limits

- **Not a full DAST.** No SQL injection, no XSS body scanning, no business-logic or authorization-model testing. Run it alongside ZAP or Burp, not instead of them.
- **Not HTTP/2 or HTTP/3 aware.** All traffic is HTTP/1.1, so HTTP/2-specific downgrade desync is out of scope — and reported as not assessed rather than passed.
- **Not a runtime control.** It tells you a header is missing; it does not add one.
- **Not a substitute for a human on the classes it flags as timing-only.** It says so in the finding.
- **Not a crawler.** It scans what the target publishes about itself and nothing it had to guess.

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

`tests/` holds the offline suite. `lab/` holds the Docker integration lab — the application, the proxies, the caches, the declared expectations and the runner; `python -m unittest discover -s tests` does not touch it, and the suite stays offline. See [`lab/README.md`](lab/README.md).

### Adding a detection module

Subclass `BaseTest` in a new `checks/` module, give it a `test_type`, add that type to `SEVERITY_BY_TEST` in `core/severity.py`, and register the class in `checks/registry.py`. Also give it an entry in `compliance/mapping.py` — an empty tuple is a valid answer, but **the decision may not be skipped**; a test enforces it.

### House rules

Three of them carry most of the weight:

1. **Every change ships with a test.** `python -m unittest discover -s tests` must pass — 787 tests, fully offline.
2. **A check must be able to say it could not judge.** Call `skip(reason)` rather than returning silently. The evidence report prints that reason against every requirement the check covers: where nothing else assessed them they read *not assessed*, and where something did they read *partly assessed* rather than passing — this is the check whose silence could be hiding the finding. A check that quietly returns nothing turns an unreachable target into a clean bill of health. Use `skip_type(type, reason)` only for a surface the control does not apply to, such as a framing requirement on a JSON reply; that says what the check saw rather than what it could not see, and it does not cost a control its pass.
3. **A detection claim is checked against a real server.** A change to what a check concludes gets a scenario in `lab/scenarios.json`, with what it should report and what it should not, and `python lab/lab.py` run against it. The lab is never edited to make the scanner pass.

Fork, branch (`feat/…` or `fix/…`), keep the suite green, open a pull request.

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

HeaderHawk is intended for authorised testing only. Some checks send deliberately malformed requests, and `--enable-desync` can affect other users' traffic. Using it against systems you do not have explicit permission to test is illegal. The authors accept no liability for misuse.

## Contact

- **Email:** [certification.kabiri@gmail.com](mailto:certification.kabiri@gmail.com)
- **Issues:** [github.com/kabiri-labs/HeaderHawk/issues](https://github.com/kabiri-labs/HeaderHawk/issues)
