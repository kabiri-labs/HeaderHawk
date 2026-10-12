# HeaderHawk integration lab

What this scanner does against real servers, compared with what was declared before it ran.

- HeaderHawk **2.20.0**, run as `python headerhawk.py <target>` with the shipped defaults.
- Generated 2026-10-12 05:30 UTC by `lab/run.py`. Re-run it with `python lab/lab.py`.
- Reporting threshold: **medium and above**, the default. Findings below it are listed where they occur and are not counted against the scanner.
- The intrusive request-smuggling confirmation needs `--enable-desync` and was never sent.

## Totals

| | Count | What it means |
| --- | --- | --- |
| True positives | 34 | A finding the scenario declared, produced as declared. |
| Absences held | 39 | Something the scenario forbade, and the scanner did not report. |
| False negatives | 1 | Declared and not produced. |
| False positives | 0 | Reported to a user and declared by nothing, or explicitly forbidden. |
| Inconclusive | 0 | The run could not settle it either way. |

## Scenarios

| Scenario | Stack | Subject | TP | Absent | FN | FP | ? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [host-injection-confirmed](#host-injection-confirmed) | scanner -> app | Host Header Injection | 2 | 1 | 0 | 0 | 0 |
| [host-injection-echo-only](#host-injection-echo-only) | scanner -> app | Host Header Injection | 2 | 1 | 0 | 0 | 0 |
| [host-injection-proxy-fixed](#host-injection-proxy-fixed) | scanner -> nginx -> app | Host Header Injection | 0 | 3 | 0 | 0 | 0 |
| [host-bypass-reflected](#host-bypass-reflected) | scanner -> app (raw HTTP) | Host Header Bypass | 6 | 1 | 0 | 0 | 0 |
| [host-bypass-guarded](#host-bypass-guarded) | scanner -> nginx (unknown host refused) -> app | Host Header Bypass | 0 | 3 | 0 | 0 | 0 |
| [open-redirect-confirmed](#open-redirect-confirmed) | scanner -> app | Open Redirect | 5 | 2 | 0 | 0 | 0 |
| [open-redirect-canonical](#open-redirect-canonical) | scanner -> app | Open Redirect | 0 | 1 | 0 | 0 | 0 |
| [cors-reflected](#cors-reflected) | scanner -> app | CORS | 2 | 0 | 0 | 0 | 0 |
| [cors-allowlist](#cors-allowlist) | scanner -> app | CORS | 0 | 5 | 0 | 0 | 0 |
| [cache-poisoning-default-key](#cache-poisoning-default-key) | scanner -> varnish (default key) -> app | Web Cache Poisoning | 1 | 0 | 0 | 0 | 0 |
| [cache-poisoning-keyed](#cache-poisoning-keyed) | scanner -> varnish (header in the key) -> app | Web Cache Poisoning | 1 | 1 | 0 | 0 | 0 |
| [cache-blind-query-key](#cache-blind-query-key) | scanner -> nginx (key without the query string) -> app | Unkeyed Input | 0 | 2 | 1 | 0 | 0 |
| [cache-deception](#cache-deception) | scanner -> app | Web Cache Deception | 1 | 0 | 0 | 0 | 0 |
| [posture-weak](#posture-weak) | scanner -> app | Response header posture | 10 | 4 | 0 | 0 | 0 |
| [posture-hardened](#posture-hardened) | scanner -> app | Response header posture | 0 | 11 | 0 | 0 | 0 |
| [posture-json](#posture-json) | scanner -> app | Response header posture | 3 | 4 | 0 | 0 | 0 |
| [posture-redirect-attribution](#posture-redirect-attribution) | scanner -> app (302) -> app | Response header posture | 1 | 0 | 0 | 0 | 0 |

## Gaps

### host-bypass-reflected

- **Judgement:** Closed. The check reported a bypass whenever the marker host came back, without first establishing that anything was refusing an unknown host, so 'Host override' - an ordinary Host header - was reported here at High. It now sends a baseline first: one well-formed request carrying this target's own host, and one carrying a host minted for the scan. An ordinary Host header turned out to be that baseline rather than a technique, and it cannot be a bypass in either direction - where an unknown host is refused it is the refusal, and where it is not, there was nothing to get past - so it left the technique list and the seven wire shapes became six. The five shapes above are unaffected: they are reported on the same evidence as before, with the baseline's answer added to the analysis, which on this target says plainly that no refusal was bypassed and that what was shown is a parser accepting a request it is required to reject.

### host-bypass-guarded

- **Judgement:** Closed. The deception check asked whether a static-looking variant of the URL was served the page rather than a 404, and never whether the page was a success, so a front-end answering every URL with the same 403 satisfied that for all five variants at once. There is now a status check before the claim, and the bar is a 2xx and nothing else: an error is the same refusal for everybody and carries nothing of the victim's to hand to the next requester, and a redirect carries no page either - its empty body would compare equal to any other empty body under the tolerant comparison, which is the same way the 403 got through. Below the bar the route is reported as not assessed with the status in the reason, rather than as a pass, so this front-end is now recorded as something nobody could look at rather than something that was found safe.

### open-redirect-confirmed

- **Judgement:** Closed by the same change as host-bypass-reflected, and this route is why it was worth closing twice over: the 'Host override' finding was a third copy of an observation already reported correctly here as a confirmed Open Redirect and a confirmed Host Header Poisoning, and it carried the highest severity of the three while describing a refusal that never happened. An ordinary Host header is now the baseline that establishes whether a refusal exists at all, not a technique that claims one was defeated, so the two findings that own this observation are the only ones that make it.

### cache-blind-query-key

- **Not produced** (the scan never said it): the scan says 'not part of its key'. Declared because this is the property the tool leads with: a check that could not look says so instead of letting the target read as clean. The reason exists inside the check - it is what PR #37 added - and the question this asserts is whether it reaches the person reading the output.
- **Judgement:** **Not produced, and it is the most serious thing this lab found.** The search did refuse to guess: it stopped because a cache answered a URL the scan had just invented. But the reason reaches nobody. Three places were checked on this run. The console prints the banner, the progress and `No vulnerabilities were found.`, and nothing about a check that could not look. The findings file is `[]`. And the evidence report says ASVS-5.0:4.1.3 **Pass**, assessed by the four checks that did run, with `not_assessed_because: []` - 25 Pass, 1 Not assessed, and that one is the baseline requirement, not this. The string `not part of its key` appears nowhere in either artefact.
- **Judgement:** Why it happens: `skip()` records the reason on the check, and `compliance/evidence.py` reads it only for controls that end up with no assessor at all. Here three other checks also map to 4.1.3, found nothing, and carried the control to Pass - so the one check that could have found a poisoning gadget on this target drops out of the record silently. A reader of the evidence file is told the requirement was met.
- **Judgement:** This is the erosion the project's own notes name: an unassessable check falling through as a pass. It is reported and not fixed, because the fix is a change to what the evidence report promises - a control assessed by some checks and blocked for others needs a third state, or a per-check note beside the Pass - and this pull request does not touch detection or reporting logic. Reproduce it with `python lab/lab.py --only cache-blind-query-key` and read `out/cache-blind-query-key.evidence.json`.

### posture-redirect-attribution

- **Judgement:** Worth a decision, not a defect in detection: the findings name the URL they came from, but the evidence report's target list names the URL that was asked for, so a per-control Pass or Fail can be earned by a different response than the one an assessor thinks they are reading. A scan of a URL that redirects off-site also leaves the target, which is why this lab's network has no route anywhere. Not fixed here: changing it is a decision about the evidence report's contract, and this pull request does not touch detection logic.

## Detail

<a id="host-injection-confirmed"></a>

### host-injection-confirmed

A forwarding header becomes the host of a link the page points a browser at. Does the scanner confirm it, and does it say so at the grade the evidence supports?

- **Target:** `http://app:8000/link`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/link --output /out/host-injection-confirmed.json --evidence /out/host-injection-confirmed.evidence.json`
- **Exit code:** 1, in 18.2s
- **Evidence:** `out/host-injection-confirmed.json`, `out/host-injection-confirmed.evidence.json`, `out/host-injection-confirmed.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Host Header Injection / Vulnerable / confirmed / Medium / X-Forwarded-Host | produced | 'X-Forwarded-Host' decides a host this response points a browser at: the marker came back as the host of a URL (hh78da1c84de81.example-collab.com) in the response body, and the same probe produced it again on a second request. Shape(s) reflected: appended to a |
| Unkeyed Input / Potentially Vulnerable / Medium / X-Forwarded-Host | produced | 'X-Forwarded-Host' changes the response - the marker was reflected in the response - so the application honours a header field an intermediary is meant to own. No cache in front of this endpoint served the changed response back, so poisoning is not demonstrate |
| not: Web Cache Poisoning | absent, as declared | - |

Reproduce the first finding:

```
curl -s -i -H 'X-Forwarded-Host: hh78da1c84de81.example-collab.com' 'http://app:8000/link'
```

<a id="host-injection-echo-only"></a>

### host-injection-echo-only

The same header, printed as text and pointed at by nothing. A scanner that calls this confirmed routing is over-claiming. Does it downgrade?

- **Target:** `http://app:8000/echo`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/echo --output /out/host-injection-echo-only.json --evidence /out/host-injection-echo-only.evidence.json`
- **Exit code:** 1, in 18.2s
- **Evidence:** `out/host-injection-echo-only.json`, `out/host-injection-echo-only.evidence.json`, `out/host-injection-echo-only.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Host Header Injection / Potentially Vulnerable / suspected / Low / X-Forwarded-Host | produced | 'X-Forwarded-Host' is copied into the response: the marker came back in the response body. Nothing in the response points a browser at a URL whose host is the marker, so the application echoes the header rather than demonstrably routing, redirecting or buildin |
| Unkeyed Input / Medium / X-Forwarded-Host | produced | 'X-Forwarded-Host' changes the response - the marker was reflected in the response - so the application honours a header field an intermediary is meant to own. No cache in front of this endpoint served the changed response back, so poisoning is not demonstrate |
| not: Host Header Injection / confirmed | absent, as declared | - |

Reproduce the first finding:

```
curl -s -i -H 'X-Forwarded-Host: hh619296907fc7.example-collab.com' 'http://app:8000/echo'
```

<a id="host-injection-proxy-fixed"></a>

### host-injection-proxy-fixed

The same application, behind a proxy that sets the forwarding headers itself. This is the fix. Does the scanner report nothing?

- **Target:** `http://allowed.lab/link`
- **Stack:** scanner -> nginx -> app
- **Command:** `python /hh/headerhawk.py http://allowed.lab/link --output /out/host-injection-proxy-fixed.json --evidence /out/host-injection-proxy-fixed.evidence.json`
- **Exit code:** 0, in 1.0s
- **Evidence:** `out/host-injection-proxy-fixed.json`, `out/host-injection-proxy-fixed.evidence.json`, `out/host-injection-proxy-fixed.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| not: Host Header Injection | absent, as declared | - |
| not: Unkeyed Input | absent, as declared | - |
| not: Host Header Poisoning | absent, as declared | - |

<a id="host-bypass-reflected"></a>

### host-bypass-reflected

An application that reads every Host header it was sent, and trusts an absolute request line. Which raw shapes reach it?

- **Target:** `http://app:8000/hostreflect`
- **Stack:** scanner -> app (raw HTTP)
- **Command:** `python /hh/headerhawk.py http://app:8000/hostreflect --output /out/host-bypass-reflected.json --evidence /out/host-bypass-reflected.evidence.json`
- **Exit code:** 1, in 17.6s
- **Evidence:** `out/host-bypass-reflected.json`, `out/host-bypass-reflected.evidence.json`, `out/host-bypass-reflected.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Host Header Bypass / High / Duplicate Host header | produced | Bypass technique: Duplicate Host header. Marker reflected in response body. Nothing here was refusing an unknown host - a well-formed request carrying one was answered 200, not refused - so no refusal was bypassed. What this shape shows is a parser accepting a |
| Host Header Bypass / High / Absolute-URI request line | produced | Bypass technique: Absolute-URI request line. Marker reflected in response body. Nothing here was refusing an unknown host - a well-formed request carrying one was answered 200, not refused - so no refusal was bypassed. What this shape shows is a parser accepti |
| Host Header Bypass / High / Indented (line-folded) Host header | produced | Bypass technique: Indented (line-folded) Host header. Marker reflected in response body. Nothing here was refusing an unknown host - a well-formed request carrying one was answered 200, not refused - so no refusal was bypassed. What this shape shows is a parse |
| Host Header Bypass / High / Tab-folded Host header | produced | Bypass technique: Tab-folded Host header. Marker reflected in response body. Nothing here was refusing an unknown host - a well-formed request carrying one was answered 200, not refused - so no refusal was bypassed. What this shape shows is a parser accepting  |
| Host Header Bypass / High / Duplicate Host header, injected first | produced | Bypass technique: Duplicate Host header, injected first. Marker reflected in response body. Nothing here was refusing an unknown host - a well-formed request carrying one was answered 200, not refused - so no refusal was bypassed. What this shape shows is a pa |
| Host Header Poisoning / suspected / Low / Host | produced | 'Host' is copied into the response: the marker came back in the response body. Nothing in the response points a browser at a URL whose host is the marker, so the application echoes the header rather than demonstrably routing, redirecting or building links on i |
| not: Host Header Bypass / Host override | absent, as declared | - |

**Judgement.** Closed. The check reported a bypass whenever the marker host came back, without first establishing that anything was refusing an unknown host, so 'Host override' - an ordinary Host header - was reported here at High. It now sends a baseline first: one well-formed request carrying this target's own host, and one carrying a host minted for the scan. An ordinary Host header turned out to be that baseline rather than a technique, and it cannot be a bypass in either direction - where an unknown host is refused it is the refusal, and where it is not, there was nothing to get past - so it left the technique list and the seven wire shapes became six. The five shapes above are unaffected: they are reported on the same evidence as before, with the baseline's answer added to the analysis, which on this target says plainly that no refusal was bypassed and that what was shown is a parser accepting a request it is required to reject.

Reproduce the first finding:

```
curl -s -i -H 'Host: app.hh2fd8d76580c9.example-collab.com' 'http://app:8000/hostreflect'
```

<a id="host-bypass-guarded"></a>

### host-bypass-guarded

A front-end that answers every host it does not know with 403. Does any raw shape get past it, and does the scanner report one that did not?

- **Target:** `http://proxy/hostreflect`
- **Stack:** scanner -> nginx (unknown host refused) -> app
- **Command:** `python /hh/headerhawk.py http://proxy/hostreflect --output /out/host-bypass-guarded.json --evidence /out/host-bypass-guarded.evidence.json`
- **Exit code:** 0, in 1.0s
- **Evidence:** `out/host-bypass-guarded.json`, `out/host-bypass-guarded.evidence.json`, `out/host-bypass-guarded.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| not: Host Header Bypass | absent, as declared | - |
| not: Host Header Injection | absent, as declared | - |
| not: Web Cache Deception | absent, as declared | - |

**Judgement.** Closed. The deception check asked whether a static-looking variant of the URL was served the page rather than a 404, and never whether the page was a success, so a front-end answering every URL with the same 403 satisfied that for all five variants at once. There is now a status check before the claim, and the bar is a 2xx and nothing else: an error is the same refusal for everybody and carries nothing of the victim's to hand to the next requester, and a redirect carries no page either - its empty body would compare equal to any other empty body under the tolerant comparison, which is the same way the 403 got through. Below the bar the route is reported as not assessed with the status in the reason, rather than as a pass, so this front-end is now recorded as something nobody could look at rather than something that was found safe.

<a id="open-redirect-confirmed"></a>

### open-redirect-confirmed

The Host header decides where a 302 sends a browser. Does the scanner confirm it with a host minted for the scan, rather than with a hostname anyone could be redirecting to?

- **Target:** `http://app:8000/redirect`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/redirect --output /out/open-redirect-confirmed.json --evidence /out/open-redirect-confirmed.evidence.json`
- **Exit code:** 1, in 11.3s
- **Evidence:** `out/open-redirect-confirmed.json`, `out/open-redirect-confirmed.evidence.json`, `out/open-redirect-confirmed.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Open Redirect / Vulnerable / confirmed / Medium / Host | produced | The redirect target follows the 'Host' header: 'https://hh6ebadea9ef5e.example-collab.com/home' points at a host minted for this scan, on a 302 a browser follows, and an identical second probe redirected the same way. No site redirects there for its own reason |
| Host Header Poisoning / Vulnerable / confirmed / Medium / Host | produced | 'Host' decides a host this response points a browser at: the marker came back as the host of a URL (hh60407c89faa0.example-collab.com) in the 'Location' header, and the same probe produced it again on a second request. Shape(s) reflected: appended to a list, p |
| Host Header Bypass / Indented (line-folded) Host header | produced | Bypass technique: Indented (line-folded) Host header. Marker reflected in header(s): ['Host'] Nothing here was refusing an unknown host - a well-formed request carrying one was answered 302, not refused - so no refusal was bypassed. What this shape shows is a  |
| Host Header Bypass / Tab-folded Host header | produced | Bypass technique: Tab-folded Host header. Marker reflected in header(s): ['Host'] Nothing here was refusing an unknown host - a well-formed request carrying one was answered 302, not refused - so no refusal was bypassed. What this shape shows is a parser accep |
| Host Header Bypass / Duplicate Host header, injected first | produced | Bypass technique: Duplicate Host header, injected first. Marker reflected in 'Location': https://hh1e325242cc8e.example-collab.com/home Nothing here was refusing an unknown host - a well-formed request carrying one was answered 302, not refused - so no refusal |
| not: Host Header Bypass / Duplicate Host header | absent, as declared | - |
| not: Host Header Bypass / Host override | absent, as declared | - |

**Judgement.** Closed by the same change as host-bypass-reflected, and this route is why it was worth closing twice over: the 'Host override' finding was a third copy of an observation already reported correctly here as a confirmed Open Redirect and a confirmed Host Header Poisoning, and it carried the highest severity of the three while describing a refusal that never happened. An ordinary Host header is now the baseline that establishes whether a refusal exists at all, not a technique that claims one was defeated, so the two findings that own this observation are the only ones that make it.

Reproduce the first finding:

```
curl -s -i -H 'Host: hh60407c89faa0.example-collab.com' 'http://app:8000/redirect'
```

<a id="open-redirect-canonical"></a>

### open-redirect-canonical

A 302 that always goes to one well-known destination, whatever the header says. The scanner sends that hostname among its probes. Does it report an open redirect that is not there?

- **Target:** `http://app:8000/canonical`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/canonical --output /out/open-redirect-canonical.json --evidence /out/open-redirect-canonical.evidence.json`
- **Exit code:** 0, in 11.3s
- **Evidence:** `out/open-redirect-canonical.json`, `out/open-redirect-canonical.evidence.json`, `out/open-redirect-canonical.log`

> Not exhaustive: this endpoint redirects off the lab network, and the response-header checks follow a redirect, so what they can assess here depends on a host that does not resolve. See posture-redirect-attribution, which is about exactly that.

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| not: Open Redirect | absent, as declared | - |

<a id="cors-reflected"></a>

### cors-reflected

Any origin mirrored back, with credentials. Both halves of that are findings. Does the scanner report both?

- **Target:** `http://app:8000/cors`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/cors --output /out/cors-reflected.json --evidence /out/cors-reflected.evidence.json`
- **Exit code:** 1, in 17.5s
- **Evidence:** `out/cors-reflected.json`, `out/cors-reflected.evidence.json`, `out/cors-reflected.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| CORS Origin Reflection / Vulnerable / confirmed / High | produced | 'Access-Control-Allow-Origin' echoed a unique origin that cannot exist (http://hhc69627d717e5.example-collab.com), so the server reflects whatever Origin it is sent instead of validating against an allowlist; credentials are allowed, so an attacker's page can  |
| CORS Null Origin / Vulnerable / confirmed / High | produced | 'Access-Control-Allow-Origin: null' is returned for 'Origin: null', which any sandboxed iframe or redirected request can present; credentials are allowed, so an attacker's page can read authenticated responses. |

Reproduce the first finding:

```
curl -s -i -H 'Origin: http://hhc69627d717e5.example-collab.com' 'http://app:8000/cors'
```

<a id="cors-allowlist"></a>

### cors-allowlist

One origin on an allowlist and no CORS headers for anyone else. Does the scanner report nothing?

- **Target:** `http://app:8000/secure/cors`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/secure/cors --output /out/cors-allowlist.json --evidence /out/cors-allowlist.evidence.json`
- **Exit code:** 0, in 17.6s
- **Evidence:** `out/cors-allowlist.json`, `out/cors-allowlist.evidence.json`, `out/cors-allowlist.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| not: CORS Origin Reflection | absent, as declared | - |
| not: CORS Null Origin | absent, as declared | - |
| not: CORS Origin Validation Bypass | absent, as declared | - |
| not: CORS Insecure Origin Trust | absent, as declared | - |
| not: CORS Wildcard With Credentials | absent, as declared | - |

<a id="cache-poisoning-default-key"></a>

### cache-poisoning-default-key

A cache with the key it ships with, in front of an application that builds links from a forwarding header. Is the poisoned copy served to a request that never sent the header?

- **Target:** `http://cache/link`
- **Stack:** scanner -> varnish (default key) -> app
- **Command:** `python /hh/headerhawk.py http://cache/link --output /out/cache-poisoning-default-key.json --evidence /out/cache-poisoning-default-key.evidence.json`
- **Exit code:** 1, in 5.4s
- **Evidence:** `out/cache-poisoning-default-key.json`, `out/cache-poisoning-default-key.evidence.json`, `out/cache-poisoning-default-key.log`

> Not exhaustive: the cache changes what every other check sees on this target, and this scenario is about one claim. The scenarios either side of it are the controlled comparison.

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Web Cache Poisoning / Vulnerable / High / X-Forwarded-Host | produced | 'X-Forwarded-Host' was found by search rather than from a fixed list, and is unkeyed: the poisoned response was served to a request that never carried the header. Cache headers: {'Age': '0', 'X-Varnish': '229409 229408'}. |

Reproduce the first finding:

```
curl -s -i -H 'X-Forwarded-Host: hh3f64fafdb918.example-collab.com' 'http://cache/link?cb=hh84c3b550ad'
```

<a id="cache-poisoning-keyed"></a>

### cache-poisoning-keyed

The same cache with the header added to the key. The application still honours it. Does the scanner stop short of calling it poisoning?

- **Target:** `http://cache-keyed/link`
- **Stack:** scanner -> varnish (header in the key) -> app
- **Command:** `python /hh/headerhawk.py http://cache-keyed/link --output /out/cache-poisoning-keyed.json --evidence /out/cache-poisoning-keyed.evidence.json`
- **Exit code:** 1, in 5.9s
- **Evidence:** `out/cache-poisoning-keyed.json`, `out/cache-poisoning-keyed.evidence.json`, `out/cache-poisoning-keyed.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Unkeyed Input / Potentially Vulnerable / Medium / X-Forwarded-Host | produced | 'X-Forwarded-Host' changes the response - the marker was reflected in the response - so the application honours a header field an intermediary is meant to own. No cache in front of this endpoint served the changed response back, so poisoning is not demonstrate |
| not: Web Cache Poisoning | absent, as declared | - |

Also reported here, outside what this scenario asserts: Host Header Injection / Vulnerable / confirmed / Medium / X-Forwarded-Host.

Reproduce the first finding:

```
curl -s -i -H 'X-Forwarded-Host: hhcb3b5736bf84.example-collab.com' 'http://cache-keyed/link'
```

<a id="cache-blind-query-key"></a>

### cache-blind-query-key

A cache that ignores the query string answers every cache-buster from one stored response. The search cannot see anything here. Does the scanner say it was blind, or does it report a clean result?

- **Target:** `http://querycache/link`
- **Stack:** scanner -> nginx (key without the query string) -> app
- **Command:** `python /hh/headerhawk.py http://querycache/link --output /out/cache-blind-query-key.json --evidence /out/cache-blind-query-key.evidence.json`
- **Exit code:** 0, in 1.1s
- **Evidence:** `out/cache-blind-query-key.json`, `out/cache-blind-query-key.evidence.json`, `out/cache-blind-query-key.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| not: Unkeyed Input | absent, as declared | - |
| not: Web Cache Poisoning | absent, as declared | - |
| the scan says 'not part of its key' | **not produced** | the scan never said it |

**Judgement.** **Not produced, and it is the most serious thing this lab found.** The search did refuse to guess: it stopped because a cache answered a URL the scan had just invented. But the reason reaches nobody. Three places were checked on this run. The console prints the banner, the progress and `No vulnerabilities were found.`, and nothing about a check that could not look. The findings file is `[]`. And the evidence report says ASVS-5.0:4.1.3 **Pass**, assessed by the four checks that did run, with `not_assessed_because: []` - 25 Pass, 1 Not assessed, and that one is the baseline requirement, not this. The string `not part of its key` appears nowhere in either artefact.

**Judgement.** Why it happens: `skip()` records the reason on the check, and `compliance/evidence.py` reads it only for controls that end up with no assessor at all. Here three other checks also map to 4.1.3, found nothing, and carried the control to Pass - so the one check that could have found a poisoning gadget on this target drops out of the record silently. A reader of the evidence file is told the requirement was met.

**Judgement.** This is the erosion the project's own notes name: an unassessable check falling through as a pass. It is reported and not fixed, because the fix is a change to what the evidence report promises - a control assessed by some checks and blocked for others needs a third state, or a per-check note beside the Pass - and this pull request does not touch detection or reporting logic. Reproduce it with `python lab/lab.py --only cache-blind-query-key` and read `out/cache-blind-query-key.evidence.json`.

<a id="cache-deception"></a>

### cache-deception

A router that ignores a path parameter, on a page a shared cache is free to store. Does the scanner see the suffix being ignored?

- **Target:** `http://app:8000/deception`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/deception --output /out/cache-deception.json --evidence /out/cache-deception.evidence.json`
- **Exit code:** 1, in 17.7s
- **Evidence:** `out/cache-deception.json`, `out/cache-deception.evidence.json`, `out/cache-deception.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Web Cache Deception / Potentially Vulnerable / Medium | produced | The application served the page rather than a 404 for 1 static-looking variant(s) of this URL (a path parameter), and nothing forbids a shared cache from storing the result (public, max-age=60). A CDN keying on the extension would file this page as a static as |

Reproduce the first finding:

```
curl -s -i -H '(path): a path parameter' 'http://app:8000/deception;.css'
```

<a id="posture-weak"></a>

### posture-weak

A page with no response-header posture at all, over plaintext. Does the scanner report what matters, stay quiet about what does not, and leave out what plaintext makes meaningless?

- **Target:** `http://app:8000/weak`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/weak --output /out/posture-weak.json --evidence /out/posture-weak.evidence.json`
- **Exit code:** 0, in 17.9s
- **Evidence:** `out/posture-weak.json`, `out/posture-weak.evidence.json`, `out/posture-weak.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Content-Security-Policy / Missing / Medium | produced | No 'Content-Security-Policy' response header field. |
| Frame Protection / Missing / Medium | produced | Neither a 'frame-ancestors' Content-Security-Policy directive nor a usable 'X-Frame-Options' header field restricts embedding. |
| Cookie HttpOnly Attribute / Missing / Medium | produced | Cookie 'sid' looks like a session or otherwise sensitive value but has no 'HttpOnly' attribute, so page script can read it. |
| X-Content-Type-Options / Missing / Low | produced | No 'X-Content-Type-Options' response header field, so a browser may MIME-sniff the response. |
| Referrer-Policy / Missing / Info | produced | No 'Referrer-Policy' response header field. Every browser still in support defaults to 'strict-origin-when-cross-origin', so the path and query are already withheld from a cross-origin referrer; the requirement asks for the field to be set explicitly. |
| Permissions-Policy / Missing / Info | produced | No 'Permissions-Policy' response header field, so powerful browser features are not restricted for this document. Reported for completeness: no catalogued requirement covers this field. |
| Cross-Origin-Opener-Policy / Missing / Low | produced | No 'Cross-Origin-Opener-Policy' response header field. |
| Version Disclosure / Low | produced | Response header field(s) expose a component version: Server: lab, ExampleServer/1.2.3; X-Powered-By: ExampleFramework/4.5. |
| Cookie SameSite Attribute / Missing / Low | produced | Cookie 'sid' has no 'SameSite' attribute. |
| Cookie Name Prefix / Missing / Low | produced | Cookie 'sid' uses neither the '__Secure-' nor the '__Host-' name prefix, so a browser does not enforce its Secure/host scoping. |
| not: Strict-Transport-Security | absent, as declared | - |
| not: Cookie Secure Attribute | absent, as declared | - |
| not: the Markdown must not mention 'Referrer-Policy: Missing' | absent, as declared | - |
| not: the Markdown must not mention 'Permissions-Policy: Missing' | absent, as declared | - |

Below the default threshold, so in the JSON record and not in what a user is shown: Cookie Name Prefix / Missing / confirmed / Low / Set-Cookie: sid, Cookie SameSite Attribute / Missing / confirmed / Low / Set-Cookie: sid, Cross-Origin-Opener-Policy / Missing / confirmed / Low / Cross-Origin-Opener-Policy, Permissions-Policy / Missing / confirmed / Info / Permissions-Policy, Referrer-Policy / Missing / confirmed / Info / Referrer-Policy, Version Disclosure / Exposed / confirmed / Low / Version Disclosure, X-Content-Type-Options / Missing / confirmed / Low / X-Content-Type-Options.

Reproduce the first finding:

```
curl -s -i 'http://app:8000/weak'
```

<a id="posture-hardened"></a>

### posture-hardened

The same application with the response headers right and a cookie that carries every attribute. Is the answer zero?

- **Target:** `http://app:8000/secure/page`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/secure/page --output /out/posture-hardened.json --evidence /out/posture-hardened.evidence.json`
- **Exit code:** 0, in 17.8s
- **Evidence:** `out/posture-hardened.json`, `out/posture-hardened.evidence.json`, `out/posture-hardened.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| not: Content-Security-Policy | absent, as declared | - |
| not: Frame Protection | absent, as declared | - |
| not: X-Content-Type-Options | absent, as declared | - |
| not: Referrer-Policy | absent, as declared | - |
| not: Permissions-Policy | absent, as declared | - |
| not: Cross-Origin-Opener-Policy | absent, as declared | - |
| not: Cookie HttpOnly Attribute | absent, as declared | - |
| not: Cookie SameSite Attribute | absent, as declared | - |
| not: Cookie Name Prefix | absent, as declared | - |
| not: CSP Violation Reporting | absent, as declared | - |
| not: Version Disclosure | absent, as declared | - |

<a id="posture-json"></a>

### posture-json

An API reply with none of the document headers. A browser renders nothing here, so they are neither failures nor passes. Does the scanner report them as not assessed, with the reason?

- **Target:** `http://app:8000/secure/json`
- **Stack:** scanner -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/secure/json --output /out/posture-json.json --evidence /out/posture-json.evidence.json`
- **Exit code:** 0, in 17.8s
- **Evidence:** `out/posture-json.json`, `out/posture-json.evidence.json`, `out/posture-json.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| control ASVS-5.0:3.4.3 | produced | Not assessed: ['Response Header Posture: the response is application/json, not a document a browser renders, so this control had nothing to act on'] |
| control ASVS-5.0:3.4.6 | produced | Not assessed: ['Response Header Posture: the response is application/json, not a document a browser renders, so this control had nothing to act on'] |
| control ASVS-5.0:3.4.5 | produced | Not assessed: ['Response Header Posture: the response is application/json, not a document a browser renders, so this control had nothing to act on'] |
| not: Frame Protection | absent, as declared | - |
| not: Referrer-Policy | absent, as declared | - |
| not: Permissions-Policy | absent, as declared | - |
| not: Content-Security-Policy | absent, as declared | - |

<a id="posture-redirect-attribution"></a>

### posture-redirect-attribution

This URL's own response is hardened; it redirects to one that is not. Whose response headers end up in the report, and does the report say whose they are?

- **Target:** `http://app:8000/offsite`
- **Stack:** scanner -> app (302) -> app
- **Command:** `python /hh/headerhawk.py http://app:8000/offsite --output /out/posture-redirect-attribution.json --evidence /out/posture-redirect-attribution.evidence.json`
- **Exit code:** 0, in 14.5s
- **Evidence:** `out/posture-redirect-attribution.json`, `out/posture-redirect-attribution.evidence.json`, `out/posture-redirect-attribution.log`

| Declared | Verdict | What the scanner said |
| --- | --- | --- |
| Content-Security-Policy / Missing | produced | No 'Content-Security-Policy' response header field. |

Also reported here, outside what this scenario asserts: Cookie HttpOnly Attribute / Missing / confirmed / Medium / Set-Cookie: sid, Frame Protection / Missing / confirmed / Medium / Frame Protection.

**Judgement.** Worth a decision, not a defect in detection: the findings name the URL they came from, but the evidence report's target list names the URL that was asked for, so a per-control Pass or Fail can be earned by a different response than the one an assessor thinks they are reading. A scan of a URL that redirects off-site also leaves the target, which is why this lab's network has no route anywhere. Not fixed here: changing it is a decision about the evidence report's contract, and this pull request does not touch detection logic.

Below the default threshold, so in the JSON record and not in what a user is shown: Cookie Name Prefix / Missing / confirmed / Low / Set-Cookie: sid, Cookie SameSite Attribute / Missing / confirmed / Low / Set-Cookie: sid, Cross-Origin-Opener-Policy / Missing / confirmed / Low / Cross-Origin-Opener-Policy, Permissions-Policy / Missing / confirmed / Info / Permissions-Policy, Referrer-Policy / Missing / confirmed / Info / Referrer-Policy, Version Disclosure / Exposed / confirmed / Low / Version Disclosure, X-Content-Type-Options / Missing / confirmed / Low / X-Content-Type-Options.

Reproduce the first finding:

```
curl -s -i 'http://app:8000/weak'
```

## Not covered

Named, so that nothing here reads as a pass it is not.

| Check | Why not | What would be needed |
| --- | --- | --- |
| HTTP Request Smuggling | A desync lab needs a front-end and a back-end that disagree about framing, which means pinning deliberately old images and accepting a timing-dependent result. A flaky scenario is worse than a named gap. | Its own compose file and its own run, with `--enable-desync`. |
| SSRF, Blind SSRF (OOB) | Confirmation needs a collaborator with a polling API. Standing one up inside a sealed network would be mocking the scanner's own evidence, which this lab does not do. | An out-of-band listener the lab owns, and a scenario that treats it as the third party it is. |
| CRLF injection | Needs a back-end that writes a header value straight to the wire; the standard library's server does not. | A raw-socket route in the lab application. |
| TLS behaviour, `--insecure` | The lab speaks plaintext, so Strict-Transport-Security and cookie `Secure` are deliberately out of scope - and the scanner is expected to say so rather than report them, which `posture-weak` asserts. | A certificate and an HTTPS front-end. |
| Auth bypass, endpoint discovery | Need an application with real sessions and a route tree. | A larger lab application. |
