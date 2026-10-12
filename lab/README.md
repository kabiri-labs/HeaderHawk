# The integration lab

HeaderHawk's unit suite answers one kind of question: given this response, does
the check draw the right conclusion? It cannot answer the other kind, because a
mock replies with whatever the test told it to. If an assumption about what a
real server does is wrong, the mock is wrong in exactly the same way and the
test passes.

Thirty-one of those tests are about this lab rather than about the scanner, in
`tests/test_integration_lab.py`. The comparison below decides whether every
other claim here holds, so it is tested like anything else that judges.

This lab answers the other kind. A real application, a real reverse proxy and
real caches, and the scanner is the same command a user runs.

```bash
python lab/lab.py
```

That brings five containers up, scans each scenario with the shipped CLI and
the shipped defaults, compares the findings with what was declared before any
of it ran, writes `lab/out/report.md`, and tears everything down again. The
exit code is non-zero if a declared finding was not produced or something was
reported that nothing declared.

```bash
python lab/lab.py --only host-injection-confirmed,cache-poisoning-default-key
python lab/lab.py --keep      # leave it running to poke at
python lab/lab.py --down      # tear down
python lab/lab.py --build     # rebuild the runner image
```

## What it is made of

| | |
| --- | --- |
| `app/server.py` | The application under test. Standard library only - no framework, nothing to install. Vulnerable routes and a secure twin for each. |
| `proxy/nginx.conf` | A front-end that refuses an unknown host and sets the forwarding headers itself. |
| `cache/open.vcl` | Varnish with the key it ships with. |
| `cache/keyed.vcl` | The same cache with the forwarding header added to the key. |
| `querycache/nginx.conf` | A cache whose key leaves the query string out, which makes a search blind. |
| `scenarios.json` | What each scenario expects, and why. |
| `run.py` | Runs inside the container: scans, compares, writes the report. |
| `lab.py` | Runs on the host: up, run, down. |

## Isolation

The compose network is `internal: true` and nothing is published. These
services are deliberately vulnerable, and they have no route to the host, to
the internet, or to anything else; the only thing that can reach them is the
runner container on the same network. That is a stronger statement than binding
to localhost, and it is also what gives the scan real hostnames to send a Host
header about - Docker's own resolver, no hosts file to edit.

It matters for a second reason. One scenario redirects to `https://example.com/`
unconditionally, because `example.com` is one of the hostnames the open-redirect
check sends and a site whose canonical destination happens to be a probe host is
exactly the false positive worth controlling for. That is the only name here that
is not the lab's own: it is IANA's reserved documentation domain, nothing in the
lab resolves it, and the sealed network is what guarantees no probe can follow a
redirect to the real site. Every other hostname is `*.lab` or `*.example.test`.

## How a scenario is declared

```json
{
  "id": "cache-poisoning-keyed",
  "target": "http://cache-keyed/link",
  "exhaustive": false,
  "expect": [{"test_type": "Unkeyed Input", "severity": "Medium",
              "why": "The header still changes the response."}],
  "forbid": [{"test_type": "Web Cache Poisoning",
              "why": "The poisoned copy is filed under its own key."}]
}
```

An entry under `expect` names the fields a finding has to have; fields it does
not name are not compared, so an expectation says what it means and nothing
more. An entry under `forbid` has to match nothing.

`exhaustive` is the part that catches over-reporting. With it on, every finding
the scanner would show a user at the default threshold has to be one this
scenario declared - so an undeclared finding is a false positive rather than
noise the lab tolerates. Findings below the default threshold are listed in the
report where they occur and are not counted against the scanner, because the
question the scenario asks is what a user is told.

Three more kinds of assertion exist because findings alone cannot answer the
question:

- `controls` reads the per-control evidence report. A scan that found nothing
  and a scan that could not look produce the same findings file, and the
  difference is the whole point: `{"status": "Not assessed",
  "reason_contains": "..."}` asserts that a control nobody could assess says
  so, and `{"status": "Partly assessed", ...}` that a control some checks
  judged while another could not look is not reported as a pass. The reason is
  read from whichever field the status puts it in.
- `log_require` asserts that the scan told the user something on the console -
  which is where a check that refused to guess explains why.
- `md_forbid` asserts that something is **not** in the Markdown report at the
  default threshold. That is how the lab tests quietness.

`judgement` is where a mismatch is classified after it has been investigated:
a gap in the scanner, or a mistake in the expectation. Both are reported. The
expectations were written from the checks' documented behaviour before anything
was run, and where the first run disagreed, the disagreement is recorded rather
than edited away.

## What it does not cover

The report lists this too, so that nothing reads as a pass it is not:
request smuggling (a desync lab needs two parsers that disagree about framing,
which means pinning deliberately old images and accepting a timing-dependent
result), SSRF and the out-of-band path (confirmation needs a collaborator with
a polling API, and standing a fake one up inside the network would be mocking
the scanner's own evidence), CRLF injection (needs a back-end that writes a
header value straight to the wire), TLS behaviour, and authenticated
discovery.

The intrusive request-smuggling confirmation needs `--enable-desync` and is
never sent by these scenarios.

## What it has found so far

Three defects, all on the lab's first runs, each closed by its own change with
its own test and the scenario that reproduced it. None was fixed by editing the
lab.

**Two over-claims, the same shape.** A check named a weakness without first
establishing that the thing it named was there to be defeated.

- `Host Header Bypass` reported a bypass whenever the marker host came back,
  without asking whether anything refused an unknown host. It now establishes
  that first, with one well-formed request carrying the target's own host and
  one carrying a host minted for the scan — and an ordinary `Host` header
  turned out to be that baseline rather than a technique.
- `Web Cache Deception` read a front-end answering every URL with the same
  `403` as a router ignoring five static-looking suffixes, which it is — except
  that an identical refusal served to everyone is not a victim's page. The bar
  is now a `2xx`, and below it the route is reported as not assessed rather
  than as a pass.

**One silent gap in the evidence report, and it was the most serious.** It was
not a detection defect at all. Behind a cache that ignores the query string the
unkeyed search correctly refused to guess — and the reason reached nobody. The
console said `No vulnerabilities were found.`, the findings file was empty, and
the evidence report filed `ASVS-5.0:4.1.3` as **Pass** on the strength of the
four checks that did run, with `not_assessed_because: []`. A reason recorded
with `skip(reason)` was carried into the evidence only for a control left with
no assessor at all, so a control assessed by some checks and blocked for others
lost the fact that anybody had been blind.

That control now reports as **partly assessed**, names the blind check under
`partly_assessed_because`, and the console prints what could not be looked at
instead of a bare clean result:

```
Could not assess (1):
- Unkeyed Input: a cache answered a URL this scan had just invented
  ('X-Cache: HIT'), so the query string is not part of its key: ...
  The compliance evidence report names the requirements each of these
  leaves short of a pass.
No vulnerabilities were found - but see what could not be assessed above;
this is not a clean bill of health for those requirements.
```

The findings file is still `[]`, which is correct: nothing was learned about
that target, and inventing a finding would be the opposite failure. What
changed is that the artefact says so. The `cache-blind-query-key` scenario now
declares both that control's status and that console line, so the lab fails if
either goes quiet again.

## Rules this lab follows

- The scanner's detection logic is never changed to make a scenario pass. A
  scenario that fails is reported as a gap.
- Nothing about the scanner is mocked, and no finding is injected.
- The lab is torn down with `--volumes` every run, so a cache cannot carry a
  stored response from one run into the next.
- `python -m unittest discover -s tests` does not run any of this. It stays
  offline, and it stays the command the repository declares.
