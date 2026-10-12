"""Run HeaderHawk against the lab and compare what it found with what was declared.

This runs inside the runner container, on the lab network. It reads
``scenarios.json`` - the expectations, written from the checks' documented
behaviour before any of this was executed - then scans each target with the
shipped CLI and the shipped defaults, and writes ``report.md``.

Three things make the comparison worth reading.

**Nothing is mocked.** Each scenario names a real stack - the application, a
reverse proxy, a cache - and the scanner is the same command a user runs, with
no flags the README does not document. The intrusive smuggling confirmation
needs ``--enable-desync`` and is therefore never sent.

**Absence is read from the evidence report, not guessed from an empty list.**
A scan that found nothing and a scan that could not look produce the same
findings file, and the difference is the whole question. So every scenario also
reads the per-control evidence, where a control nobody could assess says so
with a reason.

**An undeclared finding is a false positive.** Scenarios are exhaustive by
default: every finding the scanner would show a user at the default threshold
has to be one the scenario asked for. That is the only way round this way of
testing that can catch over-reporting, which is the failure a scanner is least
likely to notice about itself.
"""

import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

sys.path.insert(0, "/hh")

from headerhawk._meta import __version__
from headerhawk.core.exitcodes import EXIT_FINDINGS, EXIT_OK
from headerhawk.core.findings import DEFAULT_MIN_SEVERITY, reportable

LAB = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("LAB_OUT", "/out")
SCENARIOS = os.path.join(LAB, "scenarios.json")
REPORT = os.path.join(OUT, "report.md")

# How long a service gets to accept a connection before the lab gives up on it.
READY_TIMEOUT = 90
# How long one scan gets. The lab is local and every scenario is a handful of
# hundred requests, so this is a stuck-process limit, not a budget.
SCAN_TIMEOUT = 600

# Keys in an expectation that are assertions about a finding rather than
# fields of one.
META_KEYS = {"why", "analysis_contains"}


# -- running ---------------------------------------------------------------

def wait_for(targets):
    """Wait until every target accepts a TCP connection, or say which did not."""
    pending = []
    for target in sorted(targets):
        parsed = urlparse(target)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        pending.append((parsed.hostname, port))
    deadline = time.time() + READY_TIMEOUT
    unreachable = []
    for host, port in pending:
        while True:
            try:
                with socket.create_connection((host, port), timeout=2):
                    break
            except OSError:
                if time.time() > deadline:
                    unreachable.append("%s:%d" % (host, port))
                    break
                time.sleep(1)
    return unreachable


def scan(scenario):
    """Run the CLI once, and once more for Markdown when the scenario asks.

    Returns the findings, the evidence, the Markdown (or None) and how the
    process itself behaved - a crash is not a clean scan with no findings, and
    the report has to be able to tell them apart.
    """
    name = scenario["id"]
    findings_path = _fresh(os.path.join(OUT, name + ".json"))
    evidence_path = _fresh(os.path.join(OUT, name + ".evidence.json"))
    log_path = _fresh(os.path.join(OUT, name + ".log"))
    command = ["python", "/hh/headerhawk.py", scenario["target"],
               "--output", findings_path, "--evidence", evidence_path]
    started = time.time()
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   timeout=SCAN_TIMEOUT)
        output, exit_code = completed.stdout, completed.returncode
    except subprocess.TimeoutExpired as expired:
        output = (expired.output or b"") + b"\n[lab] the scan did not finish\n"
        exit_code = None
    elapsed = time.time() - started
    with open(log_path, "wb") as handle:
        handle.write(output or b"")

    findings = _load(findings_path, [])
    evidence = _load(evidence_path, {})
    console = (output or b"").decode("utf-8", "replace")
    markdown = None
    if scenario.get("markdown"):
        markdown_path = _fresh(os.path.join(OUT, name + ".md"))
        subprocess.run(["python", "/hh/headerhawk.py", scenario["target"],
                        "--output", markdown_path],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=SCAN_TIMEOUT)
        markdown = _read(markdown_path)
    return {
        "findings": findings,
        "evidence": evidence,
        "console": console,
        "markdown": markdown,
        "exit_code": exit_code,
        "seconds": round(elapsed, 1),
        "command": " ".join(command),
    }


def _fresh(path):
    """Delete an artefact left by an earlier run, and hand back its path.

    ``lab/out`` is bind-mounted and survives teardown. Without this, a scan
    that dies before writing is compared against the files the *previous* run
    left behind - and a scenario passes on data that has nothing to do with
    it, which is the one thing a lab must never do.
    """
    try:
        os.remove(path)
    except OSError:
        # Not there, or not removable. Either way nothing stale is readable,
        # and a path that cannot be written is caught by the scan's exit code.
        pass
    return path


def _load(path, fallback):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return fallback


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


# -- comparing -------------------------------------------------------------

def matches(expectation, finding):
    """Whether one finding satisfies one expectation.

    Every field named in the expectation has to be equal, case-insensitively
    for strings; ``analysis_contains`` is a substring of the analysis. Fields
    the expectation does not name are not compared, so an expectation says what
    it means to say and nothing more.
    """
    for key, wanted in expectation.items():
        if key in META_KEYS:
            continue
        actual = finding.get(key)
        if isinstance(wanted, str) and isinstance(actual, str):
            if wanted.lower() != actual.lower():
                return False
        elif wanted != actual:
            return False
    wanted_text = expectation.get("analysis_contains")
    if wanted_text:
        if wanted_text.lower() not in str(finding.get("analysis", "")).lower():
            return False
    return True


def control_status(evidence, control_id):
    """The status and reason this evidence report gives one control."""
    for control in evidence.get("controls", []):
        if control.get("id") == control_id:
            return control.get("status"), control.get("not_assessed_because")
    return None, None


def compare(scenario, result):
    """Classify one scenario: what held, what did not, and what was not asked.

    Returns a dict of lists. ``true_positive`` is a declared finding that was
    produced; ``false_negative`` is one that was not; ``false_positive`` is a
    finding the scanner would show that nothing declared, or one a scenario
    forbade; ``inconclusive`` is anything the run could not settle either way.
    """
    verdict = {"true_positive": [], "false_negative": [], "false_positive": [],
               "inconclusive": [], "passed_absence": []}
    findings = result["findings"]

    if result["exit_code"] is None:
        verdict["inconclusive"].append(
            "The scan did not finish inside %ds, so nothing it did or did not "
            "report means anything." % SCAN_TIMEOUT)
        return verdict
    if result["exit_code"] not in (EXIT_OK, EXIT_FINDINGS):
        # The scanner defines three codes and only these two mean it ran: 2 is
        # its own word for "could not run meaningfully", and anything else did
        # not leave through the CLI at all. Comparing either would let a
        # scenario whose expectations are all absences - a secure endpoint,
        # a closed cache - report every one of them as held, on the strength
        # of a scan that never happened.
        verdict["inconclusive"].append(
            "The scan exited %s, which is not one of the two codes that mean "
            "it ran (%d for nothing found, %d for findings), so neither what "
            "it reported nor what it did not report means anything."
            % (result["exit_code"], EXIT_OK, EXIT_FINDINGS))
        return verdict
    if not isinstance(findings, list):
        verdict["inconclusive"].append(
            "The scan wrote no findings file, so there is nothing to compare.")
        return verdict

    # One expectation accounts for one finding, and the next expectation has
    # to find its own. Claiming every match would let a regression that
    # reports the same defect twice hide behind a single expectation, and
    # "one defect, one finding" is a claim this tool makes. A duplicate now
    # falls through to the exhaustive sweep below and is reported there as
    # what it is: something a user was shown that nothing declared.
    claimed = set()
    for expectation in scenario.get("expect", []):
        hit = next((finding for finding in findings
                    if id(finding) not in claimed
                    and matches(expectation, finding)), None)
        if hit is None:
            verdict["false_negative"].append({"expectation": expectation})
            continue
        claimed.add(id(hit))
        verdict["true_positive"].append({
            "expectation": expectation,
            "finding": hit,
        })

    for forbidden in scenario.get("forbid", []):
        hits = [finding for finding in findings if matches(forbidden, finding)]
        if hits:
            # Counted once, as the thing the scenario named: a scenario
            # forbids a kind of finding, not a number of them. Without this
            # the exhaustive sweep reports each one again as undeclared.
            claimed.update(id(finding) for finding in hits)
            verdict["false_positive"].append({
                "reason": "forbidden by the scenario",
                "expectation": forbidden,
                "finding": hits[0],
            })
        else:
            verdict["passed_absence"].append({"expectation": forbidden})

    if scenario.get("exhaustive", True):
        for finding in findings:
            if id(finding) in claimed:
                continue
            if not reportable(finding, DEFAULT_MIN_SEVERITY):
                # Below the threshold a user sees by default. Listed in the
                # report, not counted against the scanner: the scenario is
                # about what it tells someone, and this is what it does not.
                continue
            verdict["false_positive"].append({
                "reason": "reported to a user and declared by nothing",
                "finding": finding,
            })

    for control in scenario.get("controls", []):
        status, because = control_status(result["evidence"], control["id"])
        if status is None:
            verdict["inconclusive"].append(
                "The evidence report does not mention %s at all." % control["id"])
            continue
        if status.lower() != control["status"].lower():
            verdict["false_negative"].append({
                "expectation": {"control": control["id"],
                                "why": control.get("why", "")},
                "detail": "declared %s, reported %s" % (control["status"], status),
            })
            continue
        wanted = control.get("reason_contains")
        if wanted and wanted.lower() not in str(because or "").lower():
            verdict["false_negative"].append({
                "expectation": {"control": control["id"],
                                "why": control.get("why", "")},
                "detail": "reported %s, but the reason given was %r" % (
                    status, because),
            })
            continue
        verdict["true_positive"].append({
            "expectation": {"control": control["id"],
                            "why": control.get("why", "")},
            "finding": {"analysis": "%s: %s" % (status, because or "-")},
        })

    for rule in scenario.get("log_require", []):
        # What a check says when it cannot look reaches the user on the
        # console, which is the only place a skipped search is visible at all.
        if rule["text"].lower() in result["console"].lower():
            verdict["true_positive"].append({
                "expectation": {"log": rule["text"], "why": rule.get("why", "")},
                "finding": {"analysis": "said so on the console"},
            })
        else:
            verdict["false_negative"].append({
                "expectation": {"log": rule["text"], "why": rule.get("why", "")},
                "detail": "the scan never said it",
            })

    markdown = result["markdown"]
    for rule in scenario.get("md_forbid", []):
        if markdown is None:
            verdict["inconclusive"].append(
                "No Markdown report was produced, so %r could not be checked."
                % rule["text"])
        elif rule["text"] in markdown:
            verdict["false_positive"].append({
                "reason": "shown in the Markdown report at the default threshold",
                "expectation": rule,
            })
        else:
            verdict["passed_absence"].append({"expectation": rule})

    return verdict


# -- reporting -------------------------------------------------------------

def _finding_line(finding):
    bits = [str(finding.get("test_type", "?"))]
    for key in ("test_result", "confidence", "severity", "header_name"):
        if finding.get(key):
            bits.append(str(finding[key]))
    return " / ".join(bits)


def _describe(expectation):
    if "control" in expectation:
        return "control %s" % expectation["control"]
    if "log" in expectation:
        return "the scan says %r" % expectation["log"]
    if "text" in expectation:
        return "the Markdown must not mention %r" % expectation["text"]
    bits = [str(expectation.get(key)) for key in
            ("test_type", "test_result", "confidence", "severity", "header_name")
            if expectation.get(key)]
    return " / ".join(bits) or "(any finding)"


def write_report(runs, unreachable):
    """Write the Markdown report: the totals first, then every scenario."""
    totals = {"true_positive": 0, "false_negative": 0, "false_positive": 0,
              "inconclusive": 0, "passed_absence": 0}
    for _, _, verdict in runs:
        for key in totals:
            totals[key] += len(verdict[key])

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# HeaderHawk integration lab",
        "",
        "What this scanner does against real servers, compared with what was "
        "declared before it ran.",
        "",
        "- HeaderHawk **%s**, run as `python headerhawk.py <target>` with the "
        "shipped defaults." % __version__,
        "- Generated %s by `lab/run.py`. Re-run it with `python lab/lab.py`."
        % now,
        "- Reporting threshold: **%s and above**, the default. Findings below "
        "it are listed where they occur and are not counted against the "
        "scanner." % DEFAULT_MIN_SEVERITY,
        "- The intrusive request-smuggling confirmation needs "
        "`--enable-desync` and was never sent.",
        "",
        "## Totals",
        "",
        "| | Count | What it means |",
        "| --- | --- | --- |",
        "| True positives | %d | A finding the scenario declared, produced as "
        "declared. |" % totals["true_positive"],
        "| Absences held | %d | Something the scenario forbade, and the "
        "scanner did not report. |" % totals["passed_absence"],
        "| False negatives | %d | Declared and not produced. |"
        % totals["false_negative"],
        "| False positives | %d | Reported to a user and declared by nothing, "
        "or explicitly forbidden. |" % totals["false_positive"],
        "| Inconclusive | %d | The run could not settle it either way. |"
        % totals["inconclusive"],
        "",
    ]

    if unreachable:
        lines += ["> **Not every service came up.** %s never accepted a "
                  "connection, so the scenarios that needed them are "
                  "inconclusive rather than failed."
                  % ", ".join("`%s`" % one for one in unreachable), ""]

    lines += ["## Scenarios", "",
              "| Scenario | Stack | Subject | TP | Absent | FN | FP | ? |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for scenario, result, verdict in runs:
        lines.append("| [%s](#%s) | %s | %s | %d | %d | %d | %d | %d |" % (
            scenario["id"], scenario["id"], scenario.get("stack", "-"),
            scenario.get("subject", "-"),
            len(verdict["true_positive"]), len(verdict["passed_absence"]),
            len(verdict["false_negative"]), len(verdict["false_positive"]),
            len(verdict["inconclusive"])))
    lines.append("")

    gaps = [(scenario, verdict) for scenario, _, verdict in runs
            if verdict["false_negative"] or verdict["false_positive"]
            or verdict["inconclusive"] or scenario.get("judgement")]
    lines += ["## Gaps", ""]
    if not gaps:
        lines += ["Every declared finding was produced, every forbidden one "
                  "was absent, and nothing undeclared reached a user.", ""]
    else:
        for scenario, verdict in gaps:
            lines.append("### %s" % scenario["id"])
            lines.append("")
            for entry in verdict["false_negative"]:
                detail = entry.get("detail")
                lines.append("- **Not produced** (%s): %s. %s" % (
                    detail or "no match",
                    _describe(entry["expectation"]),
                    entry["expectation"].get("why", "")))
            for entry in verdict["false_positive"]:
                shown = entry.get("finding")
                lines.append("- **Reported anyway** (%s): %s" % (
                    entry["reason"],
                    _finding_line(shown) if shown
                    else _describe(entry["expectation"])))
                if shown and shown.get("analysis"):
                    lines.append("  - %s" % shown["analysis"])
            for note in verdict["inconclusive"]:
                lines.append("- **Inconclusive:** %s" % note)
            for note in scenario.get("judgement", []):
                lines.append("- **Judgement:** %s" % note)
            lines.append("")

    lines += ["## Detail", ""]
    for scenario, result, verdict in runs:
        lines += [
            '<a id="%s"></a>' % scenario["id"],
            "",
            "### %s" % scenario["id"],
            "",
            "%s" % scenario.get("question", ""),
            "",
            "- **Target:** `%s`" % scenario["target"],
            "- **Stack:** %s" % scenario.get("stack", "-"),
            "- **Command:** `%s`" % result["command"],
            "- **Exit code:** %s, in %ss" % (
                "none - did not finish" if result["exit_code"] is None
                else result["exit_code"], result["seconds"]),
            "- **Evidence:** `out/%s.json`, `out/%s.evidence.json`, "
            "`out/%s.log`" % ((scenario["id"],) * 3),
            "",
        ]
        if scenario.get("notes"):
            for note in scenario["notes"]:
                lines.append("> %s" % note)
            lines.append("")
        lines += ["| Declared | Verdict | What the scanner said |",
                  "| --- | --- | --- |"]
        for entry in verdict["true_positive"]:
            lines.append("| %s | produced | %s |" % (
                _describe(entry["expectation"]),
                str(entry["finding"].get("analysis", ""))[:260].replace("|", "/")))
        for entry in verdict["passed_absence"]:
            lines.append("| not: %s | absent, as declared | - |"
                         % _describe(entry["expectation"]))
        for entry in verdict["false_negative"]:
            lines.append("| %s | **not produced** | %s |" % (
                _describe(entry["expectation"]), entry.get("detail", "-")))
        for entry in verdict["false_positive"]:
            shown = entry.get("finding")
            lines.append("| nothing declared this | **reported anyway** | %s |"
                         % (_finding_line(shown) if shown else entry["reason"]))
        lines.append("")
        if not scenario.get("exhaustive", True):
            # A scenario that does not claim to account for everything still
            # shows everything, so that nothing is quietly left out of view.
            declared = {_finding_line(entry["finding"])
                        for entry in verdict["true_positive"]
                        if entry.get("finding")}
            extra = sorted({_finding_line(one) for one in result["findings"]
                            if isinstance(one, dict)
                            and reportable(one, DEFAULT_MIN_SEVERITY)}
                           - declared)
            if extra:
                lines += ["Also reported here, outside what this scenario "
                          "asserts: %s." % ", ".join(extra), ""]
        for note in scenario.get("judgement", []):
            lines += ["**Judgement.** %s" % note, ""]
        below = [finding for finding in result["findings"]
                 if isinstance(finding, dict)
                 and not reportable(finding, DEFAULT_MIN_SEVERITY)]
        if below:
            lines += ["Below the default threshold, so in the JSON record and "
                      "not in what a user is shown: %s."
                      % ", ".join(sorted({_finding_line(one) for one in below})),
                      ""]
        for finding in result["findings"]:
            if isinstance(finding, dict) and finding.get("repro"):
                lines += ["Reproduce the first finding:", "",
                          "```", str(finding["repro"]).strip(), "```", ""]
                break

    lines += [
        "## Not covered",
        "",
        "Named, so that nothing here reads as a pass it is not.",
        "",
        "| Check | Why not | What would be needed |",
        "| --- | --- | --- |",
        "| HTTP Request Smuggling | A desync lab needs a front-end and a "
        "back-end that disagree about framing, which means pinning "
        "deliberately old images and accepting a timing-dependent result. A "
        "flaky scenario is worse than a named gap. | Its own compose file and "
        "its own run, with `--enable-desync`. |",
        "| SSRF, Blind SSRF (OOB) | Confirmation needs a collaborator with a "
        "polling API. Standing one up inside a sealed network would be "
        "mocking the scanner's own evidence, which this lab does not do. | An "
        "out-of-band listener the lab owns, and a scenario that treats it as "
        "the third party it is. |",
        "| CRLF injection | Needs a back-end that writes a header value "
        "straight to the wire; the standard library's server does not. | A "
        "raw-socket route in the lab application. |",
        "| TLS behaviour, `--insecure` | The lab speaks plaintext, so "
        "Strict-Transport-Security and cookie `Secure` are deliberately out "
        "of scope - and the scanner is expected to say so rather than report "
        "them, which `posture-weak` asserts. | A certificate and an HTTPS "
        "front-end. |",
        "| Auth bypass, endpoint discovery | Need an application with real "
        "sessions and a route tree. | A larger lab application. |",
        "",
    ]
    with open(REPORT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
    return totals


# -- entry point -----------------------------------------------------------

def main():
    with open(SCENARIOS, encoding="utf-8") as handle:
        scenarios = json.load(handle)["scenarios"]
    only = os.environ.get("LAB_ONLY")
    if only:
        wanted = {name.strip() for name in only.split(",") if name.strip()}
        scenarios = [one for one in scenarios if one["id"] in wanted]
    if not os.path.isdir(OUT):
        os.makedirs(OUT)

    unreachable = wait_for({one["target"] for one in scenarios})
    if unreachable:
        print("[lab] unreachable: %s" % ", ".join(unreachable))

    runs = []
    for scenario in scenarios:
        print("[lab] %s -> %s" % (scenario["id"], scenario["target"]))
        result = scan(scenario)
        verdict = compare(scenario, result)
        print("      TP %d  absent %d  FN %d  FP %d  ? %d  (%ss)" % (
            len(verdict["true_positive"]), len(verdict["passed_absence"]),
            len(verdict["false_negative"]), len(verdict["false_positive"]),
            len(verdict["inconclusive"]), result["seconds"]))
        runs.append((scenario, result, verdict))

    totals = write_report(runs, unreachable)
    print("[lab] %s" % ", ".join("%s %d" % (key.replace("_", " "), value)
                                 for key, value in sorted(totals.items())))
    print("[lab] report written to %s" % REPORT)
    failed = totals["false_negative"] + totals["false_positive"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
