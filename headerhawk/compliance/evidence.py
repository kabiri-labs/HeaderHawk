"""Turning a scan into per-control evidence.

A findings report answers "what did you break?". An assessor asks the other
question: "for each requirement, did this product meet it, and how do you know?"
This module answers that one.

The distinction that makes the answer worth anything is between a control that
was assessed and found clean, and one that was never assessed at all. A scan of
an unreachable host produces no findings; reporting that as full compliance
would be worse than producing no report. So a control is only ``Pass`` when a
check that covers it actually completed, and otherwise says why not.
"""

from collections import namedtuple
from datetime import datetime, timezone

from ..core.baseline import describe_drift
from .catalogue import CONTROLS, describe
from .mapping import controls_for

STATUS_FAIL = "Fail"
STATUS_PASS = "Pass"
STATUS_NOT_ASSESSED = "Not assessed"

# Ordered worst-first, which is how the summary and the detail are sorted.
STATUS_ORDER = [STATUS_FAIL, STATUS_NOT_ASSESSED, STATUS_PASS]

ControlResult = namedtuple(
    "ControlResult", "control status findings assessed_by not_assessed_because")


def _emitted_types(check):
    return check.emitted_types() if hasattr(check, "emitted_types") else ()


def controls_covered_by(check):
    """The catalogued controls a check (class or instance) can speak to."""
    covered = set()
    for test_type in _emitted_types(check):
        covered.update(controls_for(test_type))
    return covered


def controls_assessed_by(check):
    """The controls a check actually judged on this run.

    A check can cover several controls and reach only some of them: response
    posture assesses framing on an HTML page and has nothing to say about it on
    a JSON reply. Reading the check as a whole would either claim the framing
    control passed where nothing looked at it, or throw away the controls that
    were genuinely assessed alongside it.
    """
    unassessed = getattr(check, "unassessed", None) or {}
    covered = set()
    for test_type in _emitted_types(check):
        if test_type in unassessed:
            continue
        covered.update(controls_for(test_type))
    return covered


def controls_unassessed_by(check):
    """The controls a check covers but did not judge, each with its reason.

    A control that another of the check's types did reach is left out: one
    assessment of a control is enough to have assessed it.
    """
    unassessed = getattr(check, "unassessed", None) or {}
    if not unassessed:
        return {}
    assessed = controls_assessed_by(check)
    blocked = {}
    for test_type, reason in unassessed.items():
        for control_id in controls_for(test_type):
            if control_id not in assessed:
                blocked.setdefault(control_id, reason)
    return blocked


# The requirement a baseline comparison satisfies. Running the comparison *is*
# the change-detection mechanism 11.6.1 asks for, so performing it is what
# passes: a detected change is the mechanism working, not the control failing.
# The underlying weakness, if there is one, already fails its own 3.4.x control.
DRIFT_CONTROL = "PCI-DSS-4.0.1:11.6.1"


def build_evidence(tests, targets, stats=None, version=None, tool_name=None,
                   drift=None, scan_mode=None):
    """Build the per-control evidence for one scan.

    ``tests`` are the check instances that ran, in any order. Every catalogued
    control appears in the result, including ones this scan cannot speak to -
    an assessor needs to see the gaps, not just the answers.
    """
    findings_by_control = {}
    assessed_by = {}
    blocked_by = {}

    for test in tests:
        covered = controls_covered_by(test)
        if not covered:
            continue
        name = getattr(test, "test_type", type(test).__name__)
        if getattr(test, "assessed", False):
            for control_id in controls_assessed_by(test):
                assessed_by.setdefault(control_id, set()).add(name)
            for control_id, reason in controls_unassessed_by(test).items():
                blocked_by.setdefault(control_id, {})[name] = reason
        else:
            reason = getattr(test, "skip_reason", None) or "the check did not run"
            for control_id in covered:
                blocked_by.setdefault(control_id, {})[name] = reason
        for finding in getattr(test, "vulnerabilities_found", []):
            for control_id in finding.get("controls") or ():
                findings_by_control.setdefault(control_id, []).append(finding)

    if drift is not None:
        assessed_by.setdefault(DRIFT_CONTROL, set()).add(
            f"baseline comparison ({describe_drift(drift)})")

    results = []
    for control_id in sorted(CONTROLS):
        findings = findings_by_control.get(control_id, [])
        assessors = sorted(assessed_by.get(control_id, ()))
        blocked = blocked_by.get(control_id, {})
        if findings:
            # Evidence of a failure stands on its own; it does not matter
            # whether some other check covering the same control was blocked.
            status = STATUS_FAIL
        elif assessors:
            status = STATUS_PASS
        else:
            status = STATUS_NOT_ASSESSED
            if control_id == DRIFT_CONTROL and not blocked:
                blocked = {"baseline comparison":
                           "no baseline was supplied, so no change detection "
                           "was performed (pass --baseline <previous.json>)"}
        results.append(ControlResult(
            control=CONTROLS[control_id],
            status=status,
            findings=findings,
            assessed_by=assessors,
            not_assessed_because=(sorted(f"{name}: {reason}"
                                         for name, reason in blocked.items())
                                  if status == STATUS_NOT_ASSESSED else []),
        ))

    counts = {status: 0 for status in STATUS_ORDER}
    for result in results:
        counts[result.status] += 1

    return {
        "tool": tool_name,
        "version": version,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "targets": list(targets),
        "requests": ({"total": stats.total, "succeeded": stats.succeeded,
                      "failed": stats.failed} if stats is not None else None),
        "counts": counts,
        "controls": results,
        # Whether the scan ran as a logged-in user. Controls assessed against
        # a login page are not evidence about the product behind it, so the
        # report has to say which it was looking at.
        "scan_mode": scan_mode,
    }


def unmapped_findings(tests):
    """Findings whose type maps to no catalogued control.

    Reported alongside the evidence so nothing the scan found is silently left
    out of it just because there is no requirement to hang it on.
    """
    orphans = []
    for test in tests:
        for finding in getattr(test, "vulnerabilities_found", []):
            control_ids = finding.get("controls")
            if control_ids is None:
                control_ids = controls_for(finding.get("test_type", ""))
            if not control_ids or not any(describe(c) for c in control_ids):
                orphans.append(finding)
    return orphans
