"""Rendering the per-control evidence as Markdown or JSON."""

import json

from ..compliance.evidence import (STATUS_NOT_ASSESSED, STATUS_ORDER,
                                   STATUS_PASS, build_evidence,
                                   unmapped_findings)
from ..core.auth import NOT_CONFIGURED, UNVERIFIED
from ..core.findings import confidence_of

_STATUS_MARK = {"Fail": "FAIL", "Not assessed": "NOT ASSESSED", "Pass": "PASS"}


def _finding_line(finding):
    severity = finding.get("severity", "")
    test_type = finding.get("test_type", "Finding")
    subject = finding.get("header_name") or finding.get("param_name") or ""
    where = finding.get("url", "")
    # The confidence rides in the same bracket as the severity: an assessor
    # reading the evidence has to be able to tell what was proved from what was
    # observed once, without opening the analysis.
    parts = [f"  - **[{severity}, {confidence_of(finding)}] {test_type}**"]
    if subject:
        parts.append(f" (`{subject}`)")
    parts.append(f" — {where}")
    lines = ["".join(parts), f"    - {finding.get('analysis', '')}"]
    if finding.get("confirmation"):
        lines.append(f"    - Confirming this: {finding['confirmation']}")
    if finding.get("repro"):
        lines.append(f"    - Reproduce: `{finding['repro']}`")
    return lines


def render_markdown(evidence, orphans=()):
    """Render the evidence for a human assessor to read and cite."""
    lines = [
        f"# {evidence['tool']} Compliance Evidence",
        "",
        f"- **Tool:** {evidence['tool']} {evidence['version']}",
        f"- **Generated:** {evidence['generated']}",
        f"- **Target(s):** {', '.join(evidence['targets']) or 'n/a'}",
    ]
    if evidence.get("scan_mode"):
        lines.append(f"- **Scan mode:** {evidence['scan_mode']}")
    requests = evidence.get("requests")
    if requests:
        lines.append(f"- **Requests:** {requests['succeeded']}/{requests['total']} "
                     f"succeeded ({requests['failed']} failed)")
    lines += ["", "## Summary", "",
              "| Status | Controls |", "| --- | --- |"]
    for status in STATUS_ORDER:
        lines.append(f"| {status} | {evidence['counts'][status]} |")

    if evidence.get("scan_mode") in (UNVERIFIED, NOT_CONFIGURED):
        lines += ["",
                  "> This scan was not confirmed to be running as a logged-in "
                  "user, so these results describe whatever the target serves "
                  "anonymously. For an authenticated product that is the login "
                  "page, not the application behind it."]

    if evidence["counts"][STATUS_NOT_ASSESSED]:
        lines += ["",
                  "> A control is only reported as passing when a check that "
                  "covers it actually completed. Anything this scan could not "
                  "reach is listed as not assessed, with the reason, rather "
                  "than counted as compliant."]

    lines += ["", "## Controls", ""]
    ordered = sorted(evidence["controls"],
                     key=lambda r: (STATUS_ORDER.index(r.status), r.control.id))
    for result in ordered:
        control = result.control
        lines += [
            f"### {control.id} — {_STATUS_MARK.get(result.status, result.status)}",
            "",
            f"- **Framework:** {control.framework} {control.section}",
            f"- **Requirement:** {control.title}",
            f"- **Source:** {control.url}",
        ]
        if result.status == STATUS_PASS:
            lines.append(f"- **Assessed by:** {', '.join(result.assessed_by)}")
            lines.append("- **Evidence:** assessed, no finding.")
        elif result.status == STATUS_NOT_ASSESSED:
            reasons = result.not_assessed_because or ["no check covering this "
                                                      "control ran"]
            lines.append("- **Not assessed because:**")
            lines += [f"  - {reason}" for reason in reasons]
        else:
            if result.assessed_by:
                lines.append(f"- **Assessed by:** {', '.join(result.assessed_by)}")
            lines.append(f"- **Evidence:** {len(result.findings)} finding(s)")
            for finding in result.findings:
                lines += _finding_line(finding)
        lines.append("")

    if orphans:
        lines += ["## Findings Outside the Catalogue", "",
                  "These were found but map to no catalogued requirement, so "
                  "they appear here rather than being dropped.", ""]
        for finding in orphans:
            lines += _finding_line(finding)
        lines.append("")
    return "\n".join(lines)


def render_json(evidence, orphans=()):
    """Render the same evidence as JSON, for a dashboard or an audit pipeline."""
    payload = {
        "tool": evidence["tool"],
        "version": evidence["version"],
        "generated": evidence["generated"],
        "targets": evidence["targets"],
        "scan_mode": evidence.get("scan_mode"),
        "requests": evidence["requests"],
        "counts": evidence["counts"],
        "controls": [
            {
                "id": result.control.id,
                "framework": result.control.framework,
                "section": result.control.section,
                "requirement": result.control.title,
                "source": result.control.url,
                "status": result.status,
                "assessed_by": result.assessed_by,
                "not_assessed_because": result.not_assessed_because,
                "findings": result.findings,
            }
            for result in sorted(
                evidence["controls"],
                key=lambda r: (STATUS_ORDER.index(r.status), r.control.id))
        ],
        "findings_outside_catalogue": list(orphans),
    }
    return json.dumps(payload, indent=2, default=str)


def save_evidence(path, tests, targets, stats=None, version=None,
                  tool_name=None, drift=None, scan_mode=None):
    """Write the evidence report, choosing the format from the extension."""
    if not path:
        return
    evidence = build_evidence(tests, targets, stats=stats, version=version,
                              tool_name=tool_name, drift=drift,
                              scan_mode=scan_mode)
    orphans = unmapped_findings(tests)
    if path.rsplit(".", 1)[-1].lower() == "json":
        body = render_json(evidence, orphans)
    else:
        body = render_markdown(evidence, orphans)
    with open(path, "w") as handle:
        handle.write(body)
    print(f"\nCompliance evidence saved to {path}")
    return evidence
