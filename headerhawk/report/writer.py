"""Report writing: JSON, SARIF and Markdown, chosen by output extension."""

import json
from datetime import datetime

from ..compliance import controls_for, describe, summarise
from ..core.findings import confidence_of, finding_class_of
from ..core.severity import DEFAULT_SEVERITY, severity_for
from .sarif import build_sarif


def _control_cell(control):
    """Render a catalogued control as a link, or an unknown id as plain text."""
    if isinstance(control, str):
        return control, ""
    return f"[{control.id}]({control.url})", control.title


def _controls_line(result):
    """Render one finding's controls as links, keeping unknown ids readable."""
    control_ids = result.get("controls") or ()
    if not control_ids:
        return "none catalogued"
    rendered = []
    for control_id in control_ids:
        control = describe(control_id)
        rendered.append(f"[{control.id}]({control.url})" if control else control_id)
    return ", ".join(rendered)


def _coverage_section(results):
    """Build the control-coverage table an assessor reads before the details."""
    rows, unmapped = summarise(results)
    if not rows and not unmapped:
        return []
    lines = ["## Control Coverage\n",
             "| Control | Requirement | Findings |",
             "| --- | --- | --- |"]
    for control, count in rows:
        cell, title = _control_cell(control)
        lines.append(f"| {cell} | {title} | {count} |")
    if unmapped:
        lines.append("")
        lines.append(f"_{unmapped} finding(s) map to no catalogued control._")
    lines.append("")
    return lines


def save_results(output_file, tests, verbose):
    if not output_file or not tests:
        return
    extension = output_file.rsplit(".", 1)[-1].lower()
    results = []
    for test in tests:
        results.extend(test.all_results if verbose == 2 else [])
        results.extend(test.vulnerabilities_found)
    # Ensure every result carries a severity and its control mapping so
    # JSON/SARIF/Markdown agree - verbose-2 entries never went through record().
    for result in results:
        test_type = result.get("test_type", "")
        result.setdefault("severity", severity_for(test_type))
        result.setdefault("controls", list(controls_for(test_type)))
        result.setdefault("finding_class", finding_class_of(result))
        result.setdefault("confidence", confidence_of(result))

    if extension == "json":
        with open(output_file, "w") as handle:
            json.dump(results, handle, indent=4)
        print(f"\nResults saved to {output_file}")
        return

    if extension == "sarif":
        with open(output_file, "w") as handle:
            json.dump(build_sarif(results), handle, indent=2)
        print(f"\nSARIF report saved to {output_file}")
        return

    targets = sorted({test.target_url for test in tests})
    target_line = (targets[0] if len(targets) == 1
                   else f"{len(targets)} targets ({', '.join(targets)})")
    lines = [
        "# HeaderHawk Report",
        f"**Target(s):** {target_line}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total Findings:** {sum(len(t.vulnerabilities_found) for t in tests)}\n",
    ]
    lines.extend(_coverage_section(results))
    if results:
        lines.append("## Test Results\n")
        for result in results:
            lines.extend([
                f"### {result['test_type']}: {result['test_result']} "
                f"({result.get('severity', DEFAULT_SEVERITY)})",
                f"- **URL:** {result['url']}",
                f"- **Severity:** {result.get('severity', DEFAULT_SEVERITY)}",
                f"- **Method:** {result['method']}",
                f"- **Headers:** {result.get('headers', {})}",
                f"- **Parameter:** {result.get('param_name', '')}",
                f"- **Payload:** {result.get('payload', '')}",
                f"- **Status Code:** {result['status_code']}",
                f"- **Response Time:** {result.get('response_time', 0):.2f} seconds",
                f"- **Class:** {finding_class_of(result)}",
                f"- **Confidence:** {confidence_of(result)}",
                f"- **Controls:** {_controls_line(result)}",
                f"- **Analysis:** {result['analysis']}",
                (f"- **Confirming this:** {result['confirmation']}"
                 if result.get("confirmation") else ""),
                f"- **Reproduce:** `{result['repro']}`\n" if result.get("repro") else "",
            ])
    else:
        lines.append("No vulnerabilities were found.\n")
    with open(output_file, "w") as handle:
        handle.write("\n".join(line for line in lines if line is not None))
    print(f"\nReport saved to {output_file}")
