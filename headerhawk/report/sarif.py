"""SARIF 2.1.0 rendering of the collected findings."""

import re

from .._meta import __github_url__, __tool_name__, __version__
from ..compliance import controls_for, describe
from ..core.baseline import finding_identity
from ..core.findings import confidence_of, finding_class_of
from ..core.severity import DEFAULT_SEVERITY, SEVERITY_META, severity_for


def _control_help(control_ids):
    """Render the controls behind a rule as help text, or "" when unmapped."""
    lines = []
    for control_id in control_ids:
        control = describe(control_id)
        if control:
            lines.append(f"- {control.framework} {control.section}: "
                         f"{control.title} ({control.url})")
        else:
            lines.append(f"- {control_id}")
    if not lines:
        return ""
    return "Verifies:\n" + "\n".join(lines)


def _rule_id(test_type):
    """Turn a human test-type name into a stable SARIF rule id slug."""
    return re.sub(r"[^a-z0-9]+", "-", test_type.lower()).strip("-") or "finding"


def build_sarif(results, version=None):
    """Build a SARIF 2.1.0 log from the collected findings.

    The format is understood by GitHub code scanning and most security
    dashboards, letting the scanner plug into a product pipeline directly.
    """
    version = version or __version__
    rules = {}
    sarif_results = []
    for result in results:
        test_type = result.get("test_type", "Finding")
        rule_id = _rule_id(test_type)
        severity = result.get("severity") or severity_for(test_type)
        level, score = SEVERITY_META.get(severity, SEVERITY_META[DEFAULT_SEVERITY])
        control_ids = result.get("controls")
        if control_ids is None:
            control_ids = controls_for(test_type)
        if rule_id not in rules:
            # Controls ride on the rule as tags (code-scanning surfaces them as
            # filterable labels) and in help text, so an alert carries the
            # requirement it is evidence against without leaving the platform.
            rule = {
                "id": rule_id,
                "name": re.sub(r"\s+", "", test_type) or "Finding",
                "shortDescription": {"text": test_type},
                "properties": {"security-severity": score,
                               "tags": ["security"] + list(control_ids)},
            }
            help_text = _control_help(control_ids)
            if help_text:
                rule["help"] = {"text": help_text, "markdown": help_text}
            rules[rule_id] = rule
        location = result.get("url") or ""
        header_or_param = result.get("header_name") or result.get("param_name") or ""
        entry = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": result.get("analysis") or test_type},
            "properties": {
                "security-severity": score,
                "severity": severity,
                "method": result.get("method", ""),
                "payload": result.get("payload", ""),
                "header_or_parameter": header_or_param,
                "status_code": result.get("status_code", ""),
                "controls": list(control_ids),
                "finding_class": finding_class_of(result),
                "confidence": confidence_of(result),
                "confirmation": result.get("confirmation", ""),
            },
            "partialFingerprints": {
                # The same identity ``--baseline`` matches on, which folds the
                # marker-shaped tokens out first. Hashing the payload and URL
                # verbatim - as v1 did - put a fresh per-scan marker and
                # cache-buster into every fingerprint, so a platform saw a new
                # alert on every run and the alerts this is meant to
                # de-duplicate reopened instead. The key is versioned
                # because the algorithm changed, and re-keying costs one
                # transition: alerts a platform already holds under v1 do not
                # match a v2 fingerprint, so they close and reopen once - and
                # then stop churning, which is the point.
                "hostHeaderScanner/v2": finding_identity(result),
            },
        }
        if location:
            entry["locations"] = [{
                "physicalLocation": {"artifactLocation": {"uri": location}},
            }]
        sarif_results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": __tool_name__,
                "version": version,
                "informationUri": __github_url__,
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }
