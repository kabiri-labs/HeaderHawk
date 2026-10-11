"""Comparing a scan against a stored baseline.

A team that has accepted its current findings does not want a pipeline that
fails on all of them forever; it wants to know what changed. This compares a
scan against a previous one and reports what is new, what is fixed and what is
unchanged.

The whole thing turns on giving a finding an identity that survives between
scans. Several checks put a fresh random marker in every payload - that is what
makes their findings proof rather than guesswork - and a cache-buster lands in
the URL. Hashing those verbatim would make every finding look new on every run,
which is worse than having no baseline at all: the pipeline would fail forever
and the feature would be switched off. So the scanner's own tokens are folded
out before hashing - and only those, which is what ``core.markers`` is for.
"""

import hashlib
import json

from .markers import fold_tokens


def finding_identity(finding):
    """A hash that identifies the same finding across scans."""
    parts = (
        finding.get("test_type", ""),
        fold_tokens(finding.get("url", "")),
        finding.get("header_name") or finding.get("param_name") or "",
        fold_tokens(finding.get("payload", "")),
    )
    return hashlib.sha1("|".join(parts).encode("utf-8", "ignore")).hexdigest()


def collect_findings(tests):
    """Every finding from a set of checks, in the order they were reported."""
    return [finding
            for test in tests
            for finding in getattr(test, "vulnerabilities_found", [])]


def load_baseline(path):
    """Read a baseline written by ``--output <file>.json``.

    Returns the findings it holds, or None when the file cannot be used - a
    missing or malformed baseline must not silently turn into an empty one,
    because an empty baseline makes every current finding look new.
    """
    if not path:
        return None
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list):
        return None
    return [entry for entry in data if isinstance(entry, dict)]


def compare(current, baseline):
    """Split current findings into new / unchanged, and name what was fixed."""
    baseline_ids = {finding_identity(finding) for finding in baseline}
    current_ids = set()
    new, unchanged = [], []
    for finding in current:
        identity = finding_identity(finding)
        current_ids.add(identity)
        (unchanged if identity in baseline_ids else new).append(finding)
    fixed = [finding for finding in baseline
             if finding_identity(finding) not in current_ids]
    return {
        "new": new,
        "fixed": fixed,
        "unchanged": unchanged,
        "new_identities": {finding_identity(f) for f in new},
    }


def describe_drift(drift):
    """One line summarising a comparison, for the console and the report."""
    return (f"{len(drift['new'])} new, {len(drift['fixed'])} fixed, "
            f"{len(drift['unchanged'])} unchanged")
