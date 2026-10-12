"""Mapping of findings onto published security controls.

Findings carry the controls they demonstrate a failure of, so a report answers
"which requirement is this evidence against?" rather than leaving the reader to
work it out. See ``catalogue`` for the controls and ``mapping`` for the wiring.
"""

from .catalogue import ASVS, CONTROLS, Control, describe
from .evidence import (STATUS_FAIL, STATUS_NOT_ASSESSED,
                       STATUS_PARTLY_ASSESSED, STATUS_PASS,
                       ControlResult, build_evidence, controls_assessed_by,
                       controls_covered_by, controls_unassessed_by,
                       unmapped_findings)
from .mapping import CONTROLS_BY_TEST, controls_for

__all__ = ["ASVS", "CONTROLS", "CONTROLS_BY_TEST", "Control", "ControlResult",
           "STATUS_FAIL", "STATUS_NOT_ASSESSED",
           "STATUS_PARTLY_ASSESSED", "STATUS_PASS",
           "build_evidence", "controls_assessed_by", "controls_covered_by",
           "controls_unassessed_by", "controls_for",
           "describe", "unmapped_findings"]


def summarise(results):
    """Count findings per control, for the coverage table in a report.

    Returns ``(rows, unmapped)`` where rows are ``(Control | id, count)`` pairs
    ordered by control id, and ``unmapped`` counts findings whose type has no
    catalogued control - reported rather than hidden, so the gap is visible.
    """
    counts = {}
    unmapped = 0
    for result in results:
        control_ids = result.get("controls")
        if control_ids is None:
            control_ids = controls_for(result.get("test_type", ""))
        if not control_ids:
            unmapped += 1
            continue
        for control_id in control_ids:
            counts[control_id] = counts.get(control_id, 0) + 1
    rows = [(describe(control_id) or control_id, count)
            for control_id, count in sorted(counts.items())]
    return rows, unmapped
