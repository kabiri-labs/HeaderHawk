"""Finding classes and how they gate the process exit code.

Two very different things end up in a report. A *vulnerability* is something the
scanner proved it could do to the target. A *posture* finding is a control the
target does not have in place - real, and the reason an assessor reads the
report, but not an exploited weakness.

Keeping them apart is what lets posture checks ship without turning every
existing pipeline red: the exit code gates on vulnerabilities unless the caller
asks for more. ``--fail-on`` is that ask.
"""

CLASS_VULNERABILITY = "vulnerability"
CLASS_POSTURE = "posture"

DEFAULT_FINDING_CLASS = CLASS_VULNERABILITY

# What each --fail-on choice counts towards the exit code. "vuln" is the
# default because it is the behaviour every existing caller already relies on.
FAIL_ON_CLASSES = {
    "vuln": frozenset({CLASS_VULNERABILITY}),
    "posture": frozenset({CLASS_POSTURE}),
    "any": frozenset({CLASS_VULNERABILITY, CLASS_POSTURE}),
    "none": frozenset(),
}
DEFAULT_FAIL_ON = "vuln"


def finding_class_of(finding):
    """Return a finding's class, defaulting for entries that predate the field."""
    return finding.get("finding_class") or DEFAULT_FINDING_CLASS


# How well a finding is evidenced. The distinction already existed in prose -
# "Vulnerable" against "Potentially Vulnerable", the timing caveat on a
# smuggling finding, the cache-deception finding that says it needs a session -
# but it was a sentence rather than a field, so nothing downstream could act on
# it. As a field it travels into SARIF, the findings report and the evidence
# report, and a check that can only observe rather than prove has somewhere
# honest to say so.
CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_SUSPECTED = "suspected"
CONFIDENCE_INFORMATIONAL = "informational"

# Ordered strongest first, which is how counts are reported.
CONFIDENCE_ORDER = (CONFIDENCE_CONFIRMED, CONFIDENCE_SUSPECTED,
                    CONFIDENCE_INFORMATIONAL)

# What the result strings the checks already set mean as a confidence.
_CONFIDENCE_BY_RESULT = {
    "Vulnerable": CONFIDENCE_CONFIRMED,
    "Potentially Vulnerable": CONFIDENCE_SUSPECTED,
}


def confidence_for(finding_class, test_result):
    """The confidence a finding carries when its check does not name one.

    Derived from what the checks already say rather than assigned afresh per
    check, so introducing the field agrees with every existing finding instead
    of re-grading them all at once.

    A posture finding is confirmed by definition: it reports what the response
    did or did not carry, which is a direct observation rather than an
    inference about how the target would behave.
    """
    if finding_class == CLASS_POSTURE:
        return CONFIDENCE_CONFIRMED
    return _CONFIDENCE_BY_RESULT.get(test_result, CONFIDENCE_SUSPECTED)


def confidence_of(finding):
    """A finding's confidence, derived for entries that predate the field.

    A baseline written by an earlier version, and the verbose-2 entries that
    never went through ``record``, carry no field to read. Deriving it keeps
    them comparable instead of silently grading them as proof.
    """
    return (finding.get("confidence")
            or confidence_for(finding_class_of(finding),
                              finding.get("test_result", "")))


def count_by_confidence(tests):
    """Tally findings per confidence across every test object."""
    counts = {name: 0 for name in CONFIDENCE_ORDER}
    for test in tests:
        for finding in test.vulnerabilities_found:
            name = confidence_of(finding)
            counts[name] = counts.get(name, 0) + 1
    return counts


def count_by_class(tests):
    """Tally findings per class across every test object."""
    counts = {CLASS_VULNERABILITY: 0, CLASS_POSTURE: 0}
    for test in tests:
        for finding in test.vulnerabilities_found:
            name = finding_class_of(finding)
            counts[name] = counts.get(name, 0) + 1
    return counts


def gated_finding_count(tests, fail_on=DEFAULT_FAIL_ON, only_identities=None,
                        identity_of=None):
    """Count only the findings the chosen --fail-on setting should gate on.

    ``only_identities`` narrows that further to a specific set - used by
    --fail-on-new to gate on regressions against a baseline rather than on the
    findings a team has already accepted.

    An unrecognised setting counts nothing rather than everything: failing a
    build on a typo would be the worse of the two mistakes.
    """
    wanted = FAIL_ON_CLASSES.get(fail_on, frozenset())
    if not wanted:
        return 0
    counted = 0
    for test in tests:
        for finding in test.vulnerabilities_found:
            if finding_class_of(finding) not in wanted:
                continue
            if confidence_of(finding) == CONFIDENCE_INFORMATIONAL:
                # Context for the operator, never a gate. Nothing emits this
                # confidence yet, so no existing pipeline changes colour.
                continue
            if only_identities is not None:
                if identity_of is None or identity_of(finding) not in only_identities:
                    continue
            counted += 1
    return counted
