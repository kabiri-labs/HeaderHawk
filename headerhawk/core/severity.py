"""Severity bands for findings and their reporting metadata."""

# Default severity per finding type, used for triage and for the SARIF
# `security-severity` score that code-scanning platforms consume.
SEVERITY_BY_TEST = {
    "Host Header Injection": "Medium",
    "Host Header Poisoning": "Medium",
    "Host Header Bypass": "High",
    "Web Cache Poisoning": "High",
    "Unkeyed Input": "Medium",
    "Web Cache Deception": "High",
    "Auth Bypass": "High",
    "Virtual Host Discovery": "Low",
    "SSRF": "High",
    "URL Parameter SSRF": "High",
    "Open Redirect": "Medium",
    "Blind SSRF (OOB)": "High",
    # CORS. A permissive allowlist is downgraded per finding when the endpoint
    # does not allow credentials.
    "CRLF Response Splitting": "High",
    "CRLF Header Injection": "High",
    "HTTP Request Smuggling (CL.TE)": "High",
    "HTTP Request Smuggling (TE.CL)": "High",
    "CORS Origin Reflection": "High",
    "CORS Null Origin": "High",
    "CORS Origin Validation Bypass": "High",
    "CORS Insecure Origin Trust": "High",
    "CORS Wildcard With Credentials": "Low",
    # Response-header posture: a control that is absent, not a proven exploit.
    "Strict-Transport-Security": "Medium",
    "Content-Security-Policy": "Medium",
    "Frame Protection": "Medium",
    "X-Content-Type-Options": "Low",
    "Referrer-Policy": "Low",
    "Cross-Origin-Opener-Policy": "Low",
    "Permissions-Policy": "Low",
    "Version Disclosure": "Low",
    "CSP Script Sources": "Medium",
    "CSP Violation Reporting": "Low",
    # Cookie attributes.
    "Cookie HttpOnly Attribute": "Medium",
    "Cookie Secure Attribute": "Medium",
    "Cookie SameSite Attribute": "Low",
    "Cookie Name Prefix": "Low",
    "Cookie Size": "Low",
}
DEFAULT_SEVERITY = "Medium"

# Maps a severity band onto (SARIF result level, GitHub security-severity score).
SEVERITY_META = {
    "Critical": ("error", "9.5"),
    "High": ("error", "8.0"),
    "Medium": ("warning", "5.0"),
    "Low": ("note", "3.0"),
    "Info": ("note", "1.0"),
}


# Bands in order, so a caller can ask for "this and above". The names are
# matched case-insensitively because the CLI takes them in lower case.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_for(test_type):
    """Return the default severity band for a finding type."""
    return SEVERITY_BY_TEST.get(test_type, DEFAULT_SEVERITY)


def severity_rank(band):
    """Where a severity band sits in the order, for threshold comparisons.

    An unrecognised band ranks with the default rather than at either extreme:
    a typo must not silently hide findings, nor promote them.
    """
    return SEVERITY_RANK.get(str(band or "").strip().lower(),
                             SEVERITY_RANK[DEFAULT_SEVERITY.lower()])
