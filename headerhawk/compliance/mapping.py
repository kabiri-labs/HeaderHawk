"""Which controls each class of finding demonstrates a failure of.

A finding is mapped only where the control genuinely covers it. Several finding
types have no entry, and that is deliberate: reports say so explicitly rather
than stretching a nearby requirement to fill the column.
"""

from .catalogue import CONTROLS

CONTROLS_BY_TEST = {
    # Injecting a routing header the front-end trusts is exactly the override
    # 4.1.3 requires to be impossible. The requirement names "a header field
    # set by an intermediary layer", which is what X-Forwarded-Host and its
    # family are.
    "Host Header Injection": ("ASVS-5.0:4.1.3",),
    # The Host header is not one of them: the client sets it, by definition of
    # HTTP/1.1, so there is nothing an intermediary set for the end user to
    # override and 4.1.3 does not reach it. Poisoning a link or a reset email
    # through Host has no catalogued requirement, so it is reported without
    # one rather than citing a neighbouring id an assessor would challenge.
    # When the poisoning takes the shape of a redirect it also fails 3.7.2,
    # which the open-redirect check reports under that id.
    "Host Header Poisoning": (),
    # The bypass is a different claim about the same header: it defeats the
    # validation the *front-end* performs, so what the end user overrides is
    # the intermediary's own determination of the host. 4.1.3 reaches that.
    "Host Header Bypass": ("ASVS-5.0:4.1.3",),
    "Web Cache Poisoning": ("ASVS-5.0:4.1.3",),
    # The candidates are deliberately limited to header fields an
    # intermediary sets, which is exactly what 4.1.3 covers: finding that
    # one of them changes the response is finding that the end user can
    # override it. Fuzzing arbitrary names would not support this claim.
    "Unkeyed Input": ("ASVS-5.0:4.1.3",),
    # 14.2.5 names this attack in as many words - cache only what has the
    # expected content type and no sensitive, dynamic content - and 14.2.2
    # is the server-side half of keeping a user page out of a shared cache.
    "Web Cache Deception": ("ASVS-5.0:14.2.5", "ASVS-5.0:14.2.2"),
    # A bypass driven by a client-supplied header is both an override of an
    # intermediary's header and an authorization decision made on data the
    # consumer controls.
    "Auth Bypass": ("ASVS-5.0:4.1.3", "ASVS-5.0:8.3.1"),
    "Virtual Host Discovery": ("ASVS-5.0:13.4.5",),
    "SSRF": ("ASVS-5.0:13.2.4", "ASVS-5.0:13.2.5"),
    "URL Parameter SSRF": ("ASVS-5.0:13.2.4", "ASVS-5.0:13.2.5"),
    "Blind SSRF (OOB)": ("ASVS-5.0:13.2.4", "ASVS-5.0:13.2.5"),
    "Open Redirect": ("ASVS-5.0:3.7.2",),
    # 4.2.4 also forbids CR/LF in header values, but is scoped to HTTP/2
    # and HTTP/3; these probes exercise HTTP/1.1, so 1.2.1 - encoding
    # output so untrusted data cannot restructure the message - is the
    # requirement they actually verify.
    "CRLF Response Splitting": ("ASVS-5.0:1.2.1",),
    "CRLF Header Injection": ("ASVS-5.0:1.2.1",),
    "HTTP Request Smuggling (CL.TE)": ("ASVS-5.0:4.2.1", "ASVS-5.0:4.2.2"),
    "HTTP Request Smuggling (TE.CL)": ("ASVS-5.0:4.2.1", "ASVS-5.0:4.2.2"),
    # CORS.
    "CORS Origin Reflection": ("ASVS-5.0:3.4.2",),
    "CORS Null Origin": ("ASVS-5.0:3.4.2",),
    "CORS Origin Validation Bypass": ("ASVS-5.0:3.4.2",),
    "CORS Insecure Origin Trust": ("ASVS-5.0:3.4.2",),
    "CORS Wildcard With Credentials": ("ASVS-5.0:3.4.2",),
    # Response-header posture.
    "Strict-Transport-Security": ("ASVS-5.0:3.4.1",),
    "Content-Security-Policy": ("ASVS-5.0:3.4.3",),
    "X-Content-Type-Options": ("ASVS-5.0:3.4.4",),
    "Referrer-Policy": ("ASVS-5.0:3.4.5",),
    "Frame Protection": ("ASVS-5.0:3.4.6",),
    "Cross-Origin-Opener-Policy": ("ASVS-5.0:3.4.8",),
    "Version Disclosure": ("ASVS-5.0:13.4.6",),
    # 3.4.3 is what makes a policy meaningful, so the deeper script-source
    # analysis verifies the same requirement as the policy's presence.
    "CSP Script Sources": ("ASVS-5.0:3.4.3",),
    "CSP Violation Reporting": ("ASVS-5.0:3.4.7",),
    # Cookie attributes.
    "Cookie HttpOnly Attribute": ("ASVS-5.0:3.3.4",),
    "Cookie Secure Attribute": ("ASVS-5.0:3.3.1",),
    "Cookie SameSite Attribute": ("ASVS-5.0:3.3.2",),
    "Cookie Name Prefix": ("ASVS-5.0:3.3.1", "ASVS-5.0:3.3.3"),
    "Cookie Size": ("ASVS-5.0:3.3.5",),
    # ASVS 5.0 has no Permissions-Policy requirement, so this stays unmapped
    # rather than borrowing a neighbouring one.
    "Permissions-Policy": (),
}

# A mapping that points at an id no longer in the catalogue would render as a
# bare string in reports and quietly lose its citation, so refuse to import.
_UNKNOWN = {control_id
            for control_ids in CONTROLS_BY_TEST.values()
            for control_id in control_ids
            if control_id not in CONTROLS}
if _UNKNOWN:
    raise ImportError(
        f"compliance mapping references uncatalogued control(s): "
        f"{', '.join(sorted(_UNKNOWN))}")


def controls_for(test_type):
    """Return the control ids a finding type maps onto (empty when unmapped)."""
    return CONTROLS_BY_TEST.get(test_type, ())
