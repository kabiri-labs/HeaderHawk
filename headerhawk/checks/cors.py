"""Active testing of the CORS origin allowlist.

The `Origin` request header decides who is allowed to read a cross-origin
response, which puts it squarely in this scanner's territory: a server that
echoes whatever `Origin` it is handed has no allowlist at all, and with
credentials allowed that is a cross-origin read of authenticated data.

Findings are evidence-driven. A unique per-scan marker is sent as the origin, so
seeing it echoed back in `Access-Control-Allow-Origin` proves the server
accepted an origin that cannot exist rather than merely suggesting it.
"""

from urllib.parse import urlparse

from ..core.markers import new_token
from .base import BaseTest

ALLOW_ORIGIN = "Access-Control-Allow-Origin"
ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials"


class CORSTest(BaseTest):
    """Probe how the target validates the `Origin` request header."""

    test_type = "CORS Misconfiguration"

    # One type per root cause, so a report distinguishes "reflects anything"
    # from "trusts null" - they are fixed differently.
    REFLECTION = "CORS Origin Reflection"
    NULL_ORIGIN = "CORS Null Origin"
    VALIDATION_BYPASS = "CORS Origin Validation Bypass"
    INSECURE_ORIGIN = "CORS Insecure Origin Trust"
    WILDCARD_CREDENTIALS = "CORS Wildcard With Credentials"

    @classmethod
    def emitted_types(cls):
        return (cls.REFLECTION, cls.NULL_ORIGIN, cls.VALIDATION_BYPASS,
                cls.INSECURE_ORIGIN, cls.WILDCARD_CREDENTIALS)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        parsed = urlparse(self.target_url)
        self.scheme = (parsed.scheme or "http").lower()
        self.token = new_token()
        self._wildcard_reported = False

    def probe(self, origin):
        """Send one Origin and return (allow_origin, credentials_allowed)."""
        response = self.request("GET", headers={"Origin": origin},
                                allow_redirects=False)
        if response is None:
            return None, False
        allow_origin = response.headers.get(ALLOW_ORIGIN)
        allowed = (response.headers.get(ALLOW_CREDENTIALS) or "").strip().lower()
        self._last_status = response.status_code
        return allow_origin, allowed == "true"

    def _severity(self, credentials, base="High"):
        # Without credentials a permissive allowlist still exposes whatever the
        # endpoint serves unauthenticated, which is real but a tier lower.
        return base if credentials else "Medium"

    def _record_cors(self, test_type, origin, credentials, analysis, severity):
        self.record({
            "test_type": test_type,
            "severity": severity,
            "test_result": "Vulnerable",
            "url": self.target_url,
            "method": "GET",
            "headers": {"Origin": origin},
            "header_name": "Origin",
            "payload": origin,
            "status_code": getattr(self, "_last_status", ""),
            "analysis": analysis,
        })

    def _note_wildcard(self, allow_origin, credentials):
        """Report the '*' with credentials combination, at most once."""
        if self._wildcard_reported or allow_origin != "*" or not credentials:
            return
        self._wildcard_reported = True
        self._record_cors(
            self.WILDCARD_CREDENTIALS, "(any)", credentials,
            f"'{ALLOW_ORIGIN}: *' is served together with "
            f"'{ALLOW_CREDENTIALS}: true'. A browser refuses that combination, "
            f"so the endpoint is not exploitable through it, but the pairing "
            f"means the allowlist is not the fixed value it appears to be.",
            "Low")

    def _credentials_note(self, credentials):
        return ("credentials are allowed, so an attacker's page can read "
                "authenticated responses" if credentials else
                "credentials are not allowed, so only unauthenticated content "
                "is exposed")

    def run(self):
        # A server that echoes an origin which cannot exist has no allowlist,
        # and every narrower bypass below would be the same root cause reported
        # again. So this is probed first and short-circuits the rest.
        arbitrary = f"{self.scheme}://{self.token}.example-collab.com"
        allow_origin, credentials = self.probe(arbitrary)
        self._note_wildcard(allow_origin, credentials)
        reflects_anything = allow_origin == arbitrary
        if reflects_anything:
            self._record_cors(
                self.REFLECTION, arbitrary, credentials,
                f"'{ALLOW_ORIGIN}' echoed a unique origin that cannot exist "
                f"({arbitrary}), so the server reflects whatever Origin it is "
                f"sent instead of validating against an allowlist; "
                f"{self._credentials_note(credentials)}.",
                self._severity(credentials))

        # A null origin is allowlisted deliberately, not by reflection, so it is
        # worth probing even when the server already reflects everything - it is
        # reachable from a sandboxed iframe and fixed separately.
        allow_origin, credentials = self.probe("null")
        self._note_wildcard(allow_origin, credentials)
        if allow_origin == "null":
            self._record_cors(
                self.NULL_ORIGIN, "null", credentials,
                f"'{ALLOW_ORIGIN}: null' is returned for 'Origin: null', which "
                f"any sandboxed iframe or redirected request can present; "
                f"{self._credentials_note(credentials)}.",
                self._severity(credentials))

        if reflects_anything:
            return  # the remaining probes would restate the reflection finding

        self._probe_validation_bypasses()
        self._probe_scheme_downgrade()

    def _probe_validation_bypasses(self):
        """Origins built to slip past a substring match on the target host."""
        host = self.original_host
        cases = [
            (f"{self.scheme}://{host}.{self.token}.com",
             f"the allowlist appears to match on a prefix, so any domain "
             f"starting with '{host}.' is trusted"),
            (f"{self.scheme}://{self.token}{host}",
             f"the allowlist appears to match on a suffix without anchoring to "
             f"a dot, so any domain ending in '{host}' is trusted"),
            (f"{self.scheme}://{host}.",
             "a trailing dot resolves to the same host but is a different "
             "string, so the allowlist is compared before normalisation"),
            (f"{self.scheme}://{self.token}.{host}",
             f"any subdomain of '{host}' is trusted, so a takeover of one - or "
             f"any content injected into one - can read this origin's responses"),
        ]
        for origin, explanation in cases:
            allow_origin, credentials = self.probe(origin)
            self._note_wildcard(allow_origin, credentials)
            if allow_origin != origin:
                continue
            self._record_cors(
                self.VALIDATION_BYPASS, origin, credentials,
                f"'{ALLOW_ORIGIN}' echoed '{origin}': {explanation}; "
                f"{self._credentials_note(credentials)}.",
                self._severity(credentials))

    def _probe_scheme_downgrade(self):
        """An https origin that also trusts its plaintext self."""
        if self.scheme != "https":
            return
        origin = f"http://{self.original_host}"
        allow_origin, credentials = self.probe(origin)
        self._note_wildcard(allow_origin, credentials)
        if allow_origin != origin:
            return
        self._record_cors(
            self.INSECURE_ORIGIN, origin, credentials,
            f"'{ALLOW_ORIGIN}' echoed the plaintext origin '{origin}' for an "
            f"HTTPS endpoint, so anyone able to tamper with an HTTP page on "
            f"this host can read its responses; "
            f"{self._credentials_note(credentials)}.",
            self._severity(credentials, base="High"))
