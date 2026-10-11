"""Host-header driven open redirects.

Four payloads reach the same conclusion: the redirect target follows the Host
header. That is one defect with one place to fix it, so it is one finding
naming every payload that worked - the same rule the cache and CRLF checks
already follow.

A match here is two-sided to begin with: the status has to be a redirect a
browser follows, and the host in Location has to be the host that was sent. A
second identical probe is what separates that from a page that happened to be
redirecting at the time, and it is what lets the finding say "confirmed" rather
than leave a two-sided match reading as a guess forever.
"""

from collections import namedtuple
from urllib.parse import urlparse

from ..core.findings import CONFIDENCE_CONFIRMED, CONFIDENCE_SUSPECTED
from .base import BaseTest

# One payload whose host the Location followed.
Redirect = namedtuple("Redirect", "method payload url status_code location")

UNREPRODUCED_NOTE = (
    "Confirming this: the redirect followed the injected host once and an "
    "identical second probe did not, so it is reported as the one-off it so "
    "far is. Re-running shows whether it recurs."
)


class OpenRedirectTest(BaseTest):
    """Detect Host-header driven open redirects via the Location header."""

    test_type = "Open Redirect"
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hits = []

    def generate_payloads(self):
        payloads = ["example.com", "www.example.com", "example.com:80",
                    "www.example.com:443"]
        if self.oob_manager:
            payloads.insert(0, self.oob_manager.host("redirect"))
        elif self.oob_domain:
            payloads.insert(0, self.oob_domain.strip("/"))
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        test_cases = [
            (method, "Host", payload)
            for method in self.methods
            for payload in payloads
        ]
        self.run_pool(self.worker, test_cases, "Open Redirect Testing")
        self.report()

    @staticmethod
    def _follows(response, payload):
        """Whether this response redirects to the host that was injected."""
        injected_host = urlparse(f"http://{payload}").hostname
        response_host = urlparse(response.headers.get("Location", "")).hostname
        return bool(response_host and injected_host
                    and response_host.lower() == injected_host.lower())

    def worker(self, method, header_name, payload):
        response = self.request(method, headers={header_name: payload},
                                allow_redirects=False)
        if response is None or response.status_code not in self.REDIRECT_CODES:
            return
        if not self._follows(response, payload):
            return
        self._hits.append(Redirect(
            method=method, payload=payload, url=response.url,
            status_code=response.status_code,
            location=response.headers.get("Location", "")))

    def _follows_again(self, hit):
        """Send the same probe again and say whether it redirects the same way."""
        response = self.request(hit.method, headers={"Host": hit.payload},
                                allow_redirects=False)
        if response is None or response.status_code not in self.REDIRECT_CODES:
            return False
        return self._follows(response, hit.payload)

    def report(self):
        """One finding, naming every payload the redirect followed."""
        if not self._hits:
            return
        # Workers finish in whatever order they finish in, so the candidate
        # order is fixed here: which payload a finding is reported against must
        # not depend on the scheduler.
        hits = sorted(self._hits, key=lambda hit: (hit.method, hit.payload))
        payloads = ", ".join(sorted({hit.payload for hit in hits}))

        for hit in hits:
            if not self._follows_again(hit):
                continue
            self.record({
                "url": hit.url,
                "method": hit.method,
                "headers": {"Host": hit.payload},
                "header_name": "Host",
                "payload": hit.payload,
                "status_code": hit.status_code,
                "test_result": "Vulnerable",
                "confidence": CONFIDENCE_CONFIRMED,
                "analysis": (
                    f"The redirect target follows the 'Host' header: "
                    f"'{hit.location}' points at the host that was sent, on a "
                    f"{hit.status_code} a browser follows, and an identical "
                    f"second probe redirected the same way. Host(s) accepted: "
                    f"{payloads}."
                ),
            })
            return

        first = hits[0]
        self.record({
            "url": first.url,
            "method": first.method,
            "headers": {"Host": first.payload},
            "header_name": "Host",
            "payload": first.payload,
            "status_code": first.status_code,
            "confidence": CONFIDENCE_SUSPECTED,
            "analysis": (
                f"The redirect target followed the 'Host' header once - "
                f"'{first.location}' pointed at the host that was sent - but "
                f"an identical second probe did not redirect the same way, so "
                f"it is not reported as proof. Host(s) accepted: {payloads}."
            ),
            "confirmation": UNREPRODUCED_NOTE,
        })
