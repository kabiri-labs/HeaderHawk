"""Host-header driven open redirects.

Two things have to be true before this is a finding, and a fixed hostname can
only show one of them.

It has to reproduce: a two-sided match on one response - a redirect status and
a Location pointing at the host that was sent - is still a page that may simply
have been redirecting at the time. An identical second probe settles that.

And the destination has to actually follow the header. A fixed hostname cannot
tell "the destination follows the header" from "this is where the site always
redirects": scan a site whose canonical destination happens to be one of the
probe hosts and it matches on every probe, for reasons that have nothing to do
with the header. So confirmation rests on a host minted for this scan, which
cannot be anyone's canonical destination - and cannot be in anyone's allowlist
either, which is what ASVS 3.7.2 is about. The recognisable hostnames are still
sent, because an application that resolves a destination before redirecting to
it will take one of those and not a marker, but on their own they are reported
as the weaker evidence they are.

Several hosts reaching the same conclusion is one defect with one place to fix
it, so it is one finding naming every host that held - and only the ones that
held.
"""

from collections import namedtuple
from urllib.parse import urlparse

from ..core.findings import CONFIDENCE_CONFIRMED, CONFIDENCE_SUSPECTED
from ..core.markers import new_token
from .base import BaseTest

# One payload whose host the Location followed.
Redirect = namedtuple("Redirect", "method payload url status_code location")

UNREPRODUCED_NOTE = (
    "Confirming this: the redirect followed the injected host once and an "
    "identical second probe did not, so it is reported as the one-off it so "
    "far is. Re-running shows whether it recurs."
)

RECOGNISABLE_ONLY_NOTE = (
    "Confirming this: the destination followed a well-known hostname but not a "
    "host minted for this scan. Three things look like that - an allowlist "
    "that happens to include it, an application that resolves a destination "
    "before redirecting to it, or a site whose own canonical destination is "
    "that hostname, in which case the header had nothing to do with it. Only "
    "the first two are weaknesses, and 3.7.2 asks for an allowlist, so this is "
    "not reported as a failure of it. Re-run with --oob <your-domain> to settle "
    "it with a hostname you control."
)


class OpenRedirectTest(BaseTest):
    """Detect Host-header driven open redirects via the Location header."""

    test_type = "Open Redirect"
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    # Hostnames an assessor recognises, which an application that resolves its
    # destination will accept where a marker fails. They cannot confirm on
    # their own: a fixed hostname may be the site's own canonical destination.
    RECOGNISABLE = ("example.com", "www.example.com", "example.com:80",
                    "www.example.com:443")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hits = []
        # Payloads no site could be redirecting to for its own reasons, filled
        # in by generate_payloads: only these can confirm. Kept as state
        # because the token is minted once per scan and the report has to know
        # afterwards which payloads carried it.
        self._minted = frozenset()
        # Where the target redirects when the header names a host it does not
        # honour. That is the control: if the destination is the same whatever
        # the header says, the header is not deciding it.
        self._control_hosts = set()

    def generate_payloads(self):
        payloads = []
        if self.oob_manager:
            payloads.append(self.oob_manager.host("redirect"))
        elif self.oob_domain:
            payloads.append(self.oob_domain.strip("/"))
        payloads.append(f"{new_token()}.example-collab.com")
        self._minted = frozenset(payloads)
        return payloads + list(self.RECOGNISABLE)

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
    def _host_of(value):
        """The hostname in a URL or a bare authority, lower-cased."""
        try:
            parsed = urlparse(value if "//" in value else f"http://{value}")
            return (parsed.hostname or "").lower()
        except ValueError:
            return ""

    def _follows(self, response, payload):
        """Whether this response redirects to the host that was injected."""
        injected = self._host_of(payload)
        return bool(injected
                    and self._host_of(response.headers.get("Location", ""))
                    == injected)

    def worker(self, method, header_name, payload):
        response = self.request(method, headers={header_name: payload},
                                allow_redirects=False)
        if response is None or response.status_code not in self.REDIRECT_CODES:
            return
        if self._follows(response, payload):
            self._hits.append(Redirect(
                method=method, payload=payload, url=response.url,
                status_code=response.status_code,
                location=response.headers.get("Location", "")))
            return
        if payload in self._minted:
            # It redirected, but not where the header said: that is where the
            # target goes of its own accord. A fixed hostname cannot provide
            # this - it may be the destination the site was going to anyway.
            self._control_hosts.add(
                self._host_of(response.headers.get("Location", "")))

    def _follows_again(self, hit):
        """Send the same probe again and say whether it redirects the same way."""
        response = self.request(hit.method, headers={"Host": hit.payload},
                                allow_redirects=False)
        if response is None or response.status_code not in self.REDIRECT_CODES:
            return False
        return self._follows(response, hit.payload)

    def report(self):
        """One finding, naming every host that held on its own second probe."""
        if not self._hits:
            return
        # Workers finish in whatever order they finish in, so the candidate
        # order is fixed here: which host a finding is reported against must
        # not depend on the scheduler.
        hits = sorted(self._hits, key=lambda hit: (hit.method, hit.payload))
        # Every candidate gets its own second probe. Confirming one and
        # listing the rest would report a host as accepted that was never
        # re-tested, or that matched once and did not hold.
        held = [hit for hit in hits if self._follows_again(hit)]

        if not held:
            first = hits[0]
            self._record(first, hits, CONFIDENCE_SUSPECTED, UNREPRODUCED_NOTE, (
                f"The redirect target followed the 'Host' header once - "
                f"'{first.location}' pointed at the host that was sent - but "
                f"an identical second probe did not redirect the same way, so "
                f"it is not reported as proof."
            ))
            return

        proved = [hit for hit in held if hit.payload in self._minted]
        if proved:
            hit = proved[0]
            self._record(hit, held, CONFIDENCE_CONFIRMED, None, (
                f"The redirect target follows the 'Host' header: "
                f"'{hit.location}' points at a host minted for this scan, on "
                f"a {hit.status_code} a browser follows, and an identical "
                f"second probe redirected the same way. No site redirects "
                f"there for its own reasons, so the destination is whatever "
                f"the header says."
            ), result="Vulnerable")
            return

        hosts_held = {self._host_of(hit.payload) for hit in held}
        if self._control_hosts & hosts_held:
            # The target redirects there whatever the header says, so the
            # match was a coincidence of this being its canonical destination.
            if self.verbose == 2:
                self.all_results.append({
                    "test_type": self.test_type,
                    "url": held[0].url,
                    "method": held[0].method,
                    "header_name": "Host",
                    "payload": held[0].payload,
                    "status_code": held[0].status_code,
                    "analysis": (
                        "The redirect went to the same host when the header "
                        "named somewhere else, so this is where the target "
                        "redirects of its own accord."),
                    "test_result": "Not Vulnerable",
                })
            return

        hit = held[0]
        self._record(hit, held, CONFIDENCE_SUSPECTED, RECOGNISABLE_ONLY_NOTE, (
            f"The redirect target followed a well-known hostname twice - "
            f"'{hit.location}' - but not a host minted for this scan, so it is "
            f"not shown that the destination is whatever the header says."
        ))

    def _record(self, hit, listed, confidence, note, analysis, result=None):
        hosts = ", ".join(sorted({self._host_of(entry.payload)
                                  for entry in listed}))
        entry = {
            "url": hit.url,
            "method": hit.method,
            "headers": {"Host": hit.payload},
            "header_name": "Host",
            "payload": hit.payload,
            "status_code": hit.status_code,
            "confidence": confidence,
            "analysis": f"{analysis} Host(s) the redirect followed: {hosts}.",
        }
        if result is not None:
            entry["test_result"] = result
        if note is not None:
            entry["confirmation"] = note
        self.record(entry)
