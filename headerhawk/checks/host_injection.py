"""Routing headers an application trusts, and what reflection actually proves.

A unique marker coming back is a strong signal and a weak conclusion. It says
the application copied the header into its output. It does not say the
application *routes* on it - and a marker echoed into a debug footer is a very
different thing from a marker that became the host of a link the response tells
a browser to follow.

So the two are reported as two different grades. A marker that reaches the host
of a URL a browser would actually go to, and does so again when the same probe
is repeated, is confirmed: that is a link- or redirect-poisoning primitive. A
marker that comes back only as text is suspected, and the finding says what
would settle it.

What counts as a URL a browser would go to is deliberately narrow. A URL
printed as text - "Requested https://host/" in a diagnostic page, a field in a
JSON error - is not a destination, and neither is a ``Location`` on a response
that is not a redirect. Counting either would confirm a primitive that does not
exist, which is the distinction this check is built on.

A marker that survives into a request that never carried the header is a cache
poisoning, which is a stronger claim about a different weakness; the cache
checks own that one and this check does not restate it.
"""

import re
from collections import namedtuple
from urllib.parse import urlparse

from ..core.findings import CONFIDENCE_CONFIRMED, CONFIDENCE_SUSPECTED
from ..core.markers import new_token
from .base import BaseTest
from .mutations import mutations_for
from .wordlists import HOST_HEADERS

# An absolute URL, bracketed IPv6 authority included. The brackets have to be
# inside the match: without them the authority is truncated to something no
# parser accepts.
_URL = re.compile(r"https?://(?:\[[^\]\s]+\]|[^/\s\"'<>)\]}]+)[^\s\"'<>]*", re.I)

# A URL that something in the response points *at*: the value of an attribute
# or parameter that names a destination. This is what separates a link from a
# URL that happens to be printed on the page.
_POINTS_AT = re.compile(
    r"(?:href|src|action|url)\s*=\s*[\"']?\s*(" + _URL.pattern + r")", re.I)

ECHO_NOTE = (
    "Confirming this: the marker came back as text, not as the host of a URL "
    "anything points at, so what is shown is that the application copies the "
    "header into its output. To settle whether it routes on it, re-run with "
    "--oob <your-domain> --oob-poll-url <export-url> - an interaction arriving "
    "at your own listener proves the value was used to reach a host - and look "
    "at whether the same header poisons a cache, which the cache checks in "
    "this scan report separately."
)

UNREPRODUCED_NOTE = (
    "Confirming this: the marker did reach the host of a URL this response "
    "points at, but an identical second probe did not produce it again, so it "
    "is reported as the one-off it so far is. Re-running shows whether it "
    "recurs; --oob <your-domain> --oob-poll-url <export-url> settles whether "
    "the value is used to reach a host at all."
)

# One reflection of one shape in one header.
Reflection = namedtuple(
    "Reflection", "method header shape value url status_code places hosts")


def _host_of(url):
    """The host a browser would contact for this URL, or "" when it cannot.

    A malformed authority is not a host anyone reaches, and it is never a
    reason to stop the check: an unbracketed IPv6 address in an unrelated link
    on the page used to abort the whole thing and discard every reflection it
    had collected.
    """
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


class HostInjectionTest(BaseTest):
    """Find the routing headers an application honours, and grade the evidence.

    Each header is probed with every shape worth sending in it (see
    ``mutations``), all of them carrying the same per-scan marker. Reflections
    are collected first and reported afterwards, one finding per header, naming
    every shape that worked - five shapes of one echoed header are one defect
    with one fix.
    """

    test_type = "Host Header Injection"

    # The Host header is not one an intermediary sets - the client sets it, by
    # definition of HTTP/1.1 - so a finding about it cannot cite the
    # requirement about overriding an intermediary's header. It gets its own
    # type, and that type is deliberately unmapped. See compliance/mapping.py.
    POISONING = "Host Header Poisoning"

    # A browser follows Location on these and ignores it on everything else,
    # so a marker in a Location beside a 200 is not a redirect primitive.
    REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

    # Response headers whose value names somewhere to go.
    POINTING_HEADERS = ("Link", "Refresh")

    @classmethod
    def emitted_types(cls):
        return (cls.test_type, cls.POISONING)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.marker_token = None
        self._hits = []

    def _type_for(self, header):
        """Which finding type a header's reflection belongs to."""
        return self.POISONING if header.lower() == "host" else self.test_type

    # -- what gets sent ------------------------------------------------------

    def generate_cases(self):
        """Every (method, header, shape, value) this check will send."""
        token = new_token()
        marker = f"{token}.example-collab.com"
        out_of_band = None
        if self.oob_manager:
            out_of_band = self.oob_manager.host("host")
        elif self.oob_domain:
            out_of_band = f"{token}.{self.oob_domain.strip('/')}"
        cases = []
        for method in self.methods:
            for header in HOST_HEADERS:
                for mutation in mutations_for(header, marker,
                                              self.original_host):
                    cases.append((method, header, mutation.shape,
                                  mutation.value))
                if out_of_band:
                    # Sent as it is: the point of this one is the request
                    # leaving the target, not the shape it leaves in.
                    cases.append((method, header, "out-of-band host",
                                  out_of_band))
        return token, cases

    def run(self):
        self.marker_token, cases = self.generate_cases()
        self.run_pool(self.worker, cases, "Host Header Injection Testing")
        self.report()

    # -- probing -------------------------------------------------------------

    def _destinations(self, response):
        """Every URL in this response that a browser would actually go to."""
        urls = []
        if response.status_code in self.REDIRECT_CODES:
            urls.extend(_URL.findall(response.headers.get("Location", "") or ""))
        for name in self.POINTING_HEADERS:
            urls.extend(_URL.findall(response.headers.get(name, "") or ""))
        urls.extend(_POINTS_AT.findall(response.text or ""))
        return urls

    def _marked_hosts(self, response):
        """Hosts carrying the marker that this response points a browser at.

        The marker has to be in the *host*, not merely somewhere in the URL: in
        ``https://target@marker/`` a browser goes to the target, so reporting
        that as attacker-controlled routing would be exactly the over-claim
        this check exists to avoid.
        """
        hosts = []
        for url in self._destinations(response):
            host = _host_of(url)
            if self.marker_token in host and host not in hosts:
                hosts.append(host)
        return hosts

    def _reflection(self, method, header, shape, value, response):
        """Where this response carried the marker back, or None."""
        places = []
        if self.marker_token in (response.headers.get("Location", "") or ""):
            places.append("the 'Location' header")
        if self.marker_token in (response.text or ""):
            places.append("the response body")
        places.extend(
            f"the '{name}' header" for name, header_value in response.headers.items()
            if name.lower() != "location" and self.marker_token in str(header_value))
        if not places:
            return None
        return Reflection(
            method=method, header=header, shape=shape, value=value,
            url=response.url, status_code=response.status_code,
            places=places, hosts=self._marked_hosts(response))

    def worker(self, method, header_name, shape, value):
        response = self.request(method, headers={header_name: value},
                                allow_redirects=False)
        if response is None:
            return
        reflection = self._reflection(method, header_name, shape, value,
                                      response)
        if reflection is None:
            if self.verbose == 2:
                self.all_results.append({
                    "test_type": self.test_type,
                    "url": response.url,
                    "method": method,
                    "header_name": header_name,
                    "payload": value,
                    "status_code": response.status_code,
                    "analysis": f"Marker not reflected ({shape}).",
                    "test_result": "Not Vulnerable",
                })
            return
        self._hits.append(reflection)

    def _holds_on_a_second_probe(self, hit):
        """Send the same probe again and return the marked hosts it produces.

        One response is an observation. The same request producing the same
        attacker-controlled host twice is what makes it a finding rather than a
        coincidence of whatever that page was rendering at the time.
        """
        response = self.request(hit.method, headers={hit.header: hit.value},
                                allow_redirects=False)
        if response is None:
            return []
        return self._marked_hosts(response)

    # -- reporting -----------------------------------------------------------

    def report(self):
        """One finding per header, naming every shape that reflected."""
        by_header = {}
        for hit in self._hits:
            by_header.setdefault(hit.header, []).append(hit)
        for header in HOST_HEADERS:
            if header in by_header:
                self._report_header(header, by_header[header])

    def _report_header(self, header, hits):
        shapes = ", ".join(sorted({hit.shape for hit in hits}))
        places = ", ".join(sorted({place for hit in hits
                                   for place in hit.places}))
        # Worker threads finish in whatever order they finish in, so the
        # candidates are ordered here: which shape gets re-probed first - and
        # which one a downgraded finding is reported against - must not depend
        # on the scheduler, or the same target grades differently twice.
        routed = sorted((hit for hit in hits if hit.hosts),
                        key=lambda hit: (hit.method, hit.shape))

        # Every shape that reached a host gets its own second probe. Stopping
        # at the first would downgrade a header whose stable shape happened to
        # be collected second.
        for hit in routed:
            hosts = self._holds_on_a_second_probe(hit)
            if not hosts:
                continue
            self.record({
                "test_type": self._type_for(header),
                "url": hit.url,
                "method": hit.method,
                "headers": {header: hit.value},
                "header_name": header,
                "payload": hit.value,
                "status_code": hit.status_code,
                "test_result": "Vulnerable",
                "confidence": CONFIDENCE_CONFIRMED,
                "analysis": (
                    f"'{header}' decides a host this response points a browser "
                    f"at: the marker came back as the host of a URL "
                    f"({', '.join(hosts)}) in {places}, and the same probe "
                    f"produced it again on a second request. Shape(s) "
                    f"reflected: {shapes}."
                ),
            })
            return

        if routed:
            # It reached a host and did not do so again. Saying it never
            # reached one would contradict what the scan actually saw.
            seen = ", ".join(sorted({host for hit in routed
                                     for host in hit.hosts}))
            first = routed[0]
            analysis = (
                f"'{header}' produced a URL this response points a browser at "
                f"whose host was the marker ({seen}), in {places} - but an "
                f"identical second probe did not produce it again, so it is "
                f"not reported as proof. Shape(s) reflected: {shapes}."
            )
            note = UNREPRODUCED_NOTE
        else:
            first = hits[0]
            analysis = (
                f"'{header}' is copied into the response: the marker came back "
                f"in {places}. Nothing in the response points a browser at a "
                f"URL whose host is the marker, so the application echoes the "
                f"header rather than demonstrably routing, redirecting or "
                f"building links on it. Shape(s) reflected: {shapes}."
            )
            note = ECHO_NOTE

        self.record({
            "test_type": self._type_for(header),
            "url": first.url,
            "method": first.method,
            "headers": {header: first.value},
            "header_name": header,
            "payload": first.value,
            "status_code": first.status_code,
            "severity": "Low",
            "confidence": CONFIDENCE_SUSPECTED,
            "analysis": analysis,
            "confirmation": note,
        })
