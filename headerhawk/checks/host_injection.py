"""Routing headers an application trusts, and what reflection actually proves.

A unique marker coming back is a strong signal and a weak conclusion. It says
the application copied the header into its output. It does not say the
application *routes* on it - and a marker echoed into a debug footer is a very
different thing from a marker that became the host of a link the response tells
a browser to follow.

So the two are reported as two different grades. A marker that reaches the host
of an absolute URL, and does so again when the same probe is repeated, is
confirmed: that is a link- or redirect-poisoning primitive. A marker that comes
back only as text is suspected, and the finding says what would settle it.

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

# An absolute URL in a response, captured as far as its authority. Only the
# authority matters here: a marker inside it may be the host a browser would
# contact, while the same marker in the text beside the URL is just text.
_ABSOLUTE_URL = re.compile(r"https?://([^/\s\"'<>)\]}]+)", re.I)

SUSPECTED_NOTE = (
    "Confirming this: the marker came back as text, not as the host of a URL, "
    "so what is shown is that the application copies the header into its "
    "output. To settle whether it routes on it, re-run with --oob <your-domain> "
    "--oob-poll-url <export-url> - an interaction arriving at your own listener "
    "proves the value was used to reach a host - and look at whether the same "
    "header poisons a cache, which the cache checks in this scan report "
    "separately."
)

# One reflection of one shape in one header.
Reflection = namedtuple(
    "Reflection", "method header shape value url status_code places hosts")


class HostInjectionTest(BaseTest):
    """Find the routing headers an application honours, and grade the evidence.

    Each header is probed with every shape worth sending in it (see
    ``mutations``), all of them carrying the same per-scan marker. Reflections
    are collected first and reported afterwards, one finding per header, naming
    every shape that worked - five shapes of one echoed header are one defect
    with one fix.
    """

    test_type = "Host Header Injection"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.marker_token = None
        self._hits = []

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

    def _marked_hosts(self, *texts):
        """Hosts carrying the marker, taken from absolute URLs in the text.

        The marker has to be in the *host*, not merely somewhere in the
        authority: in ``https://target@marker.example/`` a browser goes to the
        target, so reporting that as attacker-controlled routing would be
        exactly the over-claim this check exists to avoid.
        """
        hosts = []
        for text in texts:
            for authority in _ABSOLUTE_URL.findall(text or ""):
                host = urlparse(f"http://{authority}").hostname or ""
                if self.marker_token in host and host not in hosts:
                    hosts.append(host)
        return hosts

    def _reflection(self, method, header, shape, value, response):
        """Where this response carried the marker back, or None."""
        location = response.headers.get("Location", "")
        body = response.text or ""
        places = []
        if self.marker_token in location:
            places.append("the 'Location' header")
        if self.marker_token in body:
            places.append("the response body")
        places.extend(
            f"the '{name}' header" for name, header_value in response.headers.items()
            if name.lower() != "location" and self.marker_token in str(header_value))
        if not places:
            return None
        return Reflection(
            method=method, header=header, shape=shape, value=value,
            url=response.url, status_code=response.status_code,
            places=places, hosts=self._marked_hosts(location, body))

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
        return self._marked_hosts(response.headers.get("Location", ""),
                                  response.text or "")

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
        routed = next((hit for hit in hits if hit.hosts), None)

        if routed is not None:
            hosts = self._holds_on_a_second_probe(routed)
            if hosts:
                self.record({
                    "url": routed.url,
                    "method": routed.method,
                    "headers": {header: routed.value},
                    "header_name": header,
                    "payload": routed.value,
                    "status_code": routed.status_code,
                    "test_result": "Vulnerable",
                    "confidence": CONFIDENCE_CONFIRMED,
                    "analysis": (
                        f"'{header}' decides a host this response hands a "
                        f"browser: the marker came back as the host of an "
                        f"absolute URL ({', '.join(hosts)}) in {places}, and "
                        f"the same probe produced it again on a second "
                        f"request. Shape(s) reflected: {shapes}."
                    ),
                })
                return

        # Either nothing reached the host of a URL, or it did not hold the
        # second time. Both are reflection, which is worth reporting and is not
        # proof that the application routes on the header.
        first = routed or hits[0]
        self.record({
            "url": first.url,
            "method": first.method,
            "headers": {header: first.value},
            "header_name": header,
            "payload": first.value,
            "status_code": first.status_code,
            "severity": "Low",
            "confidence": CONFIDENCE_SUSPECTED,
            "analysis": (
                f"'{header}' is copied into the response: the marker came back "
                f"in {places}. It is not the host of any absolute URL there, "
                f"so the application echoes the header rather than "
                f"demonstrably routing, redirecting or building links on it. "
                f"Shape(s) reflected: {shapes}."
            ),
            "confirmation": SUSPECTED_NOTE,
        })
