"""Finding the request headers a cache does not key on but a back-end honours.

A cache key is built from the method, host, path and query. A header field that
changes the response without appearing in that key gets the changed response
filed under the *unchanged* key - and served to everyone who asks for it next.

The existing cache-poisoning check tries six well-known names. Real holes are
rarely in the six anyone would guess, so this searches instead: candidates are
sent in batches, and a batch that moves the response is bisected until the
header responsible is isolated. Roughly log2(n) requests per hit rather than n.

Only header fields an intermediary sets are candidates. That is where cache
holes actually live, and it is also what makes the finding mean something: the
requirement being verified is that a header set by a load balancer or proxy
cannot be overridden by the end user.
"""

from urllib.parse import parse_qs, urlencode, urlparse

from ..core.markers import new_token
from ..core.scope import SCOPE_ENDPOINT
from .base import BaseTest
from .wordlists import CACHE_STATUS_HEADERS, INTERMEDIARY_HEADERS

# Statuses that mean "that request was too big or too odd", not "that header
# changed something". Treating a rejected batch as a signal would send the
# bisection chasing a header that did nothing.
REJECTION_STATUSES = {400, 413, 414, 431, 494, 502}


class UnkeyedInputTest(BaseTest):
    """Search for header fields that change a response but not its cache key."""

    test_type = "Unkeyed Input"
    scope = SCOPE_ENDPOINT

    POISONING = "Web Cache Poisoning"

    # How many candidates ride on one request, how many times the baseline is
    # sampled, and how much the body may vary between identical requests before
    # a difference stops meaning anything.
    BATCH_SIZE = 20
    BASELINE_SAMPLES = 3
    MIN_LENGTH_DELTA = 128

    @classmethod
    def emitted_types(cls):
        return (cls.test_type, cls.POISONING)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = new_token()
        self.marker = f"{self.token}.example-collab.com"
        self.baseline_statuses = set()
        self.baseline_lengths = []
        self.length_tolerance = self.MIN_LENGTH_DELTA

    # -- baseline ------------------------------------------------------------

    def _busted_url(self, buster=None):
        """The target URL with a unique query parameter appended.

        Every discovery probe gets its own, because a cache in front of the
        target would otherwise answer them all with whatever the first request
        stored - which is exactly the clean response, hiding the very headers
        being searched for. Only the confirmation step reuses one buster on
        purpose, to ask whether a poisoned response really is served back.
        """
        parsed = urlparse(self.target_url)
        query = parse_qs(parsed.query)
        query["cb"] = buster or new_token(10)
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def learn_baseline(self):
        """Sample the target repeatedly to learn how much it varies on its own.

        Without this, any page carrying a timestamp or a nonce reports every
        candidate header as significant.
        """
        for _ in range(self.BASELINE_SAMPLES):
            response = self.request("GET", url=self._busted_url(),
                                    allow_redirects=False)
            if response is None:
                continue
            self.baseline_statuses.add(response.status_code)
            self.baseline_lengths.append(len(response.content or b""))
        if not self.baseline_lengths:
            return False
        spread = max(self.baseline_lengths) - min(self.baseline_lengths)
        # Tolerate the variance the page shows by itself, doubled, and never
        # less than a fixed floor.
        self.length_tolerance = max(self.MIN_LENGTH_DELTA, spread * 2)
        return True

    def _reflects_marker(self, response):
        if self.token in (response.text or ""):
            return True
        return any(self.token in str(value)
                   for value in dict(response.headers).values())

    def differs(self, response):
        """Whether a response is outside the baseline's own variance."""
        if self._reflects_marker(response):
            return True, "the marker was reflected in the response"
        if response.status_code not in self.baseline_statuses:
            return True, (f"the status changed to {response.status_code} "
                          f"(baseline {sorted(self.baseline_statuses)})")
        length = len(response.content or b"")
        low, high = min(self.baseline_lengths), max(self.baseline_lengths)
        if length < low - self.length_tolerance or length > high + self.length_tolerance:
            return True, (f"the body length moved to {length} bytes "
                          f"(baseline {low}-{high})")
        return False, ""

    # -- probing -------------------------------------------------------------

    def _send(self, names, url=None):
        headers = {name: self.marker for name in names}
        return self.request("GET", url=url or self._busted_url(),
                            headers=headers, allow_redirects=False)

    def _batch_rejected(self, response):
        return (response.status_code in REJECTION_STATUSES
                and response.status_code not in self.baseline_statuses)

    def affects(self, names):
        """Whether this set of headers moves the response. (moved, reason)."""
        response = self._send(names)
        if response is None:
            return False, ""
        if self._batch_rejected(response):
            # The request itself was refused; nothing can be concluded from it.
            return False, ""
        return self.differs(response)

    def isolate(self, names):
        """Bisect a batch down to the individual headers that move the response.

        Splitting rather than testing one at a time is what makes searching a
        long candidate list affordable: a batch that changes nothing is ruled
        out whole.
        """
        if not names:
            return []
        moved, reason = self.affects(names)
        if not moved:
            return []
        if len(names) == 1:
            # Confirm on a second probe before believing a single header, for
            # the same reason the baseline is sampled more than once.
            again, reason_again = self.affects(names)
            return [(names[0], reason_again or reason)] if again else []
        middle = len(names) // 2
        return (self.isolate(names[:middle]) + self.isolate(names[middle:]))

    # -- confirmation --------------------------------------------------------

    def confirm_poisoning(self, name):
        """Poison a cache-busted URL through the header, then ask for it clean.

        Only a marker that survives into a request that never carried the
        header proves the response was filed under a key the header is not
        part of.
        """
        # One buster shared by both requests: the point is to ask whether
        # the cache hands the poisoned copy to a request that never sent
        # the header, which only works when both ask for the same key.
        url = self._busted_url()
        poisoned = self._send([name], url=url)
        if poisoned is None or not self._reflects_marker(poisoned):
            return None
        clean = self.request("GET", url=url, allow_redirects=False)
        if clean is None or not self._reflects_marker(clean):
            return None
        cache_info = {header: clean.headers[header]
                      for header in CACHE_STATUS_HEADERS
                      if header in clean.headers}
        return url, clean, cache_info

    # -- entry point ---------------------------------------------------------

    def run(self):
        if not self.learn_baseline():
            self.skip("the target did not answer the baseline requests, so "
                      "there was nothing to compare candidate headers against")
            return

        candidates = list(INTERMEDIARY_HEADERS)
        batches = [candidates[i:i + self.BATCH_SIZE]
                   for i in range(0, len(candidates), self.BATCH_SIZE)]
        if not self.quiet:
            print(f"\nStarting Unkeyed Input Discovery "
                  f"({len(candidates)} candidates in {len(batches)} batches)...")

        for batch in batches:
            for name, reason in self.isolate(batch):
                self.report(name, reason)

    def report(self, name, reason):
        confirmed = self.confirm_poisoning(name)
        if confirmed:
            url, clean, cache_info = confirmed
            self.record({
                "test_type": self.POISONING,
                "test_result": "Vulnerable",
                "severity": "High",
                "url": url,
                "method": "GET",
                "headers": {name: self.marker},
                "header_name": name,
                "payload": self.marker,
                "status_code": clean.status_code,
                "analysis": (
                    f"'{name}' was found by search rather than from a fixed "
                    f"list, and is unkeyed: the poisoned response was served "
                    f"to a request that never carried the header. Cache "
                    f"headers: {cache_info or 'n/a'}."
                ),
            })
            return
        self.record({
            "test_type": self.test_type,
            "test_result": "Potentially Vulnerable",
            "severity": "Medium",
            "url": self.target_url,
            "method": "GET",
            "headers": {name: self.marker},
            "header_name": name,
            "payload": self.marker,
            "status_code": "n/a",
            "analysis": (
                f"'{name}' changes the response - {reason} - so the "
                f"application honours a header field an intermediary is meant "
                f"to own. No cache in front of this endpoint served the "
                f"changed response back, so poisoning is not demonstrated "
                f"here; a cache elsewhere in the path, or on another route, "
                f"could still key on the same URL and not on this header."
            ),
        })
