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

Two things decide whether this search can see anything at all.

**What is sent.** A candidate carries a value of the shape it really holds - a
scheme header gets a scheme, a port header gets a port - because a hostname in
a header that means something else is ignored or rejected, and the header then
reads as "changes nothing" for a reason that has nothing to do with the
application. See ``candidates``.

**What counts as a change.** A cache gadget changes a URL in the page, a Link
header, a hidden form action. It does not change the page's weight, so a
comparison that waits for the body length to move misses the whole class. What
is compared is a canonical artefact: the body with the page's own noise taken
out, its status, and the response headers a cache or a browser acts on. The
length tolerance is still there for a page that will not reproduce itself, when
nothing more precise is possible.
"""

import hashlib
import re
from urllib.parse import parse_qs, urlencode, urlparse

from ..core.markers import fold_tokens, new_token
from ..core.scope import SCOPE_ENDPOINT
from .base import BaseTest
from .candidates import candidate_value
from .wordlists import CACHE_STATUS_HEADERS, INTERMEDIARY_HEADERS

# Statuses that mean "that request was too big or too odd", not "that header
# changed something". Treating a rejected batch as a signal would send the
# bisection chasing a header that did nothing.
REJECTION_STATUSES = {400, 413, 414, 431, 494, 502}

# Response headers a cache or a browser acts on, so a change in one of them is
# a change in what the response *is* rather than in how it reads.
CANONICAL_HEADERS = ("Location", "Content-Type", "Content-Language", "Link",
                     "Refresh", "Vary")

# Long-ish runs are where a page's own noise lives: nonces, CSRF tokens,
# request ids, build hashes. Ordinary words are left alone, so masking them
# cannot hide the small change this check exists to find - "example" in a
# hostname survives, "nonce00000004" does not.
_TOKENISH = re.compile(r"[A-Za-z0-9_+/=-]{6,}")

# How long a run has to be, while mixing letters and digits, before it reads as
# generated rather than written. The baseline can only show which values a page
# used while it was being sampled, never which one it will use on the next
# request, so the shape has to be masked and not just the values seen.
_GENERATED_LENGTH = 10

# The one cookie attribute worth comparing: a gadget that widens it hands the
# cookie to every subdomain. The value itself is a session id and never stable.
_COOKIE_DOMAIN = re.compile(r"domain\s*=\s*([^;,\s]+)", re.I)

# A cache saying it answered from its store.
_CACHE_HIT = re.compile(r"\bhit\b", re.I)


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
        # The artefact every baseline sample agreed on, or None when they did
        # not agree - which is the only honest answer for a page that will not
        # reproduce itself, and the reason the length tolerance is still here.
        self.baseline_artefact = None
        self._volatile = frozenset()

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
        """Sample the target repeatedly to learn how it behaves on its own.

        Without this, any page carrying a timestamp or a nonce reports every
        candidate header as significant. Returns False when the search cannot
        go ahead, having already said why.
        """
        samples = []
        for _ in range(self.BASELINE_SAMPLES):
            response = self.request("GET", url=self._busted_url(),
                                    allow_redirects=False)
            if response is None:
                continue
            samples.append(response)
            self.baseline_statuses.add(response.status_code)
            self.baseline_lengths.append(len(response.content or b""))
        if not samples:
            return False

        spread = max(self.baseline_lengths) - min(self.baseline_lengths)
        # Tolerate the variance the page shows by itself, doubled, and never
        # less than a fixed floor.
        self.length_tolerance = max(self.MIN_LENGTH_DELTA, spread * 2)

        served_from_cache = self._served_from_cache(samples)
        if served_from_cache:
            name, value = served_from_cache
            self.skip(
                f"a cache answered a URL this scan had just invented "
                f"('{name}: {value}'), so the query string is not part of its "
                f"key: a cache-buster cannot tell one probe from another here, "
                f"every candidate would read as changing nothing, and a clean "
                f"result would mean only that the search was blind")
            return False

        self._volatile = self._learn_volatile([s.text or "" for s in samples])
        artefacts = {self._artefact(sample) for sample in samples}
        self.baseline_artefact = artefacts.pop() if len(artefacts) == 1 else None
        return True

    def _served_from_cache(self, samples):
        """A cache header saying one of these came from a store, or None.

        Each baseline probe carries a cache-buster no one has asked for before,
        so every one of them must be a miss. A hit means the query is not in
        the key, and the whole search is about to be answered by the cache with
        one stored response.
        """
        for response in samples:
            for name in CACHE_STATUS_HEADERS:
                value = str(response.headers.get(name, "") or "").strip()
                if not value:
                    continue
                if name.lower() == "age":
                    if value.isdigit() and int(value) > 0:
                        return name, value
                elif _CACHE_HIT.search(value):
                    return name, value
        return None

    @staticmethod
    def _learn_volatile(bodies):
        """Tokens that are not in every sample, so the page moves them itself."""
        seen = [set(_TOKENISH.findall(body)) for body in bodies]
        if not seen:
            return frozenset()
        return frozenset(set.union(*seen) - set.intersection(*seen))

    def _artefact(self, response):
        """A hash of what this response is, with the page's own noise removed.

        What a cache gadget changes is a URL in the page, a Link header, a form
        action - twenty bytes that a length comparison cannot see. What a page
        changes by itself is a nonce or a request id, which is what the learned
        volatile tokens and the marker folding take out.
        """
        parts = [str(response.status_code), self._mask(response.text or "")]
        for name in CANONICAL_HEADERS:
            parts.append(f"{name}={self._mask(response.headers.get(name, '') or '')}")
        domains = _COOKIE_DOMAIN.findall(
            str(response.headers.get("Set-Cookie", "") or ""))
        parts.append("cookie-domain=" + ",".join(sorted(set(domains))))
        return hashlib.sha1("|".join(parts).encode("utf-8", "ignore")).hexdigest()

    def _mask(self, text):
        """The text with the page's own noise taken out, and nothing else."""
        def replace(match):
            token = match.group(0)
            if token in self._volatile:
                # Seen to move between two identical requests.
                return ""
            if (len(token) >= _GENERATED_LENGTH
                    and any(char.isdigit() for char in token)
                    and any(char.isalpha() for char in token)):
                # Shaped like something generated, so the next request will
                # carry a different one whether or not the baseline saw it.
                return ""
            return token
        return _TOKENISH.sub(replace, fold_tokens(text))

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
        if self.baseline_artefact is not None:
            if self._artefact(response) != self.baseline_artefact:
                return True, ("the response changed in a way a cache key built "
                              "from the method, host, path and query does not "
                              "capture")
            return False, ""
        # The page would not reproduce itself across the baseline samples, so
        # only a difference larger than its own variance means anything.
        length = len(response.content or b"")
        low, high = min(self.baseline_lengths), max(self.baseline_lengths)
        if length < low - self.length_tolerance or length > high + self.length_tolerance:
            return True, (f"the body length moved to {length} bytes "
                          f"(baseline {low}-{high}; the page does not "
                          f"reproduce itself, so only a change this large "
                          f"means anything)")
        return False, ""

    # -- probing -------------------------------------------------------------

    def _values_for(self, names):
        """What to send in each of these headers."""
        return {name: candidate_value(name, self.marker) for name in names}

    def _send(self, names, url=None):
        return self.request("GET", url=url or self._busted_url(),
                            headers=self._values_for(names),
                            allow_redirects=False)

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

        There are two ways to see that the cache handed the poisoned copy to a
        request that never carried the header. The marker is the stronger one,
        where the header's value can hold it: a value minted for this scan
        cannot have come from anywhere else.

        Where it cannot - a scheme, a port, an address - what is compared is
        the artefact. The clean request has to come back as the poisoned
        response rather than as the baseline. That needs a page that reproduces
        itself, and it is what lets those headers be confirmed at all; before
        it, a header with no room for a marker could never be more than
        suspected.
        """
        # One buster shared by both requests: the point is to ask whether
        # the cache hands the poisoned copy to a request that never sent
        # the header, which only works when both ask for the same key.
        url = self._busted_url()
        poisoned = self._send([name], url=url)
        if poisoned is None:
            return None
        marked = self._reflects_marker(poisoned)
        artefact = self._artefact(poisoned)
        if not marked:
            if self.baseline_artefact is None or artefact == self.baseline_artefact:
                # Nothing was stored that differs from what a clean request
                # would have been given anyway.
                return None
        clean = self.request("GET", url=url, allow_redirects=False)
        if clean is None:
            return None
        if marked:
            if not self._reflects_marker(clean):
                return None
        elif self._artefact(clean) != artefact:
            return None
        cache_info = {header: clean.headers[header]
                      for header in CACHE_STATUS_HEADERS
                      if header in clean.headers}
        return url, clean, cache_info, marked

    # -- entry point ---------------------------------------------------------

    def run(self):
        if not self.learn_baseline():
            if not self.skipped:
                self.skip("the target did not answer the baseline requests, so "
                          "there was nothing to compare candidate headers "
                          "against")
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
        value = candidate_value(name, self.marker)
        confirmed = self.confirm_poisoning(name)
        if confirmed:
            url, clean, cache_info, marked = confirmed
            proof = ("the poisoned response was served to a request that never "
                     "carried the header" if marked else
                     "a request that never carried the header was answered "
                     "with the poisoned response rather than the baseline one")
            self.record({
                "test_type": self.POISONING,
                "test_result": "Vulnerable",
                "severity": "High",
                "url": url,
                "method": "GET",
                "headers": {name: value},
                "header_name": name,
                "payload": value,
                "status_code": clean.status_code,
                "analysis": (
                    f"'{name}' was found by search rather than from a fixed "
                    f"list, and is unkeyed: {proof}. Cache headers: "
                    f"{cache_info or 'n/a'}."
                ),
            })
            return
        self.record({
            "test_type": self.test_type,
            "test_result": "Potentially Vulnerable",
            "severity": "Medium",
            "url": self.target_url,
            "method": "GET",
            "headers": {name: value},
            "header_name": name,
            "payload": value,
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
