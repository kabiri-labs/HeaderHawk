"""Virtual host discovery through the Host header."""

import re
import statistics
import uuid

from colorama import Fore

from ..core.scope import SCOPE_HOST
from .base import BaseTest
from .wordlists import DEFAULT_VHOST_WORDLIST

class VhostDiscoveryTest(BaseTest):
    """Discover internal/hidden virtual hosts via the Host header.

    Establishes a baseline by requesting a host that cannot exist (the default
    virtual host), then sends each wordlist candidate as the Host header. A
    materially different status, body length or page title means a distinct
    virtual host is being served - a common route to internal applications.
    """

    test_type = "Virtual Host Discovery"
    # Host-level: the weakness belongs to the front-end, not to a route.
    scope = SCOPE_HOST

    @staticmethod
    def _title(text):
        match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
        return match.group(1).strip()[:80] if match else ""

    # How many times the non-existent (default vhost) baseline is sampled, and
    # the smallest body-length delta that is ever allowed to count as different.
    BASELINE_SAMPLES = 3
    MIN_LENGTH_DELTA = 256

    def _measure(self, host):
        """Return (status, body_length, title) for a Host header, or None."""
        response = self.request("GET", headers={"Host": host}, allow_redirects=False)
        if response is None:
            return None
        return response.status_code, len(response.content), self._title(response.text)

    def run(self):
        candidates = self.wordlist or DEFAULT_VHOST_WORDLIST
        bogus = f"{uuid.uuid4().hex[:16]}.invalid"
        samples = [m for m in (self._measure(bogus)
                               for _ in range(self.BASELINE_SAMPLES))
                   if m is not None]
        if not samples:
            print(Fore.YELLOW + "Vhost baseline failed; skipping discovery.")
            self.skip("the default virtual host did not answer, so there was "
                      "no baseline to compare candidates against")
            return
        lengths = [length for _, length, _ in samples]
        self.baseline_status = samples[0][0]
        self.baseline_len = statistics.mean(lengths)
        self.baseline_titles = {title for _, _, title in samples}
        # Tolerance absorbs the default vhost's own page-to-page variance, so
        # dynamic content (timestamps, tokens, ads) is not mistaken for a new
        # virtual host.
        observed_spread = max(lengths) - min(lengths)
        self.len_tolerance = max(self.MIN_LENGTH_DELTA, observed_spread * 2,
                                 0.25 * self.baseline_len)
        self.run_pool(self.worker, [(c,) for c in candidates], "Virtual Host Discovery")

    def candidate_hosts(self, candidate):
        return [
            candidate,
            f"{candidate}.{self.original_host}",
            f"{candidate}.internal",
        ]

    def _distinct_signal(self, first, second):
        """Explain why two probes agree a Host is a distinct vhost, else None.

        Requiring both probes to agree filters out responses that differ from
        the baseline only because the page itself changes between requests.
        """
        status1, len1, title1 = first
        status2, len2, title2 = second
        if status1 == status2 != self.baseline_status:
            return f"status {status1} (baseline {self.baseline_status})"
        if title1 and title1 == title2 and title1 not in self.baseline_titles:
            return f"title '{title1}'"
        # Body length consistently (both probes, and mutually consistent) outside
        # the baseline's natural variance.
        if (abs(len1 - self.baseline_len) > self.len_tolerance
                and abs(len2 - self.baseline_len) > self.len_tolerance
                and abs(len1 - len2) <= self.len_tolerance):
            return (f"body length ~{int((len1 + len2) / 2)}B vs baseline "
                    f"~{int(self.baseline_len)}B")
        return None

    def worker(self, candidate):
        for host in self.candidate_hosts(candidate):
            first = self._measure(host)
            if first is None:
                continue
            status_code, length, title = first
            # Cheap pre-filter: only pay for a confirming probe when the first
            # already looks different from the baseline.
            looks_different = (
                status_code != self.baseline_status
                or (title and title not in self.baseline_titles)
                or abs(length - self.baseline_len) > self.len_tolerance
            )
            if not looks_different:
                continue
            second = self._measure(host)
            if second is None:
                continue
            signal = self._distinct_signal(first, second)
            if signal:
                self.record({
                    # The difference survived a second probe, which is this
                    # check's own definition of proof, so the finding says so
                    # rather than leaving the default "potentially".
                    "test_result": "Vulnerable",
                    "url": self.target_url,
                    "method": "GET",
                    "header_name": "Host",
                    "payload": host,
                    "status_code": status_code,
                    "analysis": (
                        f"Distinct virtual host confirmed on two probes: {signal}. "
                        f"Default (unknown host) baseline was "
                        f"{self.baseline_status}/~{int(self.baseline_len)}B."
                    ),
                })
                return  # one hit per candidate is sufficient
