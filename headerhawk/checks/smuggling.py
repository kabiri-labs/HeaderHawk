"""Timing-based detection of HTTP request smuggling (front-end/back-end desync).

When a front-end and a back-end disagree about where one request ends and the
next begins, the leftover bytes prepend to whoever uses that connection next.
The disagreement is always between two request header fields - Content-Length
and Transfer-Encoding - which is what puts this in a header scanner.

Detection is by timing, and timing alone. A probe is crafted so that the server
that loses the disagreement is left waiting for a body that will never arrive;
if the target hangs where an equivalent well-formed request returns promptly,
the two ends disagree. Nothing is smuggled and no second request is planted, so
a scan does not tamper with anyone else's traffic.

That restraint costs certainty, and every finding says so: a delay is strong
evidence, not proof. ``--enable-desync`` trades the restraint for proof, and is
off by default because the confirmation genuinely can disrupt other users.
"""

import statistics
from urllib.parse import urlparse

from colorama import Fore, Style

from ..core.markers import new_token
from ..core.output import status
from ..core.request_file import header_lines
from ..net.raw import RawHTTPClient
from ..core.scope import SCOPE_HOST
from .base import BaseTest

# Sent with every finding. The scanner should be honest about what a timing
# signal is worth and about what the stronger test costs.
TIMING_CAVEAT = (
    "This is timing evidence, not proof. A slow upstream, a rate limiter, a "
    "connection-pool stall or an overloaded back-end can produce the same delay, "
    "and a target behind a single server with no front-end cannot desync at all. "
    "To confirm, re-run this scan with --enable-desync: it plants a smuggled "
    "prefix and then issues a normal request to see whether the second one comes "
    "back affected, which distinguishes a real desync from a slow server. Be "
    "aware of what that costs - the smuggled prefix sits on the back-end "
    "connection and can attach itself to another user's request, so it can "
    "corrupt or misroute live traffic. Run it only against a system you are "
    "authorised to disrupt, and preferably outside peak hours."
)

CONFIRMED_NOTE = (
    "Confirmed by differential probe: after the smuggled prefix was planted, a "
    "following normal request came back affected by it. This is a genuine "
    "desync, not a slow server."
)


class RequestSmugglingTest(BaseTest):
    """Probe for a Content-Length / Transfer-Encoding parsing disagreement."""

    test_type = "HTTP Request Smuggling"
    # Host-level: the weakness belongs to the front-end, not to a route.
    scope = SCOPE_HOST

    CL_TE = "HTTP Request Smuggling (CL.TE)"
    TE_CL = "HTTP Request Smuggling (TE.CL)"

    # Baseline samples, and how much slower than baseline counts as a hang.
    BASELINE_SAMPLES = 3
    DELAY_FACTOR = 4
    MIN_DELAY_MARGIN = 4.0

    @classmethod
    def emitted_types(cls):
        return (cls.CL_TE, cls.TE_CL)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        parsed = urlparse(self.target_url)
        self.scheme = (parsed.scheme or "http").lower()
        self.connect_host = parsed.hostname
        self.connect_port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"
        self.baseline = None
        self.threshold = None
        self.client = RawHTTPClient(timeout=self.timeout,
                                    verify=not self._insecure(),
                                    proxy=self._proxy(),
                                    rate_limiter=self.rate_limiter)

    def _insecure(self):
        return getattr(self.session, "verify", True) is False

    def _proxy(self):
        proxies = getattr(self.session, "proxies", None) or {}
        return proxies.get("https") or proxies.get("http")

    # -- request construction ------------------------------------------------

    def _headers(self, extra):
        """The header block, from the saved request when there was one.

        Content-Length and Transfer-Encoding are always the probe's own: they
        are the disagreement being tested, so a value from the file would
        describe a different message.
        """
        if self.request_spec is not None:
            base = [line for line in header_lines(self.request_spec,
                                                  self.connect_host)
                    if not line.lower().startswith(("content-length:",
                                                    "transfer-encoding:"))]
            return base + extra
        return [f"Host: {self.connect_host}",
                "Content-Type: application/x-www-form-urlencoded",
                "Connection: close"] + extra

    def _request(self, header_lines, body):
        head = "\r\n".join([f"POST {self.path} HTTP/1.1"] + header_lines)
        return f"{head}\r\n\r\n{body}"

    def _well_formed(self):
        body = "x=1"
        return self._request(self._headers([f"Content-Length: {len(body)}"]), body)

    def _cl_te_probe(self):
        """Front-end reads Content-Length, back-end reads Transfer-Encoding.

        Content-Length covers only "1\\r\\nA", so a back-end parsing chunked
        receives one chunk and then waits for a terminating chunk that the
        front-end never forwards.
        """
        return self._request(
            self._headers(["Content-Length: 4", "Transfer-Encoding: chunked"]),
            "1\r\nA\r\nX")

    def _te_cl_probe(self):
        """Front-end reads Transfer-Encoding, back-end reads Content-Length.

        The front-end forwards up to the terminating chunk - five bytes - while
        a back-end parsing Content-Length waits for the sixth that never comes.
        """
        return self._request(
            self._headers(["Content-Length: 6", "Transfer-Encoding: chunked"]),
            "0\r\n\r\nX")

    # -- probing -------------------------------------------------------------

    def _send(self, request, read_timeout=None):
        return self.client.send_raw(self.scheme, self.connect_host,
                                    self.connect_port, request,
                                    sni_host=self.connect_host,
                                    read_timeout=read_timeout)

    def measure_baseline(self):
        """Time a well-formed request, so a slow site is not read as a hang."""
        samples = []
        for _ in range(self.BASELINE_SAMPLES):
            timed = self._send(self._well_formed())
            if timed.response is not None and not timed.timed_out:
                samples.append(timed.elapsed)
                self.note_response()
        if not samples:
            return False
        self.baseline = statistics.median(samples)
        self.threshold = max(self.baseline * self.DELAY_FACTOR,
                             self.baseline + self.MIN_DELAY_MARGIN)
        status(f"Desync baseline: {self.baseline:.2f}s "
               f"(delay threshold {self.threshold:.2f}s)")
        return True

    def _is_delayed(self, timed):
        return timed.timed_out or timed.elapsed >= self.threshold

    def _probe_twice(self, request):
        """Confirm a delay on a second probe, then re-check the baseline.

        One slow response proves nothing - the site may simply have hiccuped.
        Re-measuring afterwards separates "this probe hangs" from "the target
        got slow while we were testing", which is the dominant false positive.
        """
        first = self._send(request, read_timeout=self.threshold + 1.0)
        if not self._is_delayed(first):
            return False, first.elapsed
        second = self._send(request, read_timeout=self.threshold + 1.0)
        if not self._is_delayed(second):
            return False, second.elapsed
        control = self._send(self._well_formed())
        if control.response is None or self._is_delayed(control):
            return False, second.elapsed
        return True, second.elapsed

    # -- confirmation --------------------------------------------------------

    def _confirm_by_desync(self):
        """Plant a smuggled prefix, then see whether the next request is affected.

        Only reached with --enable-desync. The prefix is deliberately left on
        the back-end connection, which is exactly why this is opt-in.
        """
        marker = new_token()
        smuggled = (f"GET /{marker} HTTP/1.1\r\n"
                    f"X-Ignore: X")
        body = f"0\r\n\r\n{smuggled}"
        attack = self._request(
            self._headers([f"Content-Length: {len(body)}",
                           "Transfer-Encoding: chunked"]),
            body)
        self._send(attack, read_timeout=self.threshold + 1.0)

        follow_up = self._send(self._well_formed())
        if follow_up.response is None:
            return False
        baseline_status = self._send(self._well_formed()).response
        if baseline_status is None:
            return False
        # The follow-up was prefixed by the smuggled bytes, so it asks for a
        # path that does not exist and comes back differently from a clean one.
        return follow_up.response.status_code != baseline_status.status_code

    # -- reporting -----------------------------------------------------------

    def _record_desync(self, test_type, variant, request, elapsed, confirmed):
        analysis = (
            f"A {variant} probe left the target holding the connection for "
            f"{elapsed:.2f}s against a {self.baseline:.2f}s baseline, on two "
            f"consecutive probes, while a well-formed request in between "
            f"returned normally. That is the signature of the front-end and "
            f"back-end disagreeing about where the request body ends."
        )
        self.record({
            "test_type": test_type,
            "test_result": "Vulnerable" if confirmed else "Potentially Vulnerable",
            "severity": "High",
            "url": self.target_url,
            "method": "POST",
            "header_name": "Content-Length / Transfer-Encoding",
            "payload": variant,
            "status_code": "no response",
            "response_time": elapsed,
            "analysis": analysis,
            "confirmation": CONFIRMED_NOTE if confirmed else TIMING_CAVEAT,
            "raw_request": request,
        })

    # -- entry point ---------------------------------------------------------

    def run(self):
        if not self.connect_host:
            self.skip("the target URL has no hostname to connect to")
            return
        if not self.quiet and self.enable_desync:
            print(Fore.YELLOW + Style.BRIGHT +
                  "\n[!] --enable-desync is on: a confirmed desync will be "
                  "proven by planting a smuggled prefix on the target's "
                  "back-end connection, which can affect other users of that "
                  "connection.")
        if not self.measure_baseline():
            status("Desync baseline could not be measured; skipping.")
            self.skip("a timing baseline could not be measured, so a delay "
                      "would have had nothing to be compared against")
            return

        # CL.TE is probed first on purpose. On a target that is CL.TE-vulnerable,
        # the TE.CL probe leaves the front-end holding a partial request and can
        # disrupt other users, so it is only reached when CL.TE comes back clean.
        delayed, elapsed = self._probe_twice(self._cl_te_probe())
        if delayed:
            confirmed = self.enable_desync and self._confirm_by_desync()
            self._record_desync(self.CL_TE, "CL.TE", self._cl_te_probe(),
                                elapsed, confirmed)
            return

        delayed, elapsed = self._probe_twice(self._te_cl_probe())
        if delayed:
            confirmed = self.enable_desync and self._confirm_by_desync()
            self._record_desync(self.TE_CL, "TE.CL", self._te_cl_probe(),
                                elapsed, confirmed)
