"""SSRF reachable through host-routing request headers."""

import re
import statistics
import time

from colorama import Fore

from ..core.findings import CONFIDENCE_CONFIRMED, CONFIDENCE_SUSPECTED
from ..core.output import status
from ..core.scope import SCOPE_HOST
from .base import BaseTest

# What a finding says about itself when the evidence is a hint rather than
# content only an internal target could have returned. The same stance the
# smuggling check takes towards a timing hit: report it, and say what it is.
WEAK_EVIDENCE_NOTE = (
    "This rests on indirect evidence - an internal error string, a response "
    "that changed, a reply that took longer - not on content only an internal "
    "target would return. A slow response alone is never reported here, "
    "because a slow target is the likelier explanation. To settle it, re-run "
    "with --oob <your-domain> --oob-poll-url <export-url>: an interaction "
    "arriving at your own listener is proof that the request left the target."
)


class SSRFTest(BaseTest):
    """Time- and content-based SSRF detection via host routing headers."""

    test_type = "SSRF"
    # Host-level: the weakness belongs to the front-end, not to a route.
    scope = SCOPE_HOST

    # Headers that legitimately vary between two identical requests and must
    # never be treated as an SSRF signal. Stored lower-cased for case-insensitive
    # matching. Beyond this curated list, volatile headers are also learned
    # empirically from the baseline samples (see compute_baseline).
    EXCLUDED_HEADERS = frozenset(h.lower() for h in {
        "Date", "Server", "Content-Length", "Connection", "Vary",
        "Content-Type", "Set-Cookie", "Age", "Expires", "Last-Modified", "ETag",
        # Per-request identifiers / tracing / cache metadata emitted by common
        # CDNs, proxies and frameworks - always different, never SSRF evidence.
        "X-Request-Id", "X-Request-ID", "X-Correlation-Id", "X-Trace-Id",
        "X-Amz-Cf-Id", "X-Amz-Request-Id", "X-Amz-Id-2", "CF-RAY",
        "X-Served-By", "X-Timer", "X-Cache", "X-Cache-Hits", "X-Runtime",
        "Report-To", "NEL", "Keep-Alive", "X-Powered-By-Nonce", "CF-Cache-Status",
    })
    # An indicator at or above this weight is content only an internal target
    # would have returned, which is what makes a finding proof rather than a
    # hint. Everything below it - a connection error string, a changed header,
    # a slower reply - is a hint, and hints are reported as suspected however
    # many of them line up.
    PROOF_WEIGHT = 4

    # Indicators that strongly suggest the request reached an internal target.
    INDICATORS = {
        "root:x:0:0:": 5,
        "ami-id": 4,
        "instance-id": 4,
        "iam/security-credentials": 5,
        "computemetadata": 4,
        "could not resolve host": 2,
        "connection refused": 2,
        "no route to host": 3,
        "<title>phpmyadmin</title>": 4,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.typical_delay = None
        self.baseline_headers = {}
        # Headers proven stable across the baseline samples (name -> value) and
        # the set of header names that varied between otherwise identical
        # requests. Only changes to *stable* headers count as an anomaly.
        self.stable_baseline_headers = {}
        self.volatile_headers = set()
        self.results = []

    def compute_baseline(self, samples=6):
        """Measure a stable baseline latency and learn which headers are stable.

        Collects headers from every successful baseline sample so that headers
        which differ between identical requests (request ids, tracing, nonces)
        can be classified as volatile and excluded from anomaly detection - the
        dominant source of false-positive SSRF findings.
        """
        status("\nComputing baseline latency...")
        delays = []
        header_samples = []
        for i in range(samples):
            start = time.time()
            response = self.request("GET")
            if response is None:
                status(f"Request {i + 1} failed.")
                continue
            elapsed = time.time() - start
            header_samples.append(dict(response.headers))
            if i > 0:  # first sample is a warm-up, excluded from latency stats
                delays.append(elapsed)
        self._learn_header_stability(header_samples)
        if delays:
            delays.sort()
            trimmed = delays[1:-1] if len(delays) > 2 else delays
            self.typical_delay = statistics.mean(trimmed)
            status(f"Baseline latency: {self.typical_delay:.2f}s")
        else:
            self.typical_delay = 1.0
            status("Could not measure latency; defaulting to 1.00s.")

    def _learn_header_stability(self, header_samples):
        """Partition baseline headers into stable (constant) and volatile."""
        self.stable_baseline_headers = {}
        self.volatile_headers = set()
        if not header_samples:
            self.baseline_headers = {}
            return
        self.baseline_headers = dict(header_samples[0])
        names = set()
        for sample in header_samples:
            names.update(sample.keys())
        for name in names:
            values = [sample.get(name) for sample in header_samples]
            present_in_all = all(value is not None for value in values)
            constant = len(set(values)) == 1
            if present_in_all and constant:
                self.stable_baseline_headers[name] = values[0]
            else:
                # Absent from some samples or changing value -> volatile.
                self.volatile_headers.add(name.lower())

    def generate_payloads(self):
        internal_hosts = [
            "localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254",
            "metadata.google.internal", "192.168.0.1", "192.168.1.1",
            "10.0.0.1", "172.17.0.1", "127.2.2.2",
        ]
        ports = [80, 443, 8080]
        payloads = list(internal_hosts)
        payloads += [f"{host}:{port}" for host in internal_hosts for port in ports]
        if self.oob_manager:
            payloads.append(self.oob_manager.host("ssrf"))
        elif self.oob_domain:
            payloads.append(self.oob_domain.strip("/"))
        return payloads

    def run(self):
        self.compute_baseline()
        payloads = self.generate_payloads()
        ssrf_headers = ["Host", "X-Forwarded-For", "X-Forwarded-Host",
                        "X-Real-IP", "Forwarded"]
        test_cases = [
            (method, header, payload)
            for method in self.methods
            for payload in payloads
            for header in ssrf_headers
        ]
        self.run_pool(self.worker, test_cases, "SSRF Testing")
        self.analyze()

    def worker(self, method, header_name, payload):
        start = time.time()
        response = self.request(method, headers={header_name: payload})
        if response is None:
            return
        elapsed = time.time() - start
        self.results.append({
            "url": response.url,
            "method": method,
            "header_name": header_name,
            "payload": payload,
            "status_code": response.status_code,
            "response_time": elapsed,
            "response_body": (response.text or "")[:2000],
            "response_headers": dict(response.headers),
        })

    def analyze(self):
        if not self.results:
            print(Fore.YELLOW + "No SSRF responses collected for analysis.")
            return

        times = [r["response_time"] for r in self.results]
        mean_time = statistics.mean(times)
        stdev_time = statistics.stdev(times) if len(times) > 1 else 0
        # Only *slow* responses matter for time-based SSRF; fast ones are noise.
        upper_threshold = (mean_time + stdev_time * 3) if stdev_time else mean_time * 2

        patterns = {
            ind: re.compile(re.escape(ind)) for ind in self.INDICATORS
        }

        for result in self.results:
            score = 0
            notes = []

            if result["response_time"] > upper_threshold and result["response_time"] > (self.typical_delay or 0) * 2:
                # Deliberately below the recording threshold, and so is a
                # header anomaly: the two together must not add up to a
                # finding. A slow reply and a changed response id are what a
                # target under load looks like, and reporting that as SSRF at
                # High is the fastest way to teach an operator to ignore the
                # tool.
                score += 1
                notes.append(
                    f"Response time {result['response_time']:.2f}s exceeds "
                    f"threshold {upper_threshold:.2f}s."
                )

            body = result["response_body"].lower()
            strongest = 0
            for indicator, pattern in patterns.items():
                if pattern.search(body):
                    weight = self.INDICATORS[indicator]
                    score += weight
                    strongest = max(strongest, weight)
                    notes.append(f"Indicator '{indicator}' (weight {weight}).")

            anomalies = self.detect_header_anomalies(result["response_headers"])
            if anomalies:
                score += 1
                notes.append(f"Header anomalies: {anomalies}.")

            # Require a meaningful score so a lone weak signal does not fire.
            if score >= 3:
                proved = strongest >= self.PROOF_WEIGHT
                self.record({
                    "url": result["url"],
                    "method": result["method"],
                    "headers": {result["header_name"]: result["payload"]},
                    "header_name": result["header_name"],
                    "payload": result["payload"],
                    "status_code": result["status_code"],
                    "response_time": result["response_time"],
                    "analysis": " ".join(notes),
                    "test_result": ("Vulnerable" if proved
                                    else "Potentially Vulnerable"),
                    "confidence": (CONFIDENCE_CONFIRMED if proved
                                   else CONFIDENCE_SUSPECTED),
                    "confirmation": None if proved else WEAK_EVIDENCE_NOTE,
                })
            elif self.verbose == 2:
                self.all_results.append({
                    "test_type": self.test_type,
                    "url": result["url"],
                    "method": result["method"],
                    "header_name": result["header_name"],
                    "payload": result["payload"],
                    "status_code": result["status_code"],
                    "response_time": result["response_time"],
                    "analysis": "No significant anomalies detected.",
                    "test_result": "Not Vulnerable",
                })

    def detect_header_anomalies(self, response_headers):
        """Flag only meaningful header changes versus the *stable* baseline.

        Headers that are curated-dynamic or that were observed to vary across
        the baseline samples are ignored, so per-request identifiers no longer
        masquerade as SSRF evidence.
        """
        if not self.stable_baseline_headers:
            return []
        anomalies = []
        for header, value in response_headers.items():
            lowered = header.lower()
            if lowered in self.EXCLUDED_HEADERS or lowered in self.volatile_headers:
                continue
            if header in self.stable_baseline_headers:
                if value != self.stable_baseline_headers[header]:
                    anomalies.append(f"'{header}' changed")
            else:
                # A header absent from every baseline sample yet appearing now.
                anomalies.append(f"new header '{header}'")
        return anomalies
