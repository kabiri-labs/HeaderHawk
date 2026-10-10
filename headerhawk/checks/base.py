"""Shared scaffolding every check builds on."""

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import Fore, Style
from tqdm import tqdm

from ..compliance import controls_for
from ..core.findings import DEFAULT_FINDING_CLASS, confidence_for
from ..core.request_file import redact_credentials
from ..core.scope import SCOPE_ENDPOINT
from ..core.severity import severity_for
from ..report.repro import build_reproduction


class BaseTest:
    """Shared scaffolding for every test type."""

    test_type = "Base"
    # Findings default to the vulnerability class; posture checks override it.
    finding_class = DEFAULT_FINDING_CLASS
    # Most weaknesses live on the endpoint: header posture, CORS policy and
    # access control all vary by route. A few live on the host instead - a
    # front-end that mis-parses Host, or that desyncs from its back-end, does so
    # for every route at once. Running those once per discovered endpoint would
    # repeat identical work and file identical findings, so discovery runs them
    # against the requested target only.
    scope = SCOPE_ENDPOINT

    @classmethod
    def emitted_types(cls):
        """Finding types this check can emit.

        Usually just its own, but a check that reports several distinct
        issues from one pass overrides this so the severity and compliance
        maps can be checked for completeness against it.
        """
        return (cls.test_type,)

    def __init__(self, target_url, original_host, session, oob_domain=None,
                 methods=None, threads=5, verbose=1, timeout=10,
                 oob_manager=None, wordlist=None, insecure=False,
                 stats=None, quiet=False, rate_limiter=None,
                 enable_desync=False, request_spec=None):
        self.target_url = target_url
        self.original_host = original_host
        self.session = session
        self.oob_domain = oob_domain
        self.oob_manager = oob_manager
        self.wordlist = wordlist
        self.insecure = insecure
        self.methods = methods or ["GET"]
        self.threads = threads
        self.verbose = verbose
        self.timeout = timeout
        self.stats = stats
        self.quiet = quiet
        self.rate_limiter = rate_limiter
        # Only the desync check acts on this; it is accepted here so the CLI
        # can hand every check the same options.
        self.enable_desync = enable_desync
        # The saved request a scan was driven from, when there was one.
        # Its headers already ride on the session; its body has to be
        # replayed here, or a POST endpoint is tested with an empty one.
        self.request_spec = request_spec
        self.vulnerabilities_found = []
        self.all_results = []
        # An evidence report must not claim a control passed when the check
        # never got far enough to judge it, so a check tracks whether it
        # actually obtained usable data.
        self._requests_ok = 0
        self._skip_reason = None

    def body_for(self, method):
        """The saved body, when this request is the one the file described.

        Replaying it on a different method would change what is being asked of
        the endpoint, so it is only sent on the method the file used.
        """
        spec = self.request_spec
        if spec is None or spec.body is None:
            return None
        return spec.body if method.upper() == spec.method else None

    def request(self, method, url=None, headers=None, allow_redirects=True):
        """Issue a single request, returning the response or None on failure."""
        if self.rate_limiter is not None:
            self.rate_limiter.acquire()
        try:
            response = self.session.request(
                method,
                url or self.target_url,
                headers=headers,
                data=self.body_for(method),
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
            if self.stats is not None:
                self.stats.record(True)
            self._requests_ok += 1
            return response
        except requests.RequestException as exc:
            if self.stats is not None:
                self.stats.record(
                    False, tls_error=isinstance(exc, requests.exceptions.SSLError))
            return None

    def note_response(self):
        """Record a successful exchange made outside ``request`` (raw sockets)."""
        self._requests_ok += 1

    def skip(self, reason):
        """Record that the check could not complete, and why.

        The reason is printed in the evidence report next to the controls that
        were consequently left unassessed.
        """
        self._skip_reason = reason

    @property
    def assessed(self):
        """True when the check got far enough to judge the controls it covers."""
        return self._skip_reason is None and self._requests_ok > 0

    @property
    def skip_reason(self):
        """Why the check did not assess anything, or None when it did."""
        if self._skip_reason:
            return self._skip_reason
        if self._requests_ok == 0:
            return "no request to the target succeeded"
        return None

    def run_pool(self, worker, test_cases, description):
        """Run worker over test_cases with a bounded thread pool and progress bar."""
        if not test_cases:
            return
        if not self.quiet:
            print(f"\nStarting {description}...")
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(worker, *case) for case in test_cases]
                with tqdm(total=len(futures), desc=description, unit="test",
                          disable=self.quiet) as pbar:
                    for future in as_completed(futures):
                        future.result()
                        pbar.update(1)
        except KeyboardInterrupt:
            print(Fore.YELLOW + f"\n[!] {description} interrupted by user.")
            raise

    def record(self, entry):
        """Store a confirmed/suspected finding and optionally print it."""
        entry.setdefault("test_type", self.test_type)
        entry.setdefault("test_result", "Potentially Vulnerable")
        entry.setdefault("severity", severity_for(entry["test_type"]))
        entry.setdefault("controls", list(controls_for(entry["test_type"])))
        entry.setdefault("finding_class", self.finding_class)
        # Derived from the result the check set, unless the check named a
        # confidence itself. A check that proves something past a second probe
        # says so by passing it.
        entry.setdefault("confidence",
                         confidence_for(entry["finding_class"],
                                        entry["test_result"]))
        if entry.get("raw_request"):
            # The wire request is stored as evidence and reaches every report
            # format. A credential is never part of the evidence, so it is
            # taken out here rather than in each writer.
            entry["raw_request"] = redact_credentials(entry["raw_request"])
        entry["repro"] = build_reproduction(entry, self.target_url,
                                            self.insecure, self.request_spec)
        self.vulnerabilities_found.append(entry)
        if self.verbose >= 1:
            self._print_finding(entry)

    def _print_finding(self, entry):
        print(Fore.RED + Style.BRIGHT +
              f"\n[!] {entry['test_type']} Finding! "
              f"[{entry.get('severity', '')}, {entry.get('confidence', '')}]")
        print(f"URL: {entry.get('url')}")
        print(f"Method: {entry.get('method')}")
        if entry.get("header_name"):
            print(f"Header: {entry['header_name']}")
        if entry.get("param_name"):
            print(f"Parameter: {entry['param_name']}")
        print(f"Payload: {entry.get('payload')}")
        print(f"Status Code: {entry.get('status_code')}")
        if entry.get("response_time") is not None:
            print(f"Response Time: {entry['response_time']:.2f}s")
        print(Fore.YELLOW + f"Analysis: {entry.get('analysis')}")
        if entry.get("confirmation"):
            print(Fore.CYAN + f"Confirming this: {entry['confirmation']}")
        if entry.get("repro"):
            print(Fore.GREEN + f"Reproduce: {entry['repro']}")
        print(Fore.RED + "-" * 80)

    def run(self):
        raise NotImplementedError
