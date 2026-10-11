"""Tests for report writing, argument parsing and session construction."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import headerhawk as hhs
from headerhawk.cli import run_check
from tests.helpers import FakeSession


class _StubTest:
    """A stand-in test object exposing the attributes ``save_results`` reads."""

    def __init__(self, target_url, vulns, all_results=None):
        self.target_url = target_url
        self.vulnerabilities_found = vulns
        self.all_results = all_results or []


def _finding():
    return {
        "test_type": "Host Header Injection",
        "test_result": "Potentially Vulnerable",
        "url": "http://t/",
        "method": "GET",
        "headers": {"Host": "evil"},
        "payload": "evil",
        "status_code": 200,
        "analysis": "reflected",
        "repro": "curl -s -i 'http://t/'",
    }


class SaveResultsTests(unittest.TestCase):
    def test_no_output_file_is_noop(self):
        # Should simply return without raising.
        self.assertIsNone(hhs.save_results(None, [], verbose=1))

    def test_json_output(self):
        tests = [_StubTest("http://t/", [_finding()])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.json")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                data = json.load(handle)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["payload"], "evil")

    def test_markdown_output(self):
        tests = [_StubTest("http://t/", [_finding()])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.md")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                content = handle.read()
        self.assertIn("# HeaderHawk Report", content)
        self.assertIn("**Total Findings:** 1", content)
        self.assertIn("reflected", content)

    def test_markdown_output_no_findings(self):
        tests = [_StubTest("http://t/", [])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.md")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                content = handle.read()
        self.assertIn("No vulnerabilities were found.", content)


class ParseArgumentsTests(unittest.TestCase):
    def test_defaults(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.url, "http://t/")
        self.assertEqual(args.threads, 5)
        self.assertEqual(args.verbose, 1)

    def test_thread_bounds_rejected(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--threads", "50"]):
            with self.assertRaises(SystemExit):
                hhs.parse_arguments()

    def test_repeatable_headers(self):
        with mock.patch("sys.argv",
                        ["prog", "http://t/", "-H", "A: 1", "-H", "B: 2"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.headers, ["A: 1", "B: 2"])

    def test_the_help_text_describes_both_sides_of_the_exchange(self):
        # --help is the first description most people read, and for a while it
        # advertised only the request side while half the checks assess the
        # response. A stale summary there quietly misdescribes the tool.
        with mock.patch("sys.argv", ["prog", "--help"]):
            with self.assertRaises(SystemExit):
                with mock.patch("sys.stdout", io.StringIO()) as out:
                    hhs.parse_arguments()
        text = out.getvalue().lower()
        for phrase in ("request headers", "response headers", "compliance"):
            self.assertIn(phrase, text, phrase)


class BuildSessionTests(unittest.TestCase):
    def test_sets_user_agent_and_timeout(self):
        session = hhs.build_session(timeout=7, threads=5, insecure=False,
                                    proxy=None, extra_headers=None)
        self.assertIn(hhs.__version__, session.headers["User-Agent"])
        self.assertEqual(session.request_timeout, 7)

    def test_extra_headers_and_proxy_applied(self):
        session = hhs.build_session(timeout=5, threads=5, insecure=True,
                                    proxy="http://127.0.0.1:8080",
                                    extra_headers={"X-Test": "1"})
        self.assertEqual(session.headers["X-Test"], "1")
        self.assertEqual(session.proxies["http"], "http://127.0.0.1:8080")
        self.assertFalse(session.verify)


class HostBypassConstructionTests(unittest.TestCase):
    def test_insecure_mirrors_session_verify(self):
        secure = hhs.HostBypassTest("https://example.com/p?q=1", "example.com",
                                    session=FakeSession(verify=True), timeout=3)
        self.assertEqual(secure.connect_port, 443)
        self.assertEqual(secure.path, "/p?q=1")
        self.assertTrue(secure.client.verify)

        insecure = hhs.HostBypassTest("http://example.com/", "example.com",
                                      session=FakeSession(verify=False), timeout=3)
        self.assertEqual(insecure.connect_port, 80)
        self.assertFalse(insecure.client.verify)

    MARKER = "MARKER.example-collab.com"

    # Shapes that exist only because a header mapping cannot express them: two
    # values for one field name, or a line that is not "name: value" at all.
    # These are the reason there is a raw client at all.
    RAW_ONLY = (
        "Duplicate Host header",
        "Duplicate Host header, injected first",
        "Indented (line-folded) Host header",
        "Tab-folded Host header",
        "Whitespace before the Host colon",
    )

    def _techniques(self):
        test = hhs.HostBypassTest("http://example.com/", "example.com",
                                  session=FakeSession(), timeout=3)
        return {name: (line, headers)
                for name, line, headers in test.techniques(self.MARKER)}

    def test_techniques_carry_marker(self):
        techniques = self._techniques()
        self.assertIn("Duplicate Host header", techniques)
        self.assertIn("Absolute-URI request line", techniques)
        # Every technique must reference the marker somewhere.
        for request_line, headers in techniques.values():
            self.assertTrue(self.MARKER in request_line
                            or any(self.MARKER in h for h in headers))

    def test_the_duplicate_pair_is_sent_both_ways_round(self):
        # Which of two Host headers wins is a choice each implementation
        # makes, so a front-end reading the first and a back-end reading the
        # last only disagree in one direction.
        techniques = self._techniques()
        first = techniques["Duplicate Host header"][1]
        reversed_pair = techniques["Duplicate Host header, injected first"][1]
        self.assertEqual(first[0], "Host: example.com")
        self.assertEqual(first[1], f"Host: {self.MARKER}")
        self.assertEqual(reversed_pair[0], f"Host: {self.MARKER}")
        self.assertEqual(reversed_pair[1], "Host: example.com")

    def test_the_two_folds_differ_in_the_byte_that_matters(self):
        # A middlebox that strips a leading space from a continuation line
        # does not always strip a tab.
        techniques = self._techniques()
        space = techniques["Indented (line-folded) Host header"][1][1]
        tab = techniques["Tab-folded Host header"][1][1]
        self.assertTrue(space.startswith(" Host:"), space)
        self.assertTrue(tab.startswith("	Host:"), repr(tab))

    def test_whitespace_before_the_colon_is_sent_literally(self):
        # RFC 7230 says a server must reject it; one that reads it as a header
        # anyway, behind one that rejected nothing, is the bug.
        headers = self._techniques()["Whitespace before the Host colon"][1]
        self.assertIn(f"Host : {self.MARKER}", headers)

    def test_the_real_host_still_rides_on_every_pair(self):
        # A bypass that drops the valid Host is not routable, so the shapes
        # that add a line keep the original as well.
        techniques = self._techniques()
        for name in self.RAW_ONLY:
            headers = techniques[name][1]
            self.assertTrue(any("example.com" in line and self.MARKER not in line
                                for line in headers), name)

    def test_every_added_shape_needs_the_raw_client(self):
        # If a shape could be expressed as a mapping of header names to
        # values, it would not belong here - it would belong in the ordinary
        # session with the rest of them.
        for name in self.RAW_ONLY:
            headers = self._techniques()[name][1]
            host_lines = [line for line in headers
                          if "host" in line.split(":", 1)[0].lower()]
            self.assertGreater(len(host_lines), 1, name)



class _ExplodingCheck(hhs.BaseTest):
    """A check that reports a finding and then fails unexpectedly."""

    test_type = "Exploding Check"

    def run(self):
        self.note_response()
        self.record({"url": "http://t/", "method": "GET", "payload": "",
                     "status_code": 200, "analysis": "found before the failure"})
        raise ValueError("/home/someone/private/secret-notes.txt could not be read")


class RunCheckTests(unittest.TestCase):
    """A check that raises must not take the rest of the scan with it.

    Every finding reported so far, both report files and the exit code all
    depend on the run reaching the end, so an unexpected failure is contained
    around one check and recorded as a control that was not assessed.
    """

    def _run(self, check):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            run_check(check)
        return out.getvalue()

    def _exploding(self):
        return _ExplodingCheck("http://t/", "t", session=FakeSession(),
                               verbose=0, quiet=True)

    def test_the_failure_is_contained_and_the_finding_is_kept(self):
        check = self._exploding()
        printed = self._run(check)
        self.assertEqual(len(check.vulnerabilities_found), 1)
        self.assertIn("Exploding Check", printed)

    def test_the_check_counts_as_not_assessed(self):
        check = self._exploding()
        self._run(check)
        self.assertFalse(check.assessed)
        self.assertIn("ValueError", check.skip_reason)

    def test_the_published_reason_carries_no_exception_message(self):
        # The reason reaches the evidence report, and an exception message can
        # carry a local path or a fragment of a response body. The operator
        # gets the full message on the console instead.
        check = self._exploding()
        printed = self._run(check)
        self.assertNotIn("/home/someone/private/secret-notes.txt", check.skip_reason)
        self.assertIn("/home/someone/private/secret-notes.txt", printed)

    def test_an_interrupt_still_stops_the_scan(self):
        class _Interrupted(hhs.BaseTest):
            test_type = "Interrupted"

            def run(self):
                raise KeyboardInterrupt

        check = _Interrupted("http://t/", "t", session=FakeSession(),
                             verbose=0, quiet=True)
        with self.assertRaises(KeyboardInterrupt):
            run_check(check)


class MainGuardTests(unittest.TestCase):
    """A crash must not exit with the code that means findings were found."""

    def _main(self, **patch):
        with mock.patch("headerhawk.cli.run_scan", **patch):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = hhs.main()
        return code, out.getvalue()

    def test_an_unexpected_failure_exits_as_an_error(self):
        code, printed = self._main(side_effect=RuntimeError("boom"))
        self.assertEqual(code, hhs.EXIT_ERROR)
        self.assertIn("RuntimeError", printed)
        self.assertNotIn("Traceback", printed)

    def test_an_interrupt_exits_as_an_error(self):
        code, _ = self._main(side_effect=KeyboardInterrupt)
        self.assertEqual(code, hhs.EXIT_ERROR)

    def test_a_completed_scan_keeps_its_own_exit_code(self):
        code, _ = self._main(return_value=hhs.EXIT_FINDINGS)
        self.assertEqual(code, hhs.EXIT_FINDINGS)

    def test_a_deliberate_exit_is_not_rewritten(self):
        # The argument-handling paths exit on purpose; the guard must not turn
        # one of those into something else.
        with mock.patch("headerhawk.cli.run_scan",
                        side_effect=SystemExit(hhs.EXIT_ERROR)):
            with self.assertRaises(SystemExit):
                hhs.main()


class RetryPolicyTests(unittest.TestCase):
    def _retry(self):
        session = hhs.build_session(timeout=5, threads=5, insecure=False,
                                    proxy=None, extra_headers=None)
        return session.get_adapter("https://example.com/").max_retries

    def test_a_response_status_is_never_retried(self):
        # A status-driven retry is issued inside urllib3, below the rate
        # limiter and below the request counter: it would multiply the traffic
        # a scan admits to sending, and its backoff lands inside the elapsed
        # time the timing-based checks read.
        retry = self._retry()
        self.assertEqual(retry.status, 0)
        self.assertFalse(retry.status_forcelist)
        self.assertEqual(retry.read, 0)

    def test_an_unclassified_transport_error_is_not_retried(self):
        # urllib3 files an error that is neither a connect nor a read error -
        # a TLS error, say - under "other", and its documentation warns the
        # error can arrive after the request was sent. Left unset, that counter
        # is never decremented and nothing ever goes negative, so one retry
        # stays allowed however the other counters are set.
        from urllib3.exceptions import MaxRetryError, SSLError

        self.assertEqual(self._retry().other, 0)
        with self.assertRaises(MaxRetryError):
            self._retry().increment(method="GET", url="/",
                                    error=SSLError("handshake failed"))

    def test_a_failed_connection_is_still_retried_once(self):
        self.assertEqual(self._retry().connect, 1)


if __name__ == "__main__":
    unittest.main()
