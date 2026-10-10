"""Tests for severity assignment, SARIF output and batch/list input."""

import json
import os
import tempfile
import types
import unittest
from unittest import mock

import headerhawk as hhs
from headerhawk.report import sarif as hh_sarif
from tests.helpers import FakeSession


class _StubTest:
    def __init__(self, target_url, vulns, all_results=None):
        self.target_url = target_url
        self.vulnerabilities_found = vulns
        self.all_results = all_results or []


def _finding(test_type="SSRF", **extra):
    entry = {
        "test_type": test_type,
        "test_result": "Potentially Vulnerable",
        "url": "http://t/",
        "method": "GET",
        "header_name": "Host",
        "payload": "169.254.169.254",
        "status_code": 200,
        "analysis": "reached internal target",
    }
    entry.update(extra)
    return entry


class SeverityTests(unittest.TestCase):
    def test_known_types_map(self):
        self.assertEqual(hhs.severity_for("SSRF"), "High")
        self.assertEqual(hhs.severity_for("Open Redirect"), "Medium")
        self.assertEqual(hhs.severity_for("Virtual Host Discovery"), "Low")

    def test_unknown_type_falls_back(self):
        self.assertEqual(hhs.severity_for("Something New"), hhs.DEFAULT_SEVERITY)

    def test_record_assigns_severity(self):
        test = hhs.SSRFTest("http://t/", "t", session=FakeSession(), verbose=0)
        test.record({"url": "http://t/", "method": "GET", "payload": "x",
                     "status_code": 200, "analysis": "a"})
        self.assertEqual(test.vulnerabilities_found[0]["severity"], "High")

    def test_record_respects_explicit_severity(self):
        test = hhs.SSRFTest("http://t/", "t", session=FakeSession(), verbose=0)
        test.record({"url": "http://t/", "method": "GET", "payload": "x",
                     "status_code": 200, "analysis": "a", "severity": "Critical"})
        self.assertEqual(test.vulnerabilities_found[0]["severity"], "Critical")


class RuleIdTests(unittest.TestCase):
    def test_slugifies(self):
        self.assertEqual(hh_sarif._rule_id("Host Header Injection"), "host-header-injection")
        self.assertEqual(hh_sarif._rule_id("Blind SSRF (OOB)"), "blind-ssrf-oob")

    def test_empty_falls_back(self):
        self.assertEqual(hh_sarif._rule_id("!!!"), "finding")


class BuildSarifTests(unittest.TestCase):
    def test_structure_and_levels(self):
        sarif = hhs.build_sarif([
            _finding("SSRF", severity="High"),
            _finding("Open Redirect", severity="Medium", url="http://t/r"),
        ], version="9.9.9")
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "HeaderHawk")
        self.assertEqual(run["tool"]["driver"]["version"], "9.9.9")

        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"ssrf", "open-redirect"})

        results = run["results"]
        self.assertEqual(len(results), 2)
        ssrf = next(r for r in results if r["ruleId"] == "ssrf")
        self.assertEqual(ssrf["level"], "error")
        self.assertEqual(ssrf["properties"]["security-severity"], "8.0")
        self.assertEqual(ssrf["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "http://t/")
        self.assertIn("hostHeaderScanner/v2", ssrf["partialFingerprints"])

    def test_missing_severity_defaults(self):
        sarif = hhs.build_sarif([_finding("Auth Bypass")])
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["severity"], "High")


class FingerprintStabilityTests(unittest.TestCase):
    """A fingerprint has to survive the marker that makes the finding proof.

    Several checks put a fresh random marker in every payload and a fresh
    cache-buster in the URL. Hashing those verbatim gave every finding a new
    fingerprint on every run, so a platform told to de-duplicate on it reopened
    the same alert instead - the opposite of what the field is for.
    """

    FINGERPRINT = "hostHeaderScanner/v2"

    def _print(self, finding):
        sarif = hhs.build_sarif([finding])
        return sarif["runs"][0]["results"][0]["partialFingerprints"][self.FINGERPRINT]

    def test_two_scans_of_one_defect_share_a_fingerprint(self):
        first = _finding("Host Header Injection",
                         url="http://t/?cb=4f1c9ab2e7",
                         payload="9c1d4ba7f3e2.example-collab.com")
        second = _finding("Host Header Injection",
                          url="http://t/?cb=0ab33e71cc",
                          payload="77d0c9e4a1bb.example-collab.com")
        self.assertEqual(self._print(first), self._print(second))

    def test_two_different_defects_do_not(self):
        one = _finding("Host Header Injection", header_name="X-Forwarded-Host")
        other = _finding("Host Header Injection", header_name="X-Original-Host")
        self.assertNotEqual(self._print(one), self._print(other))

    def test_a_meaningful_hex_payload_is_folded_too_which_is_the_trade(self):
        # The fold is by shape, so it cannot tell a generated marker from a
        # hexadecimal value that means something: two virtual hosts named in
        # hex file under one fingerprint. Pinned rather than left to be
        # discovered, because the alternative - narrowing the fold - would
        # change the identity --baseline matches on and make every finding a
        # team has already accepted look new. Both findings still appear in
        # full in every report; only the dashboard groups them.
        one = _finding("Virtual Host Discovery", header_name="Host",
                       payload="deadbeef")
        other = _finding("Virtual Host Discovery", header_name="Host",
                         payload="cafebabe")
        self.assertEqual(self._print(one), self._print(other))
        # A name that is not hexadecimal is unaffected, which is every entry
        # of the built-in wordlist.
        self.assertNotEqual(self._print(_finding("Virtual Host Discovery",
                                                 payload="admin")),
                            self._print(_finding("Virtual Host Discovery",
                                                 payload="staging")))

    def test_the_fingerprint_is_the_identity_the_baseline_matches_on(self):
        # One definition of "the same finding" for both features, so an alert
        # that --baseline calls unchanged is not a new alert on the dashboard.
        finding = _finding("Web Cache Poisoning", payload="abc123def456.oob")
        self.assertEqual(self._print(finding), hhs.finding_identity(finding))


class SaveResultsFormatTests(unittest.TestCase):
    def test_sarif_extension_written(self):
        tests = [_StubTest("http://t/", [_finding("SSRF")])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.sarif")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                data = json.load(handle)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 1)

    def test_json_includes_severity(self):
        tests = [_StubTest("http://t/", [_finding("SSRF")])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.json")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                data = json.load(handle)
        self.assertEqual(data[0]["severity"], "High")

    def test_markdown_shows_severity_and_multiple_targets(self):
        tests = [
            _StubTest("http://a/", [_finding("SSRF", url="http://a/")]),
            _StubTest("http://b/", [_finding("Open Redirect", url="http://b/")]),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.md")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                content = handle.read()
        self.assertIn("2 targets", content)
        self.assertIn("**Severity:** High", content)

    def test_empty_tests_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.json")
            hhs.save_results(path, [], verbose=1)
            self.assertFalse(os.path.exists(path))


class ListArgumentTests(unittest.TestCase):
    def test_list_flag_parsed(self):
        with mock.patch("sys.argv", ["prog", "--list", "targets.txt"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.list, "targets.txt")
        self.assertIsNone(args.url)

    def test_neither_url_nor_list_errors(self):
        with mock.patch("sys.argv", ["prog"]):
            with self.assertRaises(SystemExit):
                hhs.parse_arguments()

    def test_positional_url_still_works(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.url, "http://t/")
        self.assertIsNone(args.list)


class LoadTargetsTests(unittest.TestCase):
    def test_single_url(self):
        args = types.SimpleNamespace(url="http://t/", list=None)
        self.assertEqual(hhs.load_targets(args), ["http://t/"])

    def test_from_list_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("http://a/\n# comment\n\nhttp://b/\n")
            path = handle.name
        try:
            args = types.SimpleNamespace(url=None, list=path)
            self.assertEqual(hhs.load_targets(args), ["http://a/", "http://b/"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
