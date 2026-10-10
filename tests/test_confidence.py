"""Tests for the confidence a finding carries.

The scanner already distinguished what it had proved from what it had merely
observed - "Vulnerable" against "Potentially Vulnerable", the timing caveat on
a smuggling finding - but only in prose. As a field, the distinction has to
travel into every output and must not change which findings gate a build.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

import headerhawk as hhs
from headerhawk.compliance.evidence import build_evidence
from headerhawk.report.evidence import render_markdown
from tests.helpers import FakeResponse, FakeSession


class _StubTest:
    """The attributes the writers and the summary read off a check."""

    def __init__(self, vulns, test_type="SSRF", target_url="http://t/"):
        self.test_type = test_type
        self.target_url = target_url
        self.vulnerabilities_found = list(vulns)
        self.all_results = []


class _Check(_StubTest):
    """A check that has already run, for the evidence builder."""

    def __init__(self, vulns, test_type="SSRF", emits=("SSRF",)):
        super().__init__(vulns, test_type=test_type)
        self.assessed = True
        self.skip_reason = None
        self._emits = tuple(emits)

    def emitted_types(self):
        return self._emits


def _finding(**extra):
    entry = {
        "test_type": "SSRF",
        "test_result": "Potentially Vulnerable",
        "url": "http://t/",
        "method": "GET",
        "header_name": "Host",
        "payload": "169.254.169.254",
        "status_code": 200,
        "severity": "High",
        "analysis": "reached internal target",
        "controls": ["ASVS-5.0:13.2.4"],
        "repro": "curl ...",
    }
    entry.update(extra)
    return entry


class DerivationTests(unittest.TestCase):
    def test_a_proved_result_is_confirmed(self):
        self.assertEqual(
            hhs.confidence_for(hhs.CLASS_VULNERABILITY, "Vulnerable"),
            hhs.CONFIDENCE_CONFIRMED)

    def test_an_unproved_result_is_suspected(self):
        self.assertEqual(
            hhs.confidence_for(hhs.CLASS_VULNERABILITY, "Potentially Vulnerable"),
            hhs.CONFIDENCE_SUSPECTED)

    def test_a_posture_finding_is_confirmed(self):
        # It reports what the response did or did not carry, which is a direct
        # observation rather than an inference about the target's behaviour.
        self.assertEqual(hhs.confidence_for(hhs.CLASS_POSTURE, "Missing"),
                         hhs.CONFIDENCE_CONFIRMED)

    def test_an_entry_without_the_field_is_derived_not_assumed(self):
        # A baseline written by an earlier version has no field to read, and
        # grading it as proof would overstate it.
        old = {"test_result": "Potentially Vulnerable"}
        self.assertEqual(hhs.confidence_of(old), hhs.CONFIDENCE_SUSPECTED)

    def test_an_unknown_result_string_is_not_promoted(self):
        self.assertEqual(hhs.confidence_of({"test_result": "Something New"}),
                         hhs.CONFIDENCE_SUSPECTED)


class RecordTests(unittest.TestCase):
    def _record(self, entry):
        test = hhs.SSRFTest("http://t/", "t", session=FakeSession(), verbose=0)
        test.record(entry)
        return test.vulnerabilities_found[0]

    def test_record_derives_the_confidence(self):
        found = self._record({"url": "http://t/", "method": "GET",
                              "payload": "x", "status_code": 200,
                              "analysis": "a"})
        self.assertEqual(found["confidence"], hhs.CONFIDENCE_SUSPECTED)

    def test_record_respects_a_confidence_the_check_named(self):
        found = self._record({"url": "http://t/", "method": "GET",
                              "payload": "x", "status_code": 200,
                              "analysis": "a",
                              "confidence": hhs.CONFIDENCE_CONFIRMED})
        self.assertEqual(found["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_a_second_probe_check_reports_what_it_proved(self):
        # Virtual host discovery confirms on two probes and says so in its
        # analysis; the grade has to agree with the sentence.
        class Session(FakeSession):
            """Answers by the Host asked for, so probe order does not matter."""

            def request(self, method, url=None, headers=None, **kwargs):
                host = (headers or {}).get("Host", "")
                if "admin" in host:
                    return FakeResponse(status_code=200,
                                        text="<title>Admin</title> console")
                return FakeResponse(status_code=404, text="no such host")

        session = Session()
        test = hhs.VhostDiscoveryTest("http://example.com/", "example.com",
                                      session=session, verbose=0, quiet=True,
                                      wordlist=["admin"])
        test.run()
        self.assertTrue(test.vulnerabilities_found)
        self.assertEqual(test.vulnerabilities_found[0]["confidence"],
                         hhs.CONFIDENCE_CONFIRMED)

    def test_a_posture_check_reports_a_direct_observation(self):
        session = FakeSession(responses=[FakeResponse(
            status_code=200, headers={"Content-Type": "text/html"},
            url="https://t/", text="<html></html>")])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t",
                                             session=session, verbose=0,
                                             quiet=True)
        test.run()
        self.assertTrue(test.vulnerabilities_found)
        for finding in test.vulnerabilities_found:
            self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED,
                             finding["test_type"])


class GatingTests(unittest.TestCase):
    """The field must not move the gate on its own."""

    def test_a_suspected_vulnerability_still_gates(self):
        tests = [_StubTest([_finding()])]
        self.assertEqual(hhs.gated_finding_count(tests, "vuln"), 1)

    def test_an_informational_finding_never_gates(self):
        tests = [_StubTest([_finding(confidence=hhs.CONFIDENCE_INFORMATIONAL)])]
        self.assertEqual(hhs.gated_finding_count(tests, "vuln"), 0)
        self.assertEqual(hhs.gated_finding_count(tests, "any"), 0)

    def test_counts_are_tallied_per_grade(self):
        tests = [_StubTest([
            _finding(),
            _finding(test_result="Vulnerable"),
            _finding(confidence=hhs.CONFIDENCE_INFORMATIONAL),
        ])]
        counts = hhs.count_by_confidence(tests)
        self.assertEqual(counts[hhs.CONFIDENCE_SUSPECTED], 1)
        self.assertEqual(counts[hhs.CONFIDENCE_CONFIRMED], 1)
        self.assertEqual(counts[hhs.CONFIDENCE_INFORMATIONAL], 1)


class OutputTests(unittest.TestCase):
    """Every format an operator or an assessor reads carries the grade."""

    def _write(self, extension, tests):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f"out.{extension}")
            with contextlib.redirect_stdout(io.StringIO()):
                hhs.save_results(path, tests, verbose=1)
            with io.open(path, encoding="utf-8") as handle:
                return handle.read()

    def test_sarif_carries_it_as_a_property(self):
        sarif = hhs.build_sarif([_finding(test_result="Vulnerable")])
        properties = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(properties["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_the_markdown_report_states_it(self):
        content = self._write("md", [_StubTest([_finding()])])
        self.assertIn("**Confidence:** suspected", content)

    def test_the_json_report_carries_the_field(self):
        data = json.loads(self._write("json", [_StubTest([_finding()])]))
        self.assertEqual(data[0]["confidence"], hhs.CONFIDENCE_SUSPECTED)

    def test_the_evidence_report_states_it_beside_the_severity(self):
        checks = [_Check([_finding()])]
        rendered = render_markdown(build_evidence(checks, ["http://t/"]))
        self.assertIn("**[High, suspected] SSRF**", rendered)

    def test_the_summary_tallies_the_grades(self):
        stats = hhs.RequestStats()
        stats.record(True)
        tests = [_StubTest([_finding(), _finding(test_result="Vulnerable")])]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            hhs.print_summary(tests, ["http://t/"], stats)
        self.assertIn("Evidence: 1 confirmed, 1 suspected", buffer.getvalue())

    def test_an_out_of_band_interaction_is_confirmed(self):
        manager = hhs.OOBManager("oob.example.com", poll_url="http://l/export")
        host = manager.host("ssrf")

        class Session:
            def get(self, url, timeout=None):
                return FakeResponse(text=f"hit from {host}")

        owner = _StubTest([])
        with contextlib.redirect_stdout(io.StringIO()):
            hhs.confirm_oob_interactions(manager, Session(), 1, [owner])
        self.assertEqual(owner.vulnerabilities_found[0]["confidence"],
                         hhs.CONFIDENCE_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
