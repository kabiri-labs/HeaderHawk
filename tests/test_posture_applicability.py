"""Tests for assessing a response-header control only where it can act.

A JSON API reply carries no document for a browser to frame, no referrer to
withhold and no script to constrain. Reporting those controls as failed there
is noise; reporting them as passed there would be worse. They are reported as
not assessed, with the reason, which is the answer this product already gives
everywhere else it cannot judge something.

The second half covers the operator's threshold: response-header posture has a
long tail of controls that almost nothing sets, so the tail stays out of the
working view by default while the compliance report keeps every one of them.
"""

import contextlib
import io
import os
import tempfile
import unittest

import requests

import headerhawk as hhs
from headerhawk.compliance.evidence import (STATUS_FAIL, STATUS_NOT_ASSESSED,
                                            STATUS_PASS, build_evidence)
from headerhawk.report.evidence import render_markdown
from tests.helpers import FakeResponse, FakeSession

# Controls that only mean something for a document a browser renders.
CSP = "ASVS-5.0:3.4.3"
REFERRER = "ASVS-5.0:3.4.5"
FRAMING = "ASVS-5.0:3.4.6"
# Controls that apply to any response.
HSTS = "ASVS-5.0:3.4.1"
SNIFFING = "ASVS-5.0:3.4.4"


def _posture(headers, url="https://t/", status_code=200, **overrides):
    """Run the posture check against one response and return the check."""
    session = FakeSession(responses=[FakeResponse(
        status_code=status_code, headers=headers, url=url, text="<html></html>")])
    test = hhs.ResponseHeaderPostureTest(url, "t", session=session,
                                         verbose=0, quiet=True, **overrides)
    test.run()
    return test


def _types(test):
    return {finding["test_type"] for finding in test.vulnerabilities_found}


def _finding(test, test_type):
    return next(f for f in test.vulnerabilities_found
                if f["test_type"] == test_type)


def _status_of(evidence, control_id):
    return next(r.status for r in evidence["controls"]
                if r.control.id == control_id)


def _result_for(evidence, control_id):
    return next(r for r in evidence["controls"] if r.control.id == control_id)


class ApplicabilityTests(unittest.TestCase):
    JSON = {"Content-Type": "application/json; charset=utf-8"}

    def test_a_json_reply_is_not_failed_on_document_controls(self):
        reported = _types(_posture(self.JSON))
        for test_type in ("Content-Security-Policy", "CSP Script Sources",
                          "Frame Protection", "Referrer-Policy",
                          "Cross-Origin-Opener-Policy", "Permissions-Policy",
                          "CSP Violation Reporting"):
            self.assertNotIn(test_type, reported)

    def test_a_json_reply_is_still_assessed_where_a_control_applies(self):
        # Transport security and MIME sniffing act on every response, and a
        # version banner is exposed whatever the media type.
        reported = _types(_posture(self.JSON))
        self.assertIn("Strict-Transport-Security", reported)
        self.assertIn("X-Content-Type-Options", reported)

    def test_the_reason_names_what_the_response_actually_was(self):
        test = _posture(self.JSON)
        reason = test.unassessed["Frame Protection"]
        self.assertIn("application/json", reason)
        self.assertIn("not a document", reason)

    def test_an_html_reply_is_assessed_as_before(self):
        reported = _types(_posture({"Content-Type": "text/html"}))
        self.assertIn("Content-Security-Policy", reported)
        self.assertIn("Frame Protection", reported)

    def test_a_reply_with_no_media_type_is_assessed(self):
        # A browser may sniff one, which is the very case nosniff exists for,
        # so assessing it is the safe direction to be wrong in.
        self.assertIn("Content-Security-Policy", _types(_posture({})))

    def test_xhtml_counts_as_a_document(self):
        reported = _types(_posture({"Content-Type": "application/xhtml+xml"}))
        self.assertIn("Content-Security-Policy", reported)

    def test_an_svg_counts_as_a_document(self):
        # Navigated to rather than drawn by an <img>, an SVG is active:
        # script inside it runs, a CSP applies to it, and it can be framed.
        reported = _types(_posture({"Content-Type": "image/svg+xml"}))
        self.assertIn("Content-Security-Policy", reported)
        self.assertIn("Frame Protection", reported)

    def test_text_and_xml_do_not(self):
        # A text document has no links to send a referrer from and no script
        # for a policy to constrain; XML is what a great many APIs answer
        # with, and assessing them there is the noise this removes.
        for media_type in ("text/plain", "text/xml", "application/xml"):
            reported = _types(_posture({"Content-Type": media_type}))
            self.assertNotIn("Content-Security-Policy", reported, media_type)


class EvidenceGranularityTests(unittest.TestCase):
    """A control nobody looked at must never read as passing."""

    JSON = {"Content-Type": "application/json"}

    def test_a_json_only_scan_does_not_claim_the_document_controls_pass(self):
        evidence = build_evidence([_posture(self.JSON)], ["https://t/"])
        for control_id in (CSP, REFERRER, FRAMING):
            self.assertEqual(_status_of(evidence, control_id),
                             STATUS_NOT_ASSESSED, control_id)

    def test_the_report_says_why_it_could_not_judge_them(self):
        evidence = build_evidence([_posture(self.JSON)], ["https://t/"])
        reasons = " ".join(_result_for(evidence, CSP).not_assessed_because)
        self.assertIn("application/json", reasons)

    def test_the_controls_that_were_assessed_are_unaffected(self):
        # The same check assessed these on the same response, so the
        # granularity must not cost them their result.
        evidence = build_evidence([_posture(self.JSON)], ["https://t/"])
        self.assertEqual(_status_of(evidence, HSTS), STATUS_FAIL)
        self.assertEqual(_status_of(evidence, SNIFFING), STATUS_FAIL)

    def test_one_html_page_in_the_scan_is_enough_to_have_assessed_them(self):
        html = _posture({"Content-Type": "text/html",
                         "Content-Security-Policy":
                             "default-src 'none'; base-uri 'none'; "
                             "script-src 'self'; frame-ancestors 'none'; "
                             "report-to csp"},
                        url="https://t/page")
        api = _posture(self.JSON, url="https://t/api")
        evidence = build_evidence([html, api], ["https://t/"])
        self.assertEqual(_status_of(evidence, CSP), STATUS_PASS)

    def test_a_check_that_did_not_run_at_all_still_blocks_everything(self):
        session = FakeSession(
            responses=[requests.RequestException("boom")])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             verbose=0, quiet=True)
        test.run()
        evidence = build_evidence([test], ["https://t/"])
        self.assertEqual(_status_of(evidence, HSTS), STATUS_NOT_ASSESSED)
        self.assertEqual(_status_of(evidence, CSP), STATUS_NOT_ASSESSED)


class SeverityCalibrationTests(unittest.TestCase):
    """The band a posture finding carries has to match its real stakes.

    None of these stop being findings - the requirement is still unmet and the
    compliance report still says so. They stop being reported at a band that
    implies an operator should act today.
    """

    HTML = {"Content-Type": "text/html"}

    def test_a_missing_referrer_policy_is_informational(self):
        # Every browser still in support already withholds the path and query
        # from a cross-origin referrer.
        finding = _finding(_posture(self.HTML), "Referrer-Policy")
        self.assertEqual(finding["severity"], "Info")
        self.assertIn("strict-origin-when-cross-origin", finding["analysis"])

    def test_a_referrer_policy_that_does_leak_keeps_its_band(self):
        headers = dict(self.HTML, **{"Referrer-Policy": "unsafe-url"})
        self.assertEqual(_finding(_posture(headers), "Referrer-Policy")["severity"],
                         "Low")

    def test_a_missing_permissions_policy_is_informational(self):
        finding = _finding(_posture(self.HTML), "Permissions-Policy")
        self.assertEqual(finding["severity"], "Info")
        self.assertIn("no catalogued requirement", finding["analysis"])

    def test_framing_restricted_only_by_x_frame_options_is_informational(self):
        headers = dict(self.HTML, **{"X-Frame-Options": "DENY"})
        finding = _finding(_posture(headers), "Frame Protection")
        self.assertEqual(finding["severity"], "Info")
        self.assertIn("not", finding["analysis"])

    def test_no_framing_protection_at_all_keeps_its_band(self):
        self.assertEqual(_finding(_posture(self.HTML), "Frame Protection")["severity"],
                         "Medium")

    def test_the_requirement_still_fails_either_way(self):
        # The point of the recalibration is the band, not the status: an
        # assessor must still see 3.4.6 fail when frame-ancestors is absent.
        headers = dict(self.HTML, **{"X-Frame-Options": "SAMEORIGIN"})
        evidence = build_evidence([_posture(headers)], ["https://t/"])
        self.assertEqual(_status_of(evidence, FRAMING), STATUS_FAIL)


class ThresholdTests(unittest.TestCase):
    """What --min-severity hides, and what it must never hide."""

    @staticmethod
    def _posture_finding(severity):
        return {"test_type": "Referrer-Policy", "test_result": "Missing",
                "severity": severity, "finding_class": hhs.CLASS_POSTURE,
                "url": "https://t/", "method": "GET", "payload": "",
                "status_code": 200, "analysis": "absent", "repro": "",
                "controls": [REFERRER]}

    @staticmethod
    def _vulnerability(severity):
        return {"test_type": "Virtual Host Discovery",
                "test_result": "Vulnerable", "severity": severity,
                "finding_class": hhs.CLASS_VULNERABILITY, "url": "http://t/",
                "method": "GET", "payload": "admin", "status_code": 200,
                "analysis": "confirmed", "repro": "", "header_name": "Host",
                "controls": ["ASVS-5.0:13.4.5"]}

    class _Stub:
        def __init__(self, vulns, test_type="Response Header Posture"):
            self.test_type = test_type
            self.target_url = "https://t/"
            self.vulnerabilities_found = list(vulns)
            self.all_results = []

    def test_the_default_hides_a_low_posture_finding(self):
        self.assertFalse(hhs.reportable(self._posture_finding("Low")))
        self.assertFalse(hhs.reportable(self._posture_finding("Info")))
        self.assertTrue(hhs.reportable(self._posture_finding("Medium")))

    def test_a_proven_vulnerability_is_never_hidden(self):
        # Virtual host discovery is filed as Low and is a confirmed internal
        # hostname. An operator asking for less noise did not ask for that.
        self.assertTrue(hhs.reportable(self._vulnerability("Low")))

    def test_a_lower_threshold_shows_the_tail_again(self):
        self.assertTrue(hhs.reportable(self._posture_finding("Info"),
                                       min_severity="info"))

    def test_an_unknown_band_is_not_silently_hidden(self):
        self.assertTrue(hhs.reportable(self._posture_finding("Odd")))

    def test_what_is_not_shown_is_not_gated_either(self):
        # An exit code with nothing printed to explain it is worse than a
        # quiet report.
        tests = [self._Stub([self._posture_finding("Low")])]
        self.assertEqual(hhs.gated_finding_count(tests, "posture"), 0)
        self.assertEqual(
            hhs.gated_finding_count(tests, "posture", min_severity="low"), 1)

    def test_the_summary_says_how_many_it_is_not_showing(self):
        stats = hhs.RequestStats()
        stats.record(True)
        tests = [self._Stub([self._posture_finding("Low"),
                             self._posture_finding("Info")])]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            hhs.print_summary(tests, ["https://t/"], stats)
        self.assertIn("Not shown: 2 posture finding(s)", buffer.getvalue())

    def test_the_findings_report_leaves_them_out_and_says_so(self):
        tests = [self._Stub([self._posture_finding("Low"),
                             self._vulnerability("Low")])]
        content = self._write(tests, "md")
        self.assertIn("Virtual Host Discovery", content)
        self.assertNotIn("Referrer-Policy", content)
        self.assertIn("1 further posture finding(s)", content)

    def _write(self, tests, extension, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f"out.{extension}")
            with contextlib.redirect_stdout(io.StringIO()):
                hhs.save_results(path, tests, verbose=1, **kwargs)
            with io.open(path, encoding="utf-8") as handle:
                return handle.read()

    def test_the_json_record_keeps_what_the_markdown_view_drops(self):
        # JSON is the complete record and the file --baseline reads back;
        # Markdown is what a person reads.
        tests = [self._Stub([self._posture_finding("Info")])]
        self.assertIn("Referrer-Policy", self._write(tests, "json"))
        self.assertNotIn("Referrer-Policy", self._write(tests, "md"))

    def test_an_unchanged_target_is_not_reported_as_new(self):
        # The documented flow: write a baseline, then compare a later scan
        # against it. A baseline missing the findings the next scan still
        # collects reports every one of them as new, run after run, which is
        # the opposite of what the flag is for.
        tests = [self._Stub([self._posture_finding("Info"),
                             self._vulnerability("Low")])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            with contextlib.redirect_stdout(io.StringIO()):
                hhs.save_results(path, tests, verbose=1)
            stored = hhs.load_baseline(path)
        self.assertEqual(len(stored), 2)
        drift = hhs.compare(hhs.collect_findings(tests), stored)
        self.assertEqual(len(drift["new"]), 0)
        self.assertEqual(len(drift["unchanged"]), 2)

    def test_lowering_the_threshold_does_not_make_old_findings_new(self):
        # Asking to see more must not fail a build on findings that were
        # already there when the baseline was taken.
        tests = [self._Stub([self._posture_finding("Info")])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            with contextlib.redirect_stdout(io.StringIO()):
                hhs.save_results(path, tests, verbose=1)
            stored = hhs.load_baseline(path)
        drift = hhs.compare(hhs.collect_findings(tests), stored)
        self.assertEqual(
            hhs.gated_finding_count(tests, "any",
                                    only_identities=drift["new_identities"],
                                    identity_of=hhs.finding_identity,
                                    min_severity="info"),
            0)

    def test_the_evidence_report_keeps_every_one_of_them(self):
        # The threshold is the operator's view; the compliance report is the
        # record, and a requirement that failed has to appear in it.
        check = self._Stub([self._posture_finding("Info")])
        check.assessed = True
        check.skip_reason = None
        check.unassessed = {}
        check.emitted_types = lambda: ("Referrer-Policy",)
        evidence = build_evidence([check], ["https://t/"])
        self.assertEqual(_status_of(evidence, REFERRER), STATUS_FAIL)
        self.assertIn("Referrer-Policy", render_markdown(evidence))


class CommandLineTests(unittest.TestCase):
    def test_the_default_threshold_is_medium(self):
        from unittest import mock

        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.min_severity, hhs.DEFAULT_MIN_SEVERITY)
        self.assertEqual(args.min_severity, "medium")

    def test_every_band_can_be_asked_for(self):
        from unittest import mock

        for band in ("info", "low", "medium", "high", "critical"):
            with mock.patch("sys.argv", ["prog", "http://t/",
                                         "--min-severity", band]):
                self.assertEqual(hhs.parse_arguments().min_severity, band)


if __name__ == "__main__":
    unittest.main()
