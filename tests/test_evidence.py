"""Tests for the per-control compliance evidence report.

The property the whole report rests on: a control is reported as passing only
when a check that covers it actually completed. A scan that reached nothing
produces no findings, and reporting that as full compliance would be worse than
producing no report at all.

The case between the two is ``Partly assessed``: several checks cover one
requirement, some judged it, and another recorded that it could not look. That
is not a pass, and the reason the blind check gave has to be readable in both
renderings - otherwise the one check that could have found the failure drops
out of the record and the requirement reads as met.
"""

import io as _io
import json
import os
import tempfile
import unittest
from unittest import mock

import requests

import headerhawk as hhs
from headerhawk.compliance.evidence import (STATUS_FAIL, STATUS_NOT_ASSESSED,
                                            STATUS_PARTLY_ASSESSED,
                                            STATUS_PASS, ControlResult,
                                            build_evidence,
                                            controls_covered_by,
                                            unmapped_findings)
from headerhawk.core import output as hh_output
from headerhawk.core.output import blind_spots
from headerhawk.report.evidence import render_json, render_markdown, save_evidence
from tests.helpers import FakeResponse, FakeSession


class _Check:
    """Stand-in for a check that has already run."""

    def __init__(self, test_type, emits, assessed=True, findings=(),
                 skip_reason=None, unassessed=None):
        self.test_type = test_type
        self._emits = tuple(emits)
        self.assessed = assessed
        self.skip_reason = skip_reason
        # Finding types this check reached but could not judge, as the real
        # ``skip_type`` records them.
        self.unassessed = dict(unassessed or {})
        self.vulnerabilities_found = list(findings)

    def emitted_types(self):
        return self._emits


def _finding(test_type, controls, severity="High"):
    return {"test_type": test_type, "controls": list(controls),
            "severity": severity, "url": "https://t/", "analysis": "because",
            "header_name": "Host", "repro": "curl ..."}


def _status_of(evidence, control_id):
    return next(r.status for r in evidence["controls"]
                if r.control.id == control_id)


def _result_for(evidence, control_id):
    return next(r for r in evidence["controls"] if r.control.id == control_id)


class StatusTests(unittest.TestCase):
    def test_a_completed_check_with_no_finding_passes(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True)]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:3.7.2"), STATUS_PASS)

    def test_a_finding_fails_the_control(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True,
                         findings=[_finding("Open Redirect", ["ASVS-5.0:3.7.2"])])]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:3.7.2"), STATUS_FAIL)

    def test_a_blocked_check_leaves_its_controls_unassessed(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=False,
                         skip_reason="the target did not answer")]
        evidence = build_evidence(checks, ["https://t/"])
        result = _result_for(evidence, "ASVS-5.0:3.7.2")
        self.assertEqual(result.status, STATUS_NOT_ASSESSED)
        self.assertEqual(result.not_assessed_because,
                         ["Open Redirect: the target did not answer"])

    def test_a_control_no_check_covers_is_unassessed(self):
        evidence = build_evidence([], ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:3.7.2"),
                         STATUS_NOT_ASSESSED)

    def test_every_catalogued_control_appears(self):
        # An assessor needs to see the gaps, not only the answers.
        evidence = build_evidence([], ["https://t/"])
        self.assertEqual({r.control.id for r in evidence["controls"]},
                         set(hhs.CONTROLS))

    def test_a_finding_beats_another_checks_failure_to_run(self):
        # 4.1.3 is covered by several checks. Evidence of a real failure stands
        # on its own even when a sibling check could not run.
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True,
                   findings=[_finding("Host Header Injection",
                                      ["ASVS-5.0:4.1.3"])]),
            _Check("Auth Bypass", ["Auth Bypass"], assessed=False,
                   skip_reason="no baseline"),
        ]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:4.1.3"), STATUS_FAIL)

    def test_a_shared_control_with_a_blind_check_does_not_pass(self):
        # It used to. One check completing was read as having assessed the
        # control, and the check that said it could not look dropped out of
        # the record entirely - which is the failure this status exists for.
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True),
            _Check("Auth Bypass", ["Auth Bypass"], assessed=False,
                   skip_reason="no baseline"),
        ]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:4.1.3"),
                         STATUS_PARTLY_ASSESSED)

    def test_a_shared_control_passes_when_nothing_was_blind(self):
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True),
            _Check("Auth Bypass", ["Auth Bypass"], assessed=True),
        ]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:4.1.3"), STATUS_PASS)


class UnreachableScanTests(unittest.TestCase):
    """The case that decides whether the report can be trusted at all."""

    def _blocked_evidence(self):
        checks = [_Check(name, emits, assessed=False,
                         skip_reason="no request to the target succeeded")
                  for name, emits in (("Open Redirect", ["Open Redirect"]),
                                      ("SSRF", ["SSRF"]))]
        return build_evidence(checks, ["https://t/"])

    def test_nothing_passes(self):
        evidence = self._blocked_evidence()
        self.assertEqual(evidence["counts"][STATUS_PASS], 0)
        self.assertEqual(evidence["counts"][STATUS_FAIL], 0)

    def test_everything_is_reported_as_not_assessed(self):
        evidence = self._blocked_evidence()
        self.assertEqual(evidence["counts"][STATUS_NOT_ASSESSED],
                         len(hhs.CONTROLS))

    def test_markdown_explains_why_that_is_not_compliance(self):
        body = render_markdown(self._blocked_evidence())
        self.assertIn("only reported as passing when a check that covers it "
                      "actually completed", body)


class CoverageMapTests(unittest.TestCase):
    def test_a_check_covers_the_controls_of_every_type_it_emits(self):
        covered = controls_covered_by(hhs.ResponseHeaderPostureTest)
        self.assertIn("ASVS-5.0:3.4.1", covered)   # HSTS
        self.assertIn("ASVS-5.0:3.3.4", covered)   # cookie HttpOnly
        self.assertIn("ASVS-5.0:13.4.6", covered)  # version disclosure

    def test_every_registered_check_covers_something_or_nothing_knowingly(self):
        # Not an assertion that every check maps - only that asking is safe.
        for check in hhs.CHECKS:
            self.assertIsInstance(controls_covered_by(check), set)


class AssessmentTrackingTests(unittest.TestCase):
    def test_a_check_that_answered_is_assessed(self):
        session = FakeSession(responses=[FakeResponse(url="https://t/")])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        self.assertTrue(test.assessed)
        self.assertIsNone(test.skip_reason)

    def test_a_check_whose_requests_all_failed_is_not_assessed(self):
        session = FakeSession(responses=[requests.RequestException()])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        self.assertFalse(test.assessed)
        self.assertEqual(test.skip_reason, "no request to the target succeeded")

    def test_a_check_that_skipped_reports_its_own_reason(self):
        session = FakeSession(responses=[FakeResponse(url="https://t/")] * 4)
        test = hhs.AuthBypassTest("https://t/", "t", session=session, timeout=1,
                                  verbose=0, quiet=True)
        test.skip("a made-up reason")
        self.assertFalse(test.assessed)
        self.assertEqual(test.skip_reason, "a made-up reason")


class UnmappedFindingTests(unittest.TestCase):
    def test_findings_outside_the_catalogue_are_collected(self):
        check = _Check("Permissions-Policy", ["Permissions-Policy"],
                       assessed=True,
                       findings=[_finding("Permissions-Policy", [])])
        self.assertEqual(len(unmapped_findings([check])), 1)

    def test_markdown_keeps_them_rather_than_dropping_them(self):
        check = _Check("Permissions-Policy", ["Permissions-Policy"],
                       assessed=True,
                       findings=[_finding("Permissions-Policy", [])])
        body = render_markdown(build_evidence([check], ["https://t/"]),
                               unmapped_findings([check]))
        self.assertIn("Findings Outside the Catalogue", body)


class PartlyAssessedTests(unittest.TestCase):
    """The gap the integration lab found, and what closes it.

    Behind a cache that ignores the query string the unkeyed search refuses to
    guess and records why. Three other checks map to the same requirement, ran
    and found nothing. Reporting that requirement as met is the erosion this
    project exists not to have, so it is reported as partly assessed and the
    reason is carried into both renderings.
    """

    BLIND = ("the cache answered a URL this scan had just invented, so the "
             "query string is not part of its key")

    def _evidence(self):
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True),
            _Check("Web Cache Poisoning", ["Web Cache Poisoning"],
                   assessed=True),
            _Check("Unkeyed Input", ["Unkeyed Input"], assessed=False,
                   skip_reason=self.BLIND),
        ]
        return build_evidence(checks, ["http://querycache/link"],
                              version="9.9.9", tool_name="HeaderHawk")

    def test_the_control_is_partly_assessed_not_passed(self):
        self.assertEqual(_status_of(self._evidence(), "ASVS-5.0:4.1.3"),
                         STATUS_PARTLY_ASSESSED)

    def test_it_still_names_the_checks_that_did_judge_it(self):
        # Partly assessed is not "nobody looked"; throwing away the checks
        # that did look would be its own dishonesty.
        result = _result_for(self._evidence(), "ASVS-5.0:4.1.3")
        self.assertEqual(result.assessed_by,
                         ["Host Header Injection", "Web Cache Poisoning"])

    def test_the_reason_the_check_recorded_is_on_the_result(self):
        result = _result_for(self._evidence(), "ASVS-5.0:4.1.3")
        self.assertEqual(result.partly_assessed_because,
                         ["Unkeyed Input: " + self.BLIND])

    def test_not_assessed_because_keeps_its_old_meaning(self):
        # A consumer reading that field is asking "did anybody look?". The
        # answer here is yes, so the field stays empty.
        result = _result_for(self._evidence(), "ASVS-5.0:4.1.3")
        self.assertEqual(result.not_assessed_because, [])

    def test_the_counts_report_it_as_its_own_status(self):
        counts = self._evidence()["counts"]
        self.assertEqual(counts[STATUS_PARTLY_ASSESSED], 1)
        self.assertEqual(counts[STATUS_PASS], 0)

    def test_a_pass_carries_no_blind_reasons(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True)]
        result = _result_for(build_evidence(checks, ["https://t/"]),
                             "ASVS-5.0:3.7.2")
        self.assertEqual(result.status, STATUS_PASS)
        self.assertEqual(result.partly_assessed_because, [])

    def test_markdown_says_who_could_not_look_and_why(self):
        body = render_markdown(self._evidence())
        self.assertIn("ASVS-5.0:4.1.3 — PARTLY ASSESSED", body)
        self.assertIn("Not looked at by:", body)
        self.assertIn(self.BLIND, body)

    def test_markdown_does_not_let_it_read_as_a_pass(self):
        body = render_markdown(self._evidence())
        self.assertNotIn("ASVS-5.0:4.1.3 — PASS", body)
        self.assertIn("this is not a pass", body)
        self.assertIn("reported as partly assessed", body)

    def test_json_carries_the_reason_in_a_field_of_its_own(self):
        payload = json.loads(render_json(self._evidence()))
        control = next(c for c in payload["controls"]
                       if c["id"] == "ASVS-5.0:4.1.3")
        self.assertEqual(control["status"], STATUS_PARTLY_ASSESSED)
        self.assertEqual(control["partly_assessed_because"],
                         ["Unkeyed Input: " + self.BLIND])
        self.assertEqual(control["not_assessed_because"], [])

    def test_partly_assessed_sorts_between_not_assessed_and_pass(self):
        # Nobody looking at a requirement is worse than somebody looking and
        # finding it clean, so the detail section orders them that way.
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True),
            _Check("Unkeyed Input", ["Unkeyed Input"], assessed=False,
                   skip_reason=self.BLIND),
            # Something to pass, so all three statuses are present to order.
            _Check("Open Redirect", ["Open Redirect"], assessed=True),
        ]
        evidence = build_evidence(checks, ["http://querycache/link"])
        statuses = [c["status"]
                    for c in json.loads(render_json(evidence))["controls"]]
        self.assertLess(statuses.index(STATUS_PARTLY_ASSESSED),
                        statuses.index(STATUS_PASS))
        self.assertLess(statuses.index(STATUS_NOT_ASSESSED),
                        statuses.index(STATUS_PARTLY_ASSESSED))

    def test_having_nothing_to_look_at_is_not_being_blind(self):
        # The distinction the status turns on. A skip_type says this surface
        # has nothing for the control to act on - a JSON reply and a framing
        # requirement - which is a statement about the response, not a gap in
        # the scan. Where another check did judge the control, nothing is
        # missing, so it still passes.
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True),
            _Check("Web Cache Poisoning",
                   ["Web Cache Poisoning", "Unkeyed Input"], assessed=True,
                   unassessed={"Unkeyed Input": "the reply is application/"
                                                "json, nothing to act on"}),
        ]
        evidence = build_evidence(checks, ["https://t/api"])
        result = _result_for(evidence, "ASVS-5.0:4.1.3")
        self.assertEqual(result.status, STATUS_PASS)
        self.assertEqual(result.partly_assessed_because, [])

    def test_nothing_to_look_at_and_nobody_else_is_still_not_assessed(self):
        # And when it is the only check covering the control, the reason it
        # gave is still the reason - that path is unchanged.
        checks = [_Check("Web Cache Poisoning", ["Web Cache Poisoning"],
                         assessed=True,
                         unassessed={"Web Cache Poisoning":
                                     "the reply is application/json"})]
        result = _result_for(build_evidence(checks, ["https://t/api"]),
                             "ASVS-5.0:4.1.3")
        self.assertEqual(result.status, STATUS_NOT_ASSESSED)
        self.assertEqual(result.not_assessed_because,
                         ["Web Cache Poisoning: the reply is application/json"])


class ControlResultShapeTests(unittest.TestCase):
    """The result type is exported from the package root, so its shape is API."""

    def test_the_five_original_fields_still_construct_it(self):
        # partly_assessed_because was added after them. Making it required
        # would turn every existing five-argument construction into a
        # TypeError, which a minor release has no business doing.
        result = ControlResult("a control", STATUS_PASS, [], ["Open Redirect"],
                               [])
        self.assertEqual(result.status, STATUS_PASS)
        self.assertEqual(result.partly_assessed_because, ())

    def test_the_new_field_is_still_passed_positionally(self):
        result = ControlResult("a control", STATUS_PARTLY_ASSESSED, [],
                               ["Host Header Injection"], [],
                               ["Unkeyed Input: blind"])
        self.assertEqual(result.partly_assessed_because,
                         ["Unkeyed Input: blind"])

    def test_build_evidence_never_relies_on_the_default(self):
        # The default exists for older callers, not for this module: a control
        # built here always says explicitly what was and was not looked at.
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True)]
        for result in build_evidence(checks, ["https://t/"])["controls"]:
            self.assertIsInstance(result.partly_assessed_because, list)


class BlindSpotsOnAFailTests(unittest.TestCase):
    """A finding decides the verdict; it does not decide what was seen."""

    def _evidence(self):
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True,
                   findings=[_finding("Host Header Injection",
                                      ["ASVS-5.0:4.1.3"])]),
            _Check("Unkeyed Input", ["Unkeyed Input"], assessed=False,
                   skip_reason="the query string is not part of its key"),
        ]
        return build_evidence(checks, ["http://querycache/link"])

    def test_the_finding_still_decides_the_verdict(self):
        self.assertEqual(_status_of(self._evidence(), "ASVS-5.0:4.1.3"),
                         STATUS_FAIL)

    def test_the_fail_still_records_what_was_not_looked_at(self):
        # How complete the finding list is depends on it.
        result = _result_for(self._evidence(), "ASVS-5.0:4.1.3")
        self.assertEqual(
            result.partly_assessed_because,
            ["Unkeyed Input: the query string is not part of its key"])

    def test_markdown_shows_it_under_the_findings(self):
        body = render_markdown(self._evidence())
        self.assertIn("ASVS-5.0:4.1.3 — FAIL", body)
        self.assertIn("Not looked at by:", body)
        self.assertIn("the query string is not part of its key", body)


class RenderingTests(unittest.TestCase):
    def _evidence(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True,
                         findings=[_finding("Open Redirect",
                                            ["ASVS-5.0:3.7.2"])])]
        return build_evidence(checks, ["https://t/"], version="9.9.9",
                              tool_name="HeaderHawk")

    def test_markdown_carries_the_provenance_an_assessor_needs(self):
        body = render_markdown(self._evidence())
        self.assertIn("HeaderHawk 9.9.9", body)
        self.assertIn("**Generated:**", body)
        self.assertIn("https://t/", body)
        self.assertIn("ASVS-5.0:3.7.2 — FAIL", body)
        self.assertIn("https://github.com/OWASP/ASVS/", body)

    def test_json_is_machine_readable_and_ordered_worst_first(self):
        payload = json.loads(render_json(self._evidence()))
        self.assertEqual(payload["version"], "9.9.9")
        statuses = [c["status"] for c in payload["controls"]]
        self.assertEqual(statuses[0], STATUS_FAIL)
        failing = payload["controls"][0]
        self.assertEqual(failing["id"], "ASVS-5.0:3.7.2")
        self.assertEqual(len(failing["findings"]), 1)

    def test_save_evidence_picks_the_format_from_the_extension(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True)]
        with tempfile.TemporaryDirectory() as tmp:
            md = os.path.join(tmp, "e.md")
            js = os.path.join(tmp, "e.json")
            save_evidence(md, checks, ["https://t/"], version="1", tool_name="HH")
            save_evidence(js, checks, ["https://t/"], version="1", tool_name="HH")
            self.assertTrue(open(md).read().startswith("# HH Compliance Evidence"))
            json.loads(open(js).read())

    def test_no_path_writes_nothing(self):
        self.assertIsNone(save_evidence(None, [], []))


class PostureReproductionTests(unittest.TestCase):
    def test_a_posture_finding_reproduces_by_fetching_the_url(self):
        # header_name on a posture finding names what was assessed, not
        # something to send; echoing it back as a request header produced a
        # command that reproduced nothing.
        session = FakeSession(responses=[
            FakeResponse(headers={"Server": "nginx/1.18.0"}, url="https://t/")])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        for finding in test.vulnerabilities_found:
            self.assertNotIn("-H", finding["repro"], finding["test_type"])
            self.assertIn("https://t/", finding["repro"])

    def test_a_request_header_finding_still_shows_the_header(self):
        test = hhs.HostInjectionTest("http://t/", "t", session=None, timeout=1,
                                     verbose=0, quiet=True)
        test.record({"test_type": "Host Header Injection", "url": "http://t/",
                     "method": "GET", "header_name": "X-Forwarded-Host",
                     "payload": "evil", "status_code": 200, "analysis": "x"})
        self.assertIn("-H 'X-Forwarded-Host: evil'",
                      test.vulnerabilities_found[0]["repro"])


class ConsoleBlindSpotTests(unittest.TestCase):
    """The console is where a skipped search is visible at all.

    `No vulnerabilities were found.` on its own is what a scan prints when it
    found nothing and what it prints when it could not look, and the lab caught
    the tool saying exactly that behind a cache that hid the answer.
    """

    BLIND = ("the cache answered a URL this scan had just invented, so the "
             "query string is not part of its key")

    class _Ran:
        def __init__(self, test_type="Host Header Injection"):
            self.target_url = "http://querycache/link"
            self.test_type = test_type
            self.vulnerabilities_found = []
            self.all_results = []

    class _Blind(_Ran):
        def __init__(self, test_type, reason):
            ConsoleBlindSpotTests._Ran.__init__(self, test_type)
            self.assessed = False
            self.skip_reason = reason

    def _summary(self, tests, stats=None):
        if stats is None:
            stats = hhs.RequestStats()
            stats.record(True)
        buffer = _io.StringIO()
        with mock.patch.object(hh_output, "_QUIET", False):
            with mock.patch("sys.stdout", buffer):
                hhs.print_summary(tests, ["http://querycache/link"], stats)
        return buffer.getvalue()

    def test_it_says_which_check_could_not_look_and_why(self):
        output = self._summary([self._Ran(),
                                self._Blind("Unkeyed Input", self.BLIND)])
        self.assertIn("Could not assess (1)", output)
        self.assertIn("Unkeyed Input", output)
        self.assertIn("not part of its key", output)

    def test_it_does_not_print_a_bare_clean_result(self):
        output = self._summary([self._Ran(),
                                self._Blind("Unkeyed Input", self.BLIND)])
        self.assertNotIn("No vulnerabilities were found.", output)
        self.assertIn("No vulnerabilities were found", output)
        self.assertIn("not a clean bill of health", output)

    def test_a_scan_with_nothing_blind_still_reports_cleanly(self):
        output = self._summary([self._Ran()])
        self.assertIn("No vulnerabilities were found.", output)
        self.assertNotIn("Could not assess", output)

    def test_an_unreachable_target_keeps_its_own_louder_message(self):
        # Every check is blind for the same reason there; listing all of them
        # would bury the one line that matters.
        stats = hhs.RequestStats()
        for _ in range(3):
            stats.record(False)
        output = self._summary(
            [self._Blind("Unkeyed Input", "no request to the target succeeded"),
             self._Blind("Open Redirect", "no request to the target succeeded")],
            stats=stats)
        self.assertIn("appear unreachable", output)
        self.assertNotIn("Could not assess", output)

    def test_only_a_check_that_could_not_look_is_listed(self):
        # A skip_type is a statement about the response, not a gap in the
        # scan, so it belongs in the evidence report and not here.
        ran = self._Ran("Response Header Posture")
        ran.unassessed = {"Content-Security-Policy": "the reply is JSON"}
        self.assertEqual(blind_spots([ran]), [])

    def test_a_check_whose_requests_all_failed_counts_as_blind(self):
        session = FakeSession(responses=[requests.RequestException()])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        self.assertEqual(blind_spots([test]),
                         [("Response Header Posture",
                           "no request to the target succeeded")])


if __name__ == "__main__":
    unittest.main()
