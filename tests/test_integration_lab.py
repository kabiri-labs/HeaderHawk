"""Tests for the integration lab's comparison, which judges everything else.

`lab/run.py` decides whether a scan of a real server matched what the scenario
declared, and every claim the lab makes rests on that decision. Three defects
in it were found by review rather than by use, and each one had the same
shape: the comparison went ahead on evidence it should have refused.

A scan that could not run produced the same empty files as a clean one, so a
scenario whose expectations are all absences reported every one of them as
held. Artefacts from an earlier run survived in the bind-mounted output
directory, so a scan that died before writing was compared against the
previous one. And a single expectation claimed every finding that matched it,
so a regression reporting one defect twice hid behind the expectation for the
first.

The module is loaded by path, not imported: `lab/` is deliberately not a
package, and nothing in it is part of the scanner. These tests are offline and
need no Docker - they exercise the comparison, not the lab.
"""

import importlib.util
import json
import os
import tempfile
import unittest

from headerhawk.core.exitcodes import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK

_HERE = os.path.dirname(os.path.abspath(__file__))
_RUN_PY = os.path.join(os.path.dirname(_HERE), "lab", "run.py")


def _load_runner():
    """Load lab/run.py as a module without making lab/ a package."""
    spec = importlib.util.spec_from_file_location("lab_run", _RUN_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


def _finding(**overrides):
    """A finding with the fields the comparison reads."""
    entry = {
        "test_type": "Host Header Injection",
        "test_result": "Vulnerable",
        "confidence": "confirmed",
        "severity": "Medium",
        "header_name": "X-Forwarded-Host",
        "analysis": "the marker came back and did so again on a second request",
        "finding_class": "vulnerability",
    }
    entry.update(overrides)
    return entry


def _result(findings=(), evidence=None, exit_code=EXIT_FINDINGS,
            console="", markdown=None):
    return {
        "findings": list(findings),
        "evidence": evidence if evidence is not None else {},
        "console": console,
        "markdown": markdown,
        "exit_code": exit_code,
        "seconds": 1.0,
        "command": "python /hh/headerhawk.py http://app:8000/link",
    }


class MatchingTests(unittest.TestCase):
    """An expectation says what it means to say, and nothing more."""

    def test_a_field_the_expectation_does_not_name_is_not_compared(self):
        self.assertTrue(runner.matches({"test_type": "Host Header Injection"},
                                       _finding(severity="Low")))

    def test_a_field_it_does_name_has_to_agree(self):
        self.assertFalse(runner.matches({"severity": "High"}, _finding()))

    def test_strings_are_compared_without_regard_to_case(self):
        self.assertTrue(runner.matches({"confidence": "CONFIRMED"}, _finding()))

    def test_the_explanation_is_not_compared_as_a_field(self):
        # 'why' is prose for the report, not an assertion about the finding.
        self.assertTrue(runner.matches(
            {"test_type": "Host Header Injection", "why": "anything at all"},
            _finding()))

    def test_the_analysis_is_matched_as_a_substring(self):
        self.assertTrue(runner.matches(
            {"analysis_contains": "second request"}, _finding()))
        self.assertFalse(runner.matches(
            {"analysis_contains": "never happened"}, _finding()))


class ExitCodeTests(unittest.TestCase):
    """A scan that could not run settles nothing either way."""

    # Every assertion this scenario makes is an absence, which is the case the
    # defect was dangerous in: a secure endpoint, a closed cache, a proxy that
    # overwrites the header.
    ABSENCES = {
        "id": "secure-endpoint",
        "target": "http://app:8000/secure/page",
        "forbid": [{"test_type": "Content-Security-Policy", "why": "set"},
                   {"test_type": "Frame Protection", "why": "set"}],
    }

    def test_an_error_exit_is_inconclusive_not_a_clean_result(self):
        verdict = runner.compare(self.ABSENCES, _result(exit_code=EXIT_ERROR))
        self.assertEqual(len(verdict["inconclusive"]), 1)
        self.assertIn("exited %d" % EXIT_ERROR, verdict["inconclusive"][0])
        # The point of the fix: nothing is recorded as having held.
        self.assertEqual(verdict["passed_absence"], [])
        self.assertEqual(verdict["false_positive"], [])
        self.assertEqual(verdict["true_positive"], [])

    def test_a_death_outside_the_cli_is_inconclusive_too(self):
        # Killed by a signal: it did not leave through the scanner's own exit
        # path, so its artefacts say nothing about the target.
        verdict = runner.compare(self.ABSENCES, _result(exit_code=-9))
        self.assertEqual(len(verdict["inconclusive"]), 1)
        self.assertEqual(verdict["passed_absence"], [])

    def test_a_timeout_is_inconclusive(self):
        verdict = runner.compare(self.ABSENCES, _result(exit_code=None))
        self.assertEqual(len(verdict["inconclusive"]), 1)
        self.assertEqual(verdict["passed_absence"], [])

    def test_nothing_found_is_a_result_and_is_compared(self):
        # 0 means the scan ran and reported nothing. That is exactly what this
        # scenario declared, so the absences hold.
        verdict = runner.compare(self.ABSENCES, _result(exit_code=EXIT_OK))
        self.assertEqual(verdict["inconclusive"], [])
        self.assertEqual(len(verdict["passed_absence"]), 2)

    def test_findings_reported_is_a_result_and_is_compared(self):
        verdict = runner.compare(
            self.ABSENCES,
            _result([_finding(test_type="Frame Protection",
                              test_result="Missing", severity="Medium")],
                    exit_code=EXIT_FINDINGS))
        self.assertEqual(verdict["inconclusive"], [])
        self.assertEqual(len(verdict["false_positive"]), 1)
        self.assertEqual(len(verdict["passed_absence"]), 1)


class FreshArtefactTests(unittest.TestCase):
    """What an earlier run left behind is never what this one is judged on."""

    def test_an_artefact_from_an_earlier_run_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "scenario.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('[{"test_type": "from the run before"}]')
            self.assertEqual(runner._fresh(path), path)
            self.assertFalse(os.path.exists(path))

    def test_a_path_that_was_never_written_is_handed_back_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "scenario.json")
            self.assertEqual(runner._fresh(path), path)
            self.assertFalse(os.path.exists(path))

    def test_a_missing_artefact_reads_as_absent_not_as_the_previous_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "gone.json")
            self.assertEqual(runner._load(path, []), [])
            self.assertEqual(runner._load(path, {}), {})


class DuplicateFindingTests(unittest.TestCase):
    """One expectation accounts for one finding."""

    SCENARIO = {
        "id": "one-defect-one-finding",
        "target": "http://app:8000/link",
        "exhaustive": True,
        "expect": [{"test_type": "Host Header Injection",
                    "why": "the marker became the host of a link"}],
    }

    def test_a_finding_reported_twice_is_reported_as_undeclared(self):
        verdict = runner.compare(self.SCENARIO,
                                 _result([_finding(), _finding()]))
        self.assertEqual(len(verdict["true_positive"]), 1)
        self.assertEqual(len(verdict["false_positive"]), 1)
        self.assertEqual(
            verdict["false_positive"][0]["finding"]["test_type"],
            "Host Header Injection")

    def test_one_finding_is_one_true_positive(self):
        verdict = runner.compare(self.SCENARIO, _result([_finding()]))
        self.assertEqual(len(verdict["true_positive"]), 1)
        self.assertEqual(verdict["false_positive"], [])

    def test_two_expectations_do_not_both_claim_one_finding(self):
        # The second expectation names nothing the first did not, so with one
        # finding on the table only one of them can be satisfied.
        scenario = dict(self.SCENARIO, expect=[
            {"test_type": "Host Header Injection", "why": "first"},
            {"test_type": "Host Header Injection", "why": "second"},
        ])
        verdict = runner.compare(scenario, _result([_finding()]))
        self.assertEqual(len(verdict["true_positive"]), 1)
        self.assertEqual(len(verdict["false_negative"]), 1)

    def test_two_expectations_are_satisfied_by_two_findings(self):
        scenario = dict(self.SCENARIO, expect=[
            {"test_type": "Host Header Injection", "header_name":
             "X-Forwarded-Host", "why": "the forwarding header"},
            {"test_type": "Host Header Injection", "header_name": "X-Host",
             "why": "and the other one"},
        ])
        verdict = runner.compare(scenario, _result(
            [_finding(), _finding(header_name="X-Host")]))
        self.assertEqual(len(verdict["true_positive"]), 2)
        self.assertEqual(verdict["false_positive"], [])


class ExhaustiveSweepTests(unittest.TestCase):
    """An undeclared finding a user would see is a false positive."""

    SCENARIO = {"id": "quiet", "target": "http://app:8000/link",
                "exhaustive": True, "expect": []}

    def test_an_undeclared_finding_above_the_threshold_is_reported(self):
        verdict = runner.compare(self.SCENARIO, _result([_finding()]))
        self.assertEqual(len(verdict["false_positive"]), 1)

    def test_a_finding_below_the_threshold_is_not_counted_against_it(self):
        # Low and Info posture findings are in the JSON record and not in what
        # the scanner shows by default, so the scenario is not about them.
        verdict = runner.compare(self.SCENARIO, _result(
            [_finding(test_type="Referrer-Policy", test_result="Missing",
                      severity="Info", finding_class="posture")]))
        self.assertEqual(verdict["false_positive"], [])

    def test_a_scenario_that_does_not_claim_to_be_exhaustive_is_not_swept(self):
        scenario = dict(self.SCENARIO, exhaustive=False)
        verdict = runner.compare(scenario, _result([_finding()]))
        self.assertEqual(verdict["false_positive"], [])


class EvidenceAssertionTests(unittest.TestCase):
    """Absence is read from the per-control evidence, not from an empty list."""

    EVIDENCE = {"controls": [
        {"id": "ASVS-5.0:3.4.3", "status": "Not assessed",
         "not_assessed_because": [
             "Response Header Posture: the response is application/json, not "
             "a document a browser renders, so this control had nothing to "
             "act on"]},
        {"id": "ASVS-5.0:4.1.3", "status": "Pass",
         "not_assessed_because": []},
    ]}

    def test_a_control_reported_as_declared_with_its_reason_holds(self):
        scenario = {"id": "json", "target": "http://app:8000/secure/json",
                    "controls": [{"id": "ASVS-5.0:3.4.3",
                                  "status": "Not assessed",
                                  "reason_contains":
                                      "not a document a browser renders",
                                  "why": "nothing to act on"}]}
        verdict = runner.compare(scenario, _result(evidence=self.EVIDENCE))
        self.assertEqual(len(verdict["true_positive"]), 1)
        self.assertEqual(verdict["false_negative"], [])

    def test_a_reason_the_evidence_does_not_give_is_a_false_negative(self):
        # The reason arrives as a list of strings; searching it has to survive
        # that, and a reason that is simply not there has to be caught.
        scenario = {"id": "json", "target": "http://app:8000/secure/json",
                    "controls": [{"id": "ASVS-5.0:3.4.3",
                                  "status": "Not assessed",
                                  "reason_contains": "not part of its key",
                                  "why": "the cache made it blind"}]}
        verdict = runner.compare(scenario, _result(evidence=self.EVIDENCE))
        self.assertEqual(len(verdict["false_negative"]), 1)

    def test_a_control_with_the_wrong_status_is_a_false_negative(self):
        scenario = {"id": "json", "target": "http://app:8000/secure/json",
                    "controls": [{"id": "ASVS-5.0:4.1.3",
                                  "status": "Not assessed",
                                  "why": "a search that could not look"}]}
        verdict = runner.compare(scenario, _result(evidence=self.EVIDENCE))
        self.assertEqual(len(verdict["false_negative"]), 1)
        self.assertIn("reported Pass",
                      verdict["false_negative"][0]["detail"])

    def test_a_control_the_evidence_never_mentions_is_inconclusive(self):
        scenario = {"id": "json", "target": "http://app:8000/secure/json",
                    "controls": [{"id": "ASVS-5.0:9.9.9", "status": "Pass",
                                  "why": "not a real requirement"}]}
        verdict = runner.compare(scenario, _result(evidence=self.EVIDENCE))
        self.assertEqual(len(verdict["inconclusive"]), 1)


class ConsoleAndMarkdownTests(unittest.TestCase):
    """What the scan told the user is an assertion of its own."""

    BLIND = {"id": "blind", "target": "http://querycache/link",
             "exhaustive": False,
             "log_require": [{"text": "not part of its key",
                              "why": "it has to say it could not look"}]}

    def test_a_reason_the_scan_printed_holds(self):
        verdict = runner.compare(self.BLIND, _result(
            console="the query string is not part of its key, so a "
                    "cache-buster cannot tell one probe from another",
            exit_code=EXIT_OK))
        self.assertEqual(len(verdict["true_positive"]), 1)

    def test_a_reason_the_scan_never_printed_is_a_false_negative(self):
        verdict = runner.compare(self.BLIND, _result(
            console="No vulnerabilities were found.", exit_code=EXIT_OK))
        self.assertEqual(len(verdict["false_negative"]), 1)

    def test_text_the_report_must_not_show_and_does_not_holds(self):
        scenario = {"id": "quiet", "target": "http://app:8000/weak",
                    "exhaustive": False, "markdown": True,
                    "md_forbid": [{"text": "Referrer-Policy: Missing",
                                   "why": "below the default threshold"}]}
        verdict = runner.compare(scenario, _result(
            markdown="### Content-Security-Policy: Missing (Medium)"))
        self.assertEqual(len(verdict["passed_absence"]), 1)

    def test_text_the_report_shows_anyway_is_a_false_positive(self):
        scenario = {"id": "quiet", "target": "http://app:8000/weak",
                    "exhaustive": False, "markdown": True,
                    "md_forbid": [{"text": "Referrer-Policy: Missing",
                                   "why": "below the default threshold"}]}
        verdict = runner.compare(scenario, _result(
            markdown="### Referrer-Policy: Missing (Info)"))
        self.assertEqual(len(verdict["false_positive"]), 1)

    def test_no_report_at_all_is_inconclusive(self):
        scenario = {"id": "quiet", "target": "http://app:8000/weak",
                    "exhaustive": False, "markdown": True,
                    "md_forbid": [{"text": "Referrer-Policy: Missing",
                                   "why": "below the default threshold"}]}
        verdict = runner.compare(scenario, _result(markdown=None))
        self.assertEqual(len(verdict["inconclusive"]), 1)


class ScenarioFileTests(unittest.TestCase):
    """The declared scenarios stay readable by the comparison that reads them."""

    def test_every_scenario_has_a_target_and_something_to_assert(self):
        path = os.path.join(os.path.dirname(_HERE), "lab", "scenarios.json")
        with open(path, encoding="utf-8") as handle:
            scenarios = json.load(handle)["scenarios"]
        self.assertTrue(scenarios)
        for scenario in scenarios:
            self.assertTrue(scenario.get("id"), scenario)
            self.assertTrue(scenario.get("target"), scenario["id"])
            assertions = sum(len(scenario.get(key, ()))
                             for key in ("expect", "forbid", "controls",
                                         "log_require", "md_forbid"))
            self.assertTrue(assertions, "%s asserts nothing" % scenario["id"])

    def test_every_expectation_explains_itself(self):
        path = os.path.join(os.path.dirname(_HERE), "lab", "scenarios.json")
        with open(path, encoding="utf-8") as handle:
            scenarios = json.load(handle)["scenarios"]
        for scenario in scenarios:
            for key in ("expect", "forbid", "controls", "log_require",
                        "md_forbid"):
                for entry in scenario.get(key, ()):
                    self.assertTrue(
                        entry.get("why"),
                        "%s: %s entry without a reason" % (scenario["id"], key))


if __name__ == "__main__":
    unittest.main()
