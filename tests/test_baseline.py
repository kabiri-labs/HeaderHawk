"""Tests for baseline comparison and regression-only gating.

The property everything rests on: the same finding, seen on two different scans,
must get the same identity. Several checks put a fresh random marker in every
payload, so hashing findings verbatim would make every one look new on every
run - a pipeline that fails forever, and a feature nobody would leave switched
on.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import headerhawk as hhs
from headerhawk.compliance.evidence import (DRIFT_CONTROL, STATUS_NOT_ASSESSED,
                                            STATUS_PASS, build_evidence)
from headerhawk.core.baseline import (collect_findings, compare,
                                      describe_drift, finding_identity,
                                      load_baseline)
from headerhawk.cli import resolve_drift
from headerhawk.core.findings import CLASS_POSTURE, CLASS_VULNERABILITY


def _finding(test_type="Host Header Injection", url="https://t/",
             header_name="X-Forwarded-Host", payload="", **extra):
    entry = {"test_type": test_type, "url": url, "header_name": header_name,
             "payload": payload, "severity": "Medium", "analysis": "a"}
    entry.update(extra)
    return entry


class _Stub:
    def __init__(self, findings):
        self.vulnerabilities_found = list(findings)


class IdentityStabilityTests(unittest.TestCase):
    def test_a_fresh_marker_does_not_make_a_finding_look_new(self):
        # Two scans of the same unchanged target, each with its own marker.
        first = _finding(payload=f"{hhs.new_token()}.example-collab.com")
        second = _finding(payload=f"{hhs.new_token()}.example-collab.com")
        self.assertEqual(finding_identity(first), finding_identity(second))

    def test_a_cache_buster_in_the_url_does_not_either(self):
        first = _finding(test_type="Web Cache Poisoning",
                         url=f"https://t/?cb={hhs.new_token(10)}")
        second = _finding(test_type="Web Cache Poisoning",
                          url=f"https://t/?cb={hhs.new_token(10)}")
        self.assertEqual(finding_identity(first), finding_identity(second))

    def test_real_markers_from_two_scans_agree(self):
        # Drive the actual marker generation rather than hand-written strings.
        first = hhs.HostInjectionTest("https://t/", "t", session=None, timeout=1)
        second = hhs.HostInjectionTest("https://t/", "t", session=None, timeout=1)
        payload_a = first.generate_cases()[1][0][3]
        payload_b = second.generate_cases()[1][0][3]
        self.assertNotEqual(payload_a, payload_b)  # genuinely different markers
        self.assertEqual(finding_identity(_finding(payload=payload_a)),
                         finding_identity(_finding(payload=payload_b)))

    def test_cors_origins_from_two_scans_agree(self):
        first = hhs.CORSTest("https://t/", "t", session=None, timeout=1)
        second = hhs.CORSTest("https://t/", "t", session=None, timeout=1)
        a = _finding("CORS Origin Reflection", header_name="Origin",
                     payload=f"https://{first.token}.example-collab.com")
        b = _finding("CORS Origin Reflection", header_name="Origin",
                     payload=f"https://{second.token}.example-collab.com")
        self.assertEqual(finding_identity(a), finding_identity(b))


class IdentityDiscriminationTests(unittest.TestCase):
    def test_different_types_differ(self):
        self.assertNotEqual(finding_identity(_finding("SSRF")),
                            finding_identity(_finding("Open Redirect")))

    def test_different_headers_differ(self):
        self.assertNotEqual(finding_identity(_finding(header_name="X-Host")),
                            finding_identity(_finding(header_name="X-Real-IP")))

    def test_different_cookies_differ(self):
        # Cookie findings are told apart by their subject, not their payload.
        self.assertNotEqual(
            finding_identity(_finding("Cookie SameSite Attribute",
                                      header_name="Set-Cookie: a")),
            finding_identity(_finding("Cookie SameSite Attribute",
                                      header_name="Set-Cookie: b")))

    def test_different_stable_payloads_differ(self):
        # A vhost name or an internal host is meaningful and must be kept.
        self.assertNotEqual(
            finding_identity(_finding("Virtual Host Discovery",
                                      header_name="Host", payload="admin")),
            finding_identity(_finding("Virtual Host Discovery",
                                      header_name="Host", payload="staging")))

    def test_different_urls_differ(self):
        self.assertNotEqual(finding_identity(_finding(url="https://a/")),
                            finding_identity(_finding(url="https://b/")))


class MarkerFoldingTests(unittest.TestCase):
    """Only the scanner's own tokens may be folded out of an identity.

    Folding every long run of hexadecimal also folded values that mean
    something - a virtual host named in hex, an identifier in a path - filing
    two distinct findings under one identity. The tokens the scanner mints
    carry a prefix so they can be told apart from everything else.
    """

    def test_a_minted_token_says_who_made_it(self):
        token = hhs.new_token()
        self.assertTrue(token.startswith(hhs.MARKER_PREFIX))
        self.assertNotEqual(token, hhs.new_token())

    def test_the_scanners_own_token_is_folded(self):
        first = _finding(payload=f"{hhs.new_token()}.example-collab.com")
        second = _finding(payload=f"{hhs.new_token()}.example-collab.com")
        self.assertEqual(finding_identity(first), finding_identity(second))

    def test_a_cache_buster_in_the_url_is_folded(self):
        first = _finding(url=f"https://t/?cb={hhs.new_token(10)}")
        second = _finding(url=f"https://t/?cb={hhs.new_token(10)}")
        self.assertEqual(finding_identity(first), finding_identity(second))

    def test_two_virtual_hosts_named_in_hex_stay_apart(self):
        # The case the shape-based fold collapsed.
        self.assertNotEqual(
            finding_identity(_finding("Virtual Host Discovery",
                                      header_name="Host", payload="deadbeef")),
            finding_identity(_finding("Virtual Host Discovery",
                                      header_name="Host", payload="cafebabe")))

    def test_two_urls_differing_only_by_a_hex_segment_stay_apart(self):
        self.assertNotEqual(
            finding_identity(_finding(url="https://t/u/4f1c9ab2e7/profile")),
            finding_identity(_finding(url="https://t/u/77d0c9e4a1/profile")))

    def test_a_marker_from_before_the_prefix_is_not_recognised(self):
        # Deliberate, and the cost of the fix. Those markers sat in contexts
        # this module cannot anchor to - a CORS origin is built around the
        # target's own hostname - so recognising them would mean folding bare
        # hexadecimal next to arbitrary text, which is the defect being fixed.
        # Identities from before the prefix change once; a comparison that
        # matches nothing says so, rather than leaving it to be guessed at.
        self.assertNotEqual(
            finding_identity(_finding(payload="9c1d4ba7f3e2.example-collab.com")),
            finding_identity(
                _finding(payload=f"{hhs.new_token()}.example-collab.com")))

    def test_an_internal_host_is_never_folded(self):
        self.assertNotEqual(
            finding_identity(_finding("SSRF", payload="169.254.169.254")),
            finding_identity(_finding("SSRF", payload="127.0.0.1")))


class BaselineDiagnosticTests(unittest.TestCase):
    """A comparison that matches nothing has to say so.

    Zero overlap between two non-empty sets is almost never what the operator
    meant, and the summary alone - every finding new, every baseline entry
    fixed - does not say why. A baseline from a version whose identities
    differed looks exactly like the wrong file for the target.
    """

    class _Args:
        def __init__(self, baseline):
            self.baseline = baseline

    def _resolve(self, stored, current):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            with io.open(path, "w", encoding="utf-8") as handle:
                json.dump(stored, handle)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                drift = resolve_drift(self._Args(path), [_Stub(current)])
            return drift, buffer.getvalue(), path

    def test_zero_overlap_is_explained(self):
        old_marker = _finding(payload="9c1d4ba7f3e2.example-collab.com")
        now = _finding(payload=f"{hhs.new_token()}.example-collab.com")
        drift, printed, path = self._resolve([old_marker], [now])
        self.assertEqual(len(drift["new"]), 1)
        self.assertEqual(drift["unchanged"], [])
        self.assertIn("Nothing in", printed)
        self.assertIn(os.path.basename(path), printed)
        self.assertIn("older version", printed)

    def test_an_overlap_is_not_explained(self):
        marker = _finding(payload=f"{hhs.new_token()}.example-collab.com")
        _, printed, _ = self._resolve([marker], [marker])
        self.assertNotIn("Nothing in", printed)

    def test_a_first_run_against_an_empty_baseline_is_not_explained(self):
        # Nothing to match is not a mismatch.
        _, printed, _ = self._resolve([], [_finding()])
        self.assertNotIn("Nothing in", printed)


class CompareTests(unittest.TestCase):
    def test_unchanged_findings_are_not_new(self):
        current = [_finding(payload=f"{hhs.new_token()}.example-collab.com")]
        baseline = [_finding(payload=f"{hhs.new_token()}.example-collab.com")]
        drift = compare(current, baseline)
        self.assertEqual(len(drift["unchanged"]), 1)
        self.assertEqual(drift["new"], [])
        self.assertEqual(drift["fixed"], [])

    def test_a_regression_is_new(self):
        drift = compare([_finding("SSRF")], [])
        self.assertEqual(len(drift["new"]), 1)
        self.assertEqual(drift["new_identities"],
                         {finding_identity(_finding("SSRF"))})

    def test_something_gone_is_fixed(self):
        drift = compare([], [_finding("SSRF")])
        self.assertEqual(len(drift["fixed"]), 1)
        self.assertEqual(drift["new"], [])

    def test_describe_reads_as_a_summary(self):
        drift = compare([_finding("SSRF")], [_finding("Open Redirect")])
        self.assertEqual(describe_drift(drift), "1 new, 1 fixed, 0 unchanged")

    def test_collect_findings_walks_every_check(self):
        tests = [_Stub([_finding("SSRF")]), _Stub([_finding("Open Redirect")])]
        self.assertEqual(len(collect_findings(tests)), 2)


class LoadBaselineTests(unittest.TestCase):
    def _write(self, body):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(body)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_reads_the_scanners_own_json_output(self):
        path = self._write(json.dumps([_finding("SSRF")]))
        self.assertEqual(len(load_baseline(path)), 1)

    def test_accepts_a_wrapped_findings_list(self):
        path = self._write(json.dumps({"findings": [_finding("SSRF")]}))
        self.assertEqual(len(load_baseline(path)), 1)

    def test_a_missing_file_is_not_an_empty_baseline(self):
        # An empty baseline would make every current finding look new, which is
        # the opposite of what the caller asked for.
        self.assertIsNone(load_baseline("/nonexistent/baseline.json"))

    def test_malformed_json_is_not_an_empty_baseline(self):
        self.assertIsNone(load_baseline(self._write("{not json")))

    def test_unexpected_shape_is_not_an_empty_baseline(self):
        self.assertIsNone(load_baseline(self._write(json.dumps("hello"))))

    def test_no_path_means_no_baseline(self):
        self.assertIsNone(load_baseline(None))


class RegressionGatingTests(unittest.TestCase):
    def _tests(self):
        return [_Stub([
            _finding("SSRF", finding_class=CLASS_VULNERABILITY),
            _finding("Referrer-Policy", header_name="Referrer-Policy",
                     finding_class=CLASS_POSTURE),
        ])]

    def test_without_a_baseline_every_finding_counts(self):
        self.assertEqual(hhs.gated_finding_count(self._tests(), "any"), 2)

    def test_gating_on_new_only_counts_the_regression(self):
        tests = self._tests()
        baseline = [_finding("SSRF", finding_class=CLASS_VULNERABILITY)]
        drift = compare(collect_findings(tests), baseline)
        counted = hhs.gated_finding_count(
            tests, "any", only_identities=drift["new_identities"],
            identity_of=finding_identity)
        self.assertEqual(counted, 1)

    def test_nothing_new_gates_nothing(self):
        tests = self._tests()
        drift = compare(collect_findings(tests), collect_findings(tests))
        counted = hhs.gated_finding_count(
            tests, "any", only_identities=drift["new_identities"],
            identity_of=finding_identity)
        self.assertEqual(counted, 0)

    def test_class_still_applies_on_top(self):
        tests = self._tests()
        drift = compare(collect_findings(tests), [])
        counted = hhs.gated_finding_count(
            tests, "vuln", only_identities=drift["new_identities"],
            identity_of=finding_identity)
        self.assertEqual(counted, 1)


class DriftControlTests(unittest.TestCase):
    def _status(self, drift):
        evidence = build_evidence([], ["https://t/"], drift=drift)
        return next(r for r in evidence["controls"]
                    if r.control.id == DRIFT_CONTROL)

    def test_running_the_comparison_is_what_satisfies_the_control(self):
        # 11.6.1 asks for a change-detection mechanism. Performing the
        # comparison is the mechanism working; a detected change is its output,
        # not a failure of the control.
        result = self._status(compare([_finding("SSRF")], []))
        self.assertEqual(result.status, STATUS_PASS)
        self.assertIn("1 new", result.assessed_by[0])

    def test_without_a_baseline_it_is_not_assessed(self):
        result = self._status(None)
        self.assertEqual(result.status, STATUS_NOT_ASSESSED)
        self.assertIn("--baseline", result.not_assessed_because[0])

    def test_the_control_is_catalogued_against_pci(self):
        control = hhs.CONTROLS[DRIFT_CONTROL]
        self.assertEqual(control.framework, "PCI DSS 4.0.1")
        self.assertEqual(control.section, "11.6.1")


class CliTests(unittest.TestCase):
    def test_fail_on_new_requires_a_baseline(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--fail-on-new"]):
            with self.assertRaises(SystemExit):
                hhs.parse_arguments()

    def test_baseline_and_fail_on_new_together_are_accepted(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--baseline", "b.json",
                                     "--fail-on-new"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.baseline, "b.json")
        self.assertTrue(args.fail_on_new)

    def test_defaults_are_off(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertIsNone(args.baseline)
        self.assertFalse(args.fail_on_new)


if __name__ == "__main__":
    unittest.main()
