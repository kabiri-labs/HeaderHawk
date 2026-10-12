"""Tests for the host validation bypass check.

The question these pin is the one the check used to skip: was there a refusal
for a bypass to get past? A marker host coming back proves a parser accepted a
shape, and on a target that validates nothing it proves nothing was defeated.
An ordinary, well-formed Host header is the baseline that settles that, which
is why it is not among the techniques any more - it cannot be a bypass in
either direction.
"""

import unittest
from urllib.parse import urlsplit

import headerhawk as hhs
from headerhawk.checks.host_bypass import HostBypassTest
from tests.helpers import FakeSession

KNOWN_HOST = "t.example"
TARGET = f"http://{KNOWN_HOST}/page"

# What the lab declares on a target that reads every Host header it is sent.
# These are the true positives the baseline control must not cost.
DECLARED_SHAPES = (
    "Duplicate Host header",
    "Absolute-URI request line",
    "Indented (line-folded) Host header",
    "Tab-folded Host header",
    "Duplicate Host header, injected first",
)


def _host_values(header_lines):
    """Every host a permissive parser would read out of these lines."""
    values = []
    for line in header_lines:
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "host":
            values.append(value.strip())
    return values


def _strict_first_host(header_lines):
    """The one host a conformant front-end reads: the first well-formed line.

    A continuation line is not a field, and RFC 7230 says whitespace before the
    colon must be rejected rather than read - so neither is a Host header here.
    """
    for line in header_lines:
        if line[:1] in (" ", "\t"):
            continue
        name, separator, value = line.partition(":")
        if not separator or name != name.strip():
            continue
        if name.lower() == "host":
            return value.strip()
    return None


def _request_line_host(request_line):
    """The host of an absolute-URI request line, or "" for an origin-form one."""
    parts = request_line.split(" ")
    target = parts[1] if len(parts) > 1 else ""
    return urlsplit(target).hostname or "" if "://" in target else ""


def _reflecting(request_line, header_lines):
    """An application that echoes every host the request named."""
    hosts = _host_values(header_lines)
    uri_host = _request_line_host(request_line)
    if uri_host:
        hosts.append(uri_host)
    body = "".join(f"<li>{host}</li>" for host in hosts)
    return hhs.RawResponse(200, [("Content-Type", "text/html")], body)


def _refuses_the_unknown(request_line, header_lines):
    """A front-end that answers 403 for any host it does not serve.

    It reads the first well-formed Host line, which is what lets a folded or
    appended second one past it and into the reflecting application behind -
    the bypass this check exists to find.
    """
    if _strict_first_host(header_lines) != KNOWN_HOST:
        return hhs.RawResponse(403, [], "Forbidden")
    return _reflecting(request_line, header_lines)


def _refuses_and_reflects_nothing(request_line, header_lines):
    """The same refusal, in front of an application that echoes nothing."""
    if _strict_first_host(header_lines) != KNOWN_HOST:
        return hhs.RawResponse(403, [], "Forbidden")
    return hhs.RawResponse(200, [], "<html>home</html>")


class _RawClient:
    """Stand-in for the raw client, answering from a policy callable."""

    def __init__(self, policy):
        self.policy = policy
        self.sent = []

    def send(self, scheme, host, port, request_line, header_lines,
             sni_host=None):
        self.sent.append((request_line, list(header_lines)))
        return self.policy(request_line, list(header_lines))


def _make(policy):
    test = HostBypassTest(TARGET, KNOWN_HOST, session=FakeSession(), timeout=1,
                          threads=1, verbose=0, quiet=True)
    test.client = _RawClient(policy)
    return test


def _run(policy):
    test = _make(policy)
    test.run()
    return test


def _by_technique(test):
    return {finding["header_name"]: finding
            for finding in test.vulnerabilities_found}


class HostOverrideTests(unittest.TestCase):
    """The false positive: a bypass reported with nothing to bypass."""

    def test_an_ordinary_host_header_is_not_among_the_techniques(self):
        # It is the baseline instead. Where an unknown host is refused it is
        # the refusal; where it is not, there was nothing to get past.
        names = [name for name, _, _ in _make(_reflecting).techniques("m.test")]
        self.assertNotIn("Host override", names)

    def test_a_target_that_validates_nothing_reports_no_host_override(self):
        test = _run(_reflecting)
        self.assertNotIn("Host override", _by_technique(test))

    def test_no_finding_claims_a_refusal_that_never_happened(self):
        for finding in _run(_reflecting).vulnerabilities_found:
            self.assertIn("Nothing here was refusing an unknown host",
                          finding["analysis"], finding["header_name"])
            self.assertNotIn("got past that refusal", finding["analysis"])


class DeclaredShapesTests(unittest.TestCase):
    """The control must not cost the findings that were always right."""

    def test_every_declared_shape_is_still_reported_at_high(self):
        found = _by_technique(_run(_reflecting))
        for shape in DECLARED_SHAPES:
            self.assertIn(shape, found)
            self.assertEqual(found[shape]["severity"], "High", shape)

    def test_the_reflection_evidence_is_still_named(self):
        found = _by_technique(_run(_reflecting))
        self.assertIn("Marker reflected in response body.",
                      found["Duplicate Host header"]["analysis"])


class RefusedHostTests(unittest.TestCase):
    """A refusal that was got past is the finding this check is named for."""

    def test_a_shape_that_got_past_a_refusal_says_so(self):
        found = _by_technique(_run(_refuses_the_unknown))
        analysis = found["Tab-folded Host header"]["analysis"]
        self.assertIn("got past that refusal", analysis)
        self.assertIn("403", analysis)
        self.assertIn("the host is validated here", analysis)

    def test_the_baseline_records_the_refusal(self):
        refused, ordinary, unknown = _run(_refuses_the_unknown).host_validation
        self.assertTrue(refused)
        self.assertEqual((ordinary, unknown), (200, 403))

    def test_a_refusal_nothing_got_past_is_reported_as_nothing(self):
        # The guarded front-end: every unknown host refused and no shape
        # reaching anything that would echo one back.
        test = _run(_refuses_and_reflects_nothing)
        self.assertEqual(test.vulnerabilities_found, [])
        self.assertTrue(test.assessed)
        self.assertTrue(test.host_validation[0])


class BaselineTests(unittest.TestCase):
    def test_two_well_formed_requests_establish_it(self):
        test = _run(_reflecting)
        ordinary, unknown = test.client.sent[0], test.client.sent[1]
        self.assertEqual(_host_values(ordinary[1]), [KNOWN_HOST])
        self.assertEqual(len(_host_values(unknown[1])), 1)
        self.assertNotEqual(_host_values(unknown[1]), [KNOWN_HOST])

    def test_the_unknown_host_is_not_the_probe_marker(self):
        # Otherwise the baseline would plant the very value the techniques
        # look for, and a reflecting target would hand it back to all of them.
        test = _run(_reflecting)
        self.assertNotIn(test.marker_token, _host_values(test.client.sent[1][1])[0])

    def test_a_dropped_connection_for_an_unknown_host_is_a_refusal(self):
        def policy(request_line, header_lines):
            if _strict_first_host(header_lines) != KNOWN_HOST:
                return None
            return _reflecting(request_line, header_lines)

        refused, ordinary, unknown = _run(policy).host_validation
        self.assertTrue(refused)
        self.assertIsNone(unknown)
        self.assertEqual(ordinary, 200)

    def test_an_unparsable_reply_is_not_read_as_a_refusal(self):
        # A status of 0 is a reply this client could not parse. Reading it as a
        # refusal would invent the precondition the baseline exists to check.
        def policy(request_line, header_lines):
            if _strict_first_host(header_lines) != KNOWN_HOST:
                return hhs.RawResponse(0, [], "")
            return _reflecting(request_line, header_lines)

        self.assertFalse(_run(policy).host_validation[0])

    def test_a_target_that_does_not_answer_is_skipped_with_a_reason(self):
        test = _run(lambda request_line, header_lines: None)
        self.assertTrue(test.skipped)
        self.assertIn("could not be established", test.skip_reason)
        self.assertEqual(test.vulnerabilities_found, [])

    def test_the_techniques_do_not_run_without_a_baseline(self):
        # Two probes attempted, nothing after them: a reflection that arrived
        # could not have been graded either way.
        test = _run(lambda request_line, header_lines: None)
        self.assertEqual(len(test.client.sent), 1)

    def test_a_url_with_no_hostname_is_skipped_before_any_request(self):
        test = HostBypassTest("http:///page", None, session=FakeSession(),
                              timeout=1, verbose=0, quiet=True)
        test.client = _RawClient(_reflecting)
        test.run()
        self.assertIn("no hostname", test.skip_reason)
        self.assertEqual(test.client.sent, [])


if __name__ == "__main__":
    unittest.main()
