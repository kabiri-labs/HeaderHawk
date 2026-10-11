"""Tests for what a reflected routing header is taken to prove.

A unique marker coming back says the application copied the header into its
output. It does not say the application routes on it. The two used to be the
same finding; they are now two grades, and these tests are what stops the
weaker one being reported as the stronger again.
"""

import unittest

import headerhawk as hhs
from tests.helpers import FakeResponse, FakeSession

TOKEN = "hhdeadbeef1234"
MARKER = f"{TOKEN}.example-collab.com"
TARGET = "app.example.com"


def _test(responder, **overrides):
    """A check whose requests are answered by ``responder(headers)``."""
    check = hhs.HostInjectionTest(f"https://{TARGET}/", TARGET,
                                  session=FakeSession(), methods=["GET"],
                                  threads=1, verbose=0, timeout=1, quiet=True,
                                  **overrides)
    check.marker_token = TOKEN
    check.request = lambda method, url=None, headers=None, **kwargs: responder(
        headers or {})
    return check


def _reflecting(**kwargs):
    """Answer every request with the same response."""
    return lambda headers: FakeResponse(url=f"https://{TARGET}/", **kwargs)


def _probe(check, header="X-Forwarded-Host", shape="plain", value=MARKER):
    check.worker("GET", header, shape, value)


class BodyTextOnlyTests(unittest.TestCase):
    """The marker echoed into the page, and nothing more."""

    def setUp(self):
        self.check = _test(_reflecting(text=f"<p>Host: {MARKER}</p>"))
        _probe(self.check)
        self.check.report()
        self.finding = self.check.vulnerabilities_found[0]

    def test_it_is_reported(self):
        # Worth reporting: the header reaches the output. Just not as proof.
        self.assertEqual(len(self.check.vulnerabilities_found), 1)

    def test_it_is_suspected_not_confirmed(self):
        self.assertEqual(self.finding["confidence"], hhs.CONFIDENCE_SUSPECTED)
        self.assertEqual(self.finding["test_result"], "Potentially Vulnerable")

    def test_it_says_what_would_settle_it(self):
        self.assertIn("--oob", self.finding["confirmation"])

    def test_it_is_banded_for_triage_not_hidden(self):
        # Low, because echoing a header is not a demonstrated exploit - but
        # still a vulnerability-class finding, so the threshold that quiets
        # posture noise does not quiet this and the gate still counts it.
        self.assertEqual(self.finding["severity"], "Low")
        self.assertEqual(self.finding["finding_class"],
                         hhs.CLASS_VULNERABILITY)
        self.assertTrue(hhs.reportable(self.finding))
        self.assertEqual(
            hhs.gated_finding_count([self.check], "vuln"), 1)


class RoutedTests(unittest.TestCase):
    """The marker became a host the response hands to a browser."""

    def _confirmed(self, **response):
        check = _test(_reflecting(**response))
        _probe(check)
        check.report()
        self.assertEqual(len(check.vulnerabilities_found), 1)
        return check.vulnerabilities_found[0]

    def test_a_location_host_confirms(self):
        finding = self._confirmed(status_code=302,
                                  headers={"Location": f"https://{MARKER}/next"})
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)
        self.assertEqual(finding["test_result"], "Vulnerable")
        self.assertIn(MARKER, finding["analysis"])

    def test_an_absolute_url_in_the_body_confirms(self):
        finding = self._confirmed(
            text=f'<a href="https://{MARKER}/reset">reset your password</a>')
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_a_confirmed_finding_keeps_its_own_band(self):
        finding = self._confirmed(status_code=302,
                                  headers={"Location": f"https://{MARKER}/"})
        self.assertEqual(finding["severity"], "Medium")

    def test_the_marker_as_userinfo_does_not_confirm(self):
        # https://target@marker/ sends a browser to the target, so calling it
        # attacker-controlled routing would be exactly the over-claim this
        # check exists to avoid.
        finding = self._confirmed(
            text=f'<a href="https://{TARGET}@{MARKER}.evil/">x</a>'
                 f'<a href="https://{MARKER}@{TARGET}/">y</a>')
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_only_userinfo_does_not_confirm(self):
        finding = self._confirmed(
            text=f'<a href="https://{MARKER}@{TARGET}/pay">pay</a>')
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)


class NavigableEvidenceTests(unittest.TestCase):
    """Only a URL something points *at* is a destination."""

    def _grade(self, **response):
        check = _test(_reflecting(**response))
        _probe(check)
        check.report()
        self.assertEqual(len(check.vulnerabilities_found), 1)
        return check.vulnerabilities_found[0]

    def test_a_url_printed_as_text_is_not_a_link(self):
        # A diagnostic page that prints the URL it reconstructed is the most
        # common shape of plain echo there is. Reading it as a link would
        # confirm a primitive that does not exist.
        finding = self._grade(
            text=f"<pre>Requested https://{MARKER}/account</pre>")
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)

    def test_a_url_in_a_json_field_is_not_a_link(self):
        finding = self._grade(text=f'{{"requested": "https://{MARKER}/"}}')
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)

    def test_a_form_action_is_a_link(self):
        finding = self._grade(
            text=f'<form action="https://{MARKER}/pay" method="post">')
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_a_meta_refresh_is_a_link(self):
        finding = self._grade(
            text=f'<meta http-equiv="refresh" content="0;url=https://{MARKER}/">')
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_a_location_on_a_redirect_is_a_link(self):
        finding = self._grade(status_code=302,
                              headers={"Location": f"https://{MARKER}/next"})
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)

    def test_a_location_on_a_non_redirect_is_not(self):
        # A browser does not follow Location beside a 200.
        finding = self._grade(status_code=200,
                              headers={"Location": f"https://{MARKER}/next"})
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)


class MalformedUrlTests(unittest.TestCase):
    def test_an_unbracketed_ipv6_authority_does_not_stop_the_check(self):
        # The authority regex used to stop at the closing bracket, and the
        # truncated result made urlparse raise - which aborted the whole check
        # and discarded every reflection it had collected.
        check = _test(_reflecting(
            text=f'<p>{MARKER}</p><a href="http://[2001:db8::1]/">peer</a>'))
        _probe(check)
        check.report()
        self.assertEqual(len(check.vulnerabilities_found), 1)

    def test_a_bracketed_ipv6_host_is_read_whole(self):
        from headerhawk.checks.host_injection import _host_of

        self.assertEqual(_host_of("http://[2001:db8::1]/"), "2001:db8::1")
        self.assertEqual(_host_of("http://[not an address/"), "")


class SecondProbeTests(unittest.TestCase):
    def test_a_host_that_does_not_come_back_twice_is_not_confirmed(self):
        # One response is an observation; the page may simply have been
        # rendering that at the time.
        answers = [
            FakeResponse(url=f"https://{TARGET}/", status_code=302,
                         headers={"Location": f"https://{MARKER}/next"}),
            FakeResponse(url=f"https://{TARGET}/", text="nothing here now"),
        ]
        check = _test(lambda headers: answers.pop(0))
        _probe(check)
        check.report()
        finding = check.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)
        self.assertEqual(answers, [])  # the second probe really was sent

    def test_the_finding_does_not_deny_what_was_seen(self):
        # It did reach a URL host once. An evidence line saying nothing
        # pointed at the marker would contradict the scan's own observation.
        answers = [
            FakeResponse(url=f"https://{TARGET}/", status_code=302,
                         headers={"Location": f"https://{MARKER}/next"}),
            FakeResponse(url=f"https://{TARGET}/", text="nothing here now"),
        ]
        check = _test(lambda headers: answers.pop(0))
        _probe(check)
        check.report()
        finding = check.vulnerabilities_found[0]
        self.assertIn("did not produce it again", finding["analysis"])
        self.assertIn(MARKER, finding["analysis"])
        self.assertNotIn("Nothing in the response points", finding["analysis"])

    def test_every_shape_that_reached_a_host_gets_its_own_probe(self):
        # Workers finish in whatever order they finish in. If only the first
        # candidate were retried, a header whose stable shape was collected
        # second would be downgraded - differently from run to run.
        listed = f"{TARGET}, {MARKER}"
        seen = []

        def responder(headers):
            value = headers.get("X-Forwarded-Host", "")
            seen.append(value)
            # Both shapes redirect to the marker at first. The list shape then
            # stops; the plain one keeps going. Sorted by shape, the list shape
            # is re-probed first, so reaching the stable one takes a second
            # attempt - which is the whole point.
            if value == listed and seen.count(listed) > 1:
                return FakeResponse(url=f"https://{TARGET}/", text="gone")
            return FakeResponse(url=f"https://{TARGET}/", status_code=302,
                                headers={"Location": f"https://{MARKER}/go"})

        check = _test(responder)
        # Collected in the order that used to decide the outcome: the transient
        # shape first, so retrying only that one downgrades the header.
        _probe(check, shape="appended to a list", value=listed)
        _probe(check, shape="plain", value=MARKER)
        check.report()
        finding = check.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)
        self.assertEqual(finding["payload"], MARKER)


class OneFindingPerHeaderTests(unittest.TestCase):
    def test_every_shape_that_worked_is_one_finding(self):
        check = _test(_reflecting(text=f"echo {MARKER}"))
        for shape, value in (("plain", MARKER),
                             ("target as a prefix", f"{TARGET}.{MARKER}"),
                             ("target as userinfo", f"{TARGET}@{MARKER}"),
                             ("appended to a list", f"{TARGET}, {MARKER}")):
            _probe(check, shape=shape, value=value)
        check.report()
        self.assertEqual(len(check.vulnerabilities_found), 1)
        analysis = check.vulnerabilities_found[0]["analysis"]
        for shape in ("plain", "target as a prefix", "target as userinfo",
                      "appended to a list"):
            self.assertIn(shape, analysis)

    def test_two_headers_are_two_findings(self):
        # One header, one place a fix goes; two headers, two.
        check = _test(_reflecting(text=f"echo {MARKER}"))
        _probe(check, header="X-Forwarded-Host")
        _probe(check, header="X-Original-Host")
        check.report()
        self.assertEqual(len(check.vulnerabilities_found), 2)
        self.assertEqual({f["header_name"] for f in check.vulnerabilities_found},
                         {"X-Forwarded-Host", "X-Original-Host"})

    def test_a_clean_target_reports_nothing(self):
        check = _test(_reflecting(text="<p>nothing of the sort</p>"))
        _probe(check)
        check.report()
        self.assertEqual(check.vulnerabilities_found, [])


class FindingTypeTests(unittest.TestCase):
    """The Host header is not a header an intermediary set.

    ASVS 4.1.3 is about a field "set by an intermediary layer" that the end
    user must not be able to override. The client sets Host, by definition of
    HTTP/1.1, so a finding about it cannot cite that requirement - and this
    product reports a finding without a requirement rather than citing a
    neighbouring one an assessor would challenge.
    """

    def _finding(self, header):
        check = _test(_reflecting(text=f"echo {MARKER}"))
        _probe(check, header=header)
        check.report()
        return check.vulnerabilities_found[0]

    def test_the_host_header_gets_its_own_type(self):
        finding = self._finding("Host")
        self.assertEqual(finding["test_type"], "Host Header Poisoning")

    def test_and_that_type_cites_no_requirement(self):
        self.assertEqual(self._finding("Host")["controls"], [])
        self.assertEqual(hhs.controls_for("Host Header Poisoning"), ())

    def test_an_intermediary_header_keeps_the_requirement_that_covers_it(self):
        finding = self._finding("X-Forwarded-Host")
        self.assertEqual(finding["test_type"], "Host Header Injection")
        self.assertEqual(finding["controls"], ["ASVS-5.0:4.1.3"])

    def test_the_new_type_is_reported_rather_than_dropped(self):
        # An unmapped finding renders at the end of the evidence report, which
        # is the whole point of allowing one.
        check = _test(_reflecting(text=f"echo {MARKER}"))
        _probe(check, header="Host")
        check.report()
        self.assertEqual(len(hhs.unmapped_findings([check])), 1)

    def test_both_types_are_declared_by_the_check(self):
        # The severity and compliance maps are checked for completeness
        # against what a check says it can emit.
        self.assertEqual(set(hhs.HostInjectionTest.emitted_types()),
                         {"Host Header Injection", "Host Header Poisoning"})


class EndToEndTests(unittest.TestCase):
    """Driven through run(), so the shapes really are sent."""

    def test_a_header_that_echoes_is_found_and_graded(self):
        def responder(headers):
            echoed = headers.get("X-Forwarded-Host", "")
            return FakeResponse(url=f"https://{TARGET}/",
                                text=f"<p>{echoed}</p>")

        check = _test(responder)
        check.marker_token = None
        check.run()
        self.assertEqual(len(check.vulnerabilities_found), 1)
        finding = check.vulnerabilities_found[0]
        self.assertEqual(finding["header_name"], "X-Forwarded-Host")
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)

    def test_a_target_that_redirects_to_the_injected_host_is_confirmed(self):
        def responder(headers):
            injected = headers.get("X-Forwarded-Host", "")
            if not injected:
                return FakeResponse(url=f"https://{TARGET}/", text="home")
            return FakeResponse(url=f"https://{TARGET}/", status_code=302,
                                headers={"Location": f"https://{injected}/go"})

        check = _test(responder)
        check.marker_token = None
        check.run()
        findings = check.vulnerabilities_found
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], hhs.CONFIDENCE_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
