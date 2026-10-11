"""Tests for the detection logic inside the individual test classes.

These exercise payload generation, response analysis and the reflection/redirect
decision code by driving the workers with queued fake responses - never the
network.
"""

import unittest

import requests

import headerhawk as hhs
from tests.helpers import FakeResponse, FakeSession


def make_test(cls, session, target="http://example.com/", host="example.com",
              **overrides):
    kwargs = dict(session=session, methods=["GET"], threads=1, verbose=1,
                  timeout=1)
    kwargs.update(overrides)
    return cls(target, host, **kwargs)


class HostInjectionMarkerTests(unittest.TestCase):
    def test_every_case_carries_the_marker(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        token, cases = test.generate_cases()
        self.assertTrue(cases)
        for _, _, shape, value in cases:
            self.assertIn(token, value, shape)

    def test_a_host_header_gets_the_shapes_worth_sending(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        _, cases = test.generate_cases()
        shapes = {shape for _, header, shape, _ in cases if header == "Host"}
        for shape in ("plain", "target as a prefix", "target as userinfo",
                      "appended to a list"):
            self.assertIn(shape, shapes)

    def test_forwarded_gets_its_own_syntax(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        _, cases = test.generate_cases()
        values = [value for _, header, _, value in cases
                  if header == "Forwarded"]
        self.assertTrue(values)
        for value in values:
            self.assertTrue(value.startswith(("host=", "for=")), value)

    def test_marker_uses_oob_manager_host(self):
        manager = hhs.OOBManager("oob.example.com")
        test = make_test(hhs.HostInjectionTest, FakeSession(), oob_manager=manager)
        _, cases = test.generate_cases()
        self.assertTrue(any("oob.example.com" in value
                            for _, _, _, value in cases))

    def test_worker_collects_a_reflection_without_reporting_it(self):
        # Reflections are gathered first and graded afterwards, so that five
        # shapes of one echoed header become one finding rather than five.
        test = make_test(hhs.HostInjectionTest, FakeSession())
        test.marker_token = "hhdeadbeef99"
        test.request = lambda *a, **k: FakeResponse(
            text="prefix hhdeadbeef99 suffix", url="http://example.com/")
        test.worker("GET", "X-Forwarded-Host", "plain",
                    "hhdeadbeef99.example-collab.com")
        self.assertEqual(len(test._hits), 1)
        self.assertEqual(test.vulnerabilities_found, [])

    def test_worker_ignores_unreflected(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        test.marker_token = "hhdeadbeef99"
        test.request = lambda *a, **k: FakeResponse(text="nothing here")
        test.worker("GET", "Host", "plain", "hhdeadbeef99.example-collab.com")
        self.assertEqual(test._hits, [])
        self.assertEqual(test.vulnerabilities_found, [])


class SSRFLogicTests(unittest.TestCase):
    def test_generate_payloads_includes_host_port_combos(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        payloads = test.generate_payloads()
        self.assertIn("169.254.169.254", payloads)
        self.assertIn("127.0.0.1:8080", payloads)

    def test_compute_baseline_measures_latency_and_learns_headers(self):
        # Drives the real baseline path end to end: it is the only caller of the
        # status() helper inside this module, so a broken import here would go
        # unnoticed until the first live scan.
        session = FakeSession(responses=[
            FakeResponse(headers={"Server": "nginx", "X-Request-Id": "a"}),
            FakeResponse(headers={"Server": "nginx", "X-Request-Id": "b"}),
            FakeResponse(headers={"Server": "nginx", "X-Request-Id": "c"}),
        ])
        test = make_test(hhs.SSRFTest, session, quiet=True)
        test.compute_baseline(samples=3)
        self.assertIsNotNone(test.typical_delay)
        self.assertEqual(test.stable_baseline_headers, {"Server": "nginx"})
        self.assertIn("x-request-id", test.volatile_headers)

    def test_compute_baseline_defaults_delay_when_every_request_fails(self):
        session = FakeSession(responses=[requests.RequestException()] * 3)
        test = make_test(hhs.SSRFTest, session, quiet=True)
        test.compute_baseline(samples=3)
        self.assertEqual(test.typical_delay, 1.0)
        self.assertEqual(test.stable_baseline_headers, {})

    def test_header_anomalies_flag_new_and_changed(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.stable_baseline_headers = {"Server": "nginx", "X-Env": "prod"}
        test.volatile_headers = {"x-request-id"}
        anomalies = test.detect_header_anomalies({
            "Server": "nginx",          # excluded -> ignored
            "X-Env": "staging",         # stable baseline header, changed
            "X-Request-Id": "abc123",   # learned volatile -> ignored
            "X-New": "1",               # genuinely new -> flagged
        })
        self.assertIn("'X-Env' changed", anomalies)
        self.assertIn("new header 'X-New'", anomalies)
        self.assertFalse(any("Request-Id" in a for a in anomalies))

    def test_header_anomalies_empty_without_stable_baseline(self):
        # With no stable reference, nothing is flagged (avoids noise-driven FPs).
        test = make_test(hhs.SSRFTest, FakeSession())
        self.assertEqual(test.detect_header_anomalies({"X-Any": "1"}), [])

    def test_learn_header_stability_partitions_headers(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test._learn_header_stability([
            {"Server": "nginx", "X-Env": "prod", "X-Req": "a"},
            {"Server": "nginx", "X-Env": "prod", "X-Req": "b"},   # X-Req varies
            {"Server": "nginx", "X-Env": "prod"},                  # X-Req absent
        ])
        self.assertEqual(test.stable_baseline_headers,
                         {"Server": "nginx", "X-Env": "prod"})
        self.assertIn("x-req", test.volatile_headers)

    def test_learn_header_stability_no_samples(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test._learn_header_stability([])
        self.assertEqual(test.stable_baseline_headers, {})
        self.assertEqual(test.volatile_headers, set())

    def test_analyze_records_high_score_indicator(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.results = [{
            "url": "http://example.com/",
            "method": "GET",
            "header_name": "Host",
            "payload": "169.254.169.254",
            "status_code": 200,
            "response_time": 0.1,
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "response_headers": {},
        }]
        test.analyze()
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertIn("root:x:0:0:", test.vulnerabilities_found[0]["analysis"])

    def test_timing_and_a_header_change_do_not_add_up_to_a_finding(self):
        # A slow reply and a response header that moved are what a target
        # under load looks like. Reported as SSRF at High, that is the fastest
        # way to teach an operator to ignore the tool, so neither signal and
        # not both together can reach the threshold.
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.stable_baseline_headers = {"Server": "nginx"}
        fast = {
            "url": "http://example.com/", "method": "GET",
            "header_name": "Host", "payload": "127.0.0.1", "status_code": 200,
            "response_time": 0.1, "response_body": "ok",
            "response_headers": {"Server": "nginx"},
        }
        slow = dict(fast, response_time=5.0,
                    response_headers={"Server": "nginx", "X-New": "1"})
        test.results = [dict(fast) for _ in range(20)] + [slow]
        test.analyze()
        self.assertEqual(test.vulnerabilities_found, [])

    def test_content_only_an_internal_target_returns_is_confirmed(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.results = [{
            "url": "http://example.com/", "method": "GET",
            "header_name": "Host", "payload": "169.254.169.254",
            "status_code": 200, "response_time": 0.1,
            "response_body": "ami-id: i-0abc", "response_headers": {},
        }]
        test.analyze()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)
        self.assertEqual(finding["test_result"], "Vulnerable")
        self.assertFalse(finding.get("confirmation"))

    def test_an_internal_error_string_is_reported_as_suspected(self):
        # Evidence that something tried to connect somewhere it should not,
        # which is worth reporting and is not proof of where it got to.
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.results = [{
            "url": "http://example.com/", "method": "GET",
            "header_name": "Host", "payload": "10.0.0.1", "status_code": 500,
            "response_time": 0.1, "response_body": "no route to host",
            "response_headers": {},
        }]
        test.analyze()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)
        self.assertIn("--oob", finding["confirmation"])

    def test_analyze_ignores_low_score(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.results = [{
            "url": "http://example.com/", "method": "GET",
            "header_name": "Host", "payload": "127.0.0.1", "status_code": 200,
            "response_time": 0.1, "response_body": "ok", "response_headers": {},
        }]
        test.analyze()
        self.assertEqual(test.vulnerabilities_found, [])


class OpenRedirectTests(unittest.TestCase):
    def test_payloads_prepend_oob(self):
        manager = hhs.OOBManager("oob.example.com")
        test = make_test(hhs.OpenRedirectTest, FakeSession(), oob_manager=manager)
        payloads = test.generate_payloads()
        self.assertIn("oob.example.com", payloads[0])

    @staticmethod
    def _redirecting(payload_host=None):
        """Answer every request with a redirect to the Host it was sent."""
        def respond(method, url=None, headers=None, **kwargs):
            host = payload_host or (headers or {}).get("Host", "")
            return FakeResponse(status_code=302, url="http://example.com/",
                                headers={"Location": f"http://{host}/"})
        return respond

    def test_worker_collects_a_matching_redirect_without_reporting_it(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession())
        test.request = self._redirecting()
        test.worker("GET", "Host", "example.com")
        self.assertEqual(len(test._hits), 1)
        self.assertEqual(test.vulnerabilities_found, [])

    def test_worker_ignores_non_matching_host(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession())
        test.request = lambda *a, **k: FakeResponse(
            status_code=302, headers={"Location": "http://real-site/"})
        test.worker("GET", "Host", "example.com")
        self.assertEqual(test._hits, [])

    def test_worker_ignores_non_redirect_status(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession())
        test.request = lambda *a, **k: FakeResponse(status_code=200)
        test.worker("GET", "Host", "example.com")
        self.assertEqual(test._hits, [])

    def test_every_accepted_host_is_one_finding(self):
        # Several payloads reach the same conclusion - the redirect follows the
        # Host header - which is one defect with one place to fix it.
        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = self._redirecting()
        test.run()
        self.assertEqual(len(test.vulnerabilities_found), 1)
        analysis = test.vulnerabilities_found[0]["analysis"]
        for host in ("example.com", "www.example.com"):
            self.assertIn(host, analysis)

    def test_only_hosts_that_held_are_listed_as_accepted(self):
        # Listing a host that matched once, or one that was never re-probed
        # because another candidate confirmed first, would report it as
        # accepted on evidence the scan does not have.
        seen = []

        def respond(method, url=None, headers=None, **kwargs):
            host = (headers or {}).get("Host", "")
            seen.append(host)
            # www.example.com redirects once and then stops; everything else
            # keeps redirecting.
            if host.startswith("www.") and seen.count(host) > 1:
                return FakeResponse(status_code=200, url="http://example.com/")
            return FakeResponse(status_code=302, url="http://example.com/",
                                headers={"Location": f"http://{host}/"})

        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = respond
        test.run()
        analysis = test.vulnerabilities_found[0]["analysis"]
        self.assertIn("example.com", analysis)
        self.assertNotIn("www.example.com", analysis)

    def test_a_minted_host_is_what_confirms(self):
        # A fixed hostname cannot tell "the destination follows the header"
        # from "this is where the site always redirects".
        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = self._redirecting()
        test.run()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)
        self.assertIn(hhs.MARKER_PREFIX, finding["payload"])

    def test_a_canonical_redirect_is_not_a_finding(self):
        # A site that always redirects to its own canonical host, ignoring the
        # header, used to be reported as a confirmed open redirect whenever
        # that host happened to be one of the probe hostnames.
        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = lambda *a, **k: FakeResponse(
            status_code=301, url="http://example.com/",
            headers={"Location": "https://example.com/"})
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])

    def test_well_known_hosts_alone_are_not_proof(self):
        # An allowlist that includes them, an application that resolves a
        # destination before redirecting, or a coincidence - 3.7.2 asks for an
        # allowlist, so none of those is reported as a failure of it.
        def respond(method, url=None, headers=None, **kwargs):
            host = (headers or {}).get("Host", "")
            if host.startswith(("example.com", "www.example.com")):
                return FakeResponse(status_code=302, url="http://example.com/",
                                    headers={"Location": f"https://{host}/go"})
            return FakeResponse(status_code=200, url="http://example.com/")

        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = respond
        test.run()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)
        self.assertIn("minted for this scan", finding["analysis"])
        self.assertIn("--oob", finding["confirmation"])

    def test_a_redirect_that_holds_twice_is_confirmed(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = self._redirecting()
        test.run()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_CONFIRMED)
        self.assertEqual(finding["test_result"], "Vulnerable")

    def test_a_redirect_that_does_not_hold_is_suspected(self):
        seen = []

        def respond(method, url=None, headers=None, **kwargs):
            host = (headers or {}).get("Host", "")
            seen.append(host)
            if seen.count(host) > 1:          # the repeat probe
                return FakeResponse(status_code=200, url="http://example.com/")
            return FakeResponse(status_code=302, url="http://example.com/",
                                headers={"Location": f"http://{host}/"})

        test = make_test(hhs.OpenRedirectTest, FakeSession(), quiet=True)
        test.request = respond
        test.run()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["confidence"], hhs.CONFIDENCE_SUSPECTED)
        self.assertIn("did not redirect the same way", finding["analysis"])


class URLParameterTests(unittest.TestCase):
    def test_is_response_different_by_status(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        test.baseline_response = FakeResponse(status_code=200, text="x" * 100)
        self.assertTrue(test.is_response_different(FakeResponse(status_code=500, text="x" * 100)))

    def test_is_response_different_by_length(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        test.baseline_response = FakeResponse(status_code=200, text="x" * 100)
        self.assertTrue(test.is_response_different(FakeResponse(status_code=200, text="x" * 200)))

    def test_is_response_same(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        test.baseline_response = FakeResponse(status_code=200, text="x" * 100)
        self.assertFalse(test.is_response_different(FakeResponse(status_code=200, text="x" * 100)))

    def test_analyze_response_scores_indicator(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        analysis = test.analyze_response(FakeResponse(text="root:x:0:0:root"))
        self.assertIsNotNone(analysis)
        self.assertIn("root:x:0:0:", analysis)

    def test_analyze_response_low_score_returns_none(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        self.assertIsNone(test.analyze_response(FakeResponse(text="permission denied")))


class CachePoisoningTests(unittest.TestCase):
    def test_url_with_buster_adds_cb_param(self):
        test = make_test(hhs.CachePoisoningTest, FakeSession(),
                         target="http://example.com/page?a=1")
        url = test._url_with_buster("xyz")
        self.assertIn("cb=xyz", url)
        self.assertIn("a=1", url)

    def test_worker_confirms_poisoning(self):
        # The worker mints the token through core.markers, so it carries the
        # scanner's prefix; both the request and the re-request bodies must
        # carry that whole token to confirm poisoning.
        token = hhs.MARKER_PREFIX + "TOKENTOKEN00"
        session = FakeSession(responses=[
            FakeResponse(text=f"reflected {token} here"),    # poison request
            FakeResponse(text=f"still {token} cached"),      # confirm request
        ])
        test = make_test(hhs.CachePoisoningTest, session)

        import uuid
        original = uuid.uuid4

        class Fixed:
            hex = "TOKENTOKEN00"

        uuid.uuid4 = lambda: Fixed()
        try:
            test.worker("X-Forwarded-Host")
        finally:
            uuid.uuid4 = original
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertEqual(test.vulnerabilities_found[0]["test_result"], "Vulnerable")


class AuthBypassTests(unittest.TestCase):
    def test_worker_records_status_improvement(self):
        test = make_test(hhs.AuthBypassTest, FakeSession())
        test.baseline_status = 403
        test.baseline_len = 10
        test.request = lambda *a, **k: FakeResponse(status_code=200, text="secret")
        test.worker("host", "X-Forwarded-Host", "localhost")
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertEqual(test.vulnerabilities_found[0]["test_result"], "Vulnerable")

    def test_worker_ignores_when_no_improvement(self):
        test = make_test(hhs.AuthBypassTest, FakeSession())
        test.baseline_status = 403
        test.baseline_len = 10
        test.request = lambda *a, **k: FakeResponse(status_code=403)
        test.worker("host", "Host", "localhost")
        self.assertEqual(test.vulnerabilities_found, [])


class VhostDiscoveryTests(unittest.TestCase):
    def test_title_extraction(self):
        self.assertEqual(hhs.VhostDiscoveryTest._title("<title> Admin </title>"), "Admin")

    def test_title_missing_returns_empty(self):
        self.assertEqual(hhs.VhostDiscoveryTest._title("<h1>no title</h1>"), "")

    def test_candidate_hosts_shapes(self):
        test = make_test(hhs.VhostDiscoveryTest, FakeSession())
        hosts = test.candidate_hosts("admin")
        self.assertIn("admin", hosts)
        self.assertIn("admin.example.com", hosts)
        self.assertIn("admin.internal", hosts)

    def _vhost_with_baseline(self):
        test = make_test(hhs.VhostDiscoveryTest, FakeSession())
        test.baseline_status = 404
        test.baseline_len = 1000
        test.baseline_titles = {"Not Found"}
        test.len_tolerance = 256
        return test

    def test_distinct_signal_stable_status_change(self):
        test = self._vhost_with_baseline()
        signal = test._distinct_signal((200, 1000, ""), (200, 1000, ""))
        self.assertIsNotNone(signal)
        self.assertIn("status 200", signal)

    def test_distinct_signal_rejects_transient_length(self):
        # First probe looks big, second matches baseline -> not consistent.
        test = self._vhost_with_baseline()
        self.assertIsNone(test._distinct_signal((404, 5000, ""), (404, 1000, "")))

    def test_distinct_signal_confirms_consistent_length(self):
        test = self._vhost_with_baseline()
        signal = test._distinct_signal((404, 5000, ""), (404, 5010, ""))
        self.assertIsNotNone(signal)
        self.assertIn("body length", signal)

    def test_distinct_signal_within_tolerance_is_none(self):
        test = self._vhost_with_baseline()
        self.assertIsNone(test._distinct_signal((404, 1100, ""), (404, 1100, "")))

    def test_worker_records_confirmed_distinct_host(self):
        test = self._vhost_with_baseline()
        # Every candidate_hosts() shape returns a stable 200 (distinct from 404).
        test._measure = lambda host: (200, 1200, "Admin")
        test.worker("admin")
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertIn("confirmed on two probes",
                      test.vulnerabilities_found[0]["analysis"])

    def test_worker_ignores_transient_difference(self):
        test = self._vhost_with_baseline()
        # First probe differs, confirming probe reverts to baseline -> dropped.
        measurements = iter([
            (404, 6000, ""), (404, 1000, ""),   # host 1: transient
            (404, 6000, ""), (404, 1000, ""),   # host 2: transient
            (404, 6000, ""), (404, 1000, ""),   # host 3: transient
        ])
        test._measure = lambda host: next(measurements)
        test.worker("admin")
        self.assertEqual(test.vulnerabilities_found, [])


if __name__ == "__main__":
    unittest.main()
