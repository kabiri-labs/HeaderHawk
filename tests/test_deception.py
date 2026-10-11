"""Tests for web cache deception.

Two conditions have to hold and they are checked separately: the router must
ignore a static-looking suffix, and a shared cache must then keep the result.
The tests below pin the separation, the exactness the confirmation needs, and
the two ways this check could become useless - by reporting one defect five
times, or by staying quiet when a response already forbids caching.
"""

import unittest

import requests

import headerhawk as hhs
from headerhawk.checks.deception import (CONFIRMATION_NOTE, DECEPTIVE_SUFFIXES,
                                         CacheDeceptionTest)
from tests.helpers import FakeResponse

TARGET = "http://t.example/dashboard"
PRIVATE = "<html>Dashboard. Balance 4242. Sign out</html>"
PUBLIC = "<html>Please Sign in</html>"


class _App:
    """A target whose router optionally ignores a static-looking tail.

    ``responder`` is given the path and whether the request carried credentials.
    """

    def __init__(self, responder):
        self.verify = True
        self.headers = {"User-Agent": "hh"}
        self.proxies = {}
        self.cookies = {"sid": "good"}
        self.calls = []
        self._responder = responder

    def request(self, method, url=None, headers=None, timeout=None,
                allow_redirects=True, **kwargs):
        self.calls.append(url)
        return self._responder(url, True)


def _static_looking(url):
    return url.split("?")[0].endswith((".css", ".js", ".png"))


def _app(*, confuses_router, caches, private_body=PRIVATE):
    """Build a responder plus the anonymous view of the same server."""
    store = {}

    def responder(url, authenticated):
        if _static_looking(url) and not confuses_router:
            return FakeResponse(404, text="", url=url)
        if _static_looking(url) and caches and url in store:
            return FakeResponse(200, text=store[url],
                                headers={"X-Cache": "HIT"}, url=url)
        body = private_body if authenticated else PUBLIC
        if _static_looking(url) and caches:
            store[url] = body
        return FakeResponse(200, text=body, headers={"X-Cache": "MISS"},
                            url=url)
    return responder


def _make(responder, anonymous_responder=None):
    test = CacheDeceptionTest(TARGET, "t.example", session=_App(responder),
                              timeout=1, verbose=0, quiet=True)
    anonymous = anonymous_responder or (lambda url: responder(url, False))
    test._anonymous_get = anonymous
    return test


def _run(responder, anonymous_responder=None):
    test = _make(responder, anonymous_responder)
    test.run()
    return test


class PathConfusionTests(unittest.TestCase):
    def test_a_router_that_404s_the_suffix_ends_it(self):
        responder = _app(confuses_router=False, caches=True)
        self.assertEqual(_run(responder).vulnerabilities_found, [])

    def test_every_suffix_shape_is_tried(self):
        responder = _app(confuses_router=False, caches=False)
        test = _run(responder)
        tried = " ".join(test.session.calls)
        for _, template in DECEPTIVE_SUFFIXES:
            tail = template.format(path="/dashboard")
            self.assertIn(tail, tried, tail)

    def test_an_unreachable_target_is_skipped_with_a_reason(self):
        test = _make(lambda url, auth: None)
        test.session.request = lambda *a, **k: (_ for _ in ()).throw(
            requests.ConnectionError("nope"))
        test.run()
        self.assertFalse(test.assessed)
        self.assertIn("no page to compare", test.skip_reason)


class ServedAPageTests(unittest.TestCase):
    """An identical refusal served to everyone is not a victim's page.

    Every URL on a front-end that answers one status answers it for all five
    suffixes at once, so "the router ignored the suffix" is satisfied by
    something that has nothing in it to hand to the next requester.
    """

    @staticmethod
    def _uniform(status, body="Forbidden"):
        def responder(url, authenticated):
            return FakeResponse(status, text=body, url=url)
        return responder

    def test_a_front_end_that_forbids_everything_is_not_a_gadget(self):
        test = _run(self._uniform(403))
        self.assertEqual(test.vulnerabilities_found, [])

    def test_the_refusal_is_reported_as_unassessed_not_as_a_pass(self):
        test = _run(self._uniform(403))
        self.assertFalse(test.assessed)
        self.assertIn("403", test.skip_reason)
        self.assertIn("nothing a shared cache could store", test.skip_reason)

    def test_a_server_error_everywhere_is_not_a_gadget_either(self):
        test = _run(self._uniform(500))
        self.assertEqual(test.vulnerabilities_found, [])
        self.assertFalse(test.assessed)

    def test_a_uniform_redirect_is_not_a_gadget(self):
        # Its body is empty or boilerplate, so two of them compare equal under
        # the tolerant comparison for the same reason two error pages do.
        test = _run(self._uniform(302, body=""))
        self.assertEqual(test.vulnerabilities_found, [])
        self.assertIn("302", test.skip_reason)

    def test_the_bar_is_a_2xx_and_nothing_else(self):
        test = _make(_app(confuses_router=True, caches=False))
        for status in (200, 201, 204, 299):
            self.assertTrue(test._served_a_page(FakeResponse(status)), status)
        for status in (301, 302, 304, 400, 403, 404, 500):
            self.assertFalse(test._served_a_page(FakeResponse(status)), status)
        self.assertFalse(test._served_a_page(None))


class ConfirmationTests(unittest.TestCase):
    def test_a_stranger_served_the_private_page_is_confirmed(self):
        responder = _app(confuses_router=True, caches=True)
        found = _run(responder).vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "High")
        self.assertEqual(found[0]["test_result"], "Vulnerable")
        self.assertIn("no cookies or authorization", found[0]["analysis"])

    def test_confirmation_stops_at_the_first_proof(self):
        responder = _app(confuses_router=True, caches=True)
        found = _run(responder).vulnerabilities_found
        self.assertEqual(len(found), 1)

    def test_a_short_page_is_still_told_apart_from_the_login_page(self):
        # The tolerant comparison used for path confusion has a 256-byte floor,
        # which is wider than either of these documents. Confirming with it
        # would read a private page and a login page as the same thing.
        test = _make(_app(confuses_router=True, caches=True))
        private = FakeResponse(200, text=PRIVATE)
        public = FakeResponse(200, text=PUBLIC)
        self.assertTrue(test._same_page(private, public))     # too tolerant
        self.assertFalse(test._identical(private, public))    # what is used

    def test_a_public_page_cached_under_a_static_key_is_not_confirmed(self):
        # The stranger gets the same bytes, but they are the bytes a stranger
        # already gets from the ordinary URL - nothing leaked.
        responder = _app(confuses_router=True, caches=True, private_body=PUBLIC)
        found = _run(responder).vulnerabilities_found
        self.assertTrue(all(f["test_result"] != "Vulnerable" for f in found))

    def test_an_anonymous_request_that_fails_does_not_confirm(self):
        responder = _app(confuses_router=True, caches=True)
        test = _make(responder, anonymous_responder=lambda url: None)
        test.run()
        self.assertTrue(all(f["test_result"] != "Vulnerable"
                            for f in test.vulnerabilities_found))


class CacheabilityTests(unittest.TestCase):
    def _with_directives(self, value):
        def responder(url, authenticated):
            if _static_looking(url):
                return FakeResponse(200, text=PRIVATE,
                                    headers={"Cache-Control": value}, url=url)
            return FakeResponse(200, text=PRIVATE, url=url)
        return responder

    def test_no_store_means_the_control_is_working(self):
        self.assertEqual(_run(self._with_directives("no-store")).
                         vulnerabilities_found, [])

    def test_private_also_means_the_control_is_working(self):
        self.assertEqual(_run(self._with_directives("private, max-age=0")).
                         vulnerabilities_found, [])

    def test_a_silent_response_is_treated_as_storable(self):
        # The attack relies on exactly this: the origin says nothing and the
        # CDN decides from the extension instead.
        found = _run(_app(confuses_router=True, caches=False)).vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "Medium")
        self.assertIn("no Cache-Control directive", found[0]["analysis"])

    def test_public_caching_is_reported(self):
        found = _run(self._with_directives("public, max-age=600")).vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_result"], "Potentially Vulnerable")


class DeduplicationTests(unittest.TestCase):
    def test_one_defect_is_one_finding_not_one_per_suffix(self):
        # Every suffix that works has the same fix.
        found = _run(_app(confuses_router=True, caches=False)).vulnerabilities_found
        self.assertEqual(len(found), 1)

    def test_the_finding_names_how_many_variants_worked(self):
        found = _run(_app(confuses_router=True, caches=False)).vulnerabilities_found
        self.assertIn(f"{len(DECEPTIVE_SUFFIXES)} static-looking variant(s)",
                      found[0]["analysis"])


class UnconfirmedReportingTests(unittest.TestCase):
    def test_it_says_what_would_confirm_it_and_what_that_needs(self):
        found = _run(_app(confuses_router=True, caches=False)).vulnerabilities_found
        self.assertEqual(found[0]["confirmation"], CONFIRMATION_NOTE)
        self.assertIn("--auth-login-url", found[0]["confirmation"])


class AnonymousSessionTests(unittest.TestCase):
    def _clean(self, headers):
        test = CacheDeceptionTest(TARGET, "t.example",
                                  session=_App(lambda u, a: None), timeout=1,
                                  quiet=True)
        test.session.headers = dict(headers)
        return test._anonymous_session()

    def test_credentials_are_stripped(self):
        clean = self._clean({"Cookie": "sid=good", "Authorization": "Bearer x",
                             "User-Agent": "hh"})
        lowered = {name.lower() for name in clean.headers}
        self.assertNotIn("cookie", lowered)
        self.assertNotIn("authorization", lowered)

    def test_the_rest_of_the_request_is_unchanged(self):
        # Same User-Agent, so a WAF does not answer it differently and make the
        # comparison meaningless.
        clean = self._clean({"User-Agent": "hh", "Accept-Language": "en"})
        self.assertEqual(clean.headers.get("User-Agent"), "hh")
        self.assertEqual(clean.headers.get("Accept-Language"), "en")

    def test_it_carries_no_cookie_jar_of_its_own(self):
        self.assertEqual(len(self._clean({}).cookies), 0)

    def test_tls_and_proxy_settings_are_carried_over(self):
        test = CacheDeceptionTest(TARGET, "t.example",
                                  session=_App(lambda u, a: None), timeout=1,
                                  quiet=True)
        test.session.verify = False
        test.session.proxies = {"http": "http://127.0.0.1:8080"}
        clean = test._anonymous_session()
        self.assertIs(clean.verify, False)
        self.assertEqual(clean.proxies, {"http": "http://127.0.0.1:8080"})


class MappingTests(unittest.TestCase):
    def test_it_verifies_the_caching_requirements(self):
        self.assertEqual(hhs.controls_for("Web Cache Deception"),
                         ("ASVS-5.0:14.2.5", "ASVS-5.0:14.2.2"))

    def test_findings_are_vulnerability_class(self):
        found = _run(_app(confuses_router=True, caches=True)).vulnerabilities_found
        self.assertEqual(found[0]["finding_class"], hhs.CLASS_VULNERABILITY)

    def test_the_check_is_endpoint_scoped(self):
        # Whether a route is cacheable is a property of the route.
        self.assertEqual(CacheDeceptionTest.scope, hhs.SCOPE_ENDPOINT)


if __name__ == "__main__":
    unittest.main()
