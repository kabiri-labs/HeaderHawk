"""Tests for unkeyed-input discovery.

Three properties carry this check. The search has to be affordable, or nobody
runs it against ninety candidates. A page that varies on its own must not report
every candidate as significant. And every discovery probe has to defeat any
cache in front of the target - without that, the first request stores the clean
response and the cache answers the entire search with it, which is exactly the
failure a live run turned up.
"""

import unittest
from urllib.parse import parse_qs, urlparse

import headerhawk as hhs
from headerhawk.checks.unkeyed import REJECTION_STATUSES, UnkeyedInputTest
from headerhawk.checks.wordlists import INTERMEDIARY_HEADERS
from tests.helpers import FakeResponse

BASE = "http://t.example/"


class _Target:
    """Session double whose response depends on the headers it is sent."""

    def __init__(self, responder):
        self.verify = True
        self.headers = {}
        self.proxies = {}
        self.calls = []
        self._responder = responder

    def request(self, method, url=None, headers=None, timeout=None,
                allow_redirects=True, data=None, **kwargs):
        self.calls.append({"url": url, "headers": dict(headers or {})})
        return self._responder(url, headers or {})


def _make(responder):
    test = UnkeyedInputTest(BASE, "t.example", session=_Target(responder),
                            timeout=1, verbose=0, quiet=True)
    return test


def _page(body):
    return FakeResponse(200, text=body, url=BASE)


def _honours(names, cached=False):
    """A target that echoes the value of any of `names` into its body."""
    store = {}

    def responder(url, headers):
        key = url
        if cached and key in store:
            return _page(store[key])
        body = "<html>home</html>"
        for name in names:
            value = next((v for k, v in headers.items()
                          if k.lower() == name.lower()), None)
            if value:
                body = f"<html>home link={value}</html>"
                break
        if cached:
            store[key] = body
        return _page(body)
    return responder


class BaselineTests(unittest.TestCase):
    def test_a_steady_page_gives_a_tight_baseline(self):
        test = _make(_honours([]))
        self.assertTrue(test.learn_baseline())
        self.assertEqual(test.baseline_statuses, {200})

    def test_a_page_that_varies_widens_the_tolerance(self):
        sizes = iter([100, 900, 500])

        def responder(url, headers):
            return _page("x" * next(sizes, 500))

        test = _make(responder)
        test.learn_baseline()
        # The page moves 800 bytes by itself, so an 800-byte move means nothing.
        self.assertGreaterEqual(test.length_tolerance, 800)

    def test_an_unreachable_target_is_skipped_with_a_reason(self):
        test = _make(lambda url, headers: None)
        test.session.request = lambda *a, **k: (_ for _ in ()).throw(
            __import__("requests").ConnectionError("nope"))
        test.run()
        self.assertFalse(test.assessed)
        self.assertIn("nothing to compare", test.skip_reason)


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.test = _make(_honours([]))
        self.test.learn_baseline()

    def test_a_reflected_marker_is_the_strongest_signal(self):
        moved, reason = self.test.differs(
            _page(f"<html>{self.test.token}</html>"))
        self.assertTrue(moved)
        self.assertIn("reflected", reason)

    def test_a_marker_in_a_response_header_counts_too(self):
        response = FakeResponse(200, headers={"Location": self.test.marker})
        self.assertTrue(self.test.differs(response)[0])

    def test_a_new_status_counts(self):
        self.assertTrue(self.test.differs(FakeResponse(500, text="x"))[0])

    def test_a_body_far_outside_the_baseline_counts(self):
        self.assertTrue(self.test.differs(_page("x" * 5000))[0])

    def test_an_identical_body_does_not(self):
        self.assertFalse(self.test.differs(_page("<html>home</html>"))[0])

    def test_a_small_change_counts_on_a_page_that_reproduces_itself(self):
        # The whole point of comparing an artefact rather than a length: a
        # cache gadget changes a URL, not the page's weight.
        self.assertTrue(self.test.differs(_page("<html>home!</html>"))[0])


class IsolationTests(unittest.TestCase):
    def test_a_single_honoured_header_is_found(self):
        test = _make(_honours(["X-Forwarded-Scheme"]))
        test.learn_baseline()
        found = test.isolate(list(INTERMEDIARY_HEADERS))
        self.assertEqual([name for name, _ in found], ["X-Forwarded-Scheme"])

    def test_two_honoured_headers_are_both_found(self):
        # Bisection has to recurse into both halves, not stop at the first hit.
        test = _make(_honours(["X-Forwarded-Scheme", "X-Wap-Profile"]))
        test.learn_baseline()
        found = {name for name, _ in test.isolate(list(INTERMEDIARY_HEADERS))}
        self.assertEqual(found, {"X-Forwarded-Scheme", "X-Wap-Profile"})

    def test_an_inert_target_yields_nothing(self):
        test = _make(_honours([]))
        test.learn_baseline()
        self.assertEqual(test.isolate(list(INTERMEDIARY_HEADERS)), [])

    def test_ruling_out_a_batch_costs_one_request(self):
        # This is what makes searching ninety candidates affordable.
        test = _make(_honours([]))
        test.learn_baseline()
        before = len(test.session.calls)
        test.isolate(list(INTERMEDIARY_HEADERS))
        self.assertEqual(len(test.session.calls) - before, 1)

    def test_finding_one_among_many_is_logarithmic(self):
        test = _make(_honours(["X-Wap-Profile"]))
        test.learn_baseline()
        before = len(test.session.calls)
        test.isolate(list(INTERMEDIARY_HEADERS))
        used = len(test.session.calls) - before
        self.assertLess(used, len(INTERMEDIARY_HEADERS) // 2, used)

    def test_a_rejected_batch_is_not_read_as_a_signal(self):
        # A 431 means the request was too big, not that a header did something.
        rejection = sorted(REJECTION_STATUSES)[0]

        def responder(url, headers):
            if len(headers) > 1:
                return FakeResponse(rejection, text="too big")
            return _page("<html>home</html>")

        test = _make(responder)
        test.learn_baseline()
        self.assertEqual(test.isolate(list(INTERMEDIARY_HEADERS)), [])


class CacheBustingTests(unittest.TestCase):
    """The regression that a live run exposed: a cache hid the whole search."""

    def _busters(self, calls):
        return [parse_qs(urlparse(call["url"]).query).get("cb", [None])[0]
                for call in calls]

    def test_every_discovery_probe_gets_its_own_buster(self):
        test = _make(_honours([]))
        test.learn_baseline()
        test.isolate(list(INTERMEDIARY_HEADERS))
        busters = self._busters(test.session.calls)
        self.assertTrue(all(busters))
        self.assertEqual(len(busters), len(set(busters)))

    def test_the_search_still_works_through_a_cache(self):
        # Without per-probe busters the baseline stores the clean response and
        # the cache answers every candidate with it, finding nothing.
        test = _make(_honours(["X-Forwarded-Scheme"], cached=True))
        test.learn_baseline()
        found = test.isolate(list(INTERMEDIARY_HEADERS))
        self.assertEqual([name for name, _ in found], ["X-Forwarded-Scheme"])

    def test_the_confirmation_pair_shares_one_buster(self):
        # The opposite requirement: proving a cache serves the poisoned copy
        # only works when both requests ask for the same key.
        test = _make(_honours(["X-Forwarded-Scheme"], cached=True))
        test.learn_baseline()
        before = len(test.session.calls)
        test.confirm_poisoning("X-Forwarded-Scheme")
        busters = self._busters(test.session.calls[before:])
        self.assertEqual(len(busters), 2)
        self.assertEqual(busters[0], busters[1])


class ReportingTests(unittest.TestCase):
    def _run(self, responder):
        test = _make(responder)
        test.run()
        return test.vulnerabilities_found

    def test_a_cache_that_serves_the_poison_is_a_confirmed_poisoning(self):
        found = self._run(_honours(["X-Forwarded-Scheme"], cached=True))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_type"], "Web Cache Poisoning")
        self.assertEqual(found[0]["severity"], "High")
        self.assertEqual(found[0]["test_result"], "Vulnerable")

    def test_no_cache_is_reported_as_unkeyed_input_not_as_poisoning(self):
        found = self._run(_honours(["X-Forwarded-Scheme"], cached=False))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_type"], "Unkeyed Input")
        self.assertEqual(found[0]["severity"], "Medium")
        self.assertEqual(found[0]["test_result"], "Potentially Vulnerable")

    def test_the_unconfirmed_finding_says_what_was_not_shown(self):
        found = self._run(_honours(["X-Forwarded-Scheme"], cached=False))
        self.assertIn("poisoning is not demonstrated", found[0]["analysis"])

    def test_an_inert_target_reports_nothing(self):
        self.assertEqual(self._run(_honours([])), [])

    def test_the_reproduction_carries_the_header(self):
        found = self._run(_honours(["X-Forwarded-Scheme"], cached=False))
        self.assertIn("-H 'X-Forwarded-Scheme:", found[0]["repro"])


class ArtefactTests(unittest.TestCase):
    """What counts as a change, and what is the page moving on its own."""

    CANONICAL = '<link rel="canonical" href="https://aa.example/x">'
    POISONED = '<link rel="canonical" href="https://bb.example/x">'

    def _page_with(self, extra=""):
        return f"<html><head>{self.CANONICAL}</head><body>home{extra}</body></html>"

    def test_a_url_that_changes_without_changing_the_length_is_found(self):
        # Identical byte counts, so no length comparison could ever see it.
        self.assertEqual(len(self.CANONICAL), len(self.POISONED))
        baseline = self._page_with()
        poisoned = baseline.replace(self.CANONICAL, self.POISONED)
        self.assertEqual(len(baseline), len(poisoned))

        test = _make(lambda url, headers: _page(
            poisoned if any(k.lower() == "x-forwarded-host" for k in headers)
            else baseline))
        test.learn_baseline()
        self.assertIsNotNone(test.baseline_artefact)
        moved, reason = test.affects(["X-Forwarded-Host"])
        self.assertTrue(moved)
        self.assertIn("cache key", reason)

    def test_a_change_only_in_a_response_header_is_found(self):
        def responder(url, headers):
            if any(k.lower() == "x-forwarded-host" for k in headers):
                return FakeResponse(200, text="<html>home</html>", url=BASE,
                                    headers={"Link": "<https://bb.example/>; rel=preload"})
            return FakeResponse(200, text="<html>home</html>", url=BASE,
                                headers={"Link": "<https://aa.example/>; rel=preload"})

        test = _make(responder)
        test.learn_baseline()
        self.assertTrue(test.affects(["X-Forwarded-Host"])[0])

    def test_a_nonce_the_page_changes_by_itself_is_not_a_change(self):
        counter = [0]

        def responder(url, headers):
            counter[0] += 1
            return _page(f'<html><meta nonce="nonce{counter[0]:08d}">home</html>')

        test = _make(responder)
        test.learn_baseline()
        # The samples agreed once the nonce was folded out, so the precise
        # comparison is in use - and the nonce still does not trip it.
        self.assertIsNotNone(test.baseline_artefact)
        self.assertFalse(test.affects(["X-Forwarded-Host"])[0])

    def test_a_page_that_will_not_reproduce_itself_falls_back(self):
        counter = [0]

        def responder(url, headers):
            counter[0] += 1
            # A different amount of content every time, not just a token.
            return _page("<html>home" + ("spam " * counter[0] * 40) + "</html>")

        test = _make(responder)
        test.learn_baseline()
        self.assertIsNone(test.baseline_artefact)
        # With no artefact to compare, only a difference beyond the page's own
        # variance means anything - the behaviour this check always had.
        self.assertFalse(test.differs(_page("<html>home!</html>"))[0])


class TypedValueTests(unittest.TestCase):
    """A candidate has to carry a value of the shape it really holds."""

    def test_a_scheme_header_is_sent_a_scheme(self):
        test = _make(_honours([]))
        values = test._values_for(["X-Forwarded-Proto", "X-Forwarded-Port",
                                   "True-Client-IP", "X-Forwarded-Host"])
        self.assertEqual(values["X-Forwarded-Proto"], "http")
        self.assertEqual(values["X-Forwarded-Port"], "8080")
        self.assertNotIn(".example-collab.com", values["True-Client-IP"])
        self.assertEqual(values["X-Forwarded-Host"], test.marker)

    def test_a_path_header_carries_the_marker_in_a_path(self):
        test = _make(_honours([]))
        value = test._values_for(["X-Original-URL"])["X-Original-URL"]
        self.assertTrue(value.startswith("/"))
        self.assertIn(test.marker, value)

    def test_a_header_with_no_room_for_a_marker_can_still_be_confirmed(self):
        # The value is "http", so there is no marker to look for: the clean
        # request has to come back as the poisoned response instead. Before
        # this, such a header could never be more than suspected.
        test = _make(_honours(["X-Forwarded-Proto"], cached=True))
        test.learn_baseline()
        confirmed = test.confirm_poisoning("X-Forwarded-Proto")
        self.assertIsNotNone(confirmed)
        self.assertFalse(confirmed[3])          # not by the marker
        found = test.vulnerabilities_found
        test.report("X-Forwarded-Proto", "the response changed")
        self.assertEqual(test.vulnerabilities_found[-1]["test_type"],
                         "Web Cache Poisoning")
        self.assertIn("rather than the baseline one",
                      test.vulnerabilities_found[-1]["analysis"])


class CacheKeyTests(unittest.TestCase):
    """A cache that ignores the query makes the whole search blind."""

    def _cached_regardless(self, header, value):
        def responder(url, headers):
            # The same stored response whatever the URL asks for.
            return FakeResponse(200, text="<html>home</html>", url=BASE,
                                headers={header: value})
        return responder

    def test_a_hit_on_an_invented_url_stops_the_search(self):
        test = _make(self._cached_regardless("X-Cache", "HIT"))
        self.assertFalse(test.learn_baseline())
        self.assertTrue(test.skipped)
        self.assertIn("not part of its key", test.skip_reason)
        self.assertIn("X-Cache", test.skip_reason)

    def test_an_age_above_zero_counts_as_a_hit(self):
        test = _make(self._cached_regardless("Age", "41"))
        self.assertFalse(test.learn_baseline())
        self.assertIn("not part of its key", test.skip_reason)

    def test_a_miss_is_not_mistaken_for_one(self):
        test = _make(self._cached_regardless("X-Cache", "MISS"))
        self.assertTrue(test.learn_baseline())

    def test_an_age_of_zero_is_not_a_hit(self):
        test = _make(self._cached_regardless("Age", "0"))
        self.assertTrue(test.learn_baseline())

    def test_the_run_reports_the_reason_rather_than_a_clean_result(self):
        # A clean result here would mean only that the search was blind.
        test = _make(self._cached_regardless("CF-Cache-Status", "HIT"))
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])
        self.assertFalse(test.assessed)
        self.assertIn("not part of its key", test.skip_reason)


class CandidateTests(unittest.TestCase):
    def test_the_candidates_are_intermediary_headers(self):
        # The 4.1.3 mapping only holds for header fields an intermediary sets;
        # fuzzing arbitrary names would not support the claim.
        for name in ("X-Forwarded-Host", "X-Real-IP", "CF-Connecting-IP",
                     "X-Original-URL", "Forwarded"):
            self.assertIn(name, INTERMEDIARY_HEADERS, name)

    def test_the_search_reaches_past_the_fixed_list(self):
        # The point of searching: these are not in the six the older check tries.
        for name in ("X-Forwarded-Scheme", "X-Wap-Profile", "CDN-Loop"):
            self.assertIn(name, INTERMEDIARY_HEADERS, name)
            self.assertNotIn(name, hhs.UNKEYED_HOST_HEADERS, name)

    def test_both_finding_types_verify_the_override_requirement(self):
        for test_type in ("Unkeyed Input", "Web Cache Poisoning"):
            self.assertEqual(hhs.controls_for(test_type), ("ASVS-5.0:4.1.3",))


if __name__ == "__main__":
    unittest.main()
