"""Tests for the standalone helper functions and small utility classes."""

import contextlib
import io
import os
import tempfile
import unittest

import requests

import headerhawk as hhs
from headerhawk.report import repro as hh_repro


class ShellQuoteTests(unittest.TestCase):
    def test_wraps_plain_value_in_single_quotes(self):
        self.assertEqual(hh_repro._shell_quote("abc"), "'abc'")

    def test_escapes_embedded_single_quote(self):
        # The classic '\'' fence keeps the value safe inside single quotes.
        self.assertEqual(hh_repro._shell_quote("a'b"), "'a'\\''b'")

    def test_stringifies_non_string_input(self):
        self.assertEqual(hh_repro._shell_quote(80), "'80'")


class ParseHeadersTests(unittest.TestCase):
    def test_parses_and_strips(self):
        result = hhs.parse_headers(["X-A: 1", "X-B:2 "])
        self.assertEqual(result, {"X-A": "1", "X-B": "2"})

    def test_ignores_lines_without_colon(self):
        self.assertEqual(hhs.parse_headers(["novalue", "X-Ok: y"]), {"X-Ok": "y"})

    def test_none_yields_empty_dict(self):
        self.assertEqual(hhs.parse_headers(None), {})

    def test_value_may_contain_colon(self):
        self.assertEqual(hhs.parse_headers(["Host: h:8080"]), {"Host": "h:8080"})


class LoadWordlistTests(unittest.TestCase):
    def test_none_path_returns_none(self):
        self.assertIsNone(hhs.load_wordlist(None))

    def test_reads_entries_skipping_blanks_and_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("admin\n\n# comment\n  staging  \n")
            path = handle.name
        try:
            self.assertEqual(hhs.load_wordlist(path), ["admin", "staging"])
        finally:
            os.unlink(path)

    def test_missing_file_returns_none(self):
        # The function warns on stderr/stdout and falls back to None; silence it.
        with contextlib.redirect_stdout(io.StringIO()):
            result = hhs.load_wordlist("/nonexistent/path/wordlist.txt")
        self.assertIsNone(result)


class BuildReproductionTests(unittest.TestCase):
    def test_curl_for_header_finding(self):
        entry = {
            "test_type": "Host Header Injection",
            "method": "GET",
            "url": "http://t/",
            "headers": {"X-Forwarded-Host": "evil.com"},
        }
        repro = hhs.build_reproduction(entry, "http://t/", insecure=False)
        self.assertTrue(repro.startswith("curl -s -i"))
        self.assertIn("-H 'X-Forwarded-Host: evil.com'", repro)
        self.assertIn("'http://t/'", repro)

    def test_curl_insecure_flag(self):
        entry = {"method": "GET", "url": "https://t/", "headers": {"H": "v"}}
        repro = hhs.build_reproduction(entry, "https://t/", insecure=True)
        self.assertTrue(repro.startswith("curl -sk -i"))

    def test_curl_custom_method(self):
        entry = {"method": "POST", "url": "http://t/", "headers": {"H": "v"}}
        repro = hhs.build_reproduction(entry, "http://t/", insecure=False)
        self.assertIn("-X POST", repro)

    def test_header_derived_from_header_name(self):
        entry = {"method": "GET", "url": "http://t/",
                 "header_name": "Host", "payload": "evil", "param_name": None}
        repro = hhs.build_reproduction(entry, "http://t/", insecure=False)
        self.assertIn("-H 'Host: evil'", repro)

    def test_raw_bypass_http_uses_ncat(self):
        entry = {
            "test_type": "Host Header Bypass",
            "raw_request": "GET / HTTP/1.1\r\nHost: evil\r\n\r\n",
        }
        repro = hhs.build_reproduction(entry, "http://example.com/", insecure=False)
        self.assertIn("ncat example.com 80", repro)
        self.assertIn("\\r\\n", repro)

    def test_raw_bypass_https_uses_openssl_with_sni(self):
        entry = {
            "test_type": "Host Header Bypass",
            "raw_request": "GET / HTTP/1.1\r\nHost: evil\r\n\r\n",
        }
        repro = hhs.build_reproduction(entry, "https://example.com/", insecure=False)
        self.assertIn("openssl s_client", repro)
        self.assertIn("-connect example.com:443", repro)
        self.assertIn("-servername example.com", repro)


class OOBManagerTests(unittest.TestCase):
    def test_host_embeds_label_and_scan_id(self):
        manager = hhs.OOBManager("oob.example.com")
        host = manager.host("ssrf")
        self.assertTrue(host.startswith("ssrf-"))
        self.assertTrue(host.endswith(".oob.example.com"))
        self.assertIn(manager.scan_id, host)
        self.assertEqual(manager.labels["ssrf"], host)

    def test_domain_is_normalised(self):
        manager = hhs.OOBManager("/.oob.example.com/")
        self.assertEqual(manager.oob_domain, "oob.example.com")

    def test_url_wraps_host(self):
        manager = hhs.OOBManager("oob.example.com")
        url = manager.url("param")
        self.assertTrue(url.startswith("http://param-"))
        self.assertTrue(url.endswith("/"))

    def test_poll_without_url_returns_empty(self):
        manager = hhs.OOBManager("oob.example.com")
        self.assertEqual(manager.poll(session=None, timeout=1), [])

    def test_poll_matches_by_host(self):
        manager = hhs.OOBManager("oob.example.com", poll_url="http://listener/export")
        host = manager.host("ssrf")

        class Session:
            def get(self, url, timeout=None):
                from tests.helpers import FakeResponse
                return FakeResponse(text=f"interaction from {host}")

        self.assertEqual(manager.poll(Session(), timeout=1), ["ssrf"])

    def test_poll_survives_request_exception(self):
        manager = hhs.OOBManager("oob.example.com", poll_url="http://listener/export")
        manager.host("ssrf")

        class Session:
            def get(self, url, timeout=None):
                raise requests.RequestException("boom")

        self.assertEqual(manager.poll(Session(), timeout=1, attempts=1), [])



class OOBAttributionTests(unittest.TestCase):
    """One interaction must not confirm every payload the scan generated.

    The scan id is part of every payload hostname, so accepting it as a match
    made a single visit mark every label - and ``confirm_oob_interactions``
    then filed one High, confirmed finding per label from one interaction.
    """

    @staticmethod
    def _session(body):
        from tests.helpers import FakeResponse

        class Session:
            def get(self, url, timeout=None):
                return FakeResponse(text=body)

        return Session()

    @staticmethod
    def _manager():
        manager = hhs.OOBManager("oob.example.com",
                                 poll_url="http://listener/export")
        hosts = {label: manager.host(label)
                 for label in ("ssrf", "param", "redirect")}
        return manager, hosts

    def test_only_the_label_whose_host_was_seen_is_a_hit(self):
        manager, hosts = self._manager()
        session = self._session(f"GET / from {hosts['ssrf']}")
        self.assertEqual(manager.poll(session, timeout=1), ["ssrf"])

    def test_a_host_is_matched_whatever_case_the_listener_logged_it_in(self):
        manager, hosts = self._manager()
        session = self._session(hosts["param"].upper())
        self.assertEqual(manager.poll(session, timeout=1), ["param"])

    def test_an_interaction_with_no_hostname_is_reported_once(self):
        # Still evidence that something left the target, but not evidence of
        # which payload did, so it is one finding rather than one per label.
        manager, _ = self._manager()
        session = self._session(f"a visit tagged {manager.scan_id} arrived")
        self.assertEqual(manager.poll(session, timeout=1, attempts=1),
                         [hhs.OOBManager.UNATTRIBUTED])


class OOBConfirmationTests(unittest.TestCase):

    class _Owner:
        """The attributes ``confirm_oob_interactions`` touches on a check."""

        def __init__(self, test_type="SSRF"):
            self.test_type = test_type
            self.target_url = "http://t/"
            self.vulnerabilities_found = []

    def _confirm(self, manager, body, owners):
        from tests.helpers import FakeResponse

        class Session:
            def get(self, url, timeout=None):
                return FakeResponse(text=body)

        with contextlib.redirect_stdout(io.StringIO()):
            hhs.confirm_oob_interactions(manager, Session(), 1, owners)

    def test_one_interaction_files_one_finding(self):
        manager = hhs.OOBManager("oob.example.com", poll_url="http://l/export")
        host = manager.host("ssrf")
        manager.host("param")
        manager.host("redirect")
        owner = self._Owner()
        self._confirm(manager, f"hit from {host}", [owner])
        self.assertEqual(len(owner.vulnerabilities_found), 1)
        self.assertEqual(owner.vulnerabilities_found[0]["header_name"], "ssrf")

    def test_an_unattributed_interaction_says_the_vector_is_unknown(self):
        manager = hhs.OOBManager("oob.example.com", poll_url="http://l/export")
        manager.host("ssrf")
        manager.host("param")
        owner = self._Owner()
        self._confirm(manager, f"tagged {manager.scan_id}", [owner])
        self.assertEqual(len(owner.vulnerabilities_found), 1)
        self.assertIn("not identified",
                      owner.vulnerabilities_found[0]["analysis"])


if __name__ == "__main__":
    unittest.main()
