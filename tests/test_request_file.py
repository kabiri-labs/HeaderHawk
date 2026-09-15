"""Tests for driving a scan from a saved HTTP request.

The point of the feature is that a real request survives the scan: the session
cookie, the content type, the body and the two dozen headers a single-page app
adds are all still there when each check runs. So the properties pinned here are
the ones that would quietly destroy that - a Host pinned from the file (which
would neutralise every Host check), a body replayed onto the wrong method, a
check's own header being appended rather than replacing the file's, and the raw
socket checks falling back to their four hand-written lines.
"""

import os
import tempfile
import unittest
from unittest import mock

import headerhawk as hhs
from headerhawk.checks.host_bypass import HostBypassTest
from headerhawk.checks.smuggling import RequestSmugglingTest
from headerhawk.core.request_file import (EXCLUDED_HEADERS, RequestFileError,
                                          header_lines, is_credential_header,
                                          load_request, parse_request,
                                          redact_credentials)
from headerhawk.report.repro import build_reproduction
from tests.helpers import FakeResponse, FakeSession

SAVED = ("POST /api/v2/orders?page=2 HTTP/1.1\r\n"
         "Host: shop.example\r\n"
         "User-Agent: Mozilla/5.0\r\n"
         "Content-Type: application/json\r\n"
         "Cookie: session=abc123; theme=dark\r\n"
         "Authorization: Bearer t0ken\r\n"
         "Content-Length: 17\r\n"
         "Connection: keep-alive\r\n"
         "\r\n"
         '{"quantity": 100}')


def _spec(text=SAVED, scheme=None):
    return parse_request(text, scheme=scheme)


def _write(text):
    # newline="" is not optional: these fixtures are raw HTTP requests whose
    # lines already end in CRLF, and text-mode translation would turn each of
    # them into "\r\r\n" on Windows. The parser would then see a blank line
    # after the request line, take it for the end of the header block, and
    # reject a file that is perfectly well formed on disk.
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         newline="")
    handle.write(text)
    handle.close()
    return handle.name


class ParsingTests(unittest.TestCase):
    def test_the_request_line_gives_the_method_and_the_path(self):
        spec = _spec()
        self.assertEqual(spec.method, "POST")
        self.assertEqual(spec.url, "https://shop.example/api/v2/orders?page=2")

    def test_the_body_is_kept(self):
        self.assertEqual(_spec().body, '{"quantity": 100}')

    def test_the_declared_content_length_bounds_the_body(self):
        # A file saved by an editor or a proxy ends with a newline that was
        # never part of the message; sending it makes the body a byte longer
        # than the request being reproduced.
        self.assertEqual(_spec(SAVED + "\n").body, '{"quantity": 100}')

    def test_a_multibyte_body_is_measured_in_bytes(self):
        # Content-Length counts octets, not characters: 'sé' is three of them,
        # so slicing by character would cut the body short.
        text = "GET /x HTTP/1.1\r\nHost: t.example\r\nContent-Length: 3\r\n\r\nsé\n"
        self.assertEqual(_spec(text).body, "sé")

    def test_without_a_declared_length_one_trailing_newline_is_dropped(self):
        spec = _spec("POST /x HTTP/1.1\r\nHost: t.example\r\n\r\nhello\n")
        self.assertEqual(spec.body, "hello")

    def test_a_request_without_a_body_has_none(self):
        spec = _spec("GET / HTTP/1.1\r\nHost: t.example\r\n\r\n")
        self.assertIsNone(spec.body)

    def test_the_headers_that_matter_are_carried(self):
        headers = _spec().headers
        self.assertEqual(headers["Cookie"], "session=abc123; theme=dark")
        self.assertEqual(headers["Authorization"], "Bearer t0ken")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_lines_separated_only_by_newlines_are_accepted(self):
        # Files saved by an editor or copied out of a terminal lose the CRs.
        spec = _spec(SAVED.replace("\r\n", "\n"))
        self.assertEqual(spec.method, "POST")
        self.assertEqual(spec.headers["Cookie"], "session=abc123; theme=dark")
        self.assertEqual(spec.body, '{"quantity": 100}')

    def test_an_obsolete_folded_header_is_rejoined(self):
        spec = _spec("GET / HTTP/1.1\r\nHost: t.example\r\n"
                     "X-Long: first\r\n\tsecond\r\n\r\n")
        self.assertEqual(spec.headers["X-Long"], "first second")

    def test_a_header_value_containing_a_colon_survives(self):
        spec = _spec("GET / HTTP/1.1\r\nHost: t.example:8443\r\n"
                     "Referer: https://a.example/x?y=1\r\n\r\n")
        self.assertEqual(spec.headers["Referer"], "https://a.example/x?y=1")


class ExcludedHeaderTests(unittest.TestCase):
    def test_host_is_not_carried(self):
        # Pinning Host would send every Host-manipulation check's payload
        # alongside the real Host, and the real one would win.
        self.assertNotIn("Host", _spec().headers)
        self.assertEqual(_spec().host, "shop.example")

    def test_the_transmission_headers_are_not_carried(self):
        # They describe the saved transmission, not the one being made.
        for name in ("Content-Length", "Connection"):
            self.assertNotIn(name, _spec().headers, name)

    def test_the_exclusions_are_matched_without_regard_to_case(self):
        spec = _spec("GET / HTTP/1.1\r\nhost: t.example\r\n"
                     "TRANSFER-ENCODING: chunked\r\n\r\n")
        self.assertEqual(spec.headers, {})

    def test_every_exclusion_is_a_transmission_or_routing_field(self):
        # A drift guard: adding an application header here would silently stop
        # scans carrying it.
        self.assertIn("host", EXCLUDED_HEADERS)
        self.assertNotIn("cookie", EXCLUDED_HEADERS)
        self.assertNotIn("authorization", EXCLUDED_HEADERS)


class SchemeTests(unittest.TestCase):
    def test_https_is_the_default(self):
        # Guessing plaintext for a request that carried a session cookie would
        # be the more dangerous default.
        self.assertTrue(_spec().url.startswith("https://"))

    def test_an_explicit_scheme_wins(self):
        self.assertTrue(_spec(scheme="http").url.startswith("http://"))

    def test_port_80_in_the_host_header_means_http(self):
        spec = _spec("GET / HTTP/1.1\r\nHost: t.example:80\r\n\r\n")
        self.assertEqual(spec.url, "http://t.example:80/")

    def test_port_443_in_the_host_header_means_https(self):
        spec = _spec("GET / HTTP/1.1\r\nHost: t.example:443\r\n\r\n")
        self.assertEqual(spec.url, "https://t.example:443/")

    def test_an_absolute_uri_request_line_is_honoured(self):
        spec = _spec("GET http://other.example/x HTTP/1.1\r\n"
                     "Host: t.example\r\n\r\n")
        self.assertEqual(spec.url, "http://other.example/x")
        self.assertEqual(spec.host, "other.example")

    def test_a_bare_root_path_is_kept(self):
        spec = _spec("GET / HTTP/1.1\r\nHost: t.example\r\n\r\n")
        self.assertEqual(spec.url, "https://t.example/")

    def test_a_request_line_missing_its_path_is_rejected(self):
        # 'GET HTTP/1.1' parses as a two-part line whose target is the version.
        # Building a URL from that would scan an address the file never named.
        with self.assertRaises(RequestFileError) as caught:
            _spec("GET HTTP/1.1\r\nHost: t.example\r\n\r\n")
        self.assertIn("beginning with '/'", str(caught.exception))


class MalformedFileTests(unittest.TestCase):
    def test_an_empty_file_is_rejected(self):
        with self.assertRaises(RequestFileError):
            _spec("")

    def test_a_first_line_that_is_not_a_request_line_is_rejected(self):
        with self.assertRaises(RequestFileError):
            _spec("hello\r\nHost: t.example\r\n\r\n")

    def test_a_header_without_a_colon_is_rejected(self):
        with self.assertRaises(RequestFileError) as caught:
            _spec("GET / HTTP/1.1\r\nHost: t.example\r\nbroken\r\n\r\n")
        self.assertIn("no colon", str(caught.exception))

    def test_no_host_and_no_absolute_url_is_rejected(self):
        with self.assertRaises(RequestFileError) as caught:
            _spec("GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n")
        self.assertIn("which host to scan", str(caught.exception))

    def test_a_missing_file_is_reported_rather_than_crashing(self):
        with self.assertRaises(RequestFileError) as caught:
            load_request("/nonexistent/request.txt")
        self.assertIn("could not read", str(caught.exception))

    def test_a_readable_file_round_trips(self):
        path = _write(SAVED)
        try:
            self.assertEqual(load_request(path).method, "POST")
        finally:
            os.unlink(path)

    def test_the_fixture_reaches_the_disk_byte_for_byte(self):
        # A saved request is CRLF on the wire and CRLF in the file. If the
        # helper that writes these fixtures lets the platform rewrite the line
        # endings, every file-based test here is handed a request the parser is
        # right to reject, and the suite blames the product for it.
        path = _write(SAVED)
        try:
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), SAVED.encode("utf-8"))
        finally:
            os.unlink(path)


class BodyReplayTests(unittest.TestCase):
    """The body goes with the method the file used, and only that one."""

    def _test(self, spec=None):
        return hhs.CORSTest("https://shop.example/api/v2/orders", "shop.example",
                            session=FakeSession(), timeout=1, quiet=True,
                            verbose=0, request_spec=spec or _spec())

    def test_the_body_rides_on_the_files_own_method(self):
        self.assertEqual(self._test().body_for("POST"), '{"quantity": 100}')

    def test_another_method_gets_no_body(self):
        # A GET carrying an order body is a different request from the one the
        # file described, and on some endpoints a destructive one.
        self.assertIsNone(self._test().body_for("GET"))

    def test_the_method_comparison_ignores_case(self):
        self.assertEqual(self._test().body_for("post"), '{"quantity": 100}')

    def test_without_a_request_file_no_body_is_sent(self):
        test = hhs.CORSTest("http://t/", "t", session=FakeSession(), timeout=1,
                            quiet=True, verbose=0)
        self.assertIsNone(test.body_for("POST"))

    def test_a_bodyless_file_sends_no_body(self):
        spec = _spec("POST /x HTTP/1.1\r\nHost: t.example\r\n\r\n")
        self.assertIsNone(self._test(spec).body_for("POST"))

    def test_the_body_reaches_the_session(self):
        session = FakeSession(responses=[FakeResponse(200)])
        test = hhs.CORSTest("https://shop.example/x", "shop.example",
                            session=session, timeout=1, quiet=True, verbose=0,
                            request_spec=_spec())
        test.request("POST")
        self.assertEqual(session.calls[0]["data"], '{"quantity": 100}')


class HeaderMergeTests(unittest.TestCase):
    """Present means replaced, absent means added - and -H beats the file."""

    def _headers(self, *argv):
        with mock.patch("sys.argv", ["prog", *argv]):
            args = hhs.parse_arguments()
        spec = hhs.resolve_request(args)
        merged = dict(spec.headers) if spec else {}
        merged.update(hhs.parse_headers(args.headers))
        return merged

    def setUp(self):
        self.path = _write(SAVED)
        self.addCleanup(os.unlink, self.path)

    def test_the_files_headers_become_the_sessions(self):
        headers = self._headers("--request", self.path)
        self.assertEqual(headers["Cookie"], "session=abc123; theme=dark")

    def test_an_explicit_header_overrides_the_files(self):
        headers = self._headers("--request", self.path,
                                "-H", "Cookie: session=other")
        self.assertEqual(headers["Cookie"], "session=other")

    def test_an_explicit_header_the_file_lacks_is_added(self):
        headers = self._headers("--request", self.path, "-H", "X-Trace: 1")
        self.assertEqual(headers["X-Trace"], "1")
        self.assertIn("Authorization", headers)

    def test_a_checks_own_header_replaces_the_files_value(self):
        # This is the merge that matters at scan time: a per-request header
        # wins over the session header of the same name, so a check testing
        # 'Referer' replaces the file's rather than sending two.
        session = FakeSession(responses=[FakeResponse(200)])
        session.headers = {"Referer": "https://shop.example/cart",
                           "Cookie": "session=abc123"}
        test = hhs.CORSTest("https://shop.example/x", "shop.example",
                            session=session, timeout=1, quiet=True, verbose=0,
                            request_spec=_spec())
        test.request("GET", headers={"Referer": "https://evil.example/"})
        sent = session.calls[0]["headers"]
        self.assertEqual(sent["Referer"], "https://evil.example/")
        self.assertNotIn("Cookie", sent)  # untouched, so the session's stands


class RawClientTests(unittest.TestCase):
    """The socket-level checks send the file's headers too, not four defaults."""

    def _bypass(self, spec):
        return HostBypassTest("https://shop.example/api/v2/orders",
                              "shop.example", session=FakeSession(), timeout=1,
                              quiet=True, verbose=0, request_spec=spec)

    def test_the_saved_headers_are_written_as_wire_lines(self):
        lines = header_lines(_spec(), "shop.example")
        self.assertEqual(lines[0], "Host: shop.example")
        self.assertIn("Cookie: session=abc123; theme=dark", lines)
        self.assertIn("Authorization: Bearer t0ken", lines)
        self.assertEqual(lines[-1], "Connection: close")

    def test_the_caller_owns_the_host_line(self):
        # The Host checks are manipulating it, so the file must not supply it.
        lines = header_lines(_spec(), "attacker.example")
        self.assertEqual(lines[0], "Host: attacker.example")
        self.assertEqual([line for line in lines
                          if line.lower().startswith("host:")], lines[:1])

    def test_every_bypass_technique_carries_the_session_cookie(self):
        # Including the two that send a second Host line: without the cookie
        # they would be probing an unauthenticated request instead.
        test = self._bypass(_spec())
        for name, _, lines in test.techniques("marker.example"):
            self.assertIn("Cookie: session=abc123; theme=dark", lines, name)

    def test_the_duplicate_host_technique_still_sends_two_host_lines(self):
        test = self._bypass(_spec())
        lines = dict((name, block) for name, _, block
                     in test.techniques("marker.example"))["Duplicate Host header"]
        hosts = [line for line in lines if line.lower().startswith("host:")]
        self.assertEqual(hosts, ["Host: shop.example", "Host: marker.example"])

    def test_without_a_request_file_the_defaults_are_unchanged(self):
        test = self._bypass(None)
        self.assertIn("Host: shop.example", test.base_lines("shop.example"))
        self.assertNotIn("Cookie: session=abc123; theme=dark",
                         test.base_lines("shop.example"))

    def test_the_smuggling_probes_own_the_length_headers(self):
        # They are the disagreement being tested; a value from the file would
        # describe a different message.
        spec = _spec(SAVED.replace("Content-Length: 17",
                                   "Transfer-Encoding: chunked"))
        test = RequestSmugglingTest("https://shop.example/x", "shop.example",
                                    session=FakeSession(), timeout=1,
                                    quiet=True, verbose=0, request_spec=spec)
        block = test._headers(["Content-Length: 4", "Transfer-Encoding: chunked"])
        self.assertEqual([line for line in block
                          if line.lower().startswith("transfer-encoding:")],
                         ["Transfer-Encoding: chunked"])
        self.assertIn("Cookie: session=abc123; theme=dark", block)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.path = _write(SAVED)
        self.addCleanup(os.unlink, self.path)

    def _args(self, *argv):
        with mock.patch("sys.argv", ["prog", *argv]):
            return hhs.parse_arguments()

    def test_the_url_may_be_omitted_when_a_request_file_is_given(self):
        args = self._args("--request", self.path)
        hhs.resolve_request(args)
        self.assertEqual(args.url, "https://shop.example/api/v2/orders?page=2")
        self.assertEqual(hhs.load_targets(args),
                         ["https://shop.example/api/v2/orders?page=2"])

    def test_an_explicit_url_wins_over_the_files(self):
        # The same saved request, replayed against a staging host.
        args = self._args("https://staging.example/api/v2/orders",
                          "--request", self.path)
        hhs.resolve_request(args)
        self.assertEqual(args.url, "https://staging.example/api/v2/orders")

    def test_the_method_defaults_to_the_files(self):
        args = self._args("--request", self.path)
        hhs.resolve_request(args)
        self.assertEqual(args.methods, "POST")

    def test_an_explicit_methods_flag_wins(self):
        args = self._args("--request", self.path, "--methods", "GET,PUT")
        hhs.resolve_request(args)
        self.assertEqual(args.methods, "GET,PUT")

    def test_the_method_still_defaults_to_get_without_a_file(self):
        args = self._args("http://t/")
        self.assertIsNone(hhs.resolve_request(args))
        self.assertIsNone(args.methods)  # main() resolves this to GET

    def test_the_request_scheme_flag_reaches_the_parser(self):
        args = self._args("--request", self.path, "--request-scheme", "http")
        spec = hhs.resolve_request(args)
        self.assertTrue(spec.url.startswith("http://"))

    def test_request_scheme_without_request_is_rejected(self):
        # It would silently do nothing otherwise.
        with self.assertRaises(SystemExit):
            self._args("http://t/", "--request-scheme", "http")

    def test_no_url_no_list_and_no_request_is_still_rejected(self):
        with self.assertRaises(SystemExit):
            self._args()

    def test_a_list_keeps_its_targets_and_the_file_supplies_the_rest(self):
        listing = _write("https://a.example/x\nhttps://b.example/y\n")
        self.addCleanup(os.unlink, listing)
        args = self._args("--request", self.path, "--list", listing)
        hhs.resolve_request(args)
        self.assertIsNone(args.url)
        self.assertEqual(hhs.load_targets(args),
                         ["https://a.example/x", "https://b.example/y"])
        self.assertEqual(args.methods, "POST")

    def test_a_malformed_file_stops_the_scan(self):
        broken = _write("not a request at all")
        self.addCleanup(os.unlink, broken)
        args = self._args("--request", broken)
        with self.assertRaises(RequestFileError):
            hhs.resolve_request(args)


class CredentialRedactionTests(unittest.TestCase):
    """A request file must not be the one input that puts a cookie in a report.

    Without one, a scan's credentials live on the session and never reach the
    output at all. Reports go to assessors, tickets and code-scanning
    dashboards, so that property has to survive this feature.
    """

    def _repro(self, entry, spec=None):
        return build_reproduction(entry, "http://shop.example/x", False,
                                  spec if spec is not None else _spec())

    def test_a_cookie_is_recognised_as_a_credential(self):
        self.assertTrue(is_credential_header("Cookie"))
        self.assertTrue(is_credential_header("authorization"))

    def test_a_custom_auth_header_is_recognised_by_convention(self):
        # There is no registry of these, and over-redacting costs a reader one
        # lookup while under-redacting publishes a live credential.
        for name in ("X-Csrf-Token", "X-Api-Key", "X-Session-Id",
                     "X-Auth-Request-User"):
            self.assertTrue(is_credential_header(name), name)

    def test_an_ordinary_header_is_not_redacted(self):
        for name in ("Content-Type", "Accept-Language", "User-Agent",
                     "X-Forwarded-Host"):
            self.assertFalse(is_credential_header(name), name)

    def test_wire_format_credential_values_are_blanked(self):
        wire = ("GET / HTTP/1.1\r\nHost: shop.example\r\n"
                "Cookie: session=abc123\r\nAccept: */*\r\n\r\n")
        out = redact_credentials(wire)
        self.assertNotIn("session=abc123", out)
        self.assertIn("Accept: */*", out)

    def test_redaction_keeps_the_line_endings(self):
        # The caller is holding a wire-format request; a dropped CR would
        # describe a different message.
        wire = "GET / HTTP/1.1\r\nCookie: a=1\r\nAccept: */*\r\n\r\n"
        out = redact_credentials(wire)
        self.assertEqual(out.count("\r\n"), wire.count("\r\n"))

    def test_a_body_line_containing_a_colon_is_left_alone(self):
        wire = 'POST / HTTP/1.1\r\nHost: t\r\n\r\n{"quantity": 100}'
        self.assertIn('{"quantity": 100}', redact_credentials(wire))

    def test_the_raw_reproduction_carries_no_cookie(self):
        entry = {"raw_request": "GET / HTTP/1.1\r\nHost: shop.example\r\n"
                                "Cookie: session=abc123\r\n"
                                "Authorization: Bearer t0ken\r\n\r\n"}
        repro = self._repro(entry)
        self.assertNotIn("session=abc123", repro)
        self.assertNotIn("Bearer t0ken", repro)

    def test_the_curl_reproduction_carries_no_cookie(self):
        entry = {"method": "POST", "url": "http://shop.example/x",
                 "headers": {"X-Forwarded-Host": "evil.example"}}
        repro = self._repro(entry)
        self.assertNotIn("session=abc123", repro)
        self.assertNotIn("t0ken", repro)
        self.assertNotIn("csrf-9f2", repro)

    def test_the_command_says_what_was_left_out(self):
        path = _write(SAVED)
        self.addCleanup(os.unlink, path)
        spec = load_request(path)
        repro = self._repro({"method": "POST"}, spec)
        self.assertIn("add the credentials", repro)
        self.assertIn(path, repro)

    def test_nothing_is_claimed_missing_when_nothing_was(self):
        spec = _spec("POST /x HTTP/1.1\r\nHost: t.example\r\n"
                     "Content-Type: text/plain\r\n\r\nhi")
        self.assertNotIn("#", self._repro({"method": "POST"}, spec))

    def test_the_stored_wire_request_is_redacted_too(self):
        # It is written to the JSON and Markdown reports as evidence, so
        # redacting only the reproduction command would still publish it.
        test = HostBypassTest("http://shop.example/x", "shop.example",
                              session=FakeSession(), timeout=1, quiet=True,
                              verbose=0, request_spec=_spec())
        test.record({"url": "http://shop.example/x", "method": "GET",
                     "raw_request": "GET / HTTP/1.1\r\nHost: shop.example\r\n"
                                    "Cookie: session=abc123\r\n\r\n"})
        stored = test.vulnerabilities_found[0]["raw_request"]
        self.assertNotIn("session=abc123", stored)
        self.assertIn("Host: shop.example", stored)

    def test_without_a_request_file_the_command_is_unchanged(self):
        entry = {"method": "GET", "url": "http://shop.example/x",
                 "headers": {"X-Forwarded-Host": "evil.example"}}
        self.assertEqual(
            build_reproduction(entry, "http://shop.example/x", False),
            "curl -s -i -H 'X-Forwarded-Host: evil.example' "
            "'http://shop.example/x'")


class ReproductionFidelityTests(unittest.TestCase):
    """What is left in has to be enough to ask the endpoint the same question."""

    def _repro(self, entry, spec=None):
        return build_reproduction(entry, "http://shop.example/x", False,
                                  spec if spec is not None else _spec())

    def test_the_content_type_is_carried(self):
        # A JSON API answers a request without it differently, and the command
        # would prove nothing.
        self.assertIn("-H 'Content-Type: application/json'",
                      self._repro({"method": "POST"}))

    def test_the_body_is_carried_on_the_files_method(self):
        self.assertIn("""--data '{"quantity": 100}'""",
                      self._repro({"method": "POST"}))

    def test_the_body_is_not_carried_on_another_method(self):
        self.assertNotIn("--data", self._repro({"method": "GET"}))

    def test_the_findings_own_header_wins_over_the_files(self):
        spec = _spec(SAVED.replace("User-Agent: Mozilla/5.0",
                                   "X-Forwarded-Host: shop.example"))
        repro = self._repro(
            {"method": "POST", "headers": {"X-Forwarded-Host": "evil.example"}},
            spec)
        self.assertIn("-H 'X-Forwarded-Host: evil.example'", repro)
        self.assertNotIn("-H 'X-Forwarded-Host: shop.example'", repro)

    def test_a_posture_finding_is_still_a_plain_fetch(self):
        entry = {"method": "GET", "url": "http://shop.example/x",
                 "header_name": "X-Frame-Options", "finding_class": "posture"}
        repro = self._repro(entry)
        self.assertNotIn("X-Frame-Options", repro)


class PlumbingTests(unittest.TestCase):
    def test_every_check_accepts_a_request_spec(self):
        # scan_target hands all of them the same options, so one that did not
        # accept it would raise at scan time rather than in a test.
        spec = _spec()
        for check in hhs.CHECKS:
            test = check("https://shop.example/x", "shop.example",
                         session=FakeSession(), timeout=1, quiet=True,
                         verbose=0, request_spec=spec)
            self.assertIs(test.request_spec, spec, check.__name__)


if __name__ == "__main__":
    unittest.main()
