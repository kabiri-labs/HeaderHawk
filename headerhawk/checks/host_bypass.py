"""Host validation bypasses that require raw, un-normalised HTTP.

A bypass is a refusal that was got past, so the refusal has to be shown to
exist before any wire shape can be said to have defeated it. That is what the
baseline below is for: one well-formed request carrying the target's own host,
and one carrying a host minted for this scan, which the target cannot know. If
the second is refused and the first is not, this target validates the host and
a shape whose marker comes back anyway got past that refusal. If it is not
refused, nothing here was validating, and a marker coming back is a permissive
parser rather than a defeated control - which is what the finding then says.

An ordinary, well-formed ``Host`` header carrying the marker is that baseline,
not a technique. It cannot be a bypass in either direction: where an unknown
host is refused it *is* the refusal, and where it is not, there was nothing to
bypass.
"""

from urllib.parse import urlparse

from .._meta import __tool_name__, __version__
from ..net.raw import RawHTTPClient
from ..core.markers import new_token
from ..core.request_file import header_lines
from ..core.scope import SCOPE_HOST
from .base import BaseTest


class HostBypassTest(BaseTest):
    """Host header validation bypasses that require raw, un-normalised HTTP.

    Establishes first whether this target refuses a host it cannot know, then
    sends duplicate Host headers, absolute-URI request lines and indented
    (line-folded) headers carrying a unique marker host and checks whether the
    marker is reflected back. What a reflection proves depends on the baseline,
    and the finding says which of the two it is.
    """

    test_type = "Host Header Bypass"
    # Host-level: the weakness belongs to the front-end, not to a route.
    scope = SCOPE_HOST

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        parsed = urlparse(self.target_url)
        self.scheme = parsed.scheme or "http"
        self.connect_host = parsed.hostname
        self.connect_port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.client = RawHTTPClient(timeout=self.timeout,
                                    verify=not self._insecure(),
                                    proxy=self._proxy(),
                                    rate_limiter=self.rate_limiter)
        # What the baseline established: (refused, ordinary status, unknown-host
        # status), with the last None when the unknown host was not answered at
        # all. None until ``run`` has settled it.
        self.host_validation = None

    def _insecure(self):
        # Mirror the verification mode chosen for the shared requests session.
        return self.session.verify is False

    def _proxy(self):
        # Reuse the proxy configured on the shared requests session so raw
        # bypass traffic is captured by the same intercepting proxy (e.g. Burp).
        proxies = getattr(self.session, "proxies", None) or {}
        return proxies.get("https") or proxies.get("http")

    def base_lines(self, host_value):
        """The header block to send, from the saved request when there was one.

        A bypass tested without the session cookie the real request carried
        would be probing a different, usually unauthenticated, request.
        """
        if self.request_spec is not None:
            return header_lines(self.request_spec, host_value)
        return [
            f"Host: {host_value}",
            f"User-Agent: Mozilla/5.0 (compatible; {__tool_name__}/{__version__})",
            "Accept: */*",
            "Connection: close",
        ]

    def second_host(self, host_value, extra_host_line):
        """``base_lines`` with a second Host line right after the first.

        The techniques that send two Host headers differ from the others only
        in that extra line, so they are built from the same block rather than
        from a hand-written one - otherwise a scan driven from a request file
        would send them without the cookie the rest of the scan carries.
        ``Host`` is always the first line, both here and in ``header_lines``.
        """
        lines = self.base_lines(host_value)
        return [lines[0], extra_host_line] + lines[1:]

    def techniques(self, marker):
        host = self.original_host
        # Each technique returns (name, request_line, header_lines).
        return [
            (
                "Duplicate Host header",
                f"GET {self.path} HTTP/1.1",
                self.second_host(host, f"Host: {marker}"),
            ),
            (
                "Absolute-URI request line",
                f"GET {self.scheme}://{marker}{self.path} HTTP/1.1",
                self.base_lines(host),
            ),
            (
                "Indented (line-folded) Host header",
                f"GET {self.path} HTTP/1.1",
                self.second_host(host, f" Host: {marker}"),
            ),
            (
                # The same obsolete fold, with a tab. A middlebox that strips
                # a leading space from a continuation line does not always
                # strip a tab, so the two reach different back-ends.
                "Tab-folded Host header",
                f"GET {self.path} HTTP/1.1",
                self.second_host(host, f"	Host: {marker}"),
            ),
            (
                # Which of two Host headers wins is a choice each
                # implementation makes for itself, so the pair is sent both
                # ways round: a front-end that reads the first and a back-end
                # that reads the last disagree in one direction only.
                "Duplicate Host header, injected first",
                f"GET {self.path} HTTP/1.1",
                self.second_host(marker, f"Host: {host}"),
            ),
            (
                # RFC 7230 says a server must reject whitespace between a
                # field name and its colon. One that reads it as a header
                # anyway, behind one that rejected nothing, is the bug.
                "Whitespace before the Host colon",
                f"GET {self.path} HTTP/1.1",
                self.second_host(host, f"Host : {marker}"),
            ),
        ]

    @staticmethod
    def _refused(status):
        """Whether a status is this target turning a request away.

        A parse failure arrives as 0 and is not read as a refusal: inventing
        one would be the mirror of the defect this baseline exists to prevent.
        """
        return status >= 400

    def _plain_request(self, host_value):
        """One well-formed request carrying ``host_value`` as the host."""
        return self.client.send(
            self.scheme, self.connect_host, self.connect_port,
            f"GET {self.path} HTTP/1.1", self.base_lines(host_value),
            sni_host=self.connect_host,
        )

    def establish_validation(self, unknown_host):
        """Whether this target refuses a host it cannot know.

        Two well-formed requests settle it: the ordinary one, and the same
        request carrying a host minted for this scan. Returns
        ``(refused, ordinary status, unknown status)``, or None when the
        ordinary request went unanswered - nothing can be established either
        way then, and a reflection could not be graded if one arrived.
        """
        ordinary = self._plain_request(self.original_host)
        if ordinary is None:
            return None
        self.note_response()
        unknown = self._plain_request(unknown_host)
        if unknown is None:
            # The front-end dropped the connection rather than answer for a
            # host it does not serve. That is a refusal.
            return True, ordinary.status_code, None
        self.note_response()
        refused = (self._refused(unknown.status_code)
                   and not self._refused(ordinary.status_code))
        return refused, ordinary.status_code, unknown.status_code

    def validation_note(self):
        """What the baseline established, in the words the finding needs."""
        refused, ordinary, unknown = self.host_validation
        if refused:
            answered = "was not answered at all" if unknown is None \
                else f"was answered {unknown}"
            return (f"A well-formed request carrying a host this target cannot "
                    f"know {answered}, while its own host was answered "
                    f"{ordinary}: the host is validated here, and this shape "
                    f"got past that refusal.")
        return (f"Nothing here was refusing an unknown host - a well-formed "
                f"request carrying one was answered {unknown}, not refused - "
                f"so no refusal was bypassed. What this shape shows is a "
                f"parser accepting a request it is required to reject, which "
                f"is what disagrees with a front-end that does validate.")

    def run(self):
        if not self.connect_host:
            self.skip("the target URL has no hostname to connect to")
            return
        token = new_token()
        marker = f"{token}.example-collab.com"
        self.marker_token = token
        # Before any shape is called a bypass, establish that there was a
        # refusal for one to get past.
        self.host_validation = self.establish_validation(
            f"{new_token()}.example-collab.com")
        if self.host_validation is None:
            self.skip("the target did not answer a well-formed request, so "
                      "whether it refuses an unknown host - which is what a "
                      "bypass would have to get past - could not be "
                      "established")
            return
        cases = [(name, line, headers)
                 for name, line, headers in self.techniques(marker)]
        self.run_pool(self.worker, cases, "Host Header Bypass Testing")

    def worker(self, technique, request_line, header_lines):
        response = self.client.send(
            self.scheme, self.connect_host, self.connect_port,
            request_line, header_lines, sni_host=self.connect_host,
        )
        if response is None:
            return
        self.note_response()
        location = response.get("Location") or ""
        reflected_body = self.marker_token in response.text
        reflected_location = self.marker_token in location
        header_hits = [
            name for name, value in response.headers
            if name.lower() != "location" and self.marker_token in value
        ]
        if not (reflected_body or reflected_location or header_hits):
            return
        notes = [f"Bypass technique: {technique}."]
        if reflected_location:
            notes.append(f"Marker reflected in 'Location': {location}")
        if reflected_body:
            notes.append("Marker reflected in response body.")
        if header_hits:
            notes.append(f"Marker reflected in header(s): {header_hits}")
        notes.append(self.validation_note())
        self.record({
            "url": self.target_url,
            "method": "GET",
            "header_name": technique,
            "payload": request_line,
            "status_code": response.status_code,
            "analysis": " ".join(notes),
            "raw_request": request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n",
        })
