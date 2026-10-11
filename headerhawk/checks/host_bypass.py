"""Host validation bypasses that require raw, un-normalised HTTP."""

from urllib.parse import urlparse

from .._meta import __tool_name__, __version__
from ..net.raw import RawHTTPClient
from ..core.markers import new_token
from ..core.request_file import header_lines
from ..core.scope import SCOPE_HOST
from .base import BaseTest


class HostBypassTest(BaseTest):
    """Host header validation bypasses that require raw, un-normalised HTTP.

    Sends duplicate Host headers, absolute-URI request lines and indented
    (line-folded) headers carrying a unique marker host, then checks whether
    the marker is reflected back - proving the validation can be bypassed.
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
                "Host override",
                f"GET {self.path} HTTP/1.1",
                self.base_lines(marker),
            ),
        ]

    def run(self):
        if not self.connect_host:
            self.skip("the target URL has no hostname to connect to")
            return
        token = new_token()
        marker = f"{token}.example-collab.com"
        self.marker_token = token
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
        self.record({
            "url": self.target_url,
            "method": "GET",
            "header_name": technique,
            "payload": request_line,
            "status_code": response.status_code,
            "analysis": " ".join(notes),
            "raw_request": request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n",
        })
