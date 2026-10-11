"""CRLF injection into response header fields (HTTP response splitting).

This is the bridge between the two halves of the scanner: untrusted input on the
request side that ends up *building* a response header. A value that reaches a
`Location` or any other response header without encoding lets a carriage return
and line feed close that header and start another one - or end the header block
entirely and begin a body the attacker wrote.

Findings are proof rather than suspicion. The injected header is named after a
unique per-scan marker, so a response header field that did not exist before and
carries that marker cannot have come from anywhere else. Nothing is guessed from
the value being echoed somewhere.

The probes are ordinary requests carrying percent-encoded control characters.
Nothing is left on a connection and no other user's traffic is affected, so this
check needs no opt-in.
"""

from urllib.parse import parse_qs, urlencode, urlparse

from ..core.markers import new_token
from .base import BaseTest

# Request headers an application is most likely to decode and copy into a
# response - the ones this scanner already knows are treated as routing input.
DECODED_REQUEST_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Referer",
]

# URL parameters whose value classically lands in a Location header.
REDIRECT_PARAMS = ["url", "next", "redirect", "dest", "destination", "uri",
                   "path", "return", "returnUrl", "continue"]


class CRLFInjectionTest(BaseTest):
    """Probe whether untrusted input can add a field to the response headers."""

    test_type = "CRLF Injection"

    URL_BORNE = "CRLF Response Splitting"
    HEADER_BORNE = "CRLF Header Injection"

    @classmethod
    def emitted_types(cls):
        return (cls.URL_BORNE, cls.HEADER_BORNE)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = new_token()
        self.marker = f"X-HeaderHawk-{self.token}"
        self._reported = set()

    # -- payloads ------------------------------------------------------------

    def encodings(self):
        """The CRLF encodings worth trying, worst-understood parser first.

        The overlong UTF-8 pair is included because some parsers decode it to a
        real CR/LF while the validation in front of them does not.
        """
        injected = f"{self.marker}:%201"
        return [
            ("percent-encoded CRLF", f"%0d%0a{injected}"),
            ("percent-encoded CR only", f"%0d{injected}"),
            ("percent-encoded LF only", f"%0a{injected}"),
            ("double-encoded CRLF", f"%250d%250a{injected}"),
            ("overlong UTF-8 CRLF", f"%e5%98%8a%e5%98%8d{injected}"),
        ]

    # -- detection -----------------------------------------------------------

    def injected_fields(self, response):
        """Response header fields carrying this scan's marker, if any."""
        found = []
        for name, value in dict(response.headers).items():
            if self.token in name:
                found.append(name)
            elif self.token in str(value) and name.lower() in ("set-cookie",):
                # A split that lands inside Set-Cookie is a cookie the attacker
                # chose, which is worth reporting on the same footing.
                found.append(f"{name} (injected cookie)")
        return found

    def _record_split(self, test_type, encoding, subject, url, response, fields,
                      *, param=None, headers=None):
        # One finding per (type, subject): the encodings are alternative ways in
        # to the same hole, not separate holes.
        key = (test_type, subject)
        if key in self._reported:
            return
        self._reported.add(key)
        entry = {
            "test_type": test_type,
            "test_result": "Vulnerable",
            "severity": "High",
            "url": url,
            "method": "GET",
            "payload": encoding,
            "status_code": response.status_code,
            "analysis": (
                f"A {encoding} sequence in {subject} added the response header "
                f"field(s) {fields} to the reply. The value reaches a response "
                f"header without encoding, so an attacker chooses what fields - "
                f"or what body - the response carries."
            ),
        }
        if param is not None:
            entry["param_name"] = param
        if headers is not None:
            entry["headers"] = headers
            entry["header_name"] = subject
        self.record(entry)

    # -- vectors -------------------------------------------------------------

    def _url_with(self, param, value):
        parsed = urlparse(self.target_url)
        query = parse_qs(parsed.query)
        query[param] = value
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def probe_parameter(self, param, encoding, payload):
        url = self._url_with(param, f"https://example.com/{payload}")
        response = self.request("GET", url=url, allow_redirects=False)
        if response is None:
            return
        fields = self.injected_fields(response)
        if fields:
            self._record_split(self.URL_BORNE, encoding, f"the '{param}' "
                               f"parameter", url, response, fields, param=param)

    def probe_path(self, encoding, payload):
        parsed = urlparse(self.target_url)
        path = (parsed.path or "/").rstrip("/")
        url = parsed._replace(path=f"{path}/{payload}").geturl()
        response = self.request("GET", url=url, allow_redirects=False)
        if response is None:
            return
        fields = self.injected_fields(response)
        if fields:
            self._record_split(self.URL_BORNE, encoding, "the URL path", url,
                               response, fields, param="(path)")

    def probe_header(self, header_name, encoding, payload):
        value = f"example.com/{payload}"
        response = self.request("GET", headers={header_name: value},
                                allow_redirects=False)
        if response is None:
            return
        fields = self.injected_fields(response)
        if fields:
            self._record_split(self.HEADER_BORNE, encoding, header_name,
                               self.target_url, response, fields,
                               headers={header_name: value})

    # -- entry point ---------------------------------------------------------

    def run(self):
        cases = []
        for encoding, payload in self.encodings():
            cases.append(("path", None, encoding, payload))
            for param in REDIRECT_PARAMS:
                cases.append(("param", param, encoding, payload))
            for header in DECODED_REQUEST_HEADERS:
                cases.append(("header", header, encoding, payload))
        self.run_pool(self.worker, cases, "CRLF Injection Testing")

    def worker(self, kind, subject, encoding, payload):
        if kind == "path":
            self.probe_path(encoding, payload)
        elif kind == "param":
            self.probe_parameter(subject, encoding, payload)
        else:
            self.probe_header(subject, encoding, payload)
