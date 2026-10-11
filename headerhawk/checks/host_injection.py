"""Reflection-based Host header injection."""

from ..core.markers import new_token
from .base import BaseTest
from .wordlists import HOST_HEADERS

class HostInjectionTest(BaseTest):
    """Reflection-based Host header injection (cache poisoning / link poisoning).

    Injects a unique random marker host and looks for it being reflected into
    the response body, the Location header or any other response header. Because
    the marker is unique, reflection is a high-confidence signal with very few
    false positives.
    """

    test_type = "Host Header Injection"

    def generate_markers(self):
        token = new_token()
        marker = f"{token}.example-collab.com"
        markers = {marker}
        # Common bypass shapes that still carry the marker.
        markers.add(f"{self.original_host}.{marker}")
        markers.add(f"{self.original_host}@{marker}")
        if self.oob_manager:
            markers.add(self.oob_manager.host("host"))
        elif self.oob_domain:
            markers.add(f"{token}.{self.oob_domain.strip('/')}")
        return token, markers

    def run(self):
        token, markers = self.generate_markers()
        self.marker_token = token
        test_cases = [
            (method, header, marker)
            for method in self.methods
            for header in HOST_HEADERS
            for marker in markers
        ]
        self.run_pool(self.worker, test_cases, "Host Header Injection Testing")

    def worker(self, method, header_name, marker):
        response = self.request(
            method,
            headers={header_name: marker},
            allow_redirects=False,
        )
        if response is None:
            return

        location = response.headers.get("Location", "")
        body = response.text or ""
        reflected_in_body = self.marker_token in body
        reflected_in_location = self.marker_token in location
        header_hits = [
            name for name, value in response.headers.items()
            if name.lower() != "location" and self.marker_token in str(value)
        ]

        if not (reflected_in_body or reflected_in_location or header_hits):
            if self.verbose == 2:
                self.all_results.append({
                    "test_type": self.test_type,
                    "url": response.url,
                    "method": method,
                    "header_name": header_name,
                    "payload": marker,
                    "status_code": response.status_code,
                    "analysis": "Marker not reflected.",
                    "test_result": "Not Vulnerable",
                })
            return

        parts = []
        if reflected_in_location:
            parts.append(f"Injected host reflected in 'Location' header: {location}")
        if reflected_in_body:
            parts.append("Injected host reflected in response body (cache/link poisoning).")
        if header_hits:
            parts.append(f"Injected host reflected in response header(s): {header_hits}")

        self.record({
            "url": response.url,
            "method": method,
            "headers": {header_name: marker},
            "header_name": header_name,
            "payload": marker,
            "status_code": response.status_code,
            "response_time": response.elapsed.total_seconds(),
            "analysis": " ".join(parts),
        })
