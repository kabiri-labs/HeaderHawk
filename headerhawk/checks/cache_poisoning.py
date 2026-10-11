"""Confirmed web cache poisoning via unkeyed headers."""

from urllib.parse import parse_qs, urlencode, urlparse

from ..core.markers import new_token

from .base import BaseTest
from .wordlists import CACHE_STATUS_HEADERS, UNKEYED_HOST_HEADERS

class CachePoisoningTest(BaseTest):
    """Confirm web cache poisoning, not just reflection.

    For each candidate unkeyed header, a unique cache-buster is added to the
    URL, a poisoning request is sent, and then the same URL is requested again
    *without* the malicious header. If the injected marker survives into the
    clean request, the response was cached - a confirmed poisoning.
    """

    test_type = "Web Cache Poisoning"

    def run(self):
        cases = [(header,) for header in UNKEYED_HOST_HEADERS]
        self.run_pool(self.worker, cases, "Web Cache Poisoning Testing")

    def _url_with_buster(self, buster):
        parsed = urlparse(self.target_url)
        query = parse_qs(parsed.query)
        query["cb"] = buster
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def worker(self, header_name):
        buster = new_token(10)
        token = new_token()
        marker = f"{token}.example-collab.com"
        url = self._url_with_buster(buster)

        poison = self.request("GET", url=url, headers={header_name: marker},
                              allow_redirects=False)
        if poison is None:
            return
        if token not in (poison.text or "") and token not in poison.headers.get("Location", ""):
            return  # not reflected, nothing to cache

        # Re-request the identical (cache-buster) URL without the header.
        confirm = self.request("GET", url=url, allow_redirects=False)
        if confirm is None:
            return
        cache_info = {h: confirm.headers[h] for h in CACHE_STATUS_HEADERS
                      if h in confirm.headers}
        poisoned = token in (confirm.text or "") or token in confirm.headers.get("Location", "")

        if poisoned:
            self.record({
                "url": url,
                "method": "GET",
                "header_name": header_name,
                "payload": marker,
                "status_code": confirm.status_code,
                "analysis": (
                    f"CONFIRMED: '{header_name}' is unkeyed and the poisoned "
                    f"response was served to a clean request. Cache headers: "
                    f"{cache_info or 'n/a'}."
                ),
                "test_result": "Vulnerable",
            })
        elif self.verbose == 2:
            self.all_results.append({
                "test_type": self.test_type,
                "url": url,
                "method": "GET",
                "header_name": header_name,
                "payload": marker,
                "status_code": poison.status_code,
                "analysis": (
                    f"Reflected via '{header_name}' but not served from cache "
                    f"on re-request (cache headers: {cache_info or 'n/a'})."
                ),
                "test_result": "Reflected (unconfirmed)",
            })
