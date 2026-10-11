"""Web cache deception: a page filed under a key that looks like an asset.

An attacker gets a victim to open `/account/profile.css`. The application's
router ignores the suffix and serves the victim's account page; the CDN sees a
`.css` and files it as a public static asset. The attacker then asks for the
same URL and is handed the victim's page out of the cache.

Three things have to be true, and they are checked separately. There has to be a
page: the gadget hands the next requester what the victim was served, and an
error carries nothing of the victim's to hand over. The router has to ignore the
suffix - otherwise the URL is a 404 and nothing follows. And a shared cache has
to store the result, which is what turns one victim's page into everyone's.

The first is the one that is easy to leave out, and leaving it out is how a
front-end answering every URL with the same 403 reads as a router ignoring five
suffixes: it is ignoring them, but an identical refusal served to everyone is
not a victim's page. The bar is a 2xx and nothing else. A redirect does not
qualify either - its body is empty or boilerplate, so two of them compare equal
under the tolerant comparison below for the same reason two error pages do.

The second is proved rather than inferred where it can be: the same URL is
requested again from a session carrying no credentials at all. Content that only
the logged-in session should have seen, coming back to an anonymous one, is a
cache handing a user's page to a stranger.
"""

from urllib.parse import urlparse

import requests

from ..core.scope import SCOPE_ENDPOINT
from .base import BaseTest
from .wordlists import CACHE_STATUS_HEADERS

# Suffixes that make a route look like a static asset to a cache while leaving
# it recognisable to a router that ignores the tail.
DECEPTIVE_SUFFIXES = [
    ("an appended extension", "{path}.css"),
    ("an extra path segment", "{path}/nonexistent.css"),
    ("a path parameter", "{path};.css"),
    ("an extra path segment naming a script", "{path}/nonexistent.js"),
    ("an extra path segment naming an image", "{path}/nonexistent.png"),
]

# Headers whose presence means a cache is in the path at all.
_CACHE_EVIDENCE = tuple(name.lower() for name in CACHE_STATUS_HEADERS)

# Credentials must not travel on the anonymous comparison request.
_CREDENTIAL_HEADERS = ("cookie", "authorization", "proxy-authorization")

CONFIRMATION_NOTE = (
    "Confirming this needs an authenticated session: run the scan with "
    "--auth-cookie or --auth-login-url so the deceptive URL can be requested "
    "once as the logged-in user and once anonymously. Content that only the "
    "first should have seen, coming back to the second, is a shared cache "
    "handing one user's page to another."
)


class CacheDeceptionTest(BaseTest):
    """Probe whether a page can be filed in a cache as if it were an asset."""

    test_type = "Web Cache Deception"
    scope = SCOPE_ENDPOINT

    # How far the body may move and still be the same page.
    LENGTH_TOLERANCE = 0.10
    MIN_LENGTH_DELTA = 256

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.baseline = None

    # -- helpers -------------------------------------------------------------

    def _anonymous_session(self):
        """A session identical to the scan's, minus anything that identifies it.

        Same TLS and proxy settings so the request travels the same path, and
        the same User-Agent so a WAF does not answer it differently - but no
        cookies and no authorization, so anything it receives came from a cache
        rather than from being logged in.
        """
        clean = requests.Session()
        clean.verify = getattr(self.session, "verify", True)
        clean.proxies = dict(getattr(self.session, "proxies", None) or {})
        clean.headers.update({
            name: value
            for name, value in dict(getattr(self.session, "headers", {})).items()
            if name.lower() not in _CREDENTIAL_HEADERS
        })
        return clean

    def _anonymous_get(self, url):
        try:
            return self._anonymous_session().request(
                "GET", url, timeout=self.timeout, allow_redirects=False,
                verify=getattr(self.session, "verify", True))
        except requests.RequestException:
            return None

    def deceptive_urls(self):
        parsed = urlparse(self.target_url)
        path = (parsed.path or "/").rstrip("/")
        for label, template in DECEPTIVE_SUFFIXES:
            yield label, parsed._replace(
                path=template.format(path=path), query="").geturl()

    @staticmethod
    def _served_a_page(response):
        """Whether this response is a page a cache could hand to someone else.

        A 2xx and nothing else. An error is the same refusal for everybody and
        has nothing of the victim's in it; a redirect carries no page either,
        and an empty body would satisfy the tolerant comparison below against
        any other empty body.
        """
        return response is not None and 200 <= response.status_code < 300

    def _same_page(self, response, other):
        """Whether two live responses render the same document.

        Tolerant on purpose: two renders of one page differ by a timestamp or a
        nonce, and this only has to answer "did the router serve the page or a
        404?".
        """
        if response is None or other is None:
            return False
        if response.status_code != other.status_code:
            return False
        length, reference = len(response.content or b""), len(other.content or b"")
        tolerance = max(self.MIN_LENGTH_DELTA, reference * self.LENGTH_TOLERANCE)
        return abs(length - reference) <= tolerance

    @staticmethod
    def _identical(response, other):
        """Whether one response is byte-for-byte the other.

        The tolerant comparison above cannot be used to confirm: on a short page
        its floor is wider than the whole document, so a private page and a
        login page read as the same thing. Exactness is also the right question
        here - a cache replays the bytes it stored, so a copy that came from one
        matches exactly, and a copy that was rendered fresh for this requester
        does not have to.
        """
        if response is None or other is None:
            return False
        return (response.status_code == other.status_code
                and (response.content or b"") == (other.content or b""))

    def shared_cache_may_store(self, response):
        """Whether a shared cache is allowed to keep this response.

        Absent directives count as storable, which is the situation the attack
        relies on: the origin says nothing, and the CDN decides from the
        extension instead.
        """
        directives = (response.headers.get("Cache-Control") or "").lower()
        if "no-store" in directives or "private" in directives:
            return False, directives
        return True, directives or "no Cache-Control directive"

    def _cache_context(self, response):
        return {name: value for name, value in dict(response.headers).items()
                if name.lower() in _CACHE_EVIDENCE}

    # -- entry point ---------------------------------------------------------

    def run(self):
        self.baseline = self.request("GET", allow_redirects=False)
        if self.baseline is None:
            self.skip("the target did not answer, so there was no page to "
                      "compare a deceptive URL against")
            return
        if not self._served_a_page(self.baseline):
            # Nothing was served that a cache could hand to the next
            # requester, so whether this route is a deception gadget was not
            # assessed here rather than found to be safe.
            self.skip(f"the target answered {self.baseline.status_code} rather "
                      f"than serving a page, so there was nothing a shared "
                      f"cache could store and hand to another requester")
            return
        # What a stranger sees at the ordinary URL. Used to tell "the cache gave
        # away the logged-in page" apart from "this page is public anyway".
        anonymous_normal = self._anonymous_get(self.target_url)

        storable = []
        for label, url in self.deceptive_urls():
            confused = self.request("GET", url=url, allow_redirects=False)
            # ``_same_page`` requires the same status as the baseline, which
            # was a 2xx to get here, so the bar above carries to every variant.
            if not self._same_page(confused, self.baseline):
                continue  # the router did not ignore the suffix; nothing follows
            if self.confirm(label, url, confused, anonymous_normal):
                return  # proved; the other suffixes would restate it
            allowed, directives = self.shared_cache_may_store(confused)
            if allowed:
                storable.append((label, url, confused, directives))
        if storable:
            # Every suffix that works is the same defect with the same fix, so
            # they are one finding that names them rather than several.
            self.report_potential(storable)

    def confirm(self, label, url, confused, anonymous_normal):
        """Ask whether a stranger is handed the same page, and report if so."""
        anonymous = self._anonymous_get(url)
        served_to_a_stranger = (
            self._identical(anonymous, confused)
            and not self._identical(anonymous, anonymous_normal))
        cache_info = self._cache_context(confused)

        if served_to_a_stranger:
            self.record({
                "test_result": "Vulnerable",
                "severity": "High",
                "url": url,
                "method": "GET",
                "header_name": "(path)",
                "payload": label,
                "status_code": confused.status_code,
                "analysis": (
                    f"With {label} the application still served the page rather "
                    f"than a 404, and requesting the same URL again with no "
                    f"cookies or authorization returned that same content - "
                    f"which an anonymous visitor does not get from the ordinary "
                    f"URL. A shared cache has filed a user's page as if it were "
                    f"a static asset. Cache headers: {cache_info or 'n/a'}."
                ),
            })
            return True
        return False

    def report_potential(self, storable):
        """One finding for every suffix the router ignored, naming them all."""
        label, url, confused, directives = storable[0]
        variants = ", ".join(entry[0] for entry in storable)
        self.record({
            "test_result": "Potentially Vulnerable",
            "severity": "Medium",
            "url": url,
            "method": "GET",
            "header_name": "(path)",
            "payload": label,
            "status_code": confused.status_code,
            "analysis": (
                f"The application served the page rather than a 404 for "
                f"{len(storable)} static-looking variant(s) of this URL "
                f"({variants}), and nothing forbids a shared cache from storing "
                f"the result ({directives}). A CDN keying on the extension "
                f"would file this page as a static asset. Cache headers: "
                f"{self._cache_context(confused) or 'n/a'}."
            ),
            "confirmation": CONFIRMATION_NOTE,
        })
