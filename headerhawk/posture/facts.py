"""What a posture rule is given to work with.

Bundling the response into one object keeps the rule signature stable: a rule
that later needs the body or the status code does not force every other rule to
change shape.
"""

from urllib.parse import urlparse

from .cookies import parse_set_cookie, set_cookie_values


class ResponseFacts:
    """The parts of a response the posture rules assess."""

    def __init__(self, url, scheme, status_code, headers, cookies):
        self.url = url
        self.scheme = scheme
        self.status_code = status_code
        # Header names lower-cased once, so rules never have to worry about the
        # casing a particular server happens to use.
        self.headers = headers
        self.cookies = cookies

    @classmethod
    def from_response(cls, response, fallback_url):
        url = getattr(response, "url", None) or fallback_url
        headers = {name.lower(): value
                   for name, value in dict(response.headers).items()}
        cookies = [cookie for cookie in
                   (parse_set_cookie(value) for value in set_cookie_values(response))
                   if cookie is not None]
        return cls(
            url=url,
            scheme=(urlparse(url).scheme or "").lower(),
            status_code=getattr(response, "status_code", None),
            headers=headers,
            cookies=cookies,
        )

    def header(self, name):
        """Case-insensitive header lookup, returning None when absent."""
        return self.headers.get(name.lower())

    @property
    def media_type(self):
        """The response's media type, lower-cased and without parameters."""
        value = self.header("content-type") or ""
        return value.split(";", 1)[0].strip().lower()

    @property
    def is_document(self):
        """Whether a browser would render this response as a document.

        The browser security controls - framing, referrer, script sources,
        opener isolation, feature permissions - all act on a document. A JSON
        or binary response has none of those to constrain.

        A response with no media type at all counts as a document: a browser
        may sniff one, which is exactly the case X-Content-Type-Options exists
        for, and assessing it is the safe direction to be wrong in.
        """
        media_type = self.media_type
        if not media_type:
            return True
        return media_type in ("text/html", "application/xhtml+xml")
