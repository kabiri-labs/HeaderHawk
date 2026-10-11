"""A deliberately vulnerable web application, and its secure twin.

Every route here exists to make one statement about HeaderHawk true or false.
The vulnerable routes are the ones a real application gets wrong - a link built
from a forwarding header, a redirect built from the Host header, an Origin
mirrored back - and each has a secure counterpart under ``/secure/`` that gets
the same thing right.

Two deliberate choices keep the scenarios from interfering with each other.

Every route but ``/weak`` sends the full set of response-posture headers, so a
scenario about host injection is not also a scenario about a missing
Content-Security-Policy. A scan of any route here should produce findings about
that route's subject and nothing else, which is what lets the runner treat an
unexpected finding as a false positive rather than as noise it has to tolerate.

And nothing sends a ``Set-Cookie`` except ``/weak``, because a cache passes a
response that carries one. The routes that have to be cacheable say so.

The standard library only: no framework, nothing to pin, nothing to install.
"""

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("LAB_PORT", "8000"))
# Inside the container this has to be every interface, because the runner
# reaches it across the compose network. Run by hand it should not be.
BIND = os.environ.get("LAB_BIND", "0.0.0.0")

# What a hardened application sends. Present on every route except /weak, so
# that posture findings belong to the posture scenarios alone.
HARDENED = (
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self'; object-src 'none'; "
     "base-uri 'none'; frame-ancestors 'none'; report-to csp-endpoint"),
    ("Reporting-Endpoints", 'csp-endpoint="/csp-reports"'),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
)

# The one origin the secure CORS route trusts.
TRUSTED_ORIGIN = "https://trusted.lab"

PAGE = ("<!doctype html><html><head><title>lab</title></head>"
        "<body><h1>{heading}</h1>{body}</body></html>")

# An authority in a request line that arrived in absolute form. A front-end
# that validates the Host header and a back-end that reads the request line
# instead disagree about which host this request was for, and that disagreement
# is the bypass the raw shapes are looking for.
_ABSOLUTE = re.compile(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", re.I)


class Lab(BaseHTTPRequestHandler):
    """One handler, routed by path."""

    protocol_version = "HTTP/1.1"
    # Not the Python version. /weak sets its own on purpose; everywhere else a
    # version string would be a finding about this harness.
    server_version = "lab"
    sys_version = ""

    def version_string(self):
        # BaseHTTPRequestHandler joins the two with a space, which leaves a
        # trailing one. /weak sends its own Server header instead.
        return self.server_version

    # -- helpers -----------------------------------------------------------

    def _hosts_sent(self):
        """Every host this request named, in the order the request named them.

        Deliberately sloppy, and deliberately realistic: an application that
        reads all of the Host headers rather than one of them, and that trusts
        an absolute request line, is the application the raw bypass shapes
        exist to find. Which of two Host headers a front-end honours is a
        choice each implementation makes for itself, so an application that
        honours both disagrees with every front-end in at least one direction.
        """
        values = list(self.headers.get_all("Host") or [])
        try:
            line = self.raw_requestline.decode("latin-1")
            absolute = _ABSOLUTE.match(line.split(" ", 1)[-1].strip())
        except (UnicodeDecodeError, AttributeError, IndexError):
            absolute = None
        if absolute:
            values.append(absolute.group(1))
        return [value.strip() for value in values if value and value.strip()]

    def _forwarded_host(self):
        """What the request says the public host is.

        X-Forwarded-Host only, with a fixed fallback. Falling back to Host
        would make the routes below report on Host as well, and a scenario
        about one header is worth more than a scenario about two.
        """
        return self.headers.get("X-Forwarded-Host") or "app.example.test"

    def _send(self, status, body=b"", content_type="text/html; charset=utf-8",
              headers=(), hardened=True):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if hardened:
            for name, value in HARDENED:
                self.send_header(name, value)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if body and not getattr(self, "_head_only", False):
            self.wfile.write(body)

    def _html(self, status, heading, body, headers=(), hardened=True):
        page = PAGE.format(heading=heading, body=body).encode("utf-8")
        self._send(status, page, headers=headers, hardened=hardened)

    # -- vulnerable routes -------------------------------------------------

    def route_link(self):
        """A link whose host comes from a forwarding header.

        The marker reaches the host of a URL the page points a browser at, so
        this is the shape HeaderHawk is entitled to call confirmed. Cacheable,
        because the same route is the back-end for the cache scenarios.
        """
        host = self._forwarded_host()
        self._html(200, "Dashboard",
                   '<p>Continue to <a href="https://{host}/next">your '
                   'account</a>.</p>'.format(host=host),
                   headers=(("Cache-Control", "public, max-age=60"),))

    def route_echo(self):
        """The same header, printed as text and pointed at by nothing.

        A diagnostic footer, a field in an error page. HeaderHawk must report
        this as the weaker thing it is: the application copies the header into
        its output, which is not a demonstration that it routes on it.
        """
        host = self._forwarded_host()
        self._html(200, "Diagnostics",
                   "<p>Requested https://{host}/ at this node.</p>"
                   .format(host=host))

    def route_redirect(self):
        """A redirect whose destination is whatever the Host header says."""
        host = self.headers.get("Host") or ""
        self._send(302, b"", content_type=None,
                   headers=(("Location",
                             "https://{host}/home".format(host=host)),))

    def route_canonical(self):
        """A redirect to one fixed, well-known destination, always.

        The header has nothing to do with where this goes. HeaderHawk sends
        ``example.com`` among its probes, and a scanner that matched a probe
        host against a canonical destination would report an open redirect
        here. Reporting nothing is the correct answer.
        """
        self._send(302, b"", content_type=None,
                   headers=(("Location", "https://example.com/"),))

    def route_cors(self):
        """Any origin, with credentials."""
        origin = self.headers.get("Origin") or "*"
        self._html(200, "Account", "<p>balance: 0</p>",
                   headers=(("Access-Control-Allow-Origin", origin),
                            ("Access-Control-Allow-Credentials", "true"),
                            ("Vary", "Origin")))

    def route_hostreflect(self):
        """Every host the request named, echoed into the page."""
        hosts = self._hosts_sent()
        items = "".join("<li>{host}</li>".format(host=host) for host in hosts)
        self._html(200, "Node", "<ul>{items}</ul>".format(items=items))

    def route_offsite(self):
        """A hardened page whose only content is a redirect somewhere else.

        Its own response headers are the hardened set. Whatever a scan of this
        URL reports about response posture, it did not learn it here.
        """
        self._send(302, b"", content_type=None,
                   headers=(("Location", "http://app:8000/weak"),))

    def route_deception(self):
        """A router that ignores a path parameter, on a cacheable page.

        "/deception;.css" is served as "/deception". A cache in front sees a
        URL ending in .css, files it as a static asset, and hands one user's
        page to the next. The suffix is ignored here on purpose: every other
        route rejects it, so the gadget belongs to this scenario alone.
        """
        self._html(200, "Statement",
                   "<p>Account 4211 - closing balance 0.</p>",
                   headers=(("Cache-Control", "public, max-age=60"),))

    def route_weak(self):
        """A page with no response-header posture at all.

        The posture scenario. It discloses a product version and sets a cookie
        with no attributes, and it is the only route that does either.
        """
        body = ('<p>Welcome back.</p><form action="/account" method="post">'
                '<input name="amount"></form>')
        self._html(200, "Portal", body, hardened=False, headers=(
            ("Server", "ExampleServer/1.2.3"),
            ("X-Powered-By", "ExampleFramework/4.5"),
            ("Set-Cookie", "sid=lab-session-value-not-a-secret; Path=/"),
            ("Cache-Control", "no-store"),
        ))

    # -- secure routes -----------------------------------------------------

    def route_secure_link(self):
        """The same page, with the host it was built from fixed."""
        self._html(200, "Dashboard",
                   '<p>Continue to <a href="https://app.example.test/next">'
                   'your account</a>.</p>',
                   headers=(("Cache-Control", "public, max-age=60"),))

    def route_secure_redirect(self):
        """A redirect to a path, so there is no host to control."""
        self._send(302, b"", content_type=None,
                   headers=(("Location", "/home"),))

    def route_secure_cors(self):
        """One origin on an allowlist, and no CORS headers for anyone else."""
        origin = self.headers.get("Origin") or ""
        headers = [("Vary", "Origin")]
        if origin == TRUSTED_ORIGIN:
            headers.append(("Access-Control-Allow-Origin", TRUSTED_ORIGIN))
            headers.append(("Access-Control-Allow-Credentials", "true"))
        self._html(200, "Account", "<p>balance: 0</p>", headers=headers)

    def route_secure_page(self):
        """A document that gets the response headers right, and a safe cookie.

        Note what is not here: Strict-Transport-Security. The lab speaks
        plaintext, where a browser ignores it, and HeaderHawk is expected not
        to ask for it. A scanner that reported it missing here would be
        reporting something that cannot be fixed.
        """
        self._html(200, "Settings", "<p>Everything is where you left it.</p>",
                   headers=(("Set-Cookie",
                             "__Host-sid=lab-session-value-not-a-secret; "
                             "Path=/; HttpOnly; Secure; SameSite=Lax"),
                            ("Cache-Control", "no-store")))

    def route_secure_json(self):
        """An API reply, so the document-only controls do not apply.

        Framing, referrer policy and permissions policy are instructions to a
        browser rendering a document. On this reply they are not weaknesses and
        they are not passes either: HeaderHawk is expected to report them as
        not assessed, with the media type as the reason.
        """
        body = json.dumps({"balance": 0, "currency": "XTS"}).encode("utf-8")
        self._send(200, body, content_type="application/json",
                   headers=(("Cache-Control", "no-store"),))

    def route_secure_inert(self):
        """A cacheable page that is the same whatever the request says.

        The back-end for the cache scenario that must come back clean: with
        nothing in the response following a header, there is no gadget for a
        cache to store.
        """
        self._html(200, "Status", "<p>All systems normal.</p>",
                   headers=(("Cache-Control", "public, max-age=60"),))

    # -- plumbing ----------------------------------------------------------

    ROUTES = {
        "/link": route_link,
        "/echo": route_echo,
        "/redirect": route_redirect,
        "/canonical": route_canonical,
        "/cors": route_cors,
        "/hostreflect": route_hostreflect,
        "/deception": route_deception,
        "/offsite": route_offsite,
        "/weak": route_weak,
        "/secure/link": route_secure_link,
        "/secure/redirect": route_secure_redirect,
        "/secure/cors": route_secure_cors,
        "/secure/page": route_secure_page,
        "/secure/json": route_secure_json,
        "/secure/inert": route_secure_inert,
    }

    def do_GET(self):
        # The path may have arrived in absolute form, which is one of the
        # bypass shapes; route on the path component either way. urlsplit and
        # not urlparse: the latter splits ";params" off the last segment, and
        # a router that ignores a path parameter is a cache-deception gadget -
        # which one route below has deliberately and the others must not have
        # by accident.
        path = urlsplit(self.path).path.rstrip("/") or "/"
        handler = self.ROUTES.get(path)
        if handler is None and ";" in path:
            # The one deliberate exception, and only for its own route.
            stripped = path.split(";", 1)[0]
            if stripped == "/deception":
                handler = self.ROUTES[stripped]
        if handler is None:
            self._html(404, "Not found", "<p>No such route.</p>")
            return
        handler(self)

    do_POST = do_GET
    do_PUT = do_GET
    do_OPTIONS = do_GET

    def do_HEAD(self):
        # Routed like the rest, with the body dropped: a HEAD that carries one
        # desynchronises a keep-alive connection, and the client would then
        # read the next response as part of this one.
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def main():
    server = ThreadingHTTPServer((BIND, PORT), Lab)
    sys.stderr.write("lab app listening on %s:%d\n" % (BIND, PORT))
    server.serve_forever()


if __name__ == "__main__":
    main()
