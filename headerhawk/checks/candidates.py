"""What value to put in a candidate header, so the header is really tested.

The unkeyed-input search used to send one per-scan marker - a hostname - as the
value of every candidate. For a header that carries a host that is exactly
right: the marker is unique, so the application cannot have echoed it from
anywhere else. For a header that carries a scheme, a port, an address or a
flag, a hostname is nonsense. The back-end ignores it or rejects the request,
and the header reads as "changes nothing" for a reason that has nothing to do
with the application.

A third of the candidate list is in that second group, so a third of the search
was spending requests to learn nothing. Each of those headers gets a value of
the shape it actually carries instead.

Only a host- or path-shaped value can carry the marker, so only those headers
can be confirmed by reflection. The rest are confirmed by the response changing
and that change being served back, which is what the canonical artefact
comparison in ``unkeyed`` is for.
"""

# Inert on purpose. 203.0.113.0/24 is the documentation range from RFC 5737:
# it routes nowhere, so an application that acts on it cannot reach anything,
# and an operator reading the evidence can see it was never a real address.
DOCUMENTATION_IP = "203.0.113.7"

# Values for the candidates whose meaning is not a host. Everything absent from
# this map gets the marker, which is the right answer for a header that names a
# host or a path - the large majority.
#
# Kept as an explicit list rather than matched on the header's name: "CF-
# IPCountry" contains "IP" and carries a country, "Front-End-Https" contains
# "Https" and carries a flag. Guessing from the name is how a header ends up
# tested with a value that means nothing in it, which is the defect this file
# exists to fix.
# Headers that name the scheme, and the flags proxies set to say the same
# thing. Their value is not fixed: it has to be the opposite of what the target
# already is. Sending "http" to an http:// target reproduces the baseline, so
# an application that rebuilds its URLs from the header looks untouched and the
# header reads as inert - a clean result from a probe that never asked anything.
SCHEME_HEADERS = frozenset({
    "x-forwarded-proto", "x-forwarded-scheme", "x-forwarded-protocol",
    "x-url-scheme",
})
SSL_FLAG_HEADERS = frozenset({"x-forwarded-ssl", "front-end-https"})
NUMERIC_FLAG_HEADERS = frozenset({"fastly-ssl"})
VISITOR_HEADERS = frozenset({"cf-visitor"})

# The port to offer, and what to offer instead when the target is already on
# it, for the same reason.
PROBE_PORT = "8080"
ALTERNATE_PORT = "8081"

TYPED_VALUES = {
    # Client address.
    "x-real-ip": DOCUMENTATION_IP,
    "x-client-ip": DOCUMENTATION_IP,
    "x-cluster-client-ip": DOCUMENTATION_IP,
    "true-client-ip": DOCUMENTATION_IP,
    "cf-connecting-ip": DOCUMENTATION_IP,
    "fastly-client-ip": DOCUMENTATION_IP,
    "fly-client-ip": DOCUMENTATION_IP,
    "x-azure-clientip": DOCUMENTATION_IP,
    "x-originating-ip": DOCUMENTATION_IP,
    "x-remote-ip": DOCUMENTATION_IP,
    "x-remote-addr": DOCUMENTATION_IP,
    "client-ip": DOCUMENTATION_IP,
    "x-proxyuser-ip": DOCUMENTATION_IP,
    "x-forwarded-for": DOCUMENTATION_IP,
    "x-forwarded-for-original": DOCUMENTATION_IP,
    "x-coming-from": DOCUMENTATION_IP,
    "x-envoy-external-address": DOCUMENTATION_IP,
    "x-edge-ip": DOCUMENTATION_IP,
    # Region and locale, which routinely decide what a page says.
    "cf-ipcountry": "ZZ",
    "x-country-code": "ZZ",
    "x-vercel-ip-country": "ZZ",
    "x-locale": "zz-ZZ",
    "x-timezone": "Etc/UTC",
    # Device and capability hints, same story.
    "x-is-mobile": "true",
    "x-device-type": "mobile",
    "save-data": "on",
    "viewport-width": "320",
    "x-wap-profile": "http://wap.example.com/profile.xml",
    # Structured values a parser would reject a hostname in.
    "x-envoy-internal": "true",
    "x-middleware-prefetch": "1",
    "x-moz": "prefetch",
    "sec-purpose": "prefetch;prerender",
    "x-purpose": "prefetch",
    "x-requested-with": "XMLHttpRequest",
    "x-http-method-override": "HEAD",
    "x-method-override": "HEAD",
    "cdn-loop": "example-cdn",
    "fastly-ff": "example-cdn",
    "akamai-origin-hop": "1",
}

# Headers whose value is a path or a URL. The marker rides in a path segment,
# so these can still be confirmed by reflection.
PATH_SHAPED = frozenset({
    "x-original-url", "x-rewrite-url", "x-override-url", "x-originating-url",
    "request-uri", "x-request-uri", "x-original-path", "x-forwarded-path",
    "x-envoy-original-path", "x-forwarded-prefix",
})


def _opposite_scheme(target_scheme):
    return "http" if (target_scheme or "").lower() == "https" else "https"


def candidate_value(header_name, marker, target_scheme="https",
                    target_port=None):
    """The value to send in this header: one of the shape it really carries.

    The marker is used wherever the shape allows it, because a unique value is
    what makes a reflection proof rather than a coincidence.

    Where the value names what the target already is - its scheme, its port -
    the probe is the opposite. Offering a target its own scheme asks it
    nothing: an application that rebuilds every absolute URL from the header
    returns exactly the baseline, and the header reads as inert.
    """
    name = (header_name or "").strip().lower()
    if name in PATH_SHAPED:
        return f"/{marker}"
    if name in SCHEME_HEADERS:
        return _opposite_scheme(target_scheme)
    if name in SSL_FLAG_HEADERS:
        return "off" if (target_scheme or "").lower() == "https" else "on"
    if name in NUMERIC_FLAG_HEADERS:
        return "0" if (target_scheme or "").lower() == "https" else "1"
    if name in VISITOR_HEADERS:
        return '{"scheme":"%s"}' % _opposite_scheme(target_scheme)
    if name == "x-forwarded-port":
        return (ALTERNATE_PORT if str(target_port or "") == PROBE_PORT
                else PROBE_PORT)
    return TYPED_VALUES.get(name, marker)


def carries_marker(header_name, marker, target_scheme="https",
                   target_port=None):
    """Whether this header's value contains the marker, and so can reflect it."""
    return marker in candidate_value(header_name, marker, target_scheme,
                                     target_port)
