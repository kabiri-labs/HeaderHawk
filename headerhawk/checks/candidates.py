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
TYPED_VALUES = {
    # Scheme. http against an https origin is the gadget: an application that
    # rebuilds absolute URLs from it downgrades every link in the page.
    "x-forwarded-proto": "http",
    "x-forwarded-scheme": "http",
    "x-forwarded-protocol": "http",
    "x-url-scheme": "http",
    # Flags, which proxies set to say the same thing a scheme does.
    "x-forwarded-ssl": "off",
    "front-end-https": "off",
    "fastly-ssl": "0",
    # Port, which an application rebuilding a URL will put back into it.
    "x-forwarded-port": "8080",
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
    "cf-visitor": '{"scheme":"http"}',
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


def candidate_value(header_name, marker):
    """The value to send in this header: one of the shape it really carries.

    The marker is used wherever the shape allows it, because a unique value is
    what makes a reflection proof rather than a coincidence.
    """
    name = (header_name or "").strip().lower()
    if name in PATH_SHAPED:
        return f"/{marker}"
    return TYPED_VALUES.get(name, marker)


def carries_marker(header_name, marker):
    """Whether this header's value contains the marker, and so can reflect it."""
    return marker in candidate_value(header_name, marker)
