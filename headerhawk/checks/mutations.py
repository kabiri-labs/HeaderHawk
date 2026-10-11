"""Marker-preserving mutations of a routing header's value.

A host-validation bug is a mismatch bug. The front-end, the language's HTTP
parser and the application framework each decide what the host is, and they do
not always agree; the hole is in the disagreement, not in the pretty form. A
single canonical hostname only tests the branch whoever wrote the validator was
thinking about, so it finds the holes they already knew to look for.

These are shapes of the same hypothesis, not a second scanner. Every one of
them still carries the per-scan marker, so the proof the check already relies on
- that value could not have come from anywhere else - applies unchanged, and a
mutation that reflects is deduplicated into the finding for its header rather
than becoming a finding of its own.

Which shapes are worth sending depends on what the header carries. A list
mutation means nothing in a header that holds a single port, and RFC 7239
parameter syntax means nothing outside ``Forwarded``.
"""

from collections import namedtuple

# One value to send, and the name of the shape it is - which is what the
# evidence names, so a reader can tell which disagreement was exploited.
Mutation = namedtuple("Mutation", "shape value")

# Headers whose value is a bare host, where a parser has to decide where the
# host ends: that decision is what these shapes disagree about.
_CARRIES_A_HOST = frozenset({
    "host", "x-forwarded-host", "x-forwarded-server", "x-host",
    "x-http-host-override", "x-original-host",
})

# Headers whose value is a URL rather than a host.
_CARRIES_A_URL = frozenset({"base-url", "request-uri"})

# RFC 7239 gives this one its own parameter syntax.
_FORWARDED = frozenset({"forwarded"})


def mutations_for(header_name, marker, original_host):
    """The shapes worth sending in this header, each carrying the marker."""
    name = (header_name or "").strip().lower()

    if name in _FORWARDED:
        return [
            Mutation("RFC 7239 host parameter", f"host={marker}"),
            # A real intermediary sends the whole element. An application that
            # reads the header by splitting on ';' or searching for "host="
            # takes the marker out of this one too.
            Mutation("RFC 7239 element",
                     f"for=192.0.2.1;host={marker};proto=http"),
        ]

    if name in _CARRIES_A_URL:
        return [
            Mutation("plain", marker),
            Mutation("absolute URL", f"https://{marker}/"),
        ]

    if name not in _CARRIES_A_HOST:
        # A client-IP, scheme, port or prefix header carries neither a host nor
        # a URL, so there is no boundary for two parsers to disagree about. The
        # marker goes in as it is, which still answers the only question worth
        # asking of those headers: is the value honoured at all?
        return [Mutation("plain", marker)]

    return [
        Mutation("plain", marker),
        # A validator that asks "does it start with my host?" accepts this.
        Mutation("target as a prefix", f"{original_host}.{marker}"),
        # One that splits on '@' as userinfo, or that does not split at all.
        Mutation("target as userinfo", f"{original_host}@{marker}"),
        # What an intermediary appending its own value looks like. An
        # application that reads the last element takes the marker.
        Mutation("appended to a list", f"{original_host}, {marker}"),
        # A validator comparing the host with the port still attached, or one
        # comparing it without.
        Mutation("with an explicit port", f"{marker}:443"),
        # The same name to a resolver, a different string to a comparison.
        Mutation("with a trailing dot", f"{marker}."),
    ]
