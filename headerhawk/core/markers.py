"""Per-scan markers, and recognising them again afterwards.

A finding is proof because the value that came back could not have come from
anywhere else: every probe carries a token minted for this scan alone. That same
uniqueness is a problem for anything that has to recognise the *same* finding
across two scans - a baseline comparison, a SARIF fingerprint - because the
token is different every time.

Folding the token out solves that, but only if what gets folded is the scanner's
own token and nothing else. Folding every long run of hexadecimal also folds a
virtual host named in hex and an identifier in a path, filing two distinct
findings under one identity. So a token is minted with a prefix that says who
made it, and only that shape is folded.
"""

import re
import uuid

# Stamped on the front of every token the scanner mints. "h" is not a
# hexadecimal digit, so the prefix cannot be read as part of the token, and a
# hexadecimal value the scanner did not produce cannot be read as one.
MARKER_PREFIX = "hh"

# What a folded token is replaced with. Two findings that differ only by their
# marker collapse onto the same text, and so onto the same identity.
PLACEHOLDER = "<token>"

# The one shape folded. A marker minted before the prefix existed is not
# recognised here, and deliberately so: those markers sat in contexts this
# module cannot anchor to - a CORS origin is built around the target's own
# hostname, an out-of-band host around the operator's own domain - so covering
# them would mean folding bare hexadecimal next to arbitrary text, which is the
# defect this module exists to fix. Identities from before the prefix therefore
# change once, and a baseline recorded then has to be taken again; a comparison
# that matches nothing says so rather than leaving it to be guessed at.
_OURS = re.compile(MARKER_PREFIX + r"[0-9a-f]{8,}", re.I)


def new_token(length=12):
    """Mint a token for this scan: unique, and recognisable as the scanner's.

    ``length`` is how much of the random part to keep, not the length of the
    result, which carries the prefix on top of it.
    """
    return MARKER_PREFIX + uuid.uuid4().hex[:length]


def fold_tokens(value):
    """Replace the scanner's own per-scan tokens with a stable placeholder.

    Anything else is left exactly as it is, including a hexadecimal value that
    means something - a virtual host named in hex, an identifier in a path -
    because folding those would file two separate findings as one.
    """
    return _OURS.sub(PLACEHOLDER, str(value or ""))
