"""The shapes a posture rule works with.

Kept in their own module so the cookie rules and the header rules can both use
them without importing each other.
"""

from collections import namedtuple

# One problem found by a rule. ``subject`` names what the finding is about - a
# header field for most rules, an individual cookie for the cookie rules - and
# becomes the finding's header_name, so two cookies failing the same rule stay
# distinguishable in a report and get separate fingerprints.
# ``severity`` overrides the rule's own band for this one issue, which is how
# a rule distinguishes a weakness that matters from one that a current browser
# already covers - a missing Referrer-Policy against one set to unsafe-url.
Issue = namedtuple("Issue", "test_result analysis subject severity",
                   defaults=(None,))

# ``assess`` takes a ResponseFacts and returns a list of Issue (empty when the
# control is in place). ``documents_only`` marks a rule that only means
# something for a response a browser renders as a document: a JSON API reply
# carries no framing, no referrer and no script to constrain, so reporting
# those controls against it is noise rather than a finding - and claiming to
# have assessed them there would be worse.
PostureRule = namedtuple("PostureRule",
                         "test_type severity assess documents_only",
                         defaults=(False,))
