"""The response-header posture check.

Unlike the active checks, this one attacks nothing: it fetches the target once
and reports the browser security controls the response does not carry. Its
findings are posture-class, so they do not fail a build unless ``--fail-on``
asks them to.
"""

from ..checks.base import BaseTest
from ..core.findings import CLASS_POSTURE
from .facts import ResponseFacts
from .rules import RULES


class ResponseHeaderPostureTest(BaseTest):
    """Assess the security header posture of the target's response.

    Redirects are followed, because the headers that matter are the ones on the
    document a browser actually renders; the finding records the URL that was
    assessed, which may differ from the URL that was requested.
    """

    test_type = "Response Header Posture"
    finding_class = CLASS_POSTURE

    @classmethod
    def emitted_types(cls):
        # Findings are named after the control they assess, not after the check,
        # so each gets its own severity, control mapping and SARIF rule.
        return tuple(rule.test_type for rule in RULES)

    def run(self):
        response = self.request("GET")
        if response is None:
            return
        facts = ResponseFacts.from_response(response, self.target_url)

        for rule in RULES:
            if rule.documents_only and not facts.is_document:
                # Not a weakness and not a pass: there is no document for the
                # control to act on, so the requirements it covers are reported
                # as unassessed with this reason rather than either.
                self.skip_type(
                    rule.test_type,
                    f"the response is {facts.media_type}, not a document a "
                    f"browser renders, so this control had nothing to act on")
                continue
            for issue in rule.assess(facts):
                self.record({
                    "test_type": rule.test_type,
                    "test_result": issue.test_result,
                    "severity": issue.severity or rule.severity,
                    "url": facts.url,
                    "method": "GET",
                    "header_name": issue.subject,
                    "payload": "",
                    "status_code": facts.status_code,
                    "analysis": issue.analysis,
                })
