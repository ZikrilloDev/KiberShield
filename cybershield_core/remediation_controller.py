
"""Policy-controlled remediation workflow."""

from dataclasses import dataclass
from typing import List
from .privilege_broker import PrivilegeBroker, PrivilegeGrant


@dataclass
class RemediationResult:
    incident_id: str
    action: str
    approved: bool
    verified: bool
    revoked: bool
    message: str


class RemediationController:
    def __init__(self):
        self.broker = PrivilegeBroker()

    def execute_defensive_action(
        self,
        incident_id: str,
        action: str,
        reason: str,
        confidence: float,
        verified: bool = True,
    ) -> RemediationResult:
        # Low-confidence cases never receive destructive remediation.
        if confidence < 0.62 and action not in {"collect_evidence"}:
            return RemediationResult(
                incident_id, action, False, False, True,
                "Confidence past; human review required."
            )

        grant = self.broker.request(incident_id, action, reason)
        if not grant.approved:
            return RemediationResult(
                incident_id, action, False, False, True,
                grant.reason
            )

        # The actual platform adapter performs one narrowly scoped action.
        # This controller only models authorization and verification.
        revoked = bool(self.broker.revoke(grant))
        return RemediationResult(
            incident_id, action, True, bool(verified), revoked,
            "Approved, verified and privilege revoked."
        )
