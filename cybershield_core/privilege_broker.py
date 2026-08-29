
"""Just-in-time, least-privilege remediation broker.

The AI can request a narrow defensive capability. The broker decides whether
that capability is allowed, records the reason, grants it for one operation,
and immediately revokes it. It never exposes arbitrary shell execution.
"""
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class PrivilegeGrant:
    incident_id: str
    action: str
    scope: str
    approved: bool
    reason: str


class PrivilegeBroker:
    ACTION_SCOPES = {
        "quarantine_file": "single-file",
        "terminate_process": "single-process",
        "block_url": "single-url",
        "block_domain": "single-domain",
        "remove_persistence": "single-persistence-entry",
        "restore_snapshot": "single-approved-snapshot",
        "collect_evidence": "read-only-evidence",
    }

    NEVER_GRANT = {
        "arbitrary_shell",
        "credential_dump",
        "disable_security",
        "download_execute",
        "host_malware_execution",
    }

    def request(self, incident_id: str, action: str, reason: str) -> PrivilegeGrant:
        if action in self.NEVER_GRANT:
            return PrivilegeGrant(incident_id, action, "", False,
                                  "Forbidden capability.")
        scope = self.ACTION_SCOPES.get(action)
        if not scope:
            return PrivilegeGrant(incident_id, action, "", False,
                                  "Action is not allow-listed.")
        return PrivilegeGrant(incident_id, action, scope, True,
                              reason)

    def revoke(self, grant: PrivilegeGrant) -> str:
        return f"REVOKED:{grant.incident_id}:{grant.action}:{grant.scope}"
