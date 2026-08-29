
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: str
    requires_confirmation: bool
    reason: str


class SafetyPolicy:
    """Hard safety boundary between AI reasoning and system actions."""

    ALLOWLIST = {
        "collect_evidence": False,
        "create_incident": False,
        "contain": False,
        "quarantine": False,
        "human_review": True,
        "rollback": True,
    }

    FORBIDDEN = {
        "arbitrary_shell",
        "cmd",
        "powershell",
        "download_execute",
        "disable_security",
        "delete_system_files",
        "credential_dump",
    }

    def authorize(self, action: str, risk_verdict: str) -> PolicyDecision:
        if action in self.FORBIDDEN:
            return PolicyDecision(False, action, True, "Forbidden action.")

        if action not in self.ALLOWLIST:
            return PolicyDecision(False, action, True, "Action is not allow-listed.")

        confirmation = self.ALLOWLIST[action]

        if risk_verdict == "HUMAN_REVIEW" and action not in {"collect_evidence", "create_incident", "human_review"}:
            return PolicyDecision(False, action, True, "Uncertain case requires human review.")

        return PolicyDecision(True, action, confirmation, "Policy approved.")
