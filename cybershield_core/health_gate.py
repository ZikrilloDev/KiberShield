
"""Preflight gate for defensive actions."""

from dataclasses import dataclass


@dataclass
class GateResult:
    allowed: bool
    reason: str


class PreflightGate:
    """Rejects actions when the environment or evidence state is unsafe."""

    def check(self, action: str, confidence: float, isolated_lab: bool = False) -> GateResult:
        if action == "execute_sample":
            return GateResult(False, "Host malware execution is never permitted.")

        if action in {"contain", "quarantine"} and confidence < 0.55:
            return GateResult(False, "Insufficient confidence; human review required.")

        if action == "dynamic_analysis" and not isolated_lab:
            return GateResult(False, "Dynamic analysis requires an isolated disposable lab.")

        return GateResult(True, "Preflight passed.")
