
"""Allow-listed defensive actions only.

AI output is data. It is never treated as a shell command.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Any


@dataclass(frozen=True)
class ActionSpec:
    name: str
    description: str
    requires_confirmation: bool


class SafeActionRegistry:
    def __init__(self) -> None:
        self._actions: Dict[str, ActionSpec] = {
            "quarantine": ActionSpec("quarantine", "Move a confirmed suspicious artifact into controlled quarantine.", False),
            "contain": ActionSpec("contain", "Apply a predefined containment policy.", False),
            "collect_evidence": ActionSpec("collect_evidence", "Collect security telemetry and hashes.", False),
            "create_incident": ActionSpec("create_incident", "Create an auditable incident record.", False),
            "rollback": ActionSpec("rollback", "Restore a previously recorded safe state.", True),
            "human_review": ActionSpec("human_review", "Escalate the case to an analyst.", True),
        }

    def get(self, name: str) -> ActionSpec:
        if name not in self._actions:
            raise ValueError(f"Action not allow-listed: {name}")
        return self._actions[name]

    def available(self):
        return tuple(self._actions.values())
