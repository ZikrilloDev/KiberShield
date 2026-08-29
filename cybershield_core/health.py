
"""Runtime health checks for CyberShield components."""

from dataclasses import dataclass
from typing import List


@dataclass
class HealthResult:
    component: str
    ok: bool
    detail: str


def check_required_paths(paths) -> List[HealthResult]:
    results = []
    for label, path in paths:
        results.append(
            HealthResult(label, path.exists(), str(path))
        )
    return results
