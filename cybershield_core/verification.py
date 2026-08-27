
from dataclasses import dataclass
from typing import List


@dataclass
class VerificationResult:
    success: bool
    checks: List[str]
    failed_checks: List[str]


class ResponseVerifier:
    """Verifies defensive response outcomes instead of assuming success."""

    def verify(self, expected_checks: List[bool], labels: List[str]) -> VerificationResult:
        failed = [label for ok, label in zip(expected_checks, labels) if not ok]
        return VerificationResult(not failed, labels, failed)
