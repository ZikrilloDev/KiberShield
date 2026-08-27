"""
Result Verifier

Verifies that tool actions completed successfully and provides:
- Post-execution verification
- Goal achievement checking
- Error diagnostics
- Recovery recommendations
"""

from typing import Any, Dict, Optional, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of post-execution verification."""
    verified: bool
    tool_name: str
    goal_achieved: bool
    evidence: List[str]
    recommendations: List[str]
    can_retry: bool = True
    error_analysis: Optional[str] = None


class ResultVerifier:
    """Verifies tool execution outcomes."""

    def __init__(self):
        self.verification_cache = {}

    def verify(self, tool_name: str, action: str, result: Any) -> VerificationResult:
        """
        Verify that an action succeeded.

        Args:
            tool_name: Name of the tool
            action: Type of action performed
            result: Result from the tool

        Returns:
            VerificationResult with verification status and recommendations
        """
        logger.info(f"Verifying {tool_name} / {action}")

        if tool_name == "scan_file":
            return self._verify_scan_file(result)
        elif tool_name == "scan_directory":
            return self._verify_scan_directory(result)
        elif tool_name == "full_system_scan":
            return self._verify_full_scan(result)
        elif tool_name == "quarantine_file":
            return self._verify_quarantine(result)
        elif tool_name == "analyze_url":
            return self._verify_url_analysis(result)
        elif tool_name == "restore_quarantine":
            return self._verify_restore(result)
        elif tool_name == "get_system_status":
            return self._verify_status(result)
        else:
            return self._verify_generic(tool_name, result)

    def _verify_scan_file(self, result: Any) -> VerificationResult:
        """Verify file scan completed."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="scan_file",
                goal_achieved=False,
                evidence=["Result not in dictionary format"],
                recommendations=["Retry scan with proper file path"],
                error_analysis="Invalid result format"
            )

        if result.get("error"):
            return VerificationResult(
                verified=False,
                tool_name="scan_file",
                goal_achieved=False,
                evidence=[result.get("error", "Unknown error")],
                recommendations=["Check file path", "Verify file permissions", "Retry scan"],
                can_retry=True
            )

        verdict = result.get("verdict", "").upper()
        risk = result.get("risk", 0)
        confidence = result.get("confidence", 0)

        goal_achieved = True  # Scan succeeded in analyzing
        evidence = [
            f"Verdict: {verdict}",
            f"Risk score: {risk}/100",
            f"Confidence: {confidence:.2f}",
        ]

        recommendations = []
        if verdict in ("MALICIOUS", "LIKELY_MALICIOUS"):
            recommendations.append("Consider quarantining this file")
            recommendations.append("Review detailed analysis before taking action")

        return VerificationResult(
            verified=True,
            tool_name="scan_file",
            goal_achieved=goal_achieved,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _verify_scan_directory(self, result: Any) -> VerificationResult:
        """Verify directory scan completed."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="scan_directory",
                goal_achieved=False,
                evidence=["Result not in dictionary format"],
                recommendations=["Retry with valid directory path"],
            )

        files_scanned = result.get("files_scanned", 0)
        threats_found = result.get("threats_found", 0)

        evidence = [
            f"Files scanned: {files_scanned}",
            f"Threats found: {threats_found}",
        ]

        recommendations = []
        if threats_found > 0:
            recommendations.append("Review detected threats")
            recommendations.append("Quarantine high-risk files")

        return VerificationResult(
            verified=True,
            tool_name="scan_directory",
            goal_achieved=True,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _verify_full_scan(self, result: Any) -> VerificationResult:
        """Verify full system scan completed."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="full_system_scan",
                goal_achieved=False,
                evidence=["Result not in dictionary format"],
                recommendations=["Restart full system scan"],
            )

        status = result.get("status", "").lower()
        complete = status == "completed"

        evidence = [
            f"Status: {status}",
            f"Start time: {result.get('start_time', 'N/A')}",
            f"End time: {result.get('end_time', 'N/A')}",
        ]

        if not complete:
            evidence.append("Scan did not complete")

        recommendations = []
        if not complete:
            recommendations.append("Retry full system scan")
            recommendations.append("Check disk space")
            recommendations.append("Ensure system idle time")

        return VerificationResult(
            verified=complete,
            tool_name="full_system_scan",
            goal_achieved=complete,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _verify_quarantine(self, result: Any) -> VerificationResult:
        """Verify file was quarantined."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="quarantine_file",
                goal_achieved=False,
                evidence=["Invalid result format"],
                recommendations=["Verify file exists and is accessible"],
            )

        success = result.get("success", False)
        quarantine_path = result.get("quarantine_path", "")

        evidence = [
            f"Quarantine success: {success}",
            f"Quarantine path: {quarantine_path}",
        ]

        if result.get("verification"):
            evidence.append("Quarantine verified")

        recommendations = []
        if not success:
            recommendations.append("Check file permissions")
            recommendations.append("Verify quarantine directory exists")
            recommendations.append("Retry quarantine operation")

        return VerificationResult(
            verified=success,
            tool_name="quarantine_file",
            goal_achieved=success,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _verify_url_analysis(self, result: Any) -> VerificationResult:
        """Verify URL analysis completed."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="analyze_url",
                goal_achieved=False,
                evidence=["Invalid result format"],
                recommendations=["Retry with valid URL"],
            )

        verdict = result.get("verdict", "").upper()
        score = result.get("score", 0)

        goal_achieved = True  # Analysis completed
        evidence = [
            f"Verdict: {verdict}",
            f"Risk score: {score}/100",
        ]

        recommendations = []
        if verdict in ("PHISHING", "SUSPICIOUS"):
            recommendations.append("Do not visit this URL")
            recommendations.append("Avoid entering credentials")

        return VerificationResult(
            verified=True,
            tool_name="analyze_url",
            goal_achieved=goal_achieved,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _verify_restore(self, result: Any) -> VerificationResult:
        """Verify file restoration from quarantine."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="restore_quarantine",
                goal_achieved=False,
                evidence=["Invalid result format"],
                recommendations=["Check quarantine file path"],
            )

        success = result.get("success", False)
        restored_path = result.get("restored_path", "")

        evidence = [
            f"Restoration success: {success}",
            f"Restored to: {restored_path}",
        ]

        return VerificationResult(
            verified=success,
            tool_name="restore_quarantine",
            goal_achieved=success,
            evidence=evidence,
            recommendations=["Virus scan the restored file before use"] if success else ["Verify quarantine file exists"],
        )

    def _verify_status(self, result: Any) -> VerificationResult:
        """Verify system status query."""
        if not isinstance(result, dict):
            return VerificationResult(
                verified=False,
                tool_name="get_system_status",
                goal_achieved=False,
                evidence=["Invalid result format"],
                recommendations=["Retry status check"],
            )

        evidence = [
            f"Status retrieved: {result.get('status', 'N/A')}",
        ]

        return VerificationResult(
            verified=True,
            tool_name="get_system_status",
            goal_achieved=True,
            evidence=evidence,
            recommendations=[],
        )

    def _verify_generic(self, tool_name: str, result: Any) -> VerificationResult:
        """Verify generic tool result."""
        if isinstance(result, dict):
            success = result.get("success", False)
            status = result.get("status", "unknown")
            error = result.get("error", "")
        else:
            success = result is not None
            status = "unknown"
            error = ""

        evidence = [f"Status: {status}"]
        if error:
            evidence.append(f"Error: {error}")

        return VerificationResult(
            verified=success,
            tool_name=tool_name,
            goal_achieved=success,
            evidence=evidence,
            recommendations=["Retry operation"] if not success else [],
        )
