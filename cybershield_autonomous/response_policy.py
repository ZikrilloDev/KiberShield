"""Deterministic, evidence-first response policy for CyberShield AI."""
from __future__ import annotations
from typing import Any, Dict, Iterable


def _risk_label(score: Any) -> str:
    try:
        n = int(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if n >= 85:
        return "CRITICAL"
    if n >= 70:
        return "HIGH"
    if n >= 40:
        return "MEDIUM"
    return "LOW"


def _fmt_bool(value: Any) -> str:
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "UNKNOWN"


def evidence_response(tool: str, result: Dict[str, Any], verification: Any = None) -> str:
    """Generate a precise response without inventing facts.

    The response is deliberately deterministic for security findings. LLMs may
    explain a verified result, but they are not allowed to invent verdicts.
    """
    success = bool(result.get("success", False))
    if not success:
        err = result.get("error") or result.get("status") or "Operation failed."
        return f"ACTION: FAILED\nREASON: {err}\nNEXT: Fix the reported error and retry."

    risk = result.get("risk_score")
    verdict = str(result.get("verdict") or result.get("status") or "UNKNOWN").upper()
    threat = result.get("threat_detected")
    target = str(result.get("target") or "")
    details = result.get("details") or []
    if isinstance(details, str):
        details = [details]

    lines = [f"RESULT: {tool}", f"VERDICT: {verdict}"]
    if risk is not None:
        lines.append(f"RISK: {risk}/100 ({_risk_label(risk)})")
    if threat is not None:
        lines.append(f"THREAT DETECTED: {_fmt_bool(threat)}")
    if target:
        lines.append(f"TARGET: {target}")

    if details:
        lines.append("EVIDENCE:")
        for item in list(details)[:8]:
            lines.append(f"- {item}")

    if verification is not None:
        verified = getattr(verification, "verified", None)
        goal = getattr(verification, "goal_achieved", None)
        if verified is not None:
            lines.append(f"VERIFICATION: {'VERIFIED' if verified else 'NOT VERIFIED'}")
        if goal is not None:
            lines.append(f"GOAL ACHIEVED: {'YES' if goal else 'NO'}")

    if threat is True:
        lines.append("NEXT: Contain/quarantine only after the applicable security policy and verification gate.")
    elif risk is not None and _risk_label(risk) in {"HIGH", "CRITICAL"}:
        lines.append("NEXT: Perform deeper analysis and collect additional evidence before remediation.")
    elif risk is not None and _risk_label(risk) == "MEDIUM":
        lines.append("NEXT: Review the evidence and run a deeper scan if the object is unfamiliar.")
    else:
        lines.append("NEXT: No remediation is justified by the reported evidence.")
    return "\n".join(lines)
