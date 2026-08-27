
"""CyberShield Level 100 defensive AI orchestration.

This is a policy-first reasoning framework: evidence is correlated, hypotheses
are challenged, confidence is estimated, actions are allow-listed, and outcomes
must be verified. It does not execute malware or arbitrary OS commands.
"""
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Hypothesis:
    name: str
    supporting: List[str] = field(default_factory=list)
    contradicting: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class BrainReport:
    verdict: str
    risk: int
    confidence: float
    hypotheses: List[Hypothesis]
    next_steps: List[str]
    escalate: bool


class Level100Brain:
    """Higher-level defensive correlation layer above the deterministic policy."""

    def reason(self, evidence: List[Dict]) -> BrainReport:
        if not evidence:
            return BrainReport(
                "HUMAN_REVIEW", 0, 0.0, [], ["Collect more evidence"], True
            )

        normalized = []
        for e in evidence:
            score = max(0.0, min(100.0, float(e.get("score", 0))))
            confidence = max(0.0, min(1.0, float(e.get("confidence", 0.5))))
            normalized.append({
                "source": str(e.get("source", "unknown")),
                "category": str(e.get("category", "unknown")).lower(),
                "indicator": str(e.get("indicator", "")),
                "score": score,
                "confidence": confidence,
            })

        # Independent categories matter more than repeated identical signals.
        categories = {x["category"] for x in normalized}
        sources = {x["source"] for x in normalized}
        weighted = sum(x["score"] * x["confidence"] for x in normalized)
        risk = min(100, round(weighted / max(1, len(normalized)) + min(12, len(categories) * 3)))

        confidence = min(
            0.99,
            0.35
            + min(0.25, len(sources) * 0.05)
            + min(0.20, len(categories) * 0.04)
            + min(0.15, sum(x["confidence"] for x in normalized) / len(normalized) * 0.15),
        )

        malicious = [x["indicator"] for x in normalized if x["score"] >= 65]
        benign = [x["indicator"] for x in normalized if x["score"] < 30]

        hypotheses = [
            Hypothesis(
                "Malicious activity",
                supporting=malicious[:8],
                contradicting=benign[:4],
                confidence=confidence if malicious else max(0.1, confidence - 0.25),
            ),
            Hypothesis(
                "Benign/legitimate activity",
                supporting=benign[:8],
                contradicting=malicious[:4],
                confidence=max(0.05, 1.0 - confidence) if benign else 0.1,
            ),
        ]

        if confidence < 0.60:
            verdict = "HUMAN_REVIEW"
            next_steps = ["Collect additional evidence", "Do not execute unknown sample", "Escalate to analyst"]
            escalate = True
        elif risk >= 85:
            verdict = "CRITICAL"
            next_steps = ["Contain", "Quarantine", "Collect evidence", "Verify response", "Notify analyst"]
            escalate = True
        elif risk >= 65:
            verdict = "HIGH"
            next_steps = ["Contain", "Quarantine if policy allows", "Verify response"]
            escalate = False
        elif risk >= 40:
            verdict = "SUSPICIOUS"
            next_steps = ["Increase monitoring", "Collect additional evidence"]
            escalate = False
        else:
            verdict = "CLEAN"
            next_steps = ["Continue monitoring"]
            escalate = False

        return BrainReport(verdict, risk, round(confidence, 2), hypotheses, next_steps, escalate)
