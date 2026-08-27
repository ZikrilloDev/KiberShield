
from dataclasses import dataclass
from typing import List, Dict, Any
from .evidence import EvidenceItem


@dataclass
class RiskResult:
    score: int
    confidence: float
    verdict: str
    reasons: List[str]
    contributing_sources: List[str]


class RiskEngine:
    """Multi-signal defensive scoring; not a malware execution engine."""

    WEIGHTS = {
        "malware": 1.25,
        "phishing": 1.20,
        "process": 1.00,
        "network": 1.00,
        "persistence": 1.15,
        "cpu": 0.70,
        "file": 0.90,
    }

    def evaluate(self, evidence: List[EvidenceItem]) -> RiskResult:
        if not evidence:
            return RiskResult(0, 0.0, "HUMAN_REVIEW",
                              ["Evidence mavjud emas"], [])

        weighted = 0.0
        confidence_sum = 0.0
        sources = set()
        reasons = []

        for e in evidence:
            weight = self.WEIGHTS.get(e.category.lower(), 0.8)
            weighted += max(0.0, min(100.0, e.score)) * weight * max(0.0, min(1.0, e.confidence))
            confidence_sum += max(0.0, min(1.0, e.confidence))
            sources.add(e.source)
            if e.score >= 60:
                reasons.append(f"{e.source}: {e.indicator}")

        denominator = max(1.0, sum(self.WEIGHTS.get(e.category.lower(), 0.8) for e in evidence))
        score = min(100, round(weighted / denominator))
        confidence = min(0.99, confidence_sum / len(evidence) + min(0.20, len(sources) * 0.03))

        if confidence < 0.55:
            verdict = "HUMAN_REVIEW"
        elif score >= 85:
            verdict = "CRITICAL"
        elif score >= 65:
            verdict = "HIGH"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return RiskResult(score, round(confidence, 2), verdict, reasons[:10], sorted(sources))
