
from dataclasses import dataclass
from typing import List
from .evidence import EvidenceItem
from .risk_engine import RiskEngine, RiskResult
from .policy import SafetyPolicy, PolicyDecision
from .verification import ResponseVerifier, VerificationResult


@dataclass
class Analysis:
    risk: RiskResult
    recommended_actions: List[str]
    policy: List[PolicyDecision]


class DefensiveAI:
    """LLM-compatible orchestration layer with deterministic safety gates."""

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.policy = SafetyPolicy()
        self.verifier = ResponseVerifier()

    def analyze(self, evidence: List[EvidenceItem]) -> Analysis:
        risk = self.risk_engine.evaluate(evidence)

        if risk.verdict == "HUMAN_REVIEW":
            actions = ["collect_evidence", "create_incident", "human_review"]
        elif risk.verdict in {"CRITICAL", "HIGH"}:
            actions = ["collect_evidence", "create_incident", "contain", "quarantine"]
        elif risk.verdict == "SUSPICIOUS":
            actions = ["collect_evidence", "create_incident"]
        else:
            actions = ["collect_evidence"]

        decisions = [self.policy.authorize(a, risk.verdict) for a in actions]
        return Analysis(risk, actions, decisions)
