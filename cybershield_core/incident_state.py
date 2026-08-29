
"""Incident state machine preventing unsafe state jumps."""

from enum import Enum


class IncidentState(str, Enum):
    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    CONTAINED = "CONTAINED"
    QUARANTINED = "QUARANTINED"
    REMEDIATED = "REMEDIATED"
    VERIFIED = "VERIFIED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    CLOSED = "CLOSED"


ALLOWED_TRANSITIONS = {
    IncidentState.DETECTED: {IncidentState.ANALYZING, IncidentState.HUMAN_REVIEW},
    IncidentState.ANALYZING: {
        IncidentState.CONTAINED, IncidentState.QUARANTINED,
        IncidentState.HUMAN_REVIEW
    },
    IncidentState.CONTAINED: {
        IncidentState.QUARANTINED, IncidentState.REMEDIATED,
        IncidentState.HUMAN_REVIEW
    },
    IncidentState.QUARANTINED: {
        IncidentState.REMEDIATED, IncidentState.HUMAN_REVIEW
    },
    IncidentState.REMEDIATED: {
        IncidentState.VERIFIED, IncidentState.HUMAN_REVIEW
    },
    IncidentState.VERIFIED: {IncidentState.CLOSED, IncidentState.HUMAN_REVIEW},
    IncidentState.HUMAN_REVIEW: {IncidentState.CLOSED},
    IncidentState.CLOSED: set(),
}


def can_transition(current: IncidentState, target: IncidentState) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())
