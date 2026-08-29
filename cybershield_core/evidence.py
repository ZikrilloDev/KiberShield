
from dataclasses import dataclass, asdict
from typing import Any, Dict, List
import time


@dataclass
class EvidenceItem:
    source: str
    category: str
    indicator: str
    score: float
    confidence: float = 0.5
    details: str = ""

    def normalized(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceStore:
    """Bounded in-memory evidence store for incident correlation."""
    def __init__(self, max_items: int = 2000):
        self.max_items = max_items
        self.items: List[EvidenceItem] = []

    def add(self, item: EvidenceItem) -> None:
        self.items.append(item)
        if len(self.items) > self.max_items:
            del self.items[:len(self.items) - self.max_items]

    def snapshot(self) -> List[Dict[str, Any]]:
        return [x.normalized() for x in self.items]

    def clear(self) -> None:
        self.items.clear()
