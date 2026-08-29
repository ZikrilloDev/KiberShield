"""
CyberShield Ultra AI — defensive language understanding and task planning.

This module intentionally separates:
1) language normalization,
2) intent/entity extraction,
3) conversation context,
4) security planning,
5) safety policy.

It does NOT execute arbitrary shell commands. High-impact operations must be
implemented by explicit, audited CyberShield tools.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Tuple


@dataclass
class Understanding:
    raw: str
    normalized: str
    intent: str
    confidence: float
    entities: Dict[str, str] = field(default_factory=dict)
    tokens: List[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class Plan:
    intent: str
    steps: List[str]
    safety: str
    requires_confirmation: bool
    escalation: bool = False


class UzbekSemanticEngine:
    """
    Lightweight semantic front-end. It handles joined words, '+', spaces,
    common slang/typos, phonetic variants, and context references. It is
    designed to sit in front of an actual LLM when one is configured.
    """

    JOIN_HINTS = {
        "qalesan": "qalaysan",
        "qales": "qalaysan",
        "qale": "qalaysan",
        "salomlar": "salom",
        "viruz": "virus",
        "virs": "virus",
        "fising": "phishing",
        "fishin": "phishing",
        "kibershild": "cybershield",
        "kibershield": "cybershield",
        "protsesor": "protsessor",
        "zararsizlantir": "zararsizlantir",
        "tekshirchi": "tekshir",
        "korchi": "ko'r",
        "qivor": "qil",
        "topvor": "top",
        "ochvor": "och",
        "yopvor": "yop",
    }

    INTENT_PATTERNS = [
        ("GREETING", r"\b(salom|assalom|qalaysan|qandaysan|nima\s+gap)\b"),
        ("FIND_THREAT", r"\b(virus|malware|trojan|troyan|phishing|reklama\s*virusi|threat).*(top|qidir|aniqla|tekshir|ko['‘’`]?r)"),
        ("SCAN_SYSTEM", r"\b(komp|kompyuter|sistem|tizim).*(tekshir|skan|scan|ko['‘’`]?r)"),
        ("SCAN_FOLDER", r"\b(papka|folder|katalog).*(tekshir|skan|scan|ko['‘’`]?r|top)"),
        ("REMEDIATE", r"\b(zararsizlantir|tozal|karantin|hal qil|yo['‘’`]?qot|olib tashla|o['‘’`]?chir)"),
        ("ANALYZE_FILE", r"\b(fayl|file|exe|dll|script).*(tahlil|analiz|tekshir|ko['‘’`]?r)"),
        ("ANALYZE_URL", r"\b(link|url|havola|sayt).*(tekshir|tahlil|analiz|xavf)"),
        ("PROCESS_CHECK", r"\b(process|protsess|jarayon).*(tekshir|ko['‘’`]?r|xavf)"),
        ("CPU_CHECK", r"\b(cpu|protsessor|processor).*(tekshir|ko['‘’`]?r|yuk|yuklama)"),
        ("HELP", r"\b(yordam|nima\s+qila\s+olasan|help)\b"),
    ]

    def _clean(self, text: str) -> str:
        s = text.lower().strip()
        s = s.replace("+", " ")
        s = re.sub(r"[_/|]+", " ", s)
        s = re.sub(r"\s+", " ", s)
        # Normalize a few apostrophe variants without destroying words.
        s = s.replace("`", "'").replace("‘", "'").replace("’", "'")
        words = []
        for w in s.split():
            words.append(self.JOIN_HINTS.get(w, w))
        s = " ".join(words)
        # Handle common fused forms.
        s = re.sub(r"\bqale\s+san\b", "qalaysan", s)
        s = re.sub(r"\bqale\s+sen\b", "qalaysan", s)
        return s

    def _tokens(self, s: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9._:@%+-]+", s)

    def understand(self, text: str, context: Optional[Dict] = None) -> Understanding:
        raw = text or ""
        norm = self._clean(raw)
        tokens = self._tokens(norm)
        intent, confidence = "GENERAL_QUERY", 0.30
        for name, pattern in self.INTENT_PATTERNS:
            if re.search(pattern, norm, flags=re.I):
                intent, confidence = name, 0.82
                break

        # Context resolution for short follow-ups such as "uni", "shuni", "hal qil".
        ctx = context or {}
        if re.search(r"\b(uni|shuni|o['’']sha|ana\s+shu)\b", norm) and ctx.get("last_entity"):
            confidence = min(0.96, confidence + 0.10)
        if intent == "GENERAL_QUERY" and ctx.get("last_intent") and len(tokens) <= 4:
            intent = ctx["last_intent"]
            confidence = min(0.90, confidence + 0.15)

        entities: Dict[str, str] = {}
        m = re.search(r"(https?://\S+|www\.\S+)", raw, re.I)
        if m:
            entities["url"] = m.group(1).rstrip(".,!?")
        m = re.search(r"(?:c:\\|[a-z]:\\|/)[^<>\"|?*\r\n]*", raw, re.I)
        if m:
            entities["path"] = m.group(0).strip()
        for key in ("virus", "malware", "trojan", "troyan", "phishing"):
            if key in norm:
                entities["threat_type"] = "trojan" if key == "troyan" else key
                break

        explanation = f"Matn normallashtirildi va intent '{intent}' sifatida baholandi."
        return Understanding(raw, norm, intent, confidence, entities, tokens, explanation)


class SecurityAgent:
    """Context-aware defensive planner; execution belongs to explicit tools."""

    def __init__(self):
        self.context: Dict = {}

    def process(self, text: str) -> Tuple[Understanding, Plan]:
        u = UzbekSemanticEngine().understand(text, self.context)

        if "path" in u.entities:
            self.context["last_entity"] = u.entities["path"]
        elif "url" in u.entities:
            self.context["last_entity"] = u.entities["url"]
        elif "threat_type" in u.entities:
            self.context["last_entity"] = u.entities["threat_type"]
        self.context["last_intent"] = u.intent

        high_impact = {"REMEDIATE"}
        if u.intent == "GREETING":
            steps = ["Salomlashish va CyberShield holatini taklif qilish."]
            return u, Plan(u.intent, steps, "NO_ACTION", False)

        if u.intent in {"FIND_THREAT", "SCAN_SYSTEM", "SCAN_FOLDER", "PROCESS_CHECK", "CPU_CHECK"}:
            steps = ["Dalil yig'ish", "Riskni baholash", "Natijani foydalanuvchiga tushuntirish"]
            return u, Plan(u.intent, steps, "READ_ONLY_FIRST", False)

        if u.intent in {"ANALYZE_FILE", "ANALYZE_URL"}:
            steps = ["Obyektni xavfsiz tahlil qilish", "Mustaqil indikatorlarni solishtirish", "Risk va ishonchni chiqarish"]
            return u, Plan(u.intent, steps, "NO_EXECUTION_UNLESS_SANDBOXED", False)

        if u.intent in high_impact:
            steps = ["Nishonni aniq aniqlash", "Riskni tasdiqlash", "Reversible quarantine/containment", "Natijani tekshirish"]
            return u, Plan(u.intent, steps, "REVERSIBLE_CONTAINMENT", True)

        return u, Plan(u.intent, ["Savolni aniqlashtirish yoki xavfsiz diagnostikani boshlash"], "NO_ARBITRARY_COMMANDS", False)


def understand(text: str, context: Optional[Dict] = None) -> Understanding:
    return UzbekSemanticEngine().understand(text, context)
