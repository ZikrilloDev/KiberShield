import re
import math
from typing import Dict, Any

class LocalAISecurityEngine:
    """API kalitlarsiz ishlaydigan lokal Evristik AI Dvigateli"""

    SUSPICIOUS_KEYWORDS = [
        "powershell -enc", "cmd /c", "bypass", "downloadstring", "invoke-expression",
        "mimikatz", "lsass", "vssadmin delete", "net stop", "reg add", "base64"
    ]

    def _calculate_entropy(self, data: str) -> float:
        """Matn yoki fayl entropiyasini hisoblash (Shifrlangan/Obfuscated kodni aniqlash)"""
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def analyze_payload(self, text: str) -> Dict[str, Any]:
        """Skript yoki buyruqni AI tahlildan o'tkazish"""
        score = 0
        reasons = []

        # 1. Kalit so'zlar bo'yicha tahlil
        for kw in self.SUSPICIOUS_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE):
                score += 30
                reasons.append(f"Zararli buyruq namunasi topildi: '{kw}'")

        # 2. Entropiya tahlili (Obfuscation ko'rsatkichi)
        entropy = self._calculate_entropy(text)
        if entropy > 5.2 and len(text) > 50:
            score += 40
            reasons.append(f"Yuqori entropiya ({round(entropy, 2)}) - Kod obfuscation qilingan bo'lishi mumkin!")

        # 3. Hex/Base64 pattern tahlili
        if re.search(r'[A-Za-z0-9+/]{50,}==', text):
            score += 25
            reasons.append("Yashirin Base64 payload shakli topildi.")

        threat_level = "XAVFSIZ"
        if score >= 70:
            threat_level = "YUQORI XAVF"
        elif score >= 35:
            threat_level = "O'RTA XAVF"

        return {
            "threat_level": threat_level,
            "score": min(score, 100),
            "entropy": round(entropy, 2),
            "reasons": reasons
        }