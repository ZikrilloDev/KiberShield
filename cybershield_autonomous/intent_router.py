"""
Intent Router - Intelligent Command to Tool Mapping

Maps user intents to appropriate security tools with:
- Deterministic intent classification
- Tool selection
- Parameter extraction
- Confidence scoring
"""

from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import re

logger = logging.getLogger(__name__)


class Intent(Enum):
    """Security command intents."""
    SCAN_SYSTEM = "scan_system"
    SCAN_FILE = "scan_file"
    SCAN_DIRECTORY = "scan_directory"
    ANALYZE_URL = "analyze_url"
    QUARANTINE = "quarantine"
    RESTORE_QUARANTINE = "restore_quarantine"
    LIST_QUARANTINE = "list_quarantine"
    DELETE_QUARANTINE = "delete_quarantine"
    PROCESS_ANALYSIS = "process_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    SYSTEM_STATUS = "system_status"
    SECURITY_STATUS = "security_status"
    DIAGNOSTICS = "diagnostics"
    HELP = "help"
    UNKNOWN = "unknown"


@dataclass
class IntentMatch:
    """Result of intent recognition."""
    intent: Intent
    confidence: float  # 0.0 - 1.0
    tool_name: str  # Recommended tool
    arguments: Dict[str, Any]
    requires_target: bool
    requires_confirmation: bool
    description: str


class IntentRouter:
    """Routes commands to appropriate security tools."""

    # Intent → Tool mapping
    INTENT_TOOLS = {
        Intent.SCAN_SYSTEM: ("full_system_scan", "Perform complete system scan"),
        Intent.SCAN_FILE: ("scan_file", "Analyze file for malware"),
        Intent.SCAN_DIRECTORY: ("scan_directory", "Scan directory for threats"),
        Intent.ANALYZE_URL: ("analyze_url", "Analyze URL for phishing/malware"),
        Intent.QUARANTINE: ("quarantine_file", "Move threat to quarantine"),
        Intent.RESTORE_QUARANTINE: ("restore_quarantine", "Restore from quarantine"),
        Intent.LIST_QUARANTINE: ("list_quarantine", "Show quarantined files"),
        Intent.DELETE_QUARANTINE: ("delete_quarantine", "Permanently delete quarantined file"),
        Intent.PROCESS_ANALYSIS: ("analyze_process", "Inspect process"),
        Intent.NETWORK_ANALYSIS: ("inspect_network", "Show network connections"),
        Intent.SYSTEM_STATUS: ("get_system_status", "Get system security status"),
        Intent.SECURITY_STATUS: ("get_security_status", "Get security component status"),
        Intent.DIAGNOSTICS: ("run_diagnostic", "Run system diagnostic"),
        Intent.HELP: ("help", "Show available commands"),
    }

    # Keywords for intent detection
    INTENT_KEYWORDS = {
        Intent.SCAN_SYSTEM: {
            "keywords": ["scan", "tekshir", "check", "проверь", "skan", "security check"],
            "negative": [],
            "priority": 1,
        },
        Intent.SCAN_FILE: {
            "keywords": ["file", "fayl", "exe", "dll", "script"],
            "negative": [],
            "priority": 2,
        },
        Intent.SCAN_DIRECTORY: {
            "keywords": ["folder", "papka", "directory", "dir", "catalogs"],
            "negative": [],
            "priority": 2,
        },
        Intent.ANALYZE_URL: {
            "keywords": ["url", "link", "havola", "website", "sayt", "http"],
            "negative": [],
            "priority": 3,
        },
        Intent.QUARANTINE: {
            "keywords": ["quarantine", "karantin", "isolate", "isolatsiya"],
            "negative": [],
            "priority": 2,
        },
        Intent.RESTORE_QUARANTINE: {
            "keywords": ["restore", "qayta", "return", "bring back"],
            "negative": [],
            "priority": 2,
        },
        Intent.LIST_QUARANTINE: {
            "keywords": ["list", "show", "ko'rsat", "karantinda"],
            "negative": [],
            "priority": 2,
        },
        Intent.PROCESS_ANALYSIS: {
            "keywords": ["process", "jarayon", "cpu", "protsess"],
            "negative": [],
            "priority": 2,
        },
        Intent.NETWORK_ANALYSIS: {
            "keywords": ["network", "connection", "internet", "tcp"],
            "negative": [],
            "priority": 2,
        },
        Intent.SYSTEM_STATUS: {
            "keywords": ["status", "holat", "health", "state"],
            "negative": [],
            "priority": 3,
        },
        Intent.SECURITY_STATUS: {
            "keywords": ["security", "xavf", "threat", "protection"],
            "negative": [],
            "priority": 3,
        },
        Intent.DIAGNOSTICS: {
            "keywords": ["diagnostic", "problem", "debug", "tuzat"],
            "negative": [],
            "priority": 2,
        },
        Intent.HELP: {
            "keywords": ["help", "yordam", "nima qila", "what", "how"],
            "negative": [],
            "priority": 4,
        },
    }

    def __init__(self):
        self.last_command: Optional[str] = None
        self.last_target: Optional[str] = None

    def recognize_intent(self, command: str) -> IntentMatch:
        """
        Recognize intent from user command.

        Returns best matching intent with confidence and tool recommendation.
        """
        command_lower = command.lower().strip()
        self.last_command = command_lower

        # Try to match intents
        matches: List[Tuple[Intent, float]] = []

        for intent, keywords_data in self.INTENT_KEYWORDS.items():
            confidence = self._calculate_confidence(
                command_lower,
                keywords_data["keywords"],
                keywords_data.get("negative", [])
            )

            if confidence > 0:
                matches.append((intent, confidence))

        if not matches:
            return IntentMatch(
                intent=Intent.UNKNOWN,
                confidence=0.0,
                tool_name="help",
                arguments={},
                requires_target=False,
                requires_confirmation=False,
                description="Could not understand command"
            )

        # Get best match
        best_intent, confidence = max(matches, key=lambda x: x[1])

        # Get tool info
        tool_name, description = self.INTENT_TOOLS.get(
            best_intent,
            ("help", "Unknown action")
        )

        # Extract arguments
        arguments = self._extract_arguments(command_lower, best_intent)

        # Determine if confirmation needed
        requires_confirmation = best_intent in {
            Intent.QUARANTINE,
            Intent.DELETE_QUARANTINE,
            Intent.RESTORE_QUARANTINE,
        }

        target = self._extract_target(command_lower)
        if target:
            self.last_target = target
            arguments["target"] = target

        return IntentMatch(
            intent=best_intent,
            confidence=confidence,
            tool_name=tool_name,
            arguments=arguments,
            requires_target=best_intent in {
                Intent.SCAN_FILE,
                Intent.SCAN_DIRECTORY,
                Intent.ANALYZE_URL,
            },
            requires_confirmation=requires_confirmation,
            description=description
        )

    def _calculate_confidence(
        self,
        text: str,
        positive_keywords: List[str],
        negative_keywords: List[str]
    ) -> float:
        """Calculate confidence score for intent."""
        if not positive_keywords:
            return 0.0

        # Count positive matches
        positive_matches = sum(
            1 for kw in positive_keywords
            if kw in text or kw.replace(" ", "") in text.replace(" ", "")
        )

        # Count negative matches
        negative_matches = sum(
            1 for kw in negative_keywords
            if kw in text or kw.replace(" ", "") in text.replace(" ", "")
        )

        if negative_matches > 0:
            return 0.0

        # Confidence based on keyword density
        max_matches = min(3, len(positive_keywords))  # Cap at 3
        confidence = min(1.0, positive_matches / max_matches)

        return confidence

    def _extract_arguments(self, command: str, intent: Intent) -> Dict[str, Any]:
        """Extract tool arguments from command."""
        args = {}

        if intent == Intent.SCAN_FILE:
            # Look for file path
            path = self._extract_path(command)
            if path:
                args["path"] = path

        elif intent == Intent.SCAN_DIRECTORY:
            # Look for directory path
            path = self._extract_path(command)
            if path:
                args["path"] = path
                args["recursive"] = True

        elif intent == Intent.ANALYZE_URL:
            # Look for URL
            url = self._extract_url(command)
            if url:
                args["url"] = url

        elif intent == Intent.QUARANTINE:
            # Look for file path
            path = self._extract_path(command)
            if path:
                args["path"] = path

        return args

    def _extract_target(self, command: str) -> Optional[str]:
        """Extract target (file/directory/URL) from command."""
        # Try common patterns
        patterns = [
            r'(["\'])(.*?)\1',  # Quoted string
            r'(https?://\S+)',  # URL
            r'([A-Za-z]:\\[^\s]+)',  # Windows path
            r'(/[^\s]+)',  # Unix path
        ]

        for pattern in patterns:
            match = re.search(pattern, command)
            if match:
                return match.group(1) if '\\' not in pattern else match.group(0)

        return None

    def _extract_path(self, command: str) -> Optional[str]:
        """Extract file or directory path from command."""
        # Common path patterns
        patterns = [
            r'(["\'])(.*?)[/\\](.*?)\1',  # Quoted path
            r'([A-Za-z]:\\[^\s"\']+)',  # Windows absolute path
            r'(\.\\[^\s"\']+)',  # Windows relative path
            r'(/[^\s"\']+)',  # Unix path
            r'(\.\.?/[^\s"\']+)',  # Unix relative path
        ]

        for pattern in patterns:
            matches = re.findall(pattern, command)
            if matches:
                if isinstance(matches[0], tuple):
                    return matches[0][-1] if matches[0][-1] else matches[0][0]
                return matches[0]

        # Try to find folder names
        if "download" in command:
            return "~/Downloads"
        elif "desktop" in command:
            return "~/Desktop"
        elif "document" in command:
            return "~/Documents"

        return None

    def _extract_url(self, command: str) -> Optional[str]:
        """Extract URL from command."""
        pattern = r'(https?://[^\s\'"]+)'
        match = re.search(pattern, command)
        if match:
            return match.group(1)
        return None

    def suggest_next_steps(self, intent: Intent, result: Dict[str, Any]) -> List[str]:
        """Suggest next steps based on intent and result."""
        suggestions = []

        if intent == Intent.SCAN_SYSTEM or intent == Intent.SCAN_FILE:
            if result.get("threat_detected"):
                suggestions.append("Review detected threats carefully")
                suggestions.append("Consider quarantining high-risk files")
                suggestions.append("Run full system scan for comprehensive analysis")

        elif intent == Intent.ANALYZE_URL:
            verdict = result.get("result", {}).get("verdict", "").upper()
            if verdict in ("PHISHING", "SUSPICIOUS"):
                suggestions.append("Do not visit this URL")
                suggestions.append("Do not enter credentials on this page")
                suggestions.append("Report suspicious URL")

        elif intent == Intent.QUARANTINE:
            if result.get("success"):
                suggestions.append("Monitor system for issues")
                suggestions.append("Run diagnostic to verify system integrity")

        return suggestions

    def get_available_intents(self) -> List[Dict[str, Any]]:
        """Get list of all available intents."""
        return [
            {
                "intent": intent.value,
                "tool": self.INTENT_TOOLS[intent][0],
                "description": self.INTENT_TOOLS[intent][1],
            }
            for intent in Intent if intent != Intent.UNKNOWN
        ]
