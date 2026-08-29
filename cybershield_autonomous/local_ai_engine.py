"""
Local AI Engine - Main Local AI Interface

Wraps local model backend with:
- System prompt management
- Context window optimization
- Token counting
- Response parsing
- Tool call extraction
"""

from typing import Optional, List, Dict, Any
import logging
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .local_model_backend import (
    LocalModelManager, LocalInferenceRequest, LocalInferenceResponse
)

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    """Structured tool call extracted from LLM response."""
    tool: str
    arguments: Dict[str, Any]
    confidence: float = 0.9


class LocalAIEngine:
    """Main interface to local AI model."""

    SYSTEM_PROMPT = """You are CyberShield, a professional cybersecurity AI assistant.

Your role:
- Understand user security commands
- Plan appropriate security actions
- Call security tools when needed
- Return structured JSON responses
- Never hallucinate results
- Always base claims on tool results

When you need to call a tool, respond with JSON:
{
  "action": "tool_call",
  "tool": "tool_name",
  "arguments": {"param": "value"}
}

Be concise, professional, and security-focused.

STRICT RESPONSE RULES:
- Never invent a scan result, process, file, URL verdict, risk score, confidence,
  action, or remediation result.
- Distinguish VERIFIED facts, INFERRED hypotheses, and UNKNOWN information.
- If evidence is missing, say UNKNOWN and request/run the appropriate read-only
  security tool instead of guessing.
- For security commands, prefer local CyberShield tools over web research.
- Web research is only for explicit current/external intelligence requests or
  when local evidence cannot answer the question.
- A security action is only COMPLETE when the tool returns a verified success.
- Do not claim "virus", "phishing", "safe", or "clean" solely from a keyword;
  require evidence from the relevant analysis pipeline."""

    def __init__(self):
        self.model_manager = LocalModelManager()
        self.initialized = False
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = 10  # Keep last 10 exchanges for context

    def initialize(self) -> bool:
        """Initialize local AI engine."""
        try:
            logger.info("Initializing LocalAIEngine...")
            if not self.model_manager.detect_and_initialize():
                logger.warning("No local AI model available - will operate in degraded mode")
                return False

            self.initialized = True
            logger.info("✓ LocalAIEngine initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize LocalAIEngine: {e}")
            return False

    def is_ready(self) -> bool:
        """Check if AI is ready."""
        return self.initialized and self.model_manager.is_ready()

    def get_status(self) -> Dict[str, Any]:
        """Get AI status."""
        return {
            "initialized": self.initialized,
            "ready": self.is_ready(),
            "model": self.model_manager.get_model_info(),
            "backend_status": self.model_manager.get_status()
        }

    def understand_command(self, command: str) -> Dict[str, Any]:
        """
        Understand user command and extract intent.

        Returns:
            {
                "original": command,
                "understood": bool,
                "intent": str,
                "confidence": float,
                "entities": dict,
                "requires_tool": bool,
                "suggested_tool": str
            }
        """
        if not self.is_ready():
            return {
                "original": command,
                "understood": False,
                "intent": "unknown",
                "confidence": 0.0,
                "error": "AI not available"
            }

        try:
            prompt = f"""Analyze this security command: "{command}"

Respond with JSON:
{{
  "intent": "scan|quarantine|analyze|status|help|...",
  "confidence": 0.0-1.0,
  "entities": {{"target": "...", "type": "..."}},
  "requires_tool": true/false,
  "suggested_tool": "scan_file|quarantine|analyze_url|..."
}}

Keep response to 2 lines max."""

            response = self._query_model(prompt, max_tokens=300)
            result = self._parse_json_response(response.text)

            if result:
                self.conversation_history.append({
                    "role": "user",
                    "content": command
                })
                self.conversation_history.append({
                    "role": "assistant",
                    "content": f"Intent: {result['intent']}"
                })
                return result

            return {
                "original": command,
                "understood": False,
                "intent": "unknown",
                "confidence": 0.0
            }

        except Exception as e:
            logger.error(f"Command understanding failed: {e}")
            return {
                "original": command,
                "understood": False,
                "intent": "unknown",
                "confidence": 0.0,
                "error": str(e)
            }

    def plan_action(self, intent: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan security action for given intent.

        Returns:
            {
                "plan": [step1, step2, ...],
                "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
                "requires_confirmation": bool,
                "estimated_duration_ms": int
            }
        """
        if not self.is_ready():
            return {
                "plan": [],
                "risk_level": "UNKNOWN",
                "error": "AI not available"
            }

        try:
            context_str = json.dumps(context, default=str)
            prompt = f"""Plan security action for intent: {intent}
Context: {context_str}

Respond with JSON:
{{
  "plan": ["step1", "step2", ...],
  "risk_level": "LOW|MEDIUM|HIGH",
  "requires_confirmation": true/false,
  "estimated_duration_ms": 0
}}

Be very concise."""

            response = self._query_model(prompt, max_tokens=300)
            result = self._parse_json_response(response.text)

            if result:
                return result

            return {
                "plan": [],
                "risk_level": "UNKNOWN"
            }

        except Exception as e:
            logger.error(f"Action planning failed: {e}")
            return {
                "plan": [],
                "risk_level": "UNKNOWN",
                "error": str(e)
            }

    def extract_tool_call(self, response_text: str) -> Optional[ToolCall]:
        """
        Extract structured tool call from model response.

        Returns ToolCall or None if no tool call found.
        """
        try:
            # Look for JSON tool call pattern
            json_pattern = r'\{[^{}]*"tool"[^{}]*\}'
            match = re.search(json_pattern, response_text, re.IGNORECASE)

            if not match:
                return None

            tool_json = json.loads(match.group())
            return ToolCall(
                tool=tool_json.get("tool", ""),
                arguments=tool_json.get("arguments", {}),
                confidence=tool_json.get("confidence", 0.9)
            )

        except Exception as e:
            logger.debug(f"Tool call extraction failed: {e}")
            return None

    def interpret_result(self, tool_result: Dict[str, Any]) -> str:
        """
        Interpret tool result and generate human-readable explanation.

        Returns:
            Natural language explanation of the result
        """
        if not self.is_ready():
            return self._format_result_offline(tool_result)

        try:
            result_str = json.dumps(tool_result, default=str)
            prompt = f"""A security tool returned this result:
{result_str}

Explain this result briefly to the user in 1-2 sentences.
Be concise and focus on actionable next steps if needed."""

            response = self._query_model(prompt, max_tokens=200)
            return response.text.strip()

        except Exception as e:
            logger.debug(f"Result interpretation failed: {e}")
            return self._format_result_offline(tool_result)

    def _query_model(self, prompt: str, max_tokens: int = 500) -> LocalInferenceResponse:
        """Query local model with system prompt and conversation context."""
        # Build context from conversation history
        context_messages = self.conversation_history[-6:]  # Last 3 exchanges

        full_prompt = self._build_prompt_with_context(prompt, context_messages)

        request = LocalInferenceRequest(
            prompt=full_prompt,
            system_prompt=self.SYSTEM_PROMPT,
            max_tokens=max_tokens,
            temperature=0.3,  # Lower temperature for consistent security decisions
            top_p=0.9,
        )

        response = self.model_manager.infer(request)

        if response.error:
            logger.error(f"Model inference error: {response.error}")

        return response

    def _build_prompt_with_context(
        self,
        prompt: str,
        context_messages: List[Dict[str, str]]
    ) -> str:
        """Build prompt with conversation context."""
        context = ""
        for msg in context_messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            context += f"{role}: {content}\n"

        return f"{context}user: {prompt}\nassistant:"

    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from model response."""
        try:
            # Find JSON object in response
            json_pattern = r'\{[^{}]*\}'
            match = re.search(json_pattern, text, re.DOTALL)

            if match:
                return json.loads(match.group())
        except:
            pass

        return None

    def _format_result_offline(self, result: Dict[str, Any]) -> str:
        """Format result without AI (offline mode)."""
        if result.get("success"):
            status = result.get("status", "completed")
            threat = result.get("threat_detected", False)
            if threat:
                return f"Threat detected. Status: {status}"
            return f"Operation completed successfully."
        else:
            error = result.get("error", "Unknown error")
            return f"Operation failed: {error}"

    def clear_history(self) -> None:
        """Clear conversation history."""
        self.conversation_history = []
        logger.info("Conversation history cleared")

    def shutdown(self) -> None:
        """Shutdown AI engine."""
        self.model_manager.shutdown()
        self.initialized = False
        logger.info("LocalAIEngine shutdown")
