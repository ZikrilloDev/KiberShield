"""
Local Autonomous Agent - Complete Offline Security Agent

Coordinates:
- LocalAIEngine (offline inference)
- IntentRouter (deterministic intent parsing)
- LocalMemory (conversation/action history)
- Tool Execution (real security operations)
- Error Recovery (self-healing)
- Verification (confirm results)
"""

import logging
import time
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from .local_ai_engine import LocalAIEngine
from .intent_router import IntentRouter
from .local_memory import LocalMemory
from .action_executor import ActionExecutor, ActionContext
from .result_verifier import ResultVerifier
from .tool_registry import ToolRegistry
from .audit_logging import log_command, log_tool_execution, log_threat_detected
from .response_policy import evidence_response

logger = logging.getLogger(__name__)


@dataclass
class AgentExecution:
    """Complete execution record of agent processing."""
    command: str
    timestamp: str
    intent: str
    confidence: float
    tool_executed: str
    tool_result: Dict[str, Any]
    verification: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: int = 0
    success: bool = False


class LocalAutonomousAgent:
    """
    Complete local autonomous security agent.

    Pipeline:
    USER COMMAND
    ↓ UNDERSTAND (LocalAIEngine)
    ↓ ROUTE INTENT (IntentRouter)
    ↓ PLAN ACTION (LocalAIEngine)
    ↓ EXECUTE TOOL (ActionExecutor)
    ↓ VERIFY RESULT (ResultVerifier)
    ↓ RECOVER (if needed)
    ↓ REPORT (LocalMemory + Response)
    """

    def __init__(self, registry: ToolRegistry):
        self.ai_engine = LocalAIEngine()
        self.intent_router = IntentRouter()
        self.memory = LocalMemory()
        self.executor = ActionExecutor(registry)
        self.verifier = ResultVerifier()
        self.registry = registry

        self.execution_history: List[AgentExecution] = []
        self.initialized = False
        self.max_iterations = 3  # Prevent infinite loops

    def initialize(self) -> bool:
        """Initialize the autonomous agent."""
        try:
            logger.info("Initializing LocalAutonomousAgent...")

            # Initialize local AI engine
            if not self.ai_engine.initialize():
                logger.warning("AI engine not available - will use fallback mode")

            self.initialized = True
            logger.info("✓ LocalAutonomousAgent initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize agent: {e}")
            return False

    def process_command(self, command: str, user_id: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Process user command through complete autonomous pipeline.

        Returns:
            (human_response, structured_result)
        """
        if not self.initialized:
            return "Agent not initialized", {"success": False, "error": "Agent not ready"}

        start_time = time.time()
        execution = AgentExecution(
            command=command,
            timestamp=datetime.now(timezone.utc).isoformat(),
            intent="unknown",
            confidence=0.0,
            tool_executed="",
            tool_result={},
            success=False,
            duration_ms=0
        )

        try:
            logger.info(f"Processing command: {command}")
            log_command(command, user_id=user_id)

            # Stage 1: UNDERSTAND user intent
            logger.debug("Stage 1: Understanding command")
            understanding = self.ai_engine.understand_command(command)

            if not understanding.get("understood", False):
                # Fallback: Use deterministic router
                intent_match = self.intent_router.recognize_intent(command)
                execution.intent = intent_match.intent.value
                execution.confidence = intent_match.confidence
            else:
                execution.intent = understanding.get("intent", "unknown")
                execution.confidence = understanding.get("confidence", 0.0)

            # Stage 2: ROUTE TO TOOL
            logger.debug(f"Stage 2: Routing intent '{execution.intent}'")
            intent_match = self.intent_router.recognize_intent(command)

            execution.tool_executed = intent_match.tool_name

            # Stage 3: EXECUTE TOOL
            logger.debug(f"Stage 3: Executing tool '{intent_match.tool_name}'")
            context = ActionContext(
                tool_name=intent_match.tool_name,
                parameters=intent_match.arguments,
                user_id=user_id,
                requires_confirmation=intent_match.requires_confirmation
            )

            tool_result = self.executor.execute(context)
            execution.tool_result = tool_result.as_dict()

            # Log tool execution
            if tool_result.success:
                log_tool_execution(
                    intent_match.tool_name,
                    "execute",
                    str(intent_match.arguments),
                    True,
                    tool_result.duration_ms,
                    user_id=user_id
                )

            # Stage 4: VERIFY RESULT
            logger.debug("Stage 4: Verifying result")
            verification = self.verifier.verify(
                tool_name=intent_match.tool_name,
                action=execution.tool_result.get("action", ""),
                result=execution.tool_result
            )
            execution.verification = {
                "verified": verification.verified,
                "goal_achieved": verification.goal_achieved,
                "evidence": verification.evidence,
                "recommendations": verification.recommendations,
            }

            # Stage 5: RECORD AND RECOVER
            logger.debug("Stage 5: Recording and recovery")
            execution.success = verification.verified

            # Log threats if detected
            if execution.tool_result.get("threat_detected"):
                log_threat_detected(
                    threat_type=execution.intent,
                    target=str(intent_match.arguments.get("target", "")),
                    risk_score=execution.tool_result.get("risk_score", 0),
                    verdict="UNKNOWN",
                    details=execution.tool_result,
                    user_id=user_id
                )

                # Record in memory
                self.memory.record_threat(
                    threat_type=execution.intent,
                    target=str(intent_match.arguments.get("target", "")),
                    risk_level="HIGH" if execution.tool_result.get("risk_score", 0) > 70 else "MEDIUM",
                    verdict=str(execution.tool_result.get("verdict", "UNKNOWN")),
                    action_taken=intent_match.tool_name
                )

            # Record action in memory
            self.memory.record_action(
                action_type=execution.intent,
                target=str(intent_match.arguments.get("target", "")),
                result="success" if execution.success else "failed",
                threat_detected=execution.tool_result.get("threat_detected", False),
                risk_score=execution.tool_result.get("risk_score"),
                details=str(execution.tool_result)
            )

            # Stage 6: GENERATE RESPONSE
            logger.debug("Stage 6: Generating response")
            response = self._generate_response(
                execution,
                intent_match,
                verification
            )

            # Record in memory
            self.memory.record_conversation(
                user_message=command,
                ai_response=response,
                intent=execution.intent,
                succeeded=execution.success
            )

            # Calculate duration
            execution.duration_ms = int((time.time() - start_time) * 1000)
            self.execution_history.append(execution)

            result_dict = {
                "success": execution.success,
                "intent": execution.intent,
                "confidence": execution.confidence,
                "tool": execution.tool_executed,
                "result": execution.tool_result,
                "verification": execution.verification,
                "duration_ms": execution.duration_ms,
            }

            logger.info(f"Command processed successfully in {execution.duration_ms}ms")
            return response, result_dict

        except Exception as e:
            logger.error(f"Agent processing error: {e}")
            execution.error = str(e)
            execution.duration_ms = int((time.time() - start_time) * 1000)
            self.execution_history.append(execution)

            error_response = f"Error: {str(e)}"
            return error_response, {
                "success": False,
                "error": str(e),
                "execution": asdict(execution)
            }

    def _generate_response(
        self,
        execution: AgentExecution,
        intent_match,
        verification
    ) -> str:
        """Generate precise, evidence-first security output.

        Security verdicts are deterministic. A local LLM can be used for
        explanation elsewhere, but it must never replace verified evidence.
        """
        return evidence_response(
            execution.tool_executed,
            execution.tool_result,
            verification,
        )

    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        return {
            "initialized": self.initialized,
            "ai_ready": self.ai_engine.is_ready(),
            "ai_status": self.ai_engine.get_status(),
            "executions": len(self.execution_history),
            "memory_stats": self.memory.get_stats(),
        }

    def get_execution_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent execution history."""
        return [asdict(e) for e in self.execution_history[-limit:]]

    def clear_history(self) -> None:
        """Clear execution history."""
        self.execution_history = []
        self.ai_engine.clear_history()
        logger.info("Agent history cleared")

    def shutdown(self) -> None:
        """Shutdown agent."""
        self.ai_engine.shutdown()
        self.memory.cleanup()
        self.initialized = False
        logger.info("LocalAutonomousAgent shutdown")
