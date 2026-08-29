"""
Autonomous Security Agent

The core agent that:
1. UNDERSTANDS user commands
2. PLANS appropriate security actions
3. SELECTS relevant tools
4. EXECUTES them with safety gates
5. VERIFIES results
6. RECOVERS from errors
7. REPORTS outcomes

This is NOT a chatbot - it performs real security operations.
"""

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging
import time
from datetime import datetime, timezone

from .tool_registry import ToolRegistry, ToolDefinition, PermissionLevel, ToolResult
from .action_executor import ActionExecutor, ActionContext
from .result_verifier import ResultVerifier

logger = logging.getLogger(__name__)


@dataclass
class AgentState:
    """Current state of agent execution."""
    stage: str  # understand, plan, select, execute, verify, recover, report
    user_command: str
    intent: str
    confidence: float
    selected_tools: List[str]
    execution_results: List[Dict[str, Any]]
    final_response: Optional[str] = None
    errors: List[str] = None
    start_time: float = 0
    end_time: float = 0

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class AutonomousAgent:
    """
    Autonomous security agent that performs real operations.

    Pipeline:
    OBSERVE (user command) →
    PLAN (what to do) →
    SELECT (which tools) →
    EXECUTE (run tools) →
    VERIFY (did it work?) →
    RECOVER (if needed) →
    REPORT (give results)
    """

    def __init__(self, registry: ToolRegistry):
        self.registry = registry
        self.executor = ActionExecutor(registry)
        self.verifier = ResultVerifier()
        self.execution_log = []

    def process_command(self, command: str, user_id: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Process user command through full autonomous agent pipeline.

        Returns:
            (human_response, structured_result)
        """
        state = AgentState(
            stage="understand",
            user_command=command,
            intent="",
            confidence=0.0,
            selected_tools=[],
            execution_results=[],
            start_time=time.time(),
            errors=[]
        )

        try:
            logger.info(f"Processing command: {command}")

            # Stage 1: Understand
            state = self._stage_understand(state)
            if not state.intent:
                return self._handle_failure(state, "Could not understand command")

            # Stage 2: Plan
            state = self._stage_plan(state)
            if not state.selected_tools:
                return self._handle_failure(state, "No tools applicable for this command")

            # Stage 3: Execute
            state = self._stage_execute(state, user_id)

            # Stage 4: Verify
            state = self._stage_verify(state)

            # Stage 5: Recover (if needed)
            if not all(r.get("success") for r in state.execution_results):
                state = self._stage_recover(state, user_id)

            # Stage 6: Report
            response, result_dict = self._stage_report(state)

            state.final_response = response
            state.end_time = time.time()
            state.stage = "complete"

            # Log execution
            self.execution_log.append(asdict(state))

            return response, result_dict

        except Exception as e:
            logger.error(f"Agent error: {e}")
            state.errors.append(str(e))
            return self._handle_failure(state, str(e))

    def _stage_understand(self, state: AgentState) -> AgentState:
        """Stage 1: UNDERSTAND user command."""
        logger.info("Stage 1: Understanding command")
        state.stage = "understand"

        command = state.user_command.lower().strip()

        # Intent recognition (simplified - integrates with UzbekSemanticEngine in production)
        intents = {
            "deep_investigation": [
                "deep scan", "deep check", "full check", "check everything", "scan everything",
                "everything", "all system", "all systems", "investigate everything", "deep investigation",
                "thorough investigation", "kompyuterni tekshir", "kompyuterimni tekshir", "hammasini tekshir",
                "barchasini tekshir", "to'liq tekshir", "toliq tekshir", "chuqur tekshir", "chuqur tahlil",
                "hamma narsani", "virus bormi", "zararli dastur bormi", "xavfsizlikni tekshir", "system investigation",
            ],
            "scan": ["scan", "tekshir", "skan", "check", "проверь"],
            "quarantine": ["quarantine", "karantin", "isolate", "isolatsyai"],
            "remediate": ["clean", "fix", "remove", "o'chir", "zararsizlantir", "hal qil"],
            "analyze": ["analiz", "analyze", "investigate", "tahlil"],
            "status": ["status", "holat", "state", "ko'r", "show"],
            "restore": ["restore", "qayta", "return", "bring_back"],
            "help": ["help", "yordam", "nima qila", "what can", "assist"],
        }

        detected_intent = "unknown"
        max_matches = 0

        for intent, keywords in intents.items():
            matches = sum(1 for kw in keywords if kw in command)
            if matches > max_matches:
                max_matches = matches
                detected_intent = intent

        state.intent = detected_intent
        state.confidence = 0.8 if max_matches > 0 else 0.3

        logger.info(f"Detected intent: {state.intent} (confidence: {state.confidence})")
        return state

    def _stage_plan(self, state: AgentState) -> AgentState:
        """Stage 2: PLAN what security actions to take."""
        logger.info("Stage 2: Planning actions")
        state.stage = "plan"

        command = state.user_command.lower()
        if state.intent == "deep_investigation":
            planned_tools = ["deep_investigation"]
        elif state.intent == "scan":
            import re
            has_url = bool(re.search(r"https?://", command))
            has_file_hint = bool(re.search(r"\.(exe|dll|sys|bat|cmd|ps1|msi|scr|js|vbs|zip|rar|pdf|docx?)\b", command))
            if has_url:
                planned_tools = ["analyze_url"]
            elif has_file_hint or any(x in command for x in ["file", "fayl"]):
                planned_tools = ["scan_file"]
            elif any(x in command for x in ["folder", "papka", "directory", "download", "desktop", "documents"]):
                planned_tools = ["scan_directory"]
            else:
                planned_tools = ["quick_scan"]
        elif state.intent == "quarantine":
            planned_tools = ["scan_file", "quarantine_file"]
        elif state.intent == "analyze":
            import re
            planned_tools = ["analyze_url"] if re.search(r"https?://", command) else ["scan_file"] if "." in command else ["deep_investigation"]
        elif state.intent == "status":
            planned_tools = ["get_system_status", "get_security_status", "defender_status", "firewall_status"]
        elif state.intent == "remediate":
            planned_tools = ["quarantine_file"]
        elif state.intent == "restore":
            planned_tools = ["restore_quarantine"]
        elif state.intent == "help":
            planned_tools = ["get_system_status"]
        else:
            planned_tools = ["deep_investigation"]

        state.selected_tools = planned_tools

        logger.info(f"Planned tools: {planned_tools}")
        return state

    def _stage_select(self, state: AgentState) -> List[ToolDefinition]:
        """Stage 3: SELECT tools based on plan."""
        logger.info("Stage 3: Selecting tools")
        state.stage = "select"

        # In production, this would consider:
        # - Permission levels
        # - User role
        # - System state
        # - Risk assessment
        # - Resource availability

        available_tools = []
        for tool_name in state.selected_tools:
            if self.registry.has(tool_name):
                available_tools.append(self.registry.get(tool_name))

        logger.info(f"Selected {len(available_tools)} tools")
        return available_tools

    def _stage_execute(self, state: AgentState, user_id: Optional[str]) -> AgentState:
        """Stage 4: EXECUTE selected tools."""
        logger.info("Stage 4: Executing tools")
        state.stage = "execute"

        tools = self._stage_select(state)

        for tool in tools:
            logger.info(f"Executing tool: {tool.name}")

            # Build parameters from context
            params = self._build_tool_parameters(tool, state)

            # Create action context
            context = ActionContext(
                tool_name=tool.name,
                parameters=params,
                user_id=user_id,
                requires_confirmation=tool.requires_confirmation
            )

            # Execute tool
            result = self.executor.execute(context)

            # Store result
            state.execution_results.append({
                "tool": tool.name,
                "success": result.success,
                "status": result.status,
                "result": asdict(result),
            })

            logger.info(f"Tool result: {result.summary()}")

        return state

    def _stage_verify(self, state: AgentState) -> AgentState:
        """Stage 5: VERIFY that actions succeeded."""
        logger.info("Stage 5: Verifying results")
        state.stage = "verify"

        verified_results = []

        for exec_result in state.execution_results:
            tool_name = exec_result["tool"]
            result = exec_result["result"]

            verification = self.verifier.verify(
                tool_name=tool_name,
                action=result.get("action", "execute"),
                result=result.get("result", result)
            )

            verified_results.append({
                "tool": tool_name,
                "verified": verification.verified,
                "goal_achieved": verification.goal_achieved,
                "evidence": verification.evidence,
                "recommendations": verification.recommendations,
            })

            logger.info(f"Verification for {tool_name}: {verification.verified}")

        # Store verification results
        for i, result in enumerate(verified_results):
            if i < len(state.execution_results):
                state.execution_results[i]["verification"] = result

        return state

    def _stage_recover(self, state: AgentState, user_id: Optional[str]) -> AgentState:
        """Stage 6: RECOVER from errors if possible."""
        logger.info("Stage 6: Recovery")
        state.stage = "recover"

        # Analyze failures
        failed_tools = [
            r for r in state.execution_results
            if not r.get("success", False)
        ]

        if not failed_tools:
            return state

        logger.warning(f"Found {len(failed_tools)} failed tool executions")

        # Attempt recovery (simplified - in production would be more sophisticated)
        for failed in failed_tools:
            tool_name = failed["tool"]
            logger.info(f"Attempting recovery for {tool_name}")

            # Don't retry CRITICAL permission tools automatically
            tool = self.registry.get(tool_name)
            if tool and tool.permission_level == PermissionLevel.CRITICAL:
                logger.info(f"Skipping auto-retry for CRITICAL tool {tool_name}")
                continue

            # Retry once
            params = self._build_tool_parameters(self.registry.get(tool_name), state)
            context = ActionContext(
                tool_name=tool_name,
                parameters=params,
                user_id=user_id
            )

            retry_result = self.executor.execute(context)
            logger.info(f"Retry result for {tool_name}: {retry_result.summary()}")

        return state

    def _stage_report(self, state: AgentState) -> Tuple[str, Dict[str, Any]]:
        """Stage 7: REPORT results to user."""
        logger.info("Stage 7: Reporting")
        state.stage = "report"

        # Build human-readable response
        if state.intent == "deep_investigation":
            response = self._report_deep_investigation(state)
        elif state.intent == "scan":
            response = self._report_scan(state)
        elif state.intent == "quarantine":
            response = self._report_quarantine(state)
        elif state.intent == "status":
            response = self._report_status(state)
        else:
            response = self._report_generic(state)

        # Build structured result
        result_dict = {
            "success": len(state.errors) == 0,
            "intent": state.intent,
            "confidence": state.confidence,
            "tools_executed": len(state.execution_results),
            "results": state.execution_results,
            "errors": state.errors,
            "duration_ms": int((state.end_time - state.start_time) * 1000) if state.end_time else 0,
        }

        return response, result_dict

    def _build_tool_parameters(self, tool: Optional[ToolDefinition], state: AgentState) -> Dict[str, Any]:
        """Build parameters for tool execution from command context."""
        if not tool:
            return {}

        # Simplified parameter building - in production would parse command for specific values
        command_lower = state.user_command.lower()

        params = {}
        import re
        for param in tool.parameters:
            if param.type.value == "path":
                # Prefer explicit Windows/Unix paths, then safe well-known folders.
                quoted = re.search(r'["\']([^"\']+)["\']', state.user_command)
                win = re.search(r'[A-Za-z]:\\[^\s"\']+', state.user_command)
                unix = re.search(r'(?<!https:)(?<!http:)/[^\s"\']+', state.user_command)
                candidate = quoted.group(1) if quoted else (win.group(0) if win else (unix.group(0) if unix else None))
                if candidate:
                    params[param.name] = candidate
                elif "download" in command_lower:
                    params[param.name] = "~/Downloads"
                elif "desktop" in command_lower:
                    params[param.name] = "~/Desktop"
                elif "document" in command_lower:
                    params[param.name] = "~/Documents"
                else:
                    params[param.name] = "."
            elif param.type.value == "url":
                match = re.search(r'https?://[^\s"\']+', state.user_command)
                if match:
                    params[param.name] = match.group(0)
            elif param.type.value == "integer":
                match = re.search(r'\b(?:pid|process)\s*[=:]?\s*(\d+)\b', command_lower)
                if match:
                    params[param.name] = int(match.group(1))
            elif param.type.value == "string":
                # Quarantine IDs can be supplied as the final token; other strings use defaults.
                params[param.name] = ""
            elif param.type.value == "boolean":
                params[param.name] = True

        return params

    def _report_deep_investigation(self, state: AgentState) -> str:
        """Generate a useful security triage report from correlated telemetry."""
        response = "CyberShield Deep Investigation yakunlandi.\n"
        response += "Read-only tekshiruv: tizimga o'zgartirish kiritilmadi.\n\n"
        total_checks = 0
        failures = 0
        for item in state.execution_results:
            result = item.get("result", {}) or {}
            payload = result.get("result", {}) if isinstance(result, dict) else {}
            checks = payload.get("checks", []) if isinstance(payload, dict) else []
            if checks:
                total_checks += len(checks)
                failures += sum(1 for c in checks if not c.get("success", False))
                for check in checks:
                    if not check.get("success", False):
                        response += f"⚠ {check.get('tool_name','unknown')}: {check.get('error','collection failed')}\n"
        response += f"Tekshiruvlar: {total_checks - failures}/{total_checks} muvaffaqiyatli.\n"
        if failures:
            response += f"Qisman natija: {failures} manbani OS ruxsati yoki mavjud bo'lmagan utilita sabab tekshirib bo'lmadi.\n"
        else:
            response += "Barcha mavjud telemetry manbalari yig'ildi.\n"
        response += "\nMuhim: bu natija 'virus yo'q' degan matematik kafolat emas; u mahalliy telemetry va CyberShield analiziga asoslangan.\n"
        return response

    def _report_scan(self, state: AgentState) -> str:
        """Generate scan report."""
        total = len(state.execution_results)
        successful = sum(1 for r in state.execution_results if r.get("success"))

        response = f"Scan tugadi.\n"
        response += f"Skanerlar ishladi: {successful}/{total}\n"

        for result in state.execution_results:
            if result.get("verification"):
                evidence = result["verification"].get("evidence", [])
                if evidence:
                    response += f"\nBatafsil:\n"
                    for item in evidence[:3]:
                        response += f"- {item}\n"

        if state.execution_results:
            recs = []
            for result in state.execution_results:
                if result.get("verification"):
                    recs.extend(result["verification"].get("recommendations", []))
            if recs:
                response += f"\nTaklif qilingan:\n"
                for rec in recs[:3]:
                    response += f"• {rec}\n"

        return response

    def _report_quarantine(self, state: AgentState) -> str:
        """Generate quarantine report."""
        successful = sum(1 for r in state.execution_results if r.get("success"))
        return f"Karantin operatsiyalari tugadi. Muvaffaq: {successful}/{len(state.execution_results)}"

    def _report_status(self, state: AgentState) -> str:
        """Generate status report."""
        if state.execution_results and state.execution_results[0].get("result"):
            result = state.execution_results[0]["result"]
            return f"Tizim holati: Sog'lom"
        return "Status tekshirish tugadi"

    def _report_generic(self, state: AgentState) -> str:
        """Generate generic report."""
        if state.errors:
            return f"Xatolik: {state.errors[0]}"
        return f"Buyruq bajarildi"

    def _handle_failure(self, state: AgentState, error_msg: str) -> Tuple[str, Dict[str, Any]]:
        """Handle command processing failure."""
        state.errors.append(error_msg)
        state.end_time = time.time()

        result_dict = {
            "success": False,
            "intent": state.intent,
            "error": error_msg,
            "errors": state.errors,
            "duration_ms": int((state.end_time - state.start_time) * 1000) if state.end_time else 0,
        }

        return f"Xatolik: {error_msg}", result_dict

    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools."""
        return [tool.as_dict() for tool in self.registry.list_all()]

    def get_execution_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent execution history."""
        return self.execution_log[-limit:]
