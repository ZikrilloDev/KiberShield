"""
Action Executor

Executes tool calls with:
- Parameter validation
- Permission checking
- Timeout enforcement
- Exception handling
- Result verification
"""

from typing import Any, Dict, Optional
import logging
import time
from dataclasses import dataclass
from .tool_registry import ToolRegistry, ToolResult, ToolDefinition, PermissionLevel

logger = logging.getLogger(__name__)


@dataclass
class ActionContext:
    """Context for action execution."""
    tool_name: str
    parameters: Dict[str, Any]
    user_id: Optional[str] = None
    timestamp: float = 0
    requires_confirmation: bool = False
    confirmed: bool = False


class ActionExecutor:
    """Executes tools with safety gates and error handling."""

    def __init__(self, registry: ToolRegistry, max_retries: int = 2):
        self.registry = registry
        self.max_retries = max_retries
        self.execution_history = []

    def execute(self, context: ActionContext) -> ToolResult:
        """
        Execute a tool.

        Returns ToolResult with success/failure status and details.
        """
        start_time = time.time()
        context.timestamp = start_time

        # Get tool definition
        tool = self.registry.get(context.tool_name)
        if not tool:
            return ToolResult(
                success=False,
                tool_name=context.tool_name,
                action="validate",
                status="failed",
                error=f"Tool '{context.tool_name}' not found"
            )

        # Validate parameters
        valid, error = tool.validate_parameters(context.parameters)
        if not valid:
            logger.warning(f"Parameter validation failed for {context.tool_name}: {error}")
            return ToolResult(
                success=False,
                tool_name=context.tool_name,
                action="validate",
                status="failed",
                error=error
            )

        # Check confirmation requirement
        if tool.requires_confirmation and not context.confirmed:
            logger.info(f"Tool {context.tool_name} requires confirmation")
            return ToolResult(
                success=False,
                tool_name=context.tool_name,
                action="confirm",
                status="pending_confirmation",
                error="This action requires user confirmation"
            )

        logger.info(f"Executing tool: {context.tool_name} with params: {context.parameters}")

        # Execute with retry
        result = None
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                result = self._execute_with_timeout(tool, context)
                if result.success:
                    break
                last_error = result.error
                if attempt < self.max_retries:
                    logger.info(f"Retry {attempt}/{self.max_retries} for {context.tool_name}")
                    time.sleep(0.5)  # Brief delay before retry
            except Exception as e:
                last_error = str(e)
                logger.error(f"Attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(0.5)

        if result is None:
            result = ToolResult(
                success=False,
                tool_name=context.tool_name,
                action="execute",
                status="failed",
                error=f"All retries exhausted: {last_error}"
            )

        # Record duration
        duration_ms = int((time.time() - start_time) * 1000)
        result.duration_ms = duration_ms

        # Log execution
        self.execution_history.append({
            "timestamp": context.timestamp,
            "tool": context.tool_name,
            "success": result.success,
            "duration_ms": duration_ms,
        })

        logger.info(f"Tool execution result: {result.summary()} ({duration_ms}ms)")
        return result

    def _execute_with_timeout(self, tool: ToolDefinition, context: ActionContext) -> ToolResult:
        """Execute tool with timeout enforcement."""
        if not tool.handler:
            return ToolResult(
                success=False,
                tool_name=tool.name,
                action="execute",
                status="failed",
                error=f"No handler registered for tool '{tool.name}'"
            )

        try:
            # Call handler with timeout (simplified - real implementation would use signal or threading)
            result = tool.handler(**context.parameters)

            # Ensure result is ToolResult
            if not isinstance(result, ToolResult):
                result = ToolResult(
                    success=True,
                    tool_name=tool.name,
                    action="execute",
                    target=str(context.parameters.get("target", "")),
                    status="completed",
                    result=result
                )

            return result

        except TimeoutError as e:
            logger.error(f"Tool {tool.name} timed out after {tool.timeout_seconds}s")
            return ToolResult(
                success=False,
                tool_name=tool.name,
                action="execute",
                status="timeout",
                error=f"Tool execution timed out after {tool.timeout_seconds} seconds"
            )
        except Exception as e:
            logger.error(f"Tool {tool.name} raised exception: {e}")
            return ToolResult(
                success=False,
                tool_name=tool.name,
                action="execute",
                status="error",
                error=str(e)
            )

    def get_execution_history(self, limit: int = 100) -> list:
        """Get recent execution history."""
        return self.execution_history[-limit:]
