"""
CyberShield Autonomous Agent Integration

This module integrates the autonomous agent system with the existing CyberShield
application, including UI callbacks, background services, and API endpoints.
"""

from typing import Any, Dict, Optional, Callable
import logging
from pathlib import Path

from .autonomous_agent import AutonomousAgent
from .tool_registry import ToolRegistry
from .tool_builders import ToolBuilder

logger = logging.getLogger(__name__)


class CyberShieldAgentIntegration:
    """Integration layer for autonomous agent with CyberShield app."""

    def __init__(self):
        self.registry = ToolRegistry()
        self.builder = ToolBuilder(self.registry)
        self.agent: Optional[AutonomousAgent] = None
        self.ui_callbacks: Dict[str, Callable] = {}
        self.is_initialized = False

    def initialize(self) -> bool:
        """Initialize the autonomous agent system."""
        try:
            logger.info("Initializing CyberShield Autonomous Agent")

            # Build all security tools
            self.builder.build_all_tools()
            logger.info(f"Registered {len(self.registry.list_all())} security tools")

            # Create agent
            self.agent = AutonomousAgent(self.registry)
            logger.info("Autonomous agent created")

            self.is_initialized = True
            logger.info("CyberShield Autonomous Agent initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize autonomous agent: {e}")
            return False

    def register_ui_callback(self, callback_name: str, callback: Callable) -> None:
        """Register callback for UI updates during agent execution."""
        self.ui_callbacks[callback_name] = callback
        logger.info(f"Registered UI callback: {callback_name}")

    def _notify_ui(self, event: str, data: Dict[str, Any]) -> None:
        """Notify UI of agent events."""
        callback = self.ui_callbacks.get(event)
        if callback:
            try:
                callback(data)
            except Exception as e:
                logger.error(f"UI callback error: {e}")

    def process_user_command(
        self,
        command: str,
        user_id: Optional[str] = None,
        on_progress: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Process user command through autonomous agent.

        Returns:
            Dictionary with response and execution details
        """
        if not self.is_initialized or not self.agent:
            return {
                "success": False,
                "error": "Agent not initialized",
                "response": "Xatolik: Agent ishga tushmadi"
            }

        if on_progress:
            self.register_ui_callback("progress", on_progress)

        try:
            # Notify UI: starting
            self._notify_ui("started", {"command": command})

            # Process through agent
            response, result = self.agent.process_command(command, user_id)

            # Notify UI: completed
            self._notify_ui("completed", {
                "command": command,
                "response": response,
                "result": result
            })

            return {
                "success": result.get("success", False),
                "response": response,
                "result": result,
                "command": command,
            }

        except Exception as e:
            logger.error(f"Command processing error: {e}")
            return {
                "success": False,
                "error": str(e),
                "response": f"Xatolik: {e}"
            }

    def get_tools_info(self) -> Dict[str, Any]:
        """Get information about available tools."""
        return self.registry.as_dict()

    def get_execution_history(self, limit: int = 50) -> list:
        """Get execution history."""
        if not self.agent:
            return []
        return self.agent.get_execution_log(limit)

    def cancel_current_operation(self) -> bool:
        """Cancel current operation (if supported)."""
        # TODO: Implement cancellation
        logger.info("Cancel requested (not yet implemented)")
        return False


# Global agent instance
_agent_instance: Optional[CyberShieldAgentIntegration] = None


def get_agent() -> CyberShieldAgentIntegration:
    """Get or create global agent instance."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = CyberShieldAgentIntegration()
    return _agent_instance


def init_agent() -> bool:
    """Initialize the global agent."""
    agent = get_agent()
    return agent.initialize()


def process_command(
    command: str,
    user_id: Optional[str] = None,
    on_progress: Optional[Callable] = None
) -> Dict[str, Any]:
    """Process command using global agent."""
    agent = get_agent()
    return agent.process_user_command(command, user_id, on_progress)


def get_available_tools() -> Dict[str, Any]:
    """Get available tools."""
    agent = get_agent()
    return agent.get_tools_info()
