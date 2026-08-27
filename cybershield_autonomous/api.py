"""
CyberShield Autonomous Agent API

RESTful API endpoints for autonomous agent functionality.
Can be used by web UI, mobile apps, or external systems.
"""

from typing import Any, Dict, Optional, List
from dataclasses import dataclass
import json

from .integration import get_agent, init_agent
from .background import get_monitor, start_autonomous_protection, stop_autonomous_protection
from .audit_logging import get_audit_logger, log_command, log_tool_execution


@dataclass
class APIResponse:
    """Standard API response format."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    message: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "message": self.message,
        }

    def as_json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.as_dict(), default=str)


class AutonomousAgentAPI:
    """API for autonomous agent operations."""

    @staticmethod
    def initialize() -> APIResponse:
        """Initialize the autonomous agent."""
        try:
            if not init_agent():
                return APIResponse(
                    success=False,
                    error="Failed to initialize agent"
                )
            return APIResponse(
                success=True,
                message="Agent initialized successfully"
            )
        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def execute_command(
        command: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> APIResponse:
        """
        Execute a command through the autonomous agent.

        Args:
            command: User command (e.g., "scan", "status", "quarantine")
            user_id: Optional user ID for audit logging
            session_id: Optional session ID for audit logging

        Returns:
            APIResponse with command result
        """
        try:
            # Log command
            log_command(command, user_id, session_id)

            # Get agent
            agent = get_agent()
            if not agent.is_initialized:
                if not agent.initialize():
                    return APIResponse(
                        success=False,
                        error="Agent not initialized"
                    )

            # Execute command
            response_text, result = agent.process_command(command, user_id)

            return APIResponse(
                success=result.get("success", False),
                data={
                    "command": command,
                    "response": response_text,
                    "result": result,
                },
                message="Command executed"
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def get_available_tools() -> APIResponse:
        """Get list of available security tools."""
        try:
            agent = get_agent()
            if not agent.is_initialized:
                agent.initialize()

            tools = agent.get_tools_info()
            return APIResponse(
                success=True,
                data=tools,
                message=f"{len(tools)} tools available"
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def get_tool_info(tool_name: str) -> APIResponse:
        """Get information about specific tool."""
        try:
            agent = get_agent()
            if not agent.is_initialized:
                agent.initialize()

            tools = agent.get_tools_info()
            if tool_name not in tools:
                return APIResponse(
                    success=False,
                    error=f"Tool '{tool_name}' not found"
                )

            return APIResponse(
                success=True,
                data=tools[tool_name],
                message=f"Tool info retrieved"
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def get_execution_history(limit: int = 50) -> APIResponse:
        """Get execution history."""
        try:
            agent = get_agent()
            if not agent.is_initialized:
                agent.initialize()

            history = agent.get_execution_log(limit)
            return APIResponse(
                success=True,
                data=history,
                message=f"{len(history)} execution records"
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def start_protection() -> APIResponse:
        """Start autonomous protection."""
        try:
            if start_autonomous_protection():
                return APIResponse(
                    success=True,
                    message="Autonomous protection started"
                )
            else:
                return APIResponse(
                    success=False,
                    error="Failed to start protection"
                )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def stop_protection() -> APIResponse:
        """Stop autonomous protection."""
        try:
            stop_autonomous_protection()
            return APIResponse(
                success=True,
                message="Autonomous protection stopped"
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def get_protection_status() -> APIResponse:
        """Get autonomous protection status."""
        try:
            monitor = get_monitor()
            status = monitor.get_status()
            return APIResponse(
                success=True,
                data=status,
                message="Protection status retrieved"
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=str(e)
            )

    @staticmethod
    def scan_file(file_path: str, user_id: Optional[str] = None) -> APIResponse:
        """Scan a specific file."""
        return AutonomousAgentAPI.execute_command(f"scan {file_path}", user_id)

    @staticmethod
    def scan_directory(dir_path: str, user_id: Optional[str] = None) -> APIResponse:
        """Scan a directory."""
        return AutonomousAgentAPI.execute_command(f"scan {dir_path}", user_id)

    @staticmethod
    def full_system_scan(user_id: Optional[str] = None) -> APIResponse:
        """Start full system scan."""
        return AutonomousAgentAPI.execute_command("full_scan", user_id)

    @staticmethod
    def analyze_url(url: str, user_id: Optional[str] = None) -> APIResponse:
        """Analyze URL for phishing."""
        return AutonomousAgentAPI.execute_command(f"check_url {url}", user_id)

    @staticmethod
    def quarantine_file(file_path: str, user_id: Optional[str] = None) -> APIResponse:
        """Quarantine a file."""
        return AutonomousAgentAPI.execute_command(f"quarantine {file_path}", user_id)

    @staticmethod
    def restore_quarantine(quarantine_id: str, user_id: Optional[str] = None) -> APIResponse:
        """Restore file from quarantine."""
        return AutonomousAgentAPI.execute_command(f"restore {quarantine_id}", user_id)

    @staticmethod
    def get_system_status(user_id: Optional[str] = None) -> APIResponse:
        """Get system security status."""
        return AutonomousAgentAPI.execute_command("status", user_id)

    @staticmethod
    def get_security_status(user_id: Optional[str] = None) -> APIResponse:
        """Get detailed security status."""
        return AutonomousAgentAPI.execute_command("security_status", user_id)


# Helper functions for convenient API access

def init_autonomous_agent() -> bool:
    """Initialize autonomous agent."""
    response = AutonomousAgentAPI.initialize()
    return response.success


def execute_agent_command(
    command: str,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Execute command and return result as dict."""
    response = AutonomousAgentAPI.execute_command(command, user_id, session_id)
    return response.as_dict()


def get_agent_tools() -> Dict[str, Any]:
    """Get available tools."""
    response = AutonomousAgentAPI.get_available_tools()
    return response.data or {}


def scan_path(path: str, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Scan file or directory."""
    response = AutonomousAgentAPI.scan_file(path, user_id)
    return response.as_dict()


def check_url(url: str, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Check URL for phishing."""
    response = AutonomousAgentAPI.analyze_url(url, user_id)
    return response.as_dict()


def get_status(user_id: Optional[str] = None) -> Dict[str, Any]:
    """Get system status."""
    response = AutonomousAgentAPI.get_system_status(user_id)
    return response.as_dict()


def enable_realtime_protection() -> Dict[str, Any]:
    """Enable real-time protection."""
    response = AutonomousAgentAPI.start_protection()
    return response.as_dict()


def disable_realtime_protection() -> Dict[str, Any]:
    """Disable real-time protection."""
    response = AutonomousAgentAPI.stop_protection()
    return response.as_dict()
