"""
Tool Registry and Definitions

This module defines all security tools available to the autonomous agent.
Each tool has:
- Name and description
- Input parameters with types and validation
- Permission level (LOW, MEDIUM, HIGH, CRITICAL)
- Result structure
- Execution handler
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class PermissionLevel(Enum):
    """Security risk level of an action."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ParameterType(Enum):
    """Parameter type validation."""
    STRING = "string"
    PATH = "path"
    URL = "url"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    LIST = "list"


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""
    name: str
    type: ParameterType
    required: bool = True
    description: str = ""
    default: Any = None
    pattern: Optional[str] = None  # Regex for validation
    enums: Optional[List[str]] = None  # Allowed values

    def validate(self, value: Any) -> tuple[bool, Optional[str]]:
        """Validate parameter value."""
        if value is None:
            if self.required:
                return False, f"Required parameter '{self.name}' is missing"
            return True, None

        if self.enums and value not in self.enums:
            return False, f"Parameter '{self.name}' must be one of: {self.enums}"

        if self.type == ParameterType.STRING:
            if not isinstance(value, str):
                return False, f"Parameter '{self.name}' must be string, got {type(value)}"
            if self.pattern:
                import re
                if not re.match(self.pattern, value):
                    return False, f"Parameter '{self.name}' does not match pattern {self.pattern}"

        elif self.type == ParameterType.PATH:
            if not isinstance(value, (str, bytes)):
                return False, f"Parameter '{self.name}' must be path, got {type(value)}"

        elif self.type == ParameterType.URL:
            if not isinstance(value, str):
                return False, f"Parameter '{self.name}' must be URL, got {type(value)}"
            if not (value.startswith("http://") or value.startswith("https://")):
                return False, f"Parameter '{self.name}' must start with http:// or https://"

        elif self.type == ParameterType.INTEGER:
            if not isinstance(value, int) or isinstance(value, bool):
                return False, f"Parameter '{self.name}' must be integer, got {type(value)}"

        elif self.type == ParameterType.BOOLEAN:
            if not isinstance(value, bool):
                return False, f"Parameter '{self.name}' must be boolean, got {type(value)}"

        elif self.type == ParameterType.LIST:
            if not isinstance(value, list):
                return False, f"Parameter '{self.name}' must be list, got {type(value)}"

        return True, None


@dataclass
class ToolResult:
    """Structured result from tool execution."""
    success: bool
    tool_name: str
    action: str
    target: str = ""
    status: str = ""
    result: Any = None
    error: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None
    threat_detected: Optional[bool] = None
    risk_score: Optional[int] = None
    details: List[str] = field(default_factory=list)
    duration_ms: int = 0

    def as_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def summary(self) -> str:
        """Get human-readable summary."""
        if self.success:
            if self.status:
                return f"✓ {self.status}"
            return f"✓ {self.action} completed"
        return f"✗ {self.error or 'Operation failed'}"


@dataclass
class ToolDefinition:
    """Definition of a security tool available to the agent."""
    name: str  # Unique identifier
    display_name: str  # User-friendly name
    description: str  # What this tool does
    category: str  # scan, analyze, contain, remediate, monitor, etc.
    permission_level: PermissionLevel
    parameters: List[ToolParameter] = field(default_factory=list)
    requires_confirmation: bool = False  # If True, ask user before executing
    timeout_seconds: int = 300
    handler: Optional[Callable] = None  # Function to execute

    def validate_parameters(self, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate all parameters."""
        for param_def in self.parameters:
            value = params.get(param_def.name)
            valid, error = param_def.validate(value)
            if not valid:
                return False, error
        return True, None

    def as_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for API responses)."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category,
            "permission_level": self.permission_level.value,
            "parameters": [asdict(p) for p in self.parameters],
            "requires_confirmation": self.requires_confirmation,
            "timeout_seconds": self.timeout_seconds,
        }


class ToolRegistry:
    """Registry of all available security tools."""

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool."""
        if tool.name in self._tools:
            logger.warning(f"Tool '{tool.name}' already registered, overwriting")
        self._tools[tool.name] = tool
        logger.info(f"Registered tool: {tool.name}")

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Get tool definition by name."""
        return self._tools.get(name)

    def list_by_category(self, category: str) -> List[ToolDefinition]:
        """List all tools in a category."""
        return [t for t in self._tools.values() if t.category == category]

    def list_by_permission(self, level: PermissionLevel) -> List[ToolDefinition]:
        """List all tools at or below permission level."""
        perm_order = {PermissionLevel.LOW: 0, PermissionLevel.MEDIUM: 1,
                      PermissionLevel.HIGH: 2, PermissionLevel.CRITICAL: 3}
        threshold = perm_order[level]
        return [t for t in self._tools.values()
                if perm_order[t.permission_level] <= threshold]

    def list_all(self) -> List[ToolDefinition]:
        """List all registered tools."""
        return list(self._tools.values())

    def has(self, name: str) -> bool:
        """Check if tool exists."""
        return name in self._tools

    def as_dict(self) -> Dict[str, Any]:
        """Convert registry to dictionary."""
        return {
            name: tool.as_dict()
            for name, tool in self._tools.items()
        }
