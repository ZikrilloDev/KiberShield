"""
CyberShield Autonomous Agent Framework

Two-tier architecture:
1. Generic Autonomous Agent (tool-based, can work with any AI)
2. Local AI Agent (OFFLINE-ONLY, no cloud dependency)

This module implements a professional cybersecurity AI agent that:
1. Works completely locally without cloud API dependency
2. Understands user security commands
3. Plans appropriate security actions using local AI
4. Routes to appropriate security tools
5. Executes tools with safety verification
6. Recovers from errors autonomously
7. Records conversation and action history locally
8. Reports outcomes clearly

NO CLOUD API - FULLY OFFLINE
"""

# Generic autonomous agent components
from .tool_registry import ToolRegistry, ToolDefinition, ToolParameter, PermissionLevel
from .autonomous_agent import AutonomousAgent
from .action_executor import ActionExecutor, ActionContext
from .result_verifier import ResultVerifier
from .tool_builders import ToolBuilder
from .integration import CyberShieldAgentIntegration, init_agent, process_command

# Local AI components (OFFLINE ONLY)
from .local_model_backend import LocalModelBackend, OllamaBackend, LlamaCppBackend, LocalModelManager
from .local_ai_engine import LocalAIEngine
from .intent_router import IntentRouter, Intent, IntentMatch
from .local_memory import LocalMemory, LocalMemoryDB, ConversationEntry, ActionHistory, ThreatAttention
from .local_autonomous_agent import LocalAutonomousAgent, AgentExecution

# Supporting components
from .audit_logging import AuditLogger, get_audit_logger, start_audit_logging, stop_audit_logging
from .background import AutonomousSecurityMonitor, get_monitor, start_autonomous_protection

__all__ = [
    # Generic agent
    "ToolRegistry",
    "ToolDefinition",
    "ToolParameter",
    "PermissionLevel",
    "AutonomousAgent",
    "ActionExecutor",
    "ActionContext",
    "ResultVerifier",
    "ToolBuilder",
    "CyberShieldAgentIntegration",
    "init_agent",
    "process_command",

    # Local AI (OFFLINE ONLY)
    "LocalModelBackend",
    "OllamaBackend",
    "LlamaCppBackend",
    "LocalModelManager",
    "LocalAIEngine",
    "IntentRouter",
    "Intent",
    "IntentMatch",
    "LocalMemory",
    "LocalMemoryDB",
    "ConversationEntry",
    "ActionHistory",
    "ThreatAttention",
    "LocalAutonomousAgent",
    "AgentExecution",

    # Support
    "AuditLogger",
    "get_audit_logger",
    "start_audit_logging",
    "stop_audit_logging",
    "AutonomousSecurityMonitor",
    "get_monitor",
    "start_autonomous_protection",
]
