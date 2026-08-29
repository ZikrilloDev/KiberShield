"""CyberShield security command registry.

This registry deliberately excludes deployment/version-control commands.
The command executor should map each command to a real implementation and
return NOT_AVAILABLE rather than pretending success when a dependency is absent.
"""
from __future__ import annotations
import json
from pathlib import Path

_CATALOG = Path(__file__).with_name("security_command_catalog.json")

def load_security_commands():
    data = json.loads(_CATALOG.read_text(encoding="utf-8"))
    return data["commands"]

SECURITY_COMMANDS = {item["name"]: item for item in load_security_commands()}

def command_names():
    return tuple(SECURITY_COMMANDS)

def is_security_command(name: str) -> bool:
    return name in SECURITY_COMMANDS
