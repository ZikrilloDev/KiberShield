"""
CyberShield Autonomous Agent Command Interface

Provides command-line interface for testing and interacting with the
autonomous agent directly.
"""

import sys
import logging
from typing import Optional
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner() -> None:
    """Print CyberShield Agent banner."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║           CyberShield Autonomous Security Agent               ║
║                       v24.0 ALPHA                            ║
╚════════════════════════════════════════════════════════════════╝

This is an AUTONOMOUS SECURITY AGENT, not a chatbot.
It will perform real security operations.

Commands:
  scan <path>        - Scan file or directory
  full_scan          - Full system scan
  deep_check         - Deep read-only host investigation
  check everything   - Correlated system investigation
  processes          - Inspect processes
  network            - Inspect interfaces/routes/connections
  services           - Inspect services
  tasks              - Inspect scheduled tasks
  startup            - Inspect startup items
  defender           - Read Defender status
  firewall           - Read firewall status
  dns                - Read DNS configuration
  hosts              - Inspect hosts file
  hash <path>        - SHA-256/SHA-1/MD5 file hashes
  inventory          - Host/OS/disk inventory
  quarantine <path>  - Quarantine suspicious file (confirmation)
  restore <id>       - Restore from quarantine (confirmation)
  check_url <url>    - Analyze URL for phishing
  status             - Get system security status
  tools              - List all available tools
  history            - Show execution history
  help               - Show this help
  exit               - Exit agent

Examples:
  scan ~/Downloads
  full_scan
  check_url https://example.com
  status
""")


def print_tools(agent) -> None:
    """Print available tools."""
    tools = agent.get_agent().get_tools_info()
    print("\n=== Available Security Tools ===\n")
    
    categories = {}
    for name, tool in tools.items():
        cat = tool.get("category", "other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((name, tool))
    
    for category in sorted(categories.keys()):
        print(f"\n{category.upper()}:")
        for name, tool in categories[category]:
            perm = tool.get("permission_level", "UNKNOWN")
            print(f"  • {tool['display_name']:30} [{perm:8}]")
            print(f"    {tool['description']}")


def print_result(result: dict) -> None:
    """Print command result in human-readable format."""
    success = result.get("success", False)
    response = result.get("response", "")
    execution_result = result.get("result", {})
    
    status = "✓" if success else "✗"
    print(f"\n{status} Status: {'Success' if success else 'Failed'}")
    
    if response:
        print(f"\nResponse:\n{response}")
    
    if execution_result:
        intent = execution_result.get("intent", "unknown")
        tools_executed = execution_result.get("tools_executed", 0)
        print(f"\nDetails:")
        print(f"  Intent: {intent}")
        print(f"  Tools executed: {tools_executed}")
        
        if execution_result.get("results"):
            print(f"  Results:")
            for r in execution_result["results"][:3]:
                tool = r.get("tool", "unknown")
                tool_success = r.get("success", False)
                tool_status = "✓" if tool_success else "✗"
                print(f"    {tool_status} {tool}: {r.get('status', 'unknown')}")
        
        if execution_result.get("errors"):
            print(f"  Errors:")
            for err in execution_result["errors"]:
                print(f"    ✗ {err}")


def print_history(agent, limit: int = 10) -> None:
    """Print execution history."""
    history = agent.get_agent().get_execution_history(limit)
    
    if not history:
        print("\nNo execution history")
        return
    
    print(f"\n=== Recent Executions ({len(history)} total) ===\n")
    for i, entry in enumerate(reversed(history), 1):
        stage = entry.get("stage", "unknown")
        intent = entry.get("intent", "unknown")
        success = "✓" if len(entry.get("errors", [])) == 0 else "✗"
        duration = entry.get("end_time", 0) - entry.get("start_time", 0)
        
        print(f"{i}. {success} [{stage:8}] {intent:10} ({duration:.2f}s)")
        if entry.get("user_command"):
            print(f"   Command: {entry['user_command']}")


def interactive_mode(agent) -> None:
    """Run in interactive command mode."""
    print_banner()
    print("\nInitializing agent...")
    
    if not agent.is_initialized:
        if not agent.initialize():
            print("✗ Failed to initialize agent")
            return
    
    print("✓ Agent ready\n")
    
    while True:
        try:
            # Get user input
            cmd = input("agent> ").strip()
            
            if not cmd:
                continue
            
            # Handle special commands
            if cmd.lower() == "exit":
                print("Exiting...")
                break
            elif cmd.lower() == "help":
                print_banner()
                continue
            elif cmd.lower() == "tools":
                print_tools(agent)
                continue
            elif cmd.lower() == "history":
                print_history(agent)
                continue
            elif cmd.lower().startswith("history "):
                try:
                    limit = int(cmd.split()[1])
                    print_history(agent, limit)
                except:
                    print("Usage: history <number>")
                continue
            
            # Process command through agent
            print("\n⏳ Processing...")
            result = agent.process_user_command(cmd)
            print_result(result)
            print()
            
        except KeyboardInterrupt:
            print("\n\nInterrupted. Type 'exit' to quit, or continue...")
        except Exception as e:
            print(f"\n✗ Error: {e}")


def command_mode(command: str, agent) -> None:
    """Run single command."""
    if not agent.is_initialized:
        if not agent.initialize():
            print("✗ Failed to initialize agent")
            return
    
    result = agent.process_user_command(command)
    print_result(result)


def main() -> int:
    """Main entry point."""
    from .integration import get_agent
    
    agent = get_agent()
    
    # Check for command-line arguments
    if len(sys.argv) > 1:
        # Single command mode
        command = " ".join(sys.argv[1:])
        command_mode(command, agent)
        return 0
    else:
        # Interactive mode
        interactive_mode(agent)
        return 0


if __name__ == "__main__":
    sys.exit(main())
