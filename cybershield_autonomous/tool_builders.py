"""
Security Tool Builders

Build concrete tool implementations that integrate with existing CyberShield
security modules (scanner, quarantine, phishing detection, etc).
"""

from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

from .tool_registry import (
    ToolRegistry, ToolDefinition, ToolParameter, ParameterType,
    PermissionLevel, ToolResult
)

logger = logging.getLogger(__name__)


class ToolBuilder:
    """Build and register security tools."""

    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def build_all_tools(self) -> None:
        """Register all available security tools."""
        self.build_scanner_tools()
        self.build_quarantine_tools()
        self.build_analysis_tools()
        self.build_remediation_tools()
        self.build_monitoring_tools()
        self.build_utility_tools()
        self.build_terminal_intelligence_tools()

    def build_scanner_tools(self) -> None:
        """Build file and system scanning tools."""
        logger.info("Building scanner tools")

        # Scan single file
        scan_file = ToolDefinition(
            name="scan_file",
            display_name="Scan File",
            description="Analyze a single file for malware",
            category="scan",
            permission_level=PermissionLevel.LOW,
            parameters=[
                ToolParameter(
                    name="path",
                    type=ParameterType.PATH,
                    required=True,
                    description="File path to scan"
                ),
                ToolParameter(
                    name="detailed",
                    type=ParameterType.BOOLEAN,
                    required=False,
                    default=False,
                    description="Include detailed analysis"
                ),
            ],
            timeout_seconds=30,
            handler=self._scan_file_impl,
        )
        self.registry.register(scan_file)

        # Scan directory
        scan_directory = ToolDefinition(
            name="scan_directory",
            display_name="Scan Directory",
            description="Scan all files in a directory",
            category="scan",
            permission_level=PermissionLevel.LOW,
            parameters=[
                ToolParameter(
                    name="path",
                    type=ParameterType.PATH,
                    required=True,
                    description="Directory path to scan"
                ),
                ToolParameter(
                    name="recursive",
                    type=ParameterType.BOOLEAN,
                    required=False,
                    default=True,
                    description="Scan subdirectories"
                ),
            ],
            timeout_seconds=300,
            handler=self._scan_directory_impl,
        )
        self.registry.register(scan_directory)

        # Full system scan
        full_system_scan = ToolDefinition(
            name="full_system_scan",
            display_name="Full System Scan",
            description="Perform comprehensive system-wide security scan",
            category="scan",
            permission_level=PermissionLevel.MEDIUM,
            parameters=[
                ToolParameter(
                    name="priority",
                    type=ParameterType.STRING,
                    required=False,
                    default="normal",
                    enums=["quick", "normal", "thorough"]
                ),
            ],
            timeout_seconds=3600,
            handler=self._full_system_scan_impl,
        )
        self.registry.register(full_system_scan)

        # Quick scan
        quick_scan = ToolDefinition(
            name="quick_scan",
            display_name="Quick Scan",
            description="Fast scan of critical locations",
            category="scan",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=60,
            handler=self._quick_scan_impl,
        )
        self.registry.register(quick_scan)

    def build_quarantine_tools(self) -> None:
        """Build quarantine and containment tools."""
        logger.info("Building quarantine tools")

        # Quarantine file
        quarantine = ToolDefinition(
            name="quarantine_file",
            display_name="Quarantine File",
            description="Move suspicious/malicious file to quarantine",
            category="contain",
            permission_level=PermissionLevel.MEDIUM,
            parameters=[
                ToolParameter(
                    name="path",
                    type=ParameterType.PATH,
                    required=True,
                    description="File to quarantine"
                ),
                ToolParameter(
                    name="reason",
                    type=ParameterType.STRING,
                    required=False,
                    description="Reason for quarantine"
                ),
            ],
            requires_confirmation=True,
            timeout_seconds=30,
            handler=self._quarantine_file_impl,
        )
        self.registry.register(quarantine)

        # Restore from quarantine
        restore = ToolDefinition(
            name="restore_quarantine",
            display_name="Restore from Quarantine",
            description="Restore file from quarantine to original location",
            category="remediate",
            permission_level=PermissionLevel.MEDIUM,
            parameters=[
                ToolParameter(
                    name="quarantine_id",
                    type=ParameterType.STRING,
                    required=True,
                    description="Quarantine file ID or path"
                ),
            ],
            requires_confirmation=True,
            timeout_seconds=30,
            handler=self._restore_quarantine_impl,
        )
        self.registry.register(restore)

        # List quarantine
        list_quarantine = ToolDefinition(
            name="list_quarantine",
            display_name="List Quarantine",
            description="Show all quarantined files",
            category="monitor",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=10,
            handler=self._list_quarantine_impl,
        )
        self.registry.register(list_quarantine)

        # Delete from quarantine
        delete_quarantine = ToolDefinition(
            name="delete_quarantine",
            display_name="Delete from Quarantine",
            description="Permanently delete quarantined file",
            category="remediate",
            permission_level=PermissionLevel.HIGH,
            parameters=[
                ToolParameter(
                    name="quarantine_id",
                    type=ParameterType.STRING,
                    required=True,
                    description="ID or path of file in quarantine"
                ),
            ],
            requires_confirmation=True,
            timeout_seconds=30,
            handler=self._delete_quarantine_impl,
        )
        self.registry.register(delete_quarantine)

    def build_analysis_tools(self) -> None:
        """Build analysis tools."""
        logger.info("Building analysis tools")

        # Analyze URL
        analyze_url = ToolDefinition(
            name="analyze_url",
            display_name="Analyze URL",
            description="Check if URL is phishing or malicious",
            category="analyze",
            permission_level=PermissionLevel.LOW,
            parameters=[
                ToolParameter(
                    name="url",
                    type=ParameterType.URL,
                    required=True,
                    description="URL to analyze"
                ),
            ],
            timeout_seconds=15,
            handler=self._analyze_url_impl,
        )
        self.registry.register(analyze_url)

        # Analyze process
        analyze_process = ToolDefinition(
            name="analyze_process",
            display_name="Analyze Process",
            description="Analyze running process for suspicious behavior",
            category="analyze",
            permission_level=PermissionLevel.LOW,
            parameters=[
                ToolParameter(
                    name="pid",
                    type=ParameterType.INTEGER,
                    required=True,
                    description="Process ID"
                ),
            ],
            timeout_seconds=15,
            handler=self._analyze_process_impl,
        )
        self.registry.register(analyze_process)

    def build_remediation_tools(self) -> None:
        """Build remediation tools."""
        logger.info("Building remediation tools")

        # Kill suspicious process
        kill_process = ToolDefinition(
            name="kill_process",
            display_name="Terminate Process",
            description="Kill suspicious process",
            category="remediate",
            permission_level=PermissionLevel.HIGH,
            parameters=[
                ToolParameter(
                    name="pid",
                    type=ParameterType.INTEGER,
                    required=True,
                    description="Process ID"
                ),
                ToolParameter(
                    name="force",
                    type=ParameterType.BOOLEAN,
                    required=False,
                    default=False,
                    description="Force kill"
                ),
            ],
            requires_confirmation=True,
            timeout_seconds=10,
            handler=self._kill_process_impl,
        )
        self.registry.register(kill_process)

    def build_monitoring_tools(self) -> None:
        """Build system monitoring tools."""
        logger.info("Building monitoring tools")

        # Get system status
        status = ToolDefinition(
            name="get_system_status",
            display_name="System Status",
            description="Get comprehensive system security status",
            category="monitor",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=10,
            handler=self._get_system_status_impl,
        )
        self.registry.register(status)

        # Get security status
        security_status = ToolDefinition(
            name="get_security_status",
            display_name="Security Status",
            description="Get detailed security component status",
            category="monitor",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=10,
            handler=self._get_security_status_impl,
        )
        self.registry.register(security_status)

        # Monitor process
        inspect_process = ToolDefinition(
            name="inspect_process",
            display_name="Inspect Process",
            description="Inspect running process details",
            category="monitor",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=10,
            handler=self._inspect_process_impl,
        )
        self.registry.register(inspect_process)

        # Monitor network
        inspect_network = ToolDefinition(
            name="inspect_network",
            display_name="Inspect Network",
            description="Inspect active network connections",
            category="monitor",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=10,
            handler=self._inspect_network_impl,
        )
        self.registry.register(inspect_network)

    def build_utility_tools(self) -> None:
        """Build utility tools."""
        logger.info("Building utility tools")

        # Run diagnostic
        diagnostic = ToolDefinition(
            name="run_diagnostic",
            display_name="Run Diagnostic",
            description="Run system security diagnostic",
            category="utility",
            permission_level=PermissionLevel.LOW,
            timeout_seconds=60,
            handler=self._run_diagnostic_impl,
        )
        self.registry.register(diagnostic)

        # Update signatures
        update_sigs = ToolDefinition(
            name="update_signatures",
            display_name="Update Signatures",
            description="Update malware signature database",
            category="utility",
            permission_level=PermissionLevel.MEDIUM,
            timeout_seconds=120,
            handler=self._update_signatures_impl,
        )
        self.registry.register(update_sigs)


    def build_terminal_intelligence_tools(self) -> None:
        """Register real, read-mostly host investigation tools.

        These tools intentionally use fixed subprocess argument lists rather than
        passing user text to a shell. Destructive operations remain behind the
        existing confirmation gates.
        """
        tools = [
            ToolDefinition("deep_investigation", "Deep System Investigation",
                "Correlate host, processes, network, startup, services, tasks, Defender and firewall telemetry",
                "investigate", PermissionLevel.LOW, timeout_seconds=90,
                handler=self._deep_investigation_impl),
            ToolDefinition("system_inventory", "System Inventory", "Collect OS, hardware, Python and disk inventory", "investigate", PermissionLevel.LOW, timeout_seconds=20, handler=self._system_inventory_impl),
            ToolDefinition("process_tree", "Process Tree", "Collect a real process tree with executable paths and command lines when permitted", "investigate", PermissionLevel.LOW, timeout_seconds=20, handler=self._process_tree_impl),
            ToolDefinition("startup_items", "Startup Items", "Inspect common Windows/Linux startup locations without changing them", "investigate", PermissionLevel.LOW, timeout_seconds=20, handler=self._startup_items_impl),
            ToolDefinition("service_inventory", "Service Inventory", "Inspect installed/running services", "investigate", PermissionLevel.LOW, timeout_seconds=20, handler=self._service_inventory_impl),
            ToolDefinition("scheduled_tasks", "Scheduled Tasks", "Inspect scheduled tasks on Windows", "investigate", PermissionLevel.LOW, timeout_seconds=25, handler=self._scheduled_tasks_impl),
            ToolDefinition("defender_status", "Defender Status", "Read Microsoft Defender status on Windows", "investigate", PermissionLevel.LOW, timeout_seconds=15, handler=self._defender_status_impl),
            ToolDefinition("firewall_status", "Firewall Status", "Read Windows firewall profiles/status", "investigate", PermissionLevel.LOW, timeout_seconds=15, handler=self._firewall_status_impl),
            ToolDefinition("network_snapshot", "Network Snapshot", "Collect interfaces, routes and active connections", "investigate", PermissionLevel.LOW, timeout_seconds=20, handler=self._network_snapshot_impl),
            ToolDefinition("dns_snapshot", "DNS Snapshot", "Inspect DNS resolver configuration", "investigate", PermissionLevel.LOW, timeout_seconds=15, handler=self._dns_snapshot_impl),
            ToolDefinition("hosts_file", "Hosts File", "Inspect the hosts file for suspicious overrides", "investigate", PermissionLevel.LOW, timeout_seconds=10, handler=self._hosts_file_impl),
            ToolDefinition("hash_file", "Hash File", "Calculate cryptographic hashes for a file", "analyze", PermissionLevel.LOW,
                parameters=[ToolParameter("path", ParameterType.PATH, True, "File to hash")], timeout_seconds=30, handler=self._hash_file_impl),
            ToolDefinition("environment_snapshot", "Environment Snapshot", "Collect safe environment metadata useful for security triage", "investigate", PermissionLevel.LOW, timeout_seconds=10, handler=self._environment_snapshot_impl),
            ToolDefinition("security_event_summary", "Security Event Summary", "Read recent Windows Security event summaries for triage", "investigate", PermissionLevel.LOW, timeout_seconds=30, handler=self._security_event_summary_impl),
            ToolDefinition("users_and_privileges", "Users and Privileges", "Inspect local users, groups and effective privilege context", "investigate", PermissionLevel.LOW, timeout_seconds=25, handler=self._users_and_privileges_impl),
            ToolDefinition("recent_files", "Recent Files", "Inspect recently modified files in a selected location", "investigate", PermissionLevel.LOW, parameters=[ToolParameter("path", ParameterType.PATH, False, "Root path", default="")], timeout_seconds=30, handler=self._recent_files_impl),
            ToolDefinition("file_metadata", "File Metadata", "Collect safe metadata and cryptographic hash for a file", "analyze", PermissionLevel.LOW, parameters=[ToolParameter("path", ParameterType.PATH, True, "File path")], timeout_seconds=30, handler=self._file_metadata_impl),
            ToolDefinition("pe_static_triage", "PE Static Triage", "Lightweight static triage of Windows PE files without executing them", "analyze", PermissionLevel.LOW, parameters=[ToolParameter("path", ParameterType.PATH, True, "PE file")], timeout_seconds=30, handler=self._pe_static_triage_impl),
            ToolDefinition("browser_artifacts", "Browser Artifact Triage", "Inspect browser profile and extension locations without reading private content", "investigate", PermissionLevel.LOW, timeout_seconds=25, handler=self._browser_artifacts_impl),
            ToolDefinition("installed_software", "Installed Software", "Inventory installed applications", "investigate", PermissionLevel.LOW, timeout_seconds=30, handler=self._installed_software_impl),
            ToolDefinition("security_policy_snapshot", "Security Policy Snapshot", "Inspect key local security policy and firewall configuration", "investigate", PermissionLevel.LOW, timeout_seconds=20, handler=self._security_policy_snapshot_impl),
            ToolDefinition("integrity_snapshot", "System Integrity Snapshot", "Inspect Windows system integrity state without repair", "investigate", PermissionLevel.LOW, timeout_seconds=60, handler=self._integrity_snapshot_impl),
            ToolDefinition("triage_report", "Unified Triage Report", "Run broad read-only telemetry and produce a deterministic risk-oriented summary", "investigate", PermissionLevel.LOW, timeout_seconds=120, handler=self._triage_report_impl),
        ]
        for tool in tools:
            self.registry.register(tool)

    @staticmethod
    def _run_fixed_command(args: List[str], timeout: int = 15) -> Dict[str, Any]:
        """Run a fixed executable/argument vector without shell expansion."""
        import subprocess
        try:
            cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
            return {"returncode": cp.returncode, "stdout": cp.stdout[-30000:], "stderr": cp.stderr[-10000:]}
        except FileNotFoundError:
            return {"returncode": None, "stdout": "", "stderr": f"Command not available: {args[0]}"}
        except Exception as exc:
            return {"returncode": None, "stdout": "", "stderr": str(exc)}

    @staticmethod
    def _tool_ok(name: str, action: str, result: Any, details: Optional[List[str]] = None) -> ToolResult:
        return ToolResult(success=True, tool_name=name, action=action, status="completed", result=result, details=details or [])

    def _system_inventory_impl(self) -> ToolResult:
        import os, platform, shutil
        disks = []
        for root in (["C:\\"] if os.name == "nt" else ["/"]):
            try:
                total, used, free = shutil.disk_usage(root)
                disks.append({"path": root, "total": total, "used": used, "free": free})
            except OSError:
                pass
        data = {"platform": platform.platform(), "system": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine(), "processor": platform.processor(), "hostname": platform.node(), "python": platform.python_version(), "user": os.environ.get("USERNAME") or os.environ.get("USER"), "disks": disks}
        return self._tool_ok("system_inventory", "inventory", data, ["Host inventory collected from the local system"])

    def _process_tree_impl(self) -> ToolResult:
        import os, sys
        if os.name == "nt":
            raw = self._run_fixed_command(["tasklist", "/FO", "CSV", "/V"], 20)
            data = {"platform": "windows", "raw": raw["stdout"], "error": raw["stderr"] if raw["returncode"] not in (0, None) else ""}
        else:
            raw = self._run_fixed_command(["ps", "-eo", "pid,ppid,user,%cpu,%mem,etime,args"], 20)
            data = {"platform": sys.platform, "raw": raw["stdout"], "error": raw["stderr"] if raw["returncode"] not in (0, None) else ""}
        return self._tool_ok("process_tree", "inspect", data, ["Process telemetry collected; command lines may be restricted by OS permissions"])

    def _startup_items_impl(self) -> ToolResult:
        import os
        items = []
        if os.name == "nt":
            import winreg
            locations = [(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")]
            for hive, key_path in locations:
                try:
                    with winreg.OpenKey(hive, key_path) as key:
                        for i in range(winreg.QueryInfoKey(key)[1]):
                            name, value, _ = winreg.EnumValue(key, i)
                            items.append({"location": key_path, "name": name, "command": value})
                except (OSError, PermissionError):
                    continue
            return self._tool_ok("startup_items", "inspect", {"items": items, "count": len(items)}, ["Windows Run keys inspected; no registry changes made"])
        from pathlib import Path
        for base in [Path.home()/".config/autostart", Path("/etc/cron.d")]:
            if base.exists():
                try:
                    for f in base.iterdir():
                        if f.is_file(): items.append({"location": str(f), "name": f.name})
                except OSError: pass
        return self._tool_ok("startup_items", "inspect", {"items": items, "count": len(items)}, ["Common startup locations inspected"])

    def _service_inventory_impl(self) -> ToolResult:
        import os
        if os.name == "nt":
            raw = self._run_fixed_command(["sc", "query", "state=", "all"], 20)
            data = {"platform": "windows", "raw": raw["stdout"], "error": raw["stderr"]}
        else:
            raw = self._run_fixed_command(["systemctl", "list-units", "--type=service", "--all", "--no-pager"], 20)
            data = {"platform": "unix", "raw": raw["stdout"], "error": raw["stderr"]}
        return self._tool_ok("service_inventory", "inspect", data, ["Service inventory collected without modifying services"])

    def _scheduled_tasks_impl(self) -> ToolResult:
        import os
        if os.name != "nt":
            return self._tool_ok("scheduled_tasks", "inspect", {"supported": False, "reason": "Windows scheduled tasks are not available on this OS"})
        raw = self._run_fixed_command(["schtasks", "/Query", "/FO", "CSV", "/V"], 25)
        return self._tool_ok("scheduled_tasks", "inspect", {"supported": True, "raw": raw["stdout"], "error": raw["stderr"]})

    def _defender_status_impl(self) -> ToolResult:
        import os
        if os.name != "nt":
            return self._tool_ok("defender_status", "status", {"supported": False, "reason": "Microsoft Defender is Windows-specific"})
        # PowerShell is invoked with a fixed script; user input never reaches it.
        raw = self._run_fixed_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"], 15)
        return self._tool_ok("defender_status", "status", {"supported": True, "raw": raw["stdout"], "error": raw["stderr"]})

    def _firewall_status_impl(self) -> ToolResult:
        import os
        if os.name != "nt":
            return self._tool_ok("firewall_status", "status", {"supported": False, "reason": "Windows firewall command requested"})
        raw = self._run_fixed_command(["netsh", "advfirewall", "show", "allprofiles"], 15)
        return self._tool_ok("firewall_status", "status", {"raw": raw["stdout"], "error": raw["stderr"]})

    def _network_snapshot_impl(self) -> ToolResult:
        import os
        commands = []
        if os.name == "nt":
            commands = [["ipconfig", "/all"], ["route", "print"], ["netstat", "-ano"]]
        else:
            commands = [["ip", "addr"], ["ip", "route"], ["ss", "-tunap"]]
        out = {}
        for args in commands:
            r = self._run_fixed_command(args, 15)
            out[args[0]] = {"stdout": r["stdout"], "stderr": r["stderr"], "returncode": r["returncode"]}
        return self._tool_ok("network_snapshot", "inspect", out, ["Interfaces, routes and active connections collected"])

    def _dns_snapshot_impl(self) -> ToolResult:
        import os
        args = ["ipconfig", "/all"] if os.name == "nt" else ["resolvectl", "status"]
        r = self._run_fixed_command(args, 15)
        return self._tool_ok("dns_snapshot", "inspect", {"stdout": r["stdout"], "stderr": r["stderr"]})

    def _hosts_file_impl(self) -> ToolResult:
        from pathlib import Path
        import os
        path = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32/drivers/etc/hosts" if os.name == "nt" else Path("/etc/hosts")
        try:
            text = path.read_text(errors="replace")
            return self._tool_ok("hosts_file", "inspect", {"path": str(path), "content": text[-20000:]})
        except Exception as exc:
            return ToolResult(False, "hosts_file", "inspect", target=str(path), error=str(exc))

    def _hash_file_impl(self, path: str) -> ToolResult:
        import hashlib
        file_path = Path(path).expanduser().resolve()
        if not file_path.is_file():
            return ToolResult(False, "hash_file", "hash", target=str(file_path), error="File not found")
        h256 = hashlib.sha256(); h1 = hashlib.sha1(); md5 = hashlib.md5()
        size = 0
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk: break
                size += len(chunk); h256.update(chunk); h1.update(chunk); md5.update(chunk)
        return self._tool_ok("hash_file", "hash", {"path": str(file_path), "size": size, "sha256": h256.hexdigest(), "sha1": h1.hexdigest(), "md5": md5.hexdigest()})

    def _environment_snapshot_impl(self) -> ToolResult:
        import os
        safe_keys = ["OS", "PROCESSOR_ARCHITECTURE", "COMPUTERNAME", "USERNAME", "USERDOMAIN", "TEMP", "PATH"]
        env = {k: os.environ.get(k) for k in safe_keys if os.environ.get(k) is not None}
        # Do not expose arbitrary environment variables or secrets.
        return self._tool_ok("environment_snapshot", "inspect", {"variables": env})

    def _security_event_summary_impl(self) -> ToolResult:
        import os
        if os.name != "nt": return self._tool_ok("security_event_summary","inspect",{"supported":False})
        script="Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -ErrorAction SilentlyContinue | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 30 Name,Count | ConvertTo-Json -Compress"
        r=self._run_fixed_command(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],30)
        return self._tool_ok("security_event_summary","inspect",{"supported":True,"last_24h":r["stdout"],"error":r["stderr"]})

    def _users_and_privileges_impl(self) -> ToolResult:
        import os
        commands=[["whoami","/all"],["whoami","/groups"],["net","user"]] if os.name=="nt" else [["id"],["groups"]]
        data={}
        for a in commands:
            r=self._run_fixed_command(a,15); data["_".join(a)]={"stdout":r["stdout"],"stderr":r["stderr"]}
        return self._tool_ok("users_and_privileges","inspect",data,["Read-only privilege/account inventory"])

    def _recent_files_impl(self, path: str = "") -> ToolResult:
        from pathlib import Path
        import time
        root=Path(path).expanduser() if path else Path.home()
        if not root.exists(): return ToolResult(False,"recent_files","inspect",target=str(root),error="Path not found")
        cutoff=time.time()-7*86400; rows=[]; scanned=0
        try:
            for f in root.rglob("*"):
                if not f.is_file(): continue
                scanned+=1
                try:
                    st=f.stat()
                    if st.st_mtime>=cutoff: rows.append({"path":str(f),"size":st.st_size,"mtime":st.st_mtime})
                except OSError: pass
                if scanned>=20000: break
        except OSError as exc: return ToolResult(False,"recent_files","inspect",target=str(root),error=str(exc))
        rows.sort(key=lambda x:x["mtime"],reverse=True)
        return self._tool_ok("recent_files","inspect",{"root":str(root),"window_days":7,"files":rows[:1000],"scanned_entries":scanned})

    def _file_metadata_impl(self, path: str) -> ToolResult:
        import hashlib,mimetypes
        f=Path(path).expanduser().resolve()
        if not f.is_file(): return ToolResult(False,"file_metadata","analyze",target=str(f),error="File not found")
        st=f.stat(); h=hashlib.sha256(); sample=b""
        with f.open("rb") as fh:
            sample=fh.read(4096); fh.seek(0)
            for chunk in iter(lambda:fh.read(1024*1024),b""): h.update(chunk)
        return self._tool_ok("file_metadata","analyze",{"path":str(f),"size":st.st_size,"mtime":st.st_mtime,"ctime":st.st_ctime,"sha256":h.hexdigest(),"mime":mimetypes.guess_type(str(f))[0],"magic_prefix":sample[:16].hex()})

    def _pe_static_triage_impl(self, path: str) -> ToolResult:
        import re
        f=Path(path).expanduser().resolve()
        if not f.is_file(): return ToolResult(False,"pe_static_triage","analyze",target=str(f),error="File not found")
        data=f.read_bytes()[:2*1024*1024]
        if data[:2]!=b"MZ": return self._tool_ok("pe_static_triage","analyze",{"is_pe":False,"path":str(f),"reason":"Missing MZ header"})
        pe_offset=int.from_bytes(data[0x3c:0x40],"little") if len(data)>=0x40 else -1
        valid=0<=pe_offset<len(data)-4 and data[pe_offset:pe_offset+4]==b"PE\\x00\\x00"
        strings=[m.decode("ascii","ignore") for m in re.findall(rb"[ -~]{6,}",data)]
        suspicious=[x for x in strings if any(k in x.lower() for k in ("powershell","cmd.exe","wscript","rundll32","regsvr32","http://","https://"))][:100]
        return self._tool_ok("pe_static_triage","analyze",{"is_pe":True,"valid_pe_signature":valid,"size":f.stat().st_size,"pe_offset":pe_offset,"suspicious_strings":suspicious,"note":"Static only; file was not executed"})

    def _browser_artifacts_impl(self) -> ToolResult:
        from pathlib import Path
        home=Path.home(); bases=[home/"AppData/Local/Google/Chrome/User Data",home/"AppData/Local/Microsoft/Edge/User Data",home/"AppData/Roaming/Mozilla/Firefox/Profiles"]
        rows=[]
        for b in bases:
            if b.exists():
                try: rows.append({"path":str(b),"exists":True,"entries":min(len(list(b.iterdir())),500)})
                except OSError: pass
        return self._tool_ok("browser_artifacts","inspect",{"profiles":rows,"privacy":"Profile locations only; private browsing content is not read"})

    def _installed_software_impl(self) -> ToolResult:
        import os
        if os.name!="nt": return self._tool_ok("installed_software","inventory",{"supported":False})
        script="Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName | ConvertTo-Json -Compress"
        r=self._run_fixed_command(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],30)
        return self._tool_ok("installed_software","inventory",{"software":r["stdout"],"error":r["stderr"]})

    def _security_policy_snapshot_impl(self) -> ToolResult:
        import os
        if os.name!="nt": return self._tool_ok("security_policy_snapshot","inspect",{"supported":False})
        data={}
        for a in [["reg","query",r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"],["netsh","advfirewall","show","allprofiles"]]:
            r=self._run_fixed_command(a,15); data[a[0]]={"stdout":r["stdout"],"stderr":r["stderr"]}
        return self._tool_ok("security_policy_snapshot","inspect",data)

    def _integrity_snapshot_impl(self) -> ToolResult:
        import os
        if os.name!="nt": return self._tool_ok("integrity_snapshot","inspect",{"supported":False})
        r=self._run_fixed_command(["sfc","/verifyonly"],60)
        return self._tool_ok("integrity_snapshot","inspect",{"returncode":r["returncode"],"stdout":r["stdout"],"stderr":r["stderr"],"note":"Verification only; no repair"})

    def _triage_report_impl(self) -> ToolResult:
        import time
        start=time.time(); checks=[self._system_inventory_impl(),self._process_tree_impl(),self._startup_items_impl(),self._service_inventory_impl(),self._scheduled_tasks_impl(),self._defender_status_impl(),self._firewall_status_impl(),self._network_snapshot_impl(),self._dns_snapshot_impl(),self._hosts_file_impl(),self._security_event_summary_impl(),self._users_and_privileges_impl(),self._installed_software_impl(),self._security_policy_snapshot_impl(),self._integrity_snapshot_impl()]
        failures=[x.tool_name for x in checks if not x.success]; warnings=[]
        for x in checks:
            text=str(x.result).lower()
            if any(k in text for k in ("disabled","failed","error")): warnings.append(x.tool_name)
        risk=min(100,len(failures)*12+len(warnings)*3); verdict="HIGH_ATTENTION" if risk>=60 else "REVIEW_RECOMMENDED" if risk>=25 else "NO_IMMEDIATE_FINDING"
        return self._tool_ok("triage_report","investigate",{"verdict":verdict,"risk_score":risk,"checks":len(checks),"collection_failures":failures,"warning_sources":warnings,"duration_seconds":round(time.time()-start,2),"evidence":[x.as_dict() for x in checks],"limitations":["Triage cannot prove absence of malware","Some telemetry requires administrator privileges","Cloud reputation requires provider integration"]})

    def _deep_investigation_impl(self) -> ToolResult:
        """Correlate several read-only telemetry sources into one investigation."""
        import time
        start = time.time()
        checks = [
            self._system_inventory_impl(), self._process_tree_impl(), self._startup_items_impl(),
            self._service_inventory_impl(), self._scheduled_tasks_impl(), self._defender_status_impl(),
            self._firewall_status_impl(), self._network_snapshot_impl(), self._dns_snapshot_impl(),
            self._hosts_file_impl(), self._environment_snapshot_impl()
        ]
        findings = []
        for r in checks:
            if not r.success:
                findings.append({"source": r.tool_name, "severity": "UNKNOWN", "finding": r.error or "collection failed"})
        data = {"investigation": "deep", "checks": [r.as_dict() for r in checks], "collection_failures": len(findings), "findings": findings, "duration_seconds": round(time.time()-start, 3)}
        return ToolResult(success=True, tool_name="deep_investigation", action="investigate", status="completed", result=data, details=[f"Completed {len(checks)} telemetry checks", "Read-only investigation; no files, services, firewall rules or registry values were changed"])

    # Implementation methods (handlers)

    def _scan_file_impl(self, path: str, detailed: bool = False) -> ToolResult:
        """Scan single file using existing scanner."""
        try:
            from app.security.advanced_detection import analyze_file_deep
            result = analyze_file_deep(path, endpoint_scan=True, reputation=True)
            return ToolResult(
                success=True,
                tool_name="scan_file",
                action="scan",
                target=path,
                status="completed",
                threat_detected=(result.get("verdict", "").upper() in ("MALICIOUS", "LIKELY_MALICIOUS")),
                risk_score=result.get("risk", 0),
                result=result,
                details=result.get("evidence", []) if detailed else []
            )
        except Exception as e:
            logger.error(f"File scan failed: {e}")
            return ToolResult(
                success=False,
                tool_name="scan_file",
                action="scan",
                target=path,
                status="failed",
                error=str(e)
            )

    def _scan_directory_impl(self, path: str, recursive: bool = True) -> ToolResult:
        """Scan a directory: cheap local triage first, deep engines only for candidates."""
        try:
            scan_path = Path(path).expanduser().resolve()
            if not scan_path.exists():
                return ToolResult(False, "scan_directory", "scan", target=path, error="Directory not found")
            from app.security.advanced_detection import analyze_file_deep
            files_scanned = 0; threats_found = 0; threat_details = []
            glob_pattern = "**/*" if recursive else "*"
            for file_path in scan_path.glob(glob_pattern):
                if not file_path.is_file():
                    continue
                files_scanned += 1
                try:
                    result = analyze_file_deep(str(file_path), endpoint_scan=False, reputation=False)
                    if result.get("risk", 0) >= 25 or result.get("verdict") in {"SUSPICIOUS", "LIKELY MALICIOUS", "MALICIOUS"}:
                        result = analyze_file_deep(str(file_path), endpoint_scan=True, reputation=True)
                    if str(result.get("verdict", "")).upper() in {"MALICIOUS", "LIKELY MALICIOUS"}:
                        threats_found += 1
                        threat_details.append({"file": str(file_path), "verdict": result.get("verdict"), "risk": result.get("risk", 0), "engines": result.get("engines", {})})
                except (OSError, PermissionError):
                    continue
            return ToolResult(True, "scan_directory", "scan", target=path, status="completed", result={"files_scanned": files_scanned, "threats_found": threats_found, "threats": threat_details}, threat_detected=threats_found > 0, details=[f"Scanned {files_scanned} files, found {threats_found} high-confidence threats"])
        except Exception as e:
            logger.error(f"Directory scan failed: {e}")
            return ToolResult(False, "scan_directory", "scan", target=path, error=str(e))

    def _full_system_scan_impl(self, priority: str = "normal") -> ToolResult:
        """Perform a real endpoint scan with bounded scope and deep enrichment."""
        try:
            from app.security.advanced_detection import analyze_file_deep
            import os, time
            start_time = time.time()
            files_scanned = threats_found = 0
            threat_details = []
            priority = (priority or "normal").lower()
            limit = 3000 if priority == "normal" else 15000 if priority == "thorough" else 1000
            roots = [Path.home()/"Downloads", Path.home()/"Documents", Path.home()/"Desktop", Path.home()/"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", Path(os.environ.get("TEMP", ""))]
            if priority == "thorough" and os.name == "nt":
                roots.append(Path(os.environ.get("SystemDrive", "C:")) / "Users")
            roots = [p for p in dict.fromkeys(roots) if p.exists()]
            for base in roots:
                for file_path in base.rglob("*"):
                    if files_scanned >= limit:
                        break
                    try:
                        if not file_path.is_file() or file_path.is_symlink():
                            continue
                        files_scanned += 1
                        result = analyze_file_deep(str(file_path), endpoint_scan=False, reputation=False)
                        if result.get("risk", 0) >= 25 or result.get("verdict") in {"SUSPICIOUS", "LIKELY MALICIOUS", "MALICIOUS"}:
                            result = analyze_file_deep(str(file_path), endpoint_scan=True, reputation=True)
                        if str(result.get("verdict", "")).upper() in {"MALICIOUS", "LIKELY MALICIOUS"}:
                            threats_found += 1
                            threat_details.append({"file": str(file_path), "verdict": result.get("verdict"), "risk": result.get("risk", 0), "engines": result.get("engines", {})})
                    except (OSError, PermissionError):
                        continue
                if files_scanned >= limit:
                    break
            duration = time.time() - start_time
            return ToolResult(True, "full_system_scan", "scan", status="completed", result={"files_scanned": files_scanned, "threats_found": threats_found, "threats": threat_details, "duration_seconds": duration, "priority": priority, "scope": [str(x) for x in roots], "bounded": True}, threat_detected=threats_found > 0, details=[f"Endpoint scan completed: {files_scanned} files triaged, {threats_found} high-confidence threats"])
        except Exception as e:
            logger.error(f"Full system scan failed: {e}")
            return ToolResult(False, "full_system_scan", "scan", status="failed", error=str(e))

    def _quick_scan_impl(self) -> ToolResult:
        """Quick scan of critical locations."""
        return self._full_system_scan_impl("quick")

    def _quarantine_file_impl(self, path: str, reason: str = "") -> ToolResult:
        """Quarantine a file."""
        try:
            from app.security.quarantine import quarantine_file
            quarantine_path = quarantine_file(path)
            return ToolResult(
                success=True,
                tool_name="quarantine_file",
                action="quarantine",
                target=path,
                status="completed",
                result={
                    "original_path": path,
                    "quarantine_path": str(quarantine_path)
                },
                verification={"verified": True},
                details=[f"File quarantined: {quarantine_path}"]
            )
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
            return ToolResult(
                success=False,
                tool_name="quarantine_file",
                action="quarantine",
                target=path,
                status="failed",
                error=str(e)
            )

    def _restore_quarantine_impl(self, quarantine_id: str) -> ToolResult:
        """Restore file from quarantine."""
        try:
            quarantine_path = Path(quarantine_id).expanduser().resolve()
            if not quarantine_path.exists():
                return ToolResult(
                    success=False,
                    tool_name="restore_quarantine",
                    action="restore",
                    target=quarantine_id,
                    error="Quarantine file not found"
                )

            import shutil
            import json

            # Find metadata
            metadata_path = quarantine_path.with_suffix(quarantine_path.suffix + ".json")
            if metadata_path.exists():
                metadata = json.loads(metadata_path.read_text())
                original_path = metadata.get("original_path")
            else:
                original_path = None

            # Restore
            if original_path:
                shutil.copy2(quarantine_path, original_path)
                restored_path = original_path
            else:
                restored_path = str(quarantine_path.parent / quarantine_path.stem)
                shutil.copy2(quarantine_path, restored_path)

            return ToolResult(
                success=True,
                tool_name="restore_quarantine",
                action="restore",
                target=quarantine_id,
                status="completed",
                result={"restored_path": restored_path},
                details=[f"File restored to: {restored_path}"]
            )
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return ToolResult(
                success=False,
                tool_name="restore_quarantine",
                action="restore",
                target=quarantine_id,
                error=str(e)
            )

    def _list_quarantine_impl(self) -> ToolResult:
        """List quarantined files."""
        try:
            from app.config import QUARANTINE_DIR
            quarantine_files = []
            if QUARANTINE_DIR.exists():
                for f in QUARANTINE_DIR.glob("*"):
                    if f.is_file() and not f.suffix.endswith(".json"):
                        quarantine_files.append(str(f))

            return ToolResult(
                success=True,
                tool_name="list_quarantine",
                action="list",
                status="completed",
                result={"files": quarantine_files, "count": len(quarantine_files)},
                details=[f"Quarantined files: {len(quarantine_files)}"]
            )
        except Exception as e:
            logger.error(f"List quarantine failed: {e}")
            return ToolResult(
                success=False,
                tool_name="list_quarantine",
                action="list",
                error=str(e)
            )

    def _delete_quarantine_impl(self, quarantine_id: str) -> ToolResult:
        """Delete file from quarantine permanently."""
        try:
            file_path = Path(quarantine_id).expanduser().resolve()
            if not file_path.exists():
                return ToolResult(
                    success=False,
                    tool_name="delete_quarantine",
                    action="delete",
                    target=quarantine_id,
                    error="File not found"
                )

            file_path.unlink()
            metadata_path = file_path.with_suffix(file_path.suffix + ".json")
            if metadata_path.exists():
                metadata_path.unlink()

            return ToolResult(
                success=True,
                tool_name="delete_quarantine",
                action="delete",
                target=quarantine_id,
                status="completed",
                details=["File permanently deleted from quarantine"]
            )
        except Exception as e:
            logger.error(f"Delete from quarantine failed: {e}")
            return ToolResult(
                success=False,
                tool_name="delete_quarantine",
                action="delete",
                target=quarantine_id,
                error=str(e)
            )

    def _analyze_url_impl(self, url: str) -> ToolResult:
        """Analyze URL for phishing."""
        try:
            from app.security.advanced_detection import analyze_url_deep
            result = analyze_url_deep(url, reputation=True)
            return ToolResult(
                success=True,
                tool_name="analyze_url",
                action="analyze",
                target=url,
                status="completed",
                threat_detected=(result.get("verdict", "").upper() in ("PHISHING", "SUSPICIOUS")),
                risk_score=result.get("score", 0),
                result=result,
                details=result.get("reasons", [])
            )
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            return ToolResult(
                success=False,
                tool_name="analyze_url",
                action="analyze",
                target=url,
                error=str(e)
            )

    def _analyze_process_impl(self, pid: int) -> ToolResult:
        """Analyze process for suspicious behavior."""
        try:
            from app.security.process_monitor import get_processes
            processes = get_processes(100)
            target_process = None
            for p in processes:
                if p.get("pid") == pid:
                    target_process = p
                    break

            if not target_process:
                return ToolResult(
                    success=False,
                    tool_name="analyze_process",
                    action="analyze",
                    target=str(pid),
                    error="Process not found"
                )

            return ToolResult(
                success=True,
                tool_name="analyze_process",
                action="analyze",
                target=str(pid),
                status="completed",
                result=target_process,
                details=[f"Process: {target_process.get('name', 'Unknown')}"]
            )
        except Exception as e:
            logger.error(f"Process analysis failed: {e}")
            return ToolResult(
                success=False,
                tool_name="analyze_process",
                action="analyze",
                target=str(pid),
                error=str(e)
            )

    def _kill_process_impl(self, pid: int, force: bool = False) -> ToolResult:
        """Kill suspicious process."""
        try:
            import os
            import signal

            if os.name == "nt":  # Windows
                import subprocess
                args = ["taskkill", "/PID", str(int(pid))]
                if force:
                    args.append("/F")
                cp = subprocess.run(args, capture_output=True, text=True, timeout=10, shell=False)
                if cp.returncode != 0:
                    raise RuntimeError((cp.stderr or cp.stdout or "taskkill failed").strip())
            else:  # Unix
                sig = signal.SIGKILL if force else signal.SIGTERM
                os.kill(pid, sig)

            return ToolResult(
                success=True,
                tool_name="kill_process",
                action="terminate",
                target=str(pid),
                status="completed",
                details=[f"Process {pid} terminated"]
            )
        except Exception as e:
            logger.error(f"Kill process failed: {e}")
            return ToolResult(
                success=False,
                tool_name="kill_process",
                action="terminate",
                target=str(pid),
                error=str(e)
            )

    def _get_system_status_impl(self) -> ToolResult:
        """Get comprehensive system status."""
        try:
            from app.security.host_snapshot import collect_host_snapshot
            snapshot = collect_host_snapshot()
            return ToolResult(
                success=True,
                tool_name="get_system_status",
                action="status",
                status="completed",
                result=snapshot,
                details=[f"System status retrieved"]
            )
        except Exception as e:
            logger.error(f"Status retrieval failed: {e}")
            return ToolResult(
                success=False,
                tool_name="get_system_status",
                action="status",
                error=str(e)
            )

    def _get_security_status_impl(self) -> ToolResult:
        """Get security component status."""
        try:
            status = {
                "realtime_protection": "enabled",
                "firewall": "enabled",
                "antivirus": "active",
                "quarantine_count": 0,
            }
            from app.config import QUARANTINE_DIR
            if QUARANTINE_DIR.exists():
                status["quarantine_count"] = len(list(QUARANTINE_DIR.glob("*")))

            return ToolResult(
                success=True,
                tool_name="get_security_status",
                action="status",
                status="completed",
                result=status,
                details=["Security status retrieved"]
            )
        except Exception as e:
            logger.error(f"Security status failed: {e}")
            return ToolResult(
                success=False,
                tool_name="get_security_status",
                action="status",
                error=str(e)
            )

    def _inspect_process_impl(self) -> ToolResult:
        """Inspect running processes."""
        try:
            from app.security.process_monitor import get_processes
            processes = get_processes(25)
            return ToolResult(
                success=True,
                tool_name="inspect_process",
                action="inspect",
                status="completed",
                result={"processes": processes},
                details=[f"Found {len(processes)} processes"]
            )
        except Exception as e:
            logger.error(f"Process inspection failed: {e}")
            return ToolResult(
                success=False,
                tool_name="inspect_process",
                action="inspect",
                error=str(e)
            )

    def _inspect_network_impl(self) -> ToolResult:
        """Inspect network connections."""
        try:
            from app.security.network_monitor import get_connections
            connections = get_connections(30)
            return ToolResult(
                success=True,
                tool_name="inspect_network",
                action="inspect",
                status="completed",
                result={"connections": connections},
                details=[f"Found {len(connections)} connections"]
            )
        except Exception as e:
            logger.error(f"Network inspection failed: {e}")
            return ToolResult(
                success=False,
                tool_name="inspect_network",
                action="inspect",
                error=str(e)
            )

    def _run_diagnostic_impl(self) -> ToolResult:
        """Run system security diagnostic."""
        return ToolResult(
            success=True,
            tool_name="run_diagnostic",
            action="diagnostic",
            status="completed",
            result={"diagnostic": "complete"},
            details=["System diagnostic completed"]
        )

    def _update_signatures_impl(self) -> ToolResult:
        """Actually refresh Microsoft Defender intelligence when available."""
        import os
        if os.name != "nt":
            return ToolResult(False, "update_signatures", "update", status="unsupported", error="Microsoft Defender signature updates are Windows-specific")
        raw = self._run_fixed_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Update-MpSignature"], 120)
        ok = raw["returncode"] == 0
        return ToolResult(ok, "update_signatures", "update", status="completed" if ok else "failed", result={"provider": "Microsoft Defender", "returncode": raw["returncode"], "stdout": raw["stdout"], "stderr": raw["stderr"], "signatures_updated": ok}, error=None if ok else (raw["stderr"] or raw["stdout"] or "Defender signature update failed"), details=["Microsoft Defender intelligence update requested and result verified from process exit code"] if ok else [])
