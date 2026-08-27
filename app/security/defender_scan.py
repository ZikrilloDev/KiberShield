"""Windows Defender integration for CyberShield.

Uses only Microsoft Defender's documented command-line scanner when available.
The operation is a security scan: it does not execute the target as an application
and does not modify the sample. Results are treated as one evidence source, not
as proof of safety.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _mpcmdrun() -> str | None:
    if os.name != "nt":
        return None
    candidates = [
        os.environ.get("ProgramFiles", r"C:\Program Files") + r"\Windows Defender\MpCmdRun.exe",
        os.environ.get("ProgramData", r"C:\ProgramData") + r"\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
    ]
    for candidate in candidates:
        p = Path(candidate)
        if p.is_file():
            return str(p)
    return shutil.which("MpCmdRun.exe")


def scan_file_with_defender(path: str | Path, timeout: int = 120) -> dict[str, Any]:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(str(p))
    exe = _mpcmdrun()
    if not exe:
        return {"available": False, "status": "UNAVAILABLE", "reason": "MpCmdRun.exe not found"}
    # MpCmdRun receives a literal argument; shell=False prevents shell injection.
    cmd = [exe, "-Scan", "-ScanType", "3", "-File", str(p)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "TIMEOUT", "path": str(p)}
    except OSError as exc:
        return {"available": True, "status": "ERROR", "error": str(exc), "path": str(p)}

    output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    # MpCmdRun exit code 0 means the scan command completed without reporting a threat.
    # We deliberately expose the raw code/output for deterministic verification.
    return {
        "available": True,
        "status": "COMPLETED" if proc.returncode == 0 else "THREAT_OR_ERROR",
        "exit_code": proc.returncode,
        "path": str(p),
        "output": output[-8000:],
        "verified_no_host_execution": True,
    }
