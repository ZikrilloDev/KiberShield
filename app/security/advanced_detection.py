"""Multi-engine defensive detection and evidence fusion.

This module never executes samples or opens URLs as a browser. It combines
local static evidence with optional reputation/endpoint engines and reports
which engines actually produced evidence. A missing engine is UNKNOWN, never
CLEAN.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from app.security.scanner import analyze_file
from app.security.authenticode import verify_signature
from app.security.defender_scan import scan_file_with_defender
from app.security.hybrid_intel import virus_total_hash, virus_total_url
from app.security.phishing_guard import analyze_url as local_url_analysis


def _clamav_file(path: Path, timeout: int = 90) -> dict[str, Any]:
    exe = shutil.which("clamscan")
    if not exe:
        return {"available": False, "status": "UNAVAILABLE"}
    try:
        cp = subprocess.run(
            [exe, "--no-summary", "--stdout", str(path)],
            capture_output=True, text=True, timeout=timeout, shell=False,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()[-6000:]
        infected = " FOUND" in output or cp.returncode == 1
        return {"available": True, "status": "THREAT" if infected else "CLEAN" if cp.returncode == 0 else "ERROR",
                "exit_code": cp.returncode, "output": output}
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "TIMEOUT"}
    except OSError as exc:
        return {"available": True, "status": "ERROR", "error": type(exc).__name__}


def _file_score(static: dict[str, Any], signature: dict[str, Any], defender: dict[str, Any], vt: dict[str, Any], clam: dict[str, Any]) -> tuple[int, float, str, list[dict[str, Any]]]:
    score = int(static.get("risk", 0) or 0)
    evidence = list(static.get("evidence") or [])
    independent = 0
    threat_engines = 0

    if defender.get("status") == "THREAT_OR_ERROR" and defender.get("exit_code") not in (0, None):
        output = str(defender.get("output", ""))
        code = int(defender.get("exit_code") or -1)
        confirmed = code == 2 or any(x in output.lower() for x in ("threat", "detected", "malware", "found"))
        evidence.append({"code": "DEFENDER_RESULT", "severity": "critical" if confirmed else "medium", "source": "Microsoft Defender", "detail": output[-1500:], "score": 88 if confirmed else 8})
        if confirmed:
            threat_engines += 1
            independent += 1
    if clam.get("status") == "THREAT":
        evidence.append({"code": "CLAMAV_THREAT", "severity": "critical", "source": "ClamAV", "detail": clam.get("output", "")[-1000:], "score": 90})
        score = max(score, 95); threat_engines += 1; independent += 1
    if vt.get("malicious"):
        evidence.append({"code": "VT_THREAT", "severity": "critical", "source": "VirusTotal", "detail": str(vt.get("stats", {})), "score": 95})
        score = 100; threat_engines += 1; independent += 1
    if signature.get("enabled") and signature.get("status") not in {"Valid", "VALID"} and static.get("pe"):
        evidence.append({"code": "AUTHENTICODE", "severity": "medium", "source": "Windows Authenticode", "detail": signature.get("status", "UNKNOWN"), "score": 12})

    # Corroboration raises confidence only when independent engines agree.
    if threat_engines >= 2:
        score = min(100, score + 10)
    score = min(100, score)
    if score >= 85 and threat_engines >= 1:
        verdict = "MALICIOUS"
    elif score >= 70:
        verdict = "LIKELY MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif score >= 20:
        verdict = "UNKNOWN"
    else:
        verdict = "CLEAN"

    base_conf = float(static.get("confidence", .6) or .6)
    confidence = min(.995, base_conf + .08 * independent + .04 * min(len(evidence), 6))
    if vt.get("status") == "CLEAN" or defender.get("status") == "COMPLETED" or clam.get("status") == "CLEAN":
        # A clean reputation/scan does not prove safety; it only slightly improves
        # confidence in a low-risk result.
        if score < 40:
            confidence = min(.98, confidence + .02)
    return score, round(confidence, 3), verdict, evidence


def analyze_file_deep(path: str | Path, *, endpoint_scan: bool = True, reputation: bool = True) -> dict[str, Any]:
    p = Path(path).expanduser().resolve()
    static = analyze_file(p)
    signature = verify_signature(p) if static.get("pe") else {"enabled": False, "status": "NOT_APPLICABLE"}
    defender = {"available": False, "status": "SKIPPED"}
    if endpoint_scan and (static.get("pe") or p.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".msi", ".scr"} or static.get("risk", 0) >= 25):
        defender = scan_file_with_defender(p)
    vt = virus_total_hash(static.get("sha256", "")) if reputation else {"enabled": False, "status": "DISABLED", "malicious": False}
    clam = _clamav_file(p) if endpoint_scan else {"available": False, "status": "SKIPPED"}
    score, confidence, verdict, evidence = _file_score(static, signature, defender, vt, clam)
    return {
        **static,
        "risk": score,
        "verdict": verdict,
        "confidence": confidence,
        "evidence": evidence,
        "engines": {
            "static": {"status": "COMPLETED"},
            "authenticode": signature,
            "defender": defender,
            "virustotal_hash": vt,
            "clamav": clam,
        },
        "execution_performed": False,
        "engine_policy": "multi_engine_evidence_fusion",
    }


def _dns_intel(host: str) -> dict[str, Any]:
    if not host:
        return {"status": "INVALID"}
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})[:20]
        return {"status": "RESOLVED", "ips": ips}
    except (OSError, socket.gaierror) as exc:
        return {"status": "UNRESOLVED", "error": type(exc).__name__}


def analyze_url_deep(url: str, *, reputation: bool = True) -> dict[str, Any]:
    local = local_url_analysis(url)
    vt = virus_total_url(url) if reputation else {"enabled": False, "status": "DISABLED", "malicious": False}
    dns = _dns_intel(local.get("host", ""))
    score = int(local.get("score", 0) or 0)
    reasons = list(local.get("reasons") or [])
    evidence = list(local.get("evidence") or [])
    if vt.get("malicious"):
        score = 100
        reasons.append("VirusTotal URL reputation: malicious")
        evidence.append({"code": "VT_URL_THREAT", "severity": "critical", "source": "VirusTotal", "detail": str(vt.get("stats", {})), "score": 95})
    if dns.get("status") == "UNRESOLVED" and score >= 20:
        score = min(100, score + 8)
        reasons.append("Hostname DNS orqali yechilmadi")
    if local.get("reputation", {}).get("malicious"):
        score = 100
    score = min(100, score)
    verdict = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "SUSPICIOUS" if score >= 35 else "LOW"
    independent = 1 + int(bool(local.get("reputation", {}).get("malicious"))) + int(bool(vt.get("malicious")))
    confidence = min(.995, float(local.get("confidence", .6)) + .06 * independent)
    return {**local, "score": score, "verdict": verdict, "confidence": round(confidence, 3),
            "reasons": list(dict.fromkeys(reasons)), "evidence": evidence,
            "engines": {"local_heuristics": {"status": "COMPLETED"}, "google_safe_browsing": local.get("reputation", {}), "virustotal_url": vt, "dns": dns},
            "network_request_performed": bool(local.get("network_request_performed")),
            "page_opened": False, "javascript_executed": False}
