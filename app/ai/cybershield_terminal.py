"""CyberShield Security Terminal.

A deterministic, terminal-like command layer for defensive operations.
It deliberately does NOT expose arbitrary cmd.exe/PowerShell execution.
Every command maps to a bounded CyberShield security function.
"""
from __future__ import annotations

import json
import shlex
import socket
from pathlib import Path
from typing import Any

from app.ai.terminal_intelligence import inspect_host
from app.security.scanner import analyze_file, scan_directory
from app.security.advanced_detection import analyze_file_deep, analyze_url_deep
from app.security.process_monitor import get_processes
from app.security.network_monitor import get_connections, get_local_network_info
from app.security.defender_scan import scan_file_with_defender
from app.security.quarantine import quarantine_file
from app.security.lab_controller import assess_dynamic_lab_readiness
from app.security.self_diagnostics import run_self_diagnostics
from app.database.database import (
    add_scan, add_url_scan, get_recent_scans, get_recent_url_scans,
    get_recent_audit, get_incident_counts, add_audit
)
from app.i18n import terminal_tr


class CommandError(ValueError):
    pass


ALIASES = {
    "help": {"help", "yordam", "помощь", "?"},
    "status": {"status", "holat", "статус", "security-status"},
    "scan": {"scan", "tekshir", "скан", "проверить"},
    "deep-scan": {"deep-scan", "deep_scan", "chuqur-tekshir", "глубокий-скан"},
    "host": {"host", "inspect", "system", "tizim", "компьютер", "система"},
    "processes": {"processes", "process", "jarayonlar", "процессы"},
    "network": {"network", "net", "tarmoq", "сеть"},
    "services": {"services", "xizmatlar", "службы"},
    "tasks": {"tasks", "vazifalar", "задачи"},
    "defender": {"defender", "himoya", "защитник"},
    "hash": {"hash", "xesh", "хэш", "sha256"},
    "url": {"url", "fishing", "phishing", "link", "havola", "ссылка"},
    "quarantine": {"quarantine", "karantin", "карантин"},
    "lab": {"lab", "sandbox", "xavfsiz-lab", "лаборатория"},
    "diagnostics": {"diagnostics", "diag", "diagnostika", "диагностика"},
    "history": {"history", "tarix", "история"},
    "incidents": {"incidents", "hodisalar", "инциденты"},
    "clear": {"clear", "toza", "очистить"},
}


def _canonical(name: str) -> str | None:
    n = name.strip().lower()
    for command, values in ALIASES.items():
        if n in values:
            return command
    return None


def _fmt_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return str(value)


def _json(data: Any, limit: int = 12000) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    return text if len(text) <= limit else text[:limit] + "\n… output truncated"


class CyberShieldTerminal:
    """Safe command interpreter usable by the GUI and real console."""

    def __init__(self, language: str = "uz"):
        self.language = language
        self.history: list[str] = []

    def set_language(self, language: str) -> None:
        self.language = language

    def help_text(self) -> str:
        if self.language == "en":
            return (
                "CyberShield Security Terminal\n"
                "────────────────────────────────────────\n"
                "scan <file|dir>              — static malware scan\n"
                "deep-scan <file>             — deeper static + Defender/reputation checks\n"
                "hash <file>                  — SHA-256 / SHA-1 / MD5\n"
                "url <https://…>              — phishing/URL analysis; no page execution\n"
                "host                         — read-only host inventory\n"
                "processes                    — running process telemetry\n"
                "network                      — interfaces + connections\n"
                "services                     — Windows services (read-only)\n"
                "tasks                        — scheduled tasks (read-only)\n"
                "defender                     — Microsoft Defender status\n"
                "lab                          — isolated-lab readiness check\n"
                "diagnostics                  — CyberShield self-diagnostics\n"
                "incidents                    — open incident counts\n"
                "history                      — recent terminal commands\n"
                "quarantine <file> --confirm  — reversible quarantine\n"
                "status                       — security engine status\n"
                "help                         — this help\n"
                "clear                        — clear terminal output\n\n"
                "SAFE MODE: arbitrary cmd.exe / PowerShell / shell execution is blocked."
            )
        if self.language == "ru":
            return (
                "Терминал безопасности CyberShield\n"
                "────────────────────────────────────────\n"
                "скан <файл|папка>            — статический анализ\n"
                "глубокий-скан <файл>         — углублённый анализ + Defender/репутация\n"
                "хэш <файл>                   — SHA-256 / SHA-1 / MD5\n"
                "ссылка <https://…>           — анализ фишинга без открытия страницы\n"
                "система                      — инвентаризация хоста (только чтение)\n"
                "процессы                     — телеметрия процессов\n"
                "сеть                         — интерфейсы и соединения\n"
                "службы                       — службы Windows\n"
                "задачи                       — планировщик задач\n"
                "защитник                     — состояние Microsoft Defender\n"
                "лаборатория                  — проверка готовности изолированной лаборатории\n"
                "диагностика                  — самодиагностика CyberShield\n"
                "инциденты                    — открытые инциденты\n"
                "история                      — история команд\n"
                "карантин <файл> --confirm    — обратимый карантин\n"
                "статус                       — состояние движка\n"
                "помощь                       — эта справка\n"
                "очистить                     — очистить терминал\n\n"
                "БЕЗОПАСНЫЙ РЕЖИМ: произвольный CMD/PowerShell/shell заблокирован."
            )
        return (
            "CyberShield Xavfsizlik Terminali\n"
            "────────────────────────────────────────\n"
            "tekshir <fayl|papka>          — statik zararli dastur skani\n"
            "chuqur-tekshir <fayl>        — chuqur statik + Defender/reputatsiya\n"
            "xesh <fayl>                  — SHA-256 / SHA-1 / MD5\n"
            "havola <https://…>           — fishing/URL tahlili; sahifa ochilmaydi\n"
            "tizim                        — host inventarizatsiyasi (faqat o‘qish)\n"
            "jarayonlar                   — ishlayotgan jarayonlar\n"
            "tarmoq                       — interfeyslar va ulanishlar\n"
            "xizmatlar                    — Windows xizmatlari\n"
            "vazifalar                    — rejalashtirilgan vazifalar\n"
            "himoya                       — Microsoft Defender holati\n"
            "xavfsiz-lab                  — izolyatsiyalangan lab tayyorgarligi\n"
            "diagnostika                  — CyberShield o‘z-o‘zini tekshirish\n"
            "hodisalar                    — ochiq hodisalar\n"
            "tarix                        — terminal buyruqlari tarixi\n"
            "karantin <fayl> --confirm    — qaytariladigan karantin\n"
            "holat                        — xavfsizlik dvigateli holati\n"
            "yordam                       — shu yordam\n"
            "toza                         — terminalni tozalash\n\n"
            "XAVFSIZ REJIM: ixtiyoriy CMD/PowerShell/shell bajarilishi bloklangan."
        )

    def _detect_language(self, token: str) -> None:
        t = token.strip().lower()
        if t in {"tekshir", "chuqur-tekshir", "tizim", "jarayonlar", "tarmoq", "xizmatlar", "vazifalar", "himoya", "xesh", "havola", "karantin", "xavfsiz-lab", "diagnostika", "hodisalar", "tarix", "yordam", "holat", "toza"}:
            self.language = "uz"
        elif t in {"проверить", "глубокий-скан", "система", "компьютер", "процессы", "сеть", "службы", "задачи", "защитник", "хэш", "ссылка", "карантин", "лаборатория", "диагностика", "инциденты", "история", "помощь", "статус", "очистить"}:
            self.language = "ru"
        elif t in {"scan", "deep-scan", "host", "processes", "network", "services", "tasks", "defender", "hash", "url", "quarantine", "lab", "diagnostics", "incidents", "history", "help", "status", "clear", "inspect", "system", "net", "link", "phishing", "sandbox"}:
            self.language = "en"

    def execute(self, line: str) -> str:
        raw = line.strip()
        if not raw:
            return ""
        self.history.append(raw)
        self.history = self.history[-100:]
        try:
            tokens = shlex.split(raw, posix=False)
        except ValueError as exc:
            return f"ERROR: invalid command syntax: {exc}"
        if not tokens:
            return ""
        tokens = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in {chr(34), chr(39)} else t for t in tokens]
        self._detect_language(tokens[0])
        if tokens[0].lower() in {"cs", "cybershield", "cybershield.exe"}:
            tokens = tokens[1:]
        if not tokens:
            return self.help_text()
        command = _canonical(tokens[0])
        if command is None:
            return (
                "BLOCKED: command not in CyberShield security command set.\n"
                "Arbitrary cmd.exe / PowerShell / shell execution is disabled.\n\n" + self.help_text()
            )
        args = tokens[1:]
        try:
            if command == "help": return self.help_text()
            if command == "status": return self._status()
            if command == "scan": return self._scan(args, deep=False)
            if command == "deep-scan": return self._scan(args, deep=True)
            if command == "host": return self._host()
            if command == "processes": return self._processes(args)
            if command == "network": return self._network(args)
            if command == "services": return self._host_section("services")
            if command == "tasks": return self._host_section("scheduled_tasks")
            if command == "defender": return self._defender_status()
            if command == "hash": return self._hash(args)
            if command == "url": return self._url(args)
            if command == "quarantine": return self._quarantine(args)
            if command == "lab": return self._lab()
            if command == "diagnostics": return self._diagnostics()
            if command == "history": return self._history()
            if command == "incidents": return _json(get_incident_counts())
            if command == "clear": return "__CLEAR__"
        except Exception as exc:
            return f"ERROR: {type(exc).__name__}: {exc}"
        return "ERROR: command handler unavailable"

    def _scan(self, args: list[str], deep: bool) -> str:
        if not args:
            raise CommandError("Usage: scan <file|directory>")
        target = Path(" ".join(args)).expanduser()
        if not target.exists():
            raise FileNotFoundError(str(target))
        if target.is_dir():
            rows = scan_directory(target, limit=500)
            risky = sorted(rows, key=lambda x: int(x.get("risk", 0)), reverse=True)
            return _json({"target": str(target.resolve()), "files_scanned": len(rows), "top_risks": risky[:20]})
        result = analyze_file_deep(target, endpoint_scan=True, reputation=True) if deep else analyze_file(target)
        add_scan(result["path"], result["sha256"], result.get("risk", 0), result.get("verdict", "UNKNOWN"), result.get("evidence", []))
        add_audit("terminal_scan", result["path"], result.get("verdict"), {"deep": deep, "risk": result.get("risk", 0)})
        summary = {k: result.get(k) for k in ("path", "size", "sha256", "risk", "verdict", "confidence", "signature_status", "execution_performed")}
        summary["size_human"] = _fmt_bytes(int(result.get("size", 0)))
        summary["evidence"] = result.get("evidence", result.get("indicators", []))[:30]
        return _json(summary)

    def _hash(self, args: list[str]) -> str:
        if not args: raise CommandError("Usage: hash <file>")
        p = Path(" ".join(args)).expanduser().resolve()
        result = analyze_file(p)
        return _json({"file": str(p), "sha256": result["sha256"], "sha1": result["sha1"], "md5": result["md5"], "size": result["size"]})

    def _url(self, args: list[str]) -> str:
        if not args: raise CommandError("Usage: url <https://example.com/>")
        url = " ".join(args).strip()
        result = analyze_url_deep(url, reputation=True)
        add_url_scan(url, result.get("score", result.get("risk", 0)), result.get("verdict", "UNKNOWN"), result.get("confidence", 0.0), result.get("reasons", []))
        add_audit("terminal_url_analysis", url, result.get("verdict"), {"network_request_performed": result.get("network_request_performed", False)})
        return _json(result)

    def _host(self) -> str:
        return _json(inspect_host())

    def _host_section(self, key: str) -> str:
        return _json(inspect_host().get(key, {}))

    def _processes(self, args: list[str]) -> str:
        limit = 30
        if args:
            try: limit = max(1, min(200, int(args[0])))
            except ValueError: pass
        return _json(get_processes(limit))

    def _network(self, args: list[str]) -> str:
        return _json({"local": get_local_network_info(), "connections": get_connections(100)})

    def _defender_status(self) -> str:
        host = inspect_host().get("security_products", {})
        return _json(host)

    def _quarantine(self, args: list[str]) -> str:
        if not args: raise CommandError("Usage: quarantine <file> --confirm")
        if "--confirm" not in args:
            return "CONFIRMATION REQUIRED: quarantine is reversible but moves the original file. Re-run with --confirm."
        clean = [a for a in args if a != "--confirm"]
        p = Path(" ".join(clean)).expanduser().resolve()
        dst = quarantine_file(p)
        add_audit("terminal_quarantine", str(p), "completed", {"quarantine_path": str(dst)})
        return _json({"status": "QUARANTINED", "original": str(p), "quarantine": str(dst), "reversible": True})

    def _lab(self) -> str:
        d = assess_dynamic_lab_readiness()
        return _json({"status": d.status, "message": d.message, "actions": d.actions, "host_execution": "BLOCKED"})

    def _diagnostics(self) -> str:
        return _json(run_self_diagnostics().as_dict())

    def _history(self) -> str:
        return "\n".join(f"{i+1:02d}  {v}" for i, v in enumerate(self.history[-30:])) or "No history"

    def _status(self) -> str:
        diag = run_self_diagnostics()
        return _json({
            "engine": "ONLINE",
            "mode": "DEFENSIVE",
            "host_execution": "BLOCKED",
            "terminal": "READY",
            "diagnostics_ok": diag.ok,
            "failed_modules": list(diag.failed),
            "open_incidents": get_incident_counts(),
            "recent_scans": get_recent_scans(5),
            "recent_urls": get_recent_url_scans(5),
            "hostname": socket.gethostname(),
        })
