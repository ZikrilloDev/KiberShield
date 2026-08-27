"""
Comprehensive Audit Logging for Autonomous Agent

Tracks all agent operations with:
- Timestamp
- User/command
- Intent/action
- Tool execution
- Results/threats
- Errors
- Recovery attempts
"""

import logging
import json
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from queue import Queue

logger = logging.getLogger(__name__)


class AuditLevel(Enum):
    """Audit log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    THREAT = "THREAT"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class AuditEntry:
    """Single audit log entry."""
    timestamp: str
    level: str
    component: str  # autonomous_agent, tool, scanner, etc.
    event: str  # command, execute, verify, etc.
    details: Dict[str, Any]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    duration_ms: Optional[int] = None
    result: Optional[str] = None  # success, failed, pending
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def as_json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.as_dict(), default=str)


class AuditLogger:
    """Comprehensive audit logging system."""

    def __init__(self, log_dir: Optional[Path] = None, buffer_size: int = 1000):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for log files (default: ./logs)
            buffer_size: Queue buffer size before flushing
        """
        self.log_dir = Path(log_dir or "./logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.buffer = Queue(maxsize=buffer_size)
        self.running = False
        self.writer_thread = None

        # Create rotating file handlers
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Setup logging handlers for different log levels."""
        # Main audit log
        audit_log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        
        # Create file handler
        handler = logging.FileHandler(audit_log_file, encoding='utf-8')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        # Get or create logger
        audit_logger = logging.getLogger("cybershield_audit")
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.DEBUG)
        self.audit_logger = audit_logger

    def start(self) -> None:
        """Start audit logging service."""
        if self.running:
            return

        self.running = True
        self.writer_thread = threading.Thread(target=self._write_loop, daemon=True)
        self.writer_thread.start()
        logger.info("Audit logging started")

    def stop(self) -> None:
        """Stop audit logging service."""
        self.running = False
        if self.writer_thread:
            self.writer_thread.join(timeout=5)
            self.writer_thread = None
        self._flush()
        logger.info("Audit logging stopped")

    def log_command(
        self,
        command: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """Log user command."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.INFO.value,
            component="autonomous_agent",
            event="user_command",
            details={"command": command},
            user_id=user_id,
            session_id=session_id,
            result="pending"
        )
        self._queue_entry(entry)

    def log_intent(
        self,
        command: str,
        intent: str,
        confidence: float,
        session_id: Optional[str] = None
    ) -> None:
        """Log intent detection."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.INFO.value,
            component="autonomous_agent",
            event="intent_detected",
            details={
                "command": command,
                "intent": intent,
                "confidence": confidence
            },
            session_id=session_id,
            result="success" if confidence > 0.7 else "uncertain"
        )
        self._queue_entry(entry)

    def log_tool_execution(
        self,
        tool_name: str,
        action: str,
        target: str,
        success: bool,
        duration_ms: int,
        error: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """Log tool execution."""
        level = AuditLevel.ERROR.value if not success else AuditLevel.INFO.value
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            component="tool_executor",
            event="tool_execution",
            details={
                "tool": tool_name,
                "action": action,
                "target": target
            },
            session_id=session_id,
            duration_ms=duration_ms,
            result="success" if success else "failed",
            error=error
        )
        self._queue_entry(entry)

    def log_threat_detected(
        self,
        threat_type: str,
        target: str,
        risk_score: int,
        verdict: str,
        details: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> None:
        """Log threat detection."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.THREAT.value,
            component="threat_analyzer",
            event="threat_detected",
            details={
                "threat_type": threat_type,
                "target": target,
                "risk_score": risk_score,
                "verdict": verdict,
                **details
            },
            session_id=session_id,
            result="threat_confirmed"
        )
        self._queue_entry(entry)

    def log_quarantine(
        self,
        file_path: str,
        reason: str,
        success: bool,
        quarantine_path: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """Log file quarantine."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.INFO.value if success else AuditLevel.WARNING.value,
            component="quarantine_engine",
            event="file_quarantined",
            details={
                "file_path": file_path,
                "reason": reason,
                "quarantine_path": quarantine_path
            },
            session_id=session_id,
            result="success" if success else "failed"
        )
        self._queue_entry(entry)

    def log_verification(
        self,
        tool_name: str,
        verified: bool,
        goal_achieved: bool,
        evidence: list,
        session_id: Optional[str] = None
    ) -> None:
        """Log result verification."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.INFO.value,
            component="result_verifier",
            event="verification_complete",
            details={
                "tool": tool_name,
                "verified": verified,
                "goal_achieved": goal_achieved,
                "evidence_count": len(evidence)
            },
            session_id=session_id,
            result="verified" if verified else "unverified"
        )
        self._queue_entry(entry)

    def log_error(
        self,
        component: str,
        error_msg: str,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None
    ) -> None:
        """Log error."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.ERROR.value,
            component=component,
            event="error",
            details=details or {},
            session_id=session_id,
            error=error_msg,
            result="error"
        )
        self._queue_entry(entry)

    def log_recovery(
        self,
        tool_name: str,
        error: str,
        recovery_action: str,
        success: bool,
        session_id: Optional[str] = None
    ) -> None:
        """Log error recovery attempt."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=AuditLevel.WARNING.value,
            component="recovery_engine",
            event="recovery_attempted",
            details={
                "tool": tool_name,
                "original_error": error,
                "recovery_action": recovery_action
            },
            session_id=session_id,
            result="success" if success else "failed"
        )
        self._queue_entry(entry)

    def _queue_entry(self, entry: AuditEntry) -> None:
        """Queue log entry for writing."""
        try:
            self.buffer.put_nowait(entry)
        except:
            # Buffer full - flush and retry
            self._flush()
            try:
                self.buffer.put_nowait(entry)
            except:
                logger.error("Failed to queue audit entry")

    def _write_loop(self) -> None:
        """Background thread for writing logs."""
        while self.running:
            try:
                # Batch write entries
                entries = []
                while not self.buffer.empty() and len(entries) < 100:
                    try:
                        entry = self.buffer.get_nowait()
                        entries.append(entry)
                    except:
                        break

                if entries:
                    self._write_entries(entries)

                # Periodic flush
                if len(entries) < 10:
                    threading.Event().wait(1)

            except Exception as e:
                logger.error(f"Write loop error: {e}")

    def _write_entries(self, entries: list) -> None:
        """Write entries to audit log."""
        try:
            for entry in entries:
                self.audit_logger.info(entry.as_json())
        except Exception as e:
            logger.error(f"Failed to write audit entries: {e}")

    def _flush(self) -> None:
        """Flush all pending entries."""
        entries = []
        while not self.buffer.empty():
            try:
                entries.append(self.buffer.get_nowait())
            except:
                break

        if entries:
            self._write_entries(entries)

    def get_log_path(self) -> Path:
        """Get audit log directory."""
        return self.log_dir


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def start_audit_logging() -> None:
    """Start audit logging."""
    logger = get_audit_logger()
    logger.start()


def stop_audit_logging() -> None:
    """Stop audit logging."""
    logger = get_audit_logger()
    logger.stop()


def log_command(
    command: str,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None
) -> None:
    """Log user command."""
    get_audit_logger().log_command(command, user_id, session_id)


def log_tool_execution(
    tool_name: str,
    action: str,
    target: str,
    success: bool,
    duration_ms: int,
    error: Optional[str] = None,
    session_id: Optional[str] = None
) -> None:
    """Log tool execution."""
    get_audit_logger().log_tool_execution(
        tool_name, action, target, success, duration_ms, error, session_id
    )


def log_threat_detected(
    threat_type: str,
    target: str,
    risk_score: int,
    verdict: str,
    details: Dict[str, Any],
    session_id: Optional[str] = None
) -> None:
    """Log threat detection."""
    get_audit_logger().log_threat_detected(
        threat_type, target, risk_score, verdict, details, session_id
    )
