"""
Local Memory System - Offline Conversation and Action History

Stores:
- Conversation history
- Security actions
- Threat history
- Scan results
- User preferences

All stored locally with optional encryption.
"""

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ConversationEntry:
    """Single conversation exchange."""
    timestamp: str
    user_message: str
    ai_response: str
    intent: str
    succeeded: bool


@dataclass
class ActionHistory:
    """Security action record."""
    timestamp: str
    action_type: str  # scan, quarantine, analyze, etc.
    target: str
    result: str  # success, failed, pending
    threat_detected: bool = False
    risk_score: Optional[int] = None
    details: Optional[str] = None


@dataclass
class ThreatAttention:
    """Threat detection record."""
    timestamp: str
    threat_type: str
    target: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    verdict: str
    action_taken: Optional[str] = None
    resolved: bool = False


class LocalMemoryDB:
    """Local SQLite database for memory storage."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or "./data/cybershield_memory.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_db()

    def _initialize_db(self) -> None:
        """Initialize database schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS conversations (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        user_message TEXT NOT NULL,
                        ai_response TEXT NOT NULL,
                        intent TEXT,
                        succeeded BOOLEAN
                    )
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS actions (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        target TEXT,
                        result TEXT,
                        threat_detected BOOLEAN,
                        risk_score INTEGER,
                        details TEXT
                    )
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        target TEXT,
                        risk_level TEXT,
                        verdict TEXT,
                        action_taken TEXT,
                        resolved BOOLEAN
                    )
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS preferences (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )
                """)

                conn.commit()
            logger.info(f"Memory database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize memory database: {e}")

    def add_conversation(self, entry: ConversationEntry) -> bool:
        """Add conversation entry."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO conversations
                    (timestamp, user_message, ai_response, intent, succeeded)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    entry.timestamp,
                    entry.user_message,
                    entry.ai_response,
                    entry.intent,
                    entry.succeeded
                ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add conversation: {e}")
            return False

    def get_recent_conversations(self, limit: int = 20) -> List[ConversationEntry]:
        """Get recent conversation history."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT timestamp, user_message, ai_response, intent, succeeded
                    FROM conversations
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

                return [
                    ConversationEntry(*row)
                    for row in reversed(cursor.fetchall())
                ]
        except Exception as e:
            logger.error(f"Failed to get conversations: {e}")
            return []

    def add_action(self, action: ActionHistory) -> bool:
        """Add action record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO actions
                    (timestamp, action_type, target, result, threat_detected, risk_score, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    action.timestamp,
                    action.action_type,
                    action.target,
                    action.result,
                    action.threat_detected,
                    action.risk_score,
                    action.details
                ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add action: {e}")
            return False

    def get_recent_actions(self, limit: int = 50) -> List[ActionHistory]:
        """Get recent action history."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT timestamp, action_type, target, result, threat_detected, risk_score, details
                    FROM actions
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

                return [
                    ActionHistory(*row)
                    for row in reversed(cursor.fetchall())
                ]
        except Exception as e:
            logger.error(f"Failed to get actions: {e}")
            return []

    def add_threat(self, threat: ThreatAttention) -> bool:
        """Add threat record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO threats
                    (timestamp, threat_type, target, risk_level, verdict, action_taken, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    threat.timestamp,
                    threat.threat_type,
                    threat.target,
                    threat.risk_level,
                    threat.verdict,
                    threat.action_taken,
                    threat.resolved
                ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add threat: {e}")
            return False

    def get_threat_history(self, limit: int = 50, hours: int = 24) -> List[ThreatAttention]:
        """Get threat history from last N hours."""
        try:
            cutoff_time = (
                datetime.now(timezone.utc) - timedelta(hours=hours)
            ).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT timestamp, threat_type, target, risk_level, verdict, action_taken, resolved
                    FROM threats
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (cutoff_time, limit))

                return [
                    ThreatAttention(*row)
                    for row in reversed(cursor.fetchall())
                ]
        except Exception as e:
            logger.error(f"Failed to get threat history: {e}")
            return []

    def set_preference(self, key: str, value: str) -> bool:
        """Set user preference."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO preferences (key, value)
                    VALUES (?, ?)
                """, (key, value))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to set preference: {e}")
            return False

    def get_preference(self, key: str, default: str = "") -> str:
        """Get user preference."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT value FROM preferences WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                return row[0] if row else default
        except Exception as e:
            logger.error(f"Failed to get preference: {e}")
            return default

    def get_statistics(self) -> Dict[str, Any]:
        """Get memory statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM conversations")
                conv_count = cursor.fetchone()[0]

                cursor = conn.execute("SELECT COUNT(*) FROM actions")
                action_count = cursor.fetchone()[0]

                cursor = conn.execute("SELECT COUNT(*) FROM threats")
                threat_count = cursor.fetchone()[0]

                return {
                    "conversations": conv_count,
                    "actions": action_count,
                    "threats": threat_count,
                    "database_size_mb": self.db_path.stat().st_size / (1024**2),
                }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

    def cleanup_old_data(self, days: int = 30) -> bool:
        """Remove data older than N days."""
        try:
            cutoff_time = (
                datetime.now(timezone.utc) - timedelta(days=days)
            ).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM conversations WHERE timestamp < ?", (cutoff_time,))
                conn.execute("DELETE FROM actions WHERE timestamp < ?", (cutoff_time,))
                conn.execute("DELETE FROM threats WHERE timestamp < ? AND resolved = true", (cutoff_time,))
                conn.commit()

            logger.info(f"Cleaned up data older than {days} days")
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            return False


class LocalMemory:
    """High-level local memory interface."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db = LocalMemoryDB(db_path)

    def record_conversation(
        self,
        user_message: str,
        ai_response: str,
        intent: str,
        succeeded: bool
    ) -> None:
        """Record user-AI exchange."""
        entry = ConversationEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_message=user_message,
            ai_response=ai_response,
            intent=intent,
            succeeded=succeeded
        )
        self.db.add_conversation(entry)

    def record_action(
        self,
        action_type: str,
        target: str,
        result: str,
        threat_detected: bool = False,
        risk_score: Optional[int] = None,
        details: Optional[str] = None
    ) -> None:
        """Record security action."""
        action = ActionHistory(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_type=action_type,
            target=target,
            result=result,
            threat_detected=threat_detected,
            risk_score=risk_score,
            details=details
        )
        self.db.add_action(action)

    def record_threat(
        self,
        threat_type: str,
        target: str,
        risk_level: str,
        verdict: str,
        action_taken: Optional[str] = None
    ) -> None:
        """Record detected threat."""
        threat = ThreatAttention(
            timestamp=datetime.now(timezone.utc).isoformat(),
            threat_type=threat_type,
            target=target,
            risk_level=risk_level,
            verdict=verdict,
            action_taken=action_taken,
            resolved=False
        )
        self.db.add_threat(threat)

    def get_context(self, max_items: int = 10) -> Dict[str, Any]:
        """Get recent context for AI."""
        return {
            "recent_conversations": [
                asdict(c) for c in self.db.get_recent_conversations(max_items//2)
            ],
            "recent_actions": [
                asdict(a) for a in self.db.get_recent_actions(max_items//2)
            ],
            "recent_threats": [
                asdict(t) for t in self.db.get_threat_history(5)
            ],
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        return self.db.get_statistics()

    def cleanup(self, days: int = 30) -> None:
        """Clean up old data."""
        self.db.cleanup_old_data(days)
