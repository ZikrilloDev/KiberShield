"""
CyberShield Autonomous Background Service

Continuous, autonomous security monitoring and protection.

This service runs in the background and:
- Continuously monitors file system for new/modified files
- Analyzes suspicious processes
- Monitors network connections
- Detects and quarantines threats autonomously
- Provides real-time alerts
"""

import threading
import time
import logging
from typing import Optional, Callable
from pathlib import Path
from datetime import datetime, timezone

from .integration import get_agent, init_agent

logger = logging.getLogger(__name__)


class AutonomousSecurityMonitor:
    """Real-time autonomous security monitoring service."""

    def __init__(self, interval: float = 5.0, max_workers: int = 4):
        """
        Initialize monitor.

        Args:
            interval: Monitoring interval in seconds
            max_workers: Max concurrent analysis threads
        """
        self.interval = interval
        self.max_workers = max_workers
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.stats = {
            "files_monitored": 0,
            "threats_detected": 0,
            "files_quarantined": 0,
            "uptime_seconds": 0,
            "start_time": None,
        }
        self.alert_callbacks = []
        self.initialized = False

    def initialize(self) -> bool:
        """Initialize the monitor."""
        try:
            logger.info("Initializing Autonomous Security Monitor")
            if not init_agent():
                logger.error("Failed to initialize agent")
                return False
            self.initialized = True
            logger.info("Autonomous Security Monitor initialized")
            return True
        except Exception as e:
            logger.error(f"Monitor initialization failed: {e}")
            return False

    def start(self) -> None:
        """Start monitoring service."""
        if self.running:
            logger.warning("Monitor already running")
            return

        if not self.initialized:
            if not self.initialize():
                logger.error("Cannot start monitor - initialization failed")
                return

        self.running = True
        self.stats["start_time"] = datetime.now(timezone.utc)
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Autonomous Security Monitor started")

    def stop(self) -> None:
        """Stop monitoring service."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None
        logger.info("Autonomous Security Monitor stopped")

    def register_alert_callback(self, callback: Callable) -> None:
        """Register callback for threat alerts."""
        self.alert_callbacks.append(callback)
        logger.info("Alert callback registered")

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        logger.info("Autonomous monitoring loop started")
        scan_counter = 0

        try:
            while self.running:
                try:
                    scan_counter += 1

                    # Log every N iterations
                    if scan_counter % 60 == 0:
                        elapsed = (datetime.now(timezone.utc) - self.stats["start_time"]).total_seconds()
                        logger.info(f"Monitor running ({elapsed:.0f}s): "
                                   f"{self.stats['files_monitored']} files, "
                                   f"{self.stats['threats_detected']} threats detected, "
                                   f"{self.stats['files_quarantined']} quarantined")

                    # Run autonomous monitoring
                    self._autonomous_scan_cycle()

                    # Regular status update
                    if scan_counter % 360 == 0:  # Every 30 minutes
                        self._periodic_full_status()

                    self.stats["uptime_seconds"] = (datetime.now(timezone.utc) - self.stats["start_time"]).total_seconds()
                    time.sleep(self.interval)

                except Exception as e:
                    logger.error(f"Monitor cycle error: {e}")
                    time.sleep(self.interval)

        except Exception as e:
            logger.error(f"Monitor loop crashed: {e}")
        finally:
            logger.info("Autonomous monitoring loop stopped")

    def _autonomous_scan_cycle(self) -> None:
        """Execute autonomous security scan cycle."""
        try:
            agent = get_agent()
            if not agent.is_initialized:
                return

            # Run lightweight autonomous checks
            commands = [
                "quick_scan",
                "status",
            ]

            for command in commands:
                try:
                    result = agent.process_user_command(command)

                    if result.get("success"):
                        self.stats["files_monitored"] += 1

                        # Check for threats
                        execution_result = result.get("result", {})
                        if execution_result.get("results"):
                            for r in execution_result["results"]:
                                if r.get("result", {}).get("threat_detected"):
                                    self.stats["threats_detected"] += 1
                                    self._alert_threat(command, r)

                except Exception as e:
                    logger.debug(f"Scan cycle error: {e}")

        except Exception as e:
            logger.error(f"Autonomous scan error: {e}")

    def _periodic_full_status(self) -> None:
        """Run periodic full status check."""
        try:
            agent = get_agent()
            if not agent.is_initialized:
                return

            result = agent.process_user_command("get_security_status")
            if result.get("success"):
                logger.info(f"Periodic status: {result.get('result', {})}")

        except Exception as e:
            logger.debug(f"Status check error: {e}")

    def _alert_threat(self, scan_type: str, result: dict) -> None:
        """Alert registered callbacks about detected threat."""
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": scan_type,
            "threat_details": result,
        }

        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def get_stats(self) -> dict:
        """Get monitoring statistics."""
        return dict(self.stats)

    def get_status(self) -> dict:
        """Get monitor status."""
        return {
            "running": self.running,
            "initialized": self.initialized,
            "uptime_seconds": self.stats.get("uptime_seconds", 0),
            "start_time": self.stats.get("start_time"),
            "stats": self.get_stats(),
        }


# Global monitor instance
_monitor_instance: Optional[AutonomousSecurityMonitor] = None


def get_monitor() -> AutonomousSecurityMonitor:
    """Get or create global monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = AutonomousSecurityMonitor()
    return _monitor_instance


def start_autonomous_protection() -> bool:
    """Start autonomous security protection."""
    monitor = get_monitor()
    if monitor.initialize():
        monitor.start()
        return True
    return False


def stop_autonomous_protection() -> None:
    """Stop autonomous protection."""
    monitor = get_monitor()
    monitor.stop()


def get_protection_status() -> dict:
    """Get protection status."""
    monitor = get_monitor()
    return monitor.get_status()


def register_threat_alert(callback: Callable) -> None:
    """Register callback for threat alerts."""
    monitor = get_monitor()
    monitor.register_alert_callback(callback)
