
"""Fail-closed sandbox safety validation."""

from dataclasses import dataclass
from .sandbox_orchestrator import SandboxJob


@dataclass(frozen=True)
class PolicyCheck:
    passed: bool
    failures: list


def validate(job: SandboxJob) -> PolicyCheck:
    p = job.policy
    failures = []

    if not p.disposable:
        failures.append("VM must be disposable")
    if not p.automatic_rollback:
        failures.append("Automatic rollback must be enabled")
    if p.network_mode != "isolated":
        failures.append("Network must be isolated")
    if p.shared_folders:
        failures.append("Shared folders must be disabled")
    if p.clipboard:
        failures.append("Clipboard sharing must be disabled")
    if p.host_drives:
        failures.append("Host drive access must be disabled")
    if p.audio or p.printer or p.gpu_passthrough:
        failures.append("Unnecessary host integration must be disabled")
    if p.max_runtime_seconds <= 0 or p.max_runtime_seconds > 3600:
        failures.append("Runtime limit must be 1..3600 seconds")

    return PolicyCheck(not failures, failures)
