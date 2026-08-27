
"""Disposable sandbox orchestration for CyberShield.

This module is an orchestration/policy layer. It prepares a disposable analysis
job and records the required isolation policy. It deliberately does not execute
an unknown sample itself; a platform adapter must enforce the isolation boundary.
"""

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List
import uuid


class SandboxBackend(str, Enum):
    WINDOWS_SANDBOX = "windows_sandbox"
    HYPER_V = "hyper_v"
    VMWARE = "vmware"
    VIRTUALBOX = "virtualbox"


@dataclass(frozen=True)
class SandboxPolicy:
    network_mode: str = "isolated"
    shared_folders: bool = False
    clipboard: bool = False
    host_drives: bool = False
    audio: bool = False
    printer: bool = False
    gpu_passthrough: bool = False
    automatic_rollback: bool = True
    disposable: bool = True
    max_runtime_seconds: int = 300


@dataclass
class SandboxJob:
    job_id: str
    sample_sha256: str
    backend: SandboxBackend
    policy: SandboxPolicy
    status: str = "CREATED"


class SandboxOrchestrator:
    """Creates controlled, disposable analysis jobs.

    A real platform adapter is required to provision/run the VM. The core never
    turns an AI response into a raw hypervisor or OS command.
    """

    def __init__(self):
        self.jobs: Dict[str, SandboxJob] = {}

    def create_job(self, sample_sha256: str,
                   backend: SandboxBackend = SandboxBackend.WINDOWS_SANDBOX,
                   max_runtime_seconds: int = 300) -> SandboxJob:
        if not sample_sha256 or len(sample_sha256) != 64:
            raise ValueError("sample_sha256 must be a SHA-256 hex digest")

        policy = SandboxPolicy(max_runtime_seconds=max_runtime_seconds)
        job = SandboxJob(
            job_id="LAB-" + uuid.uuid4().hex[:12].upper(),
            sample_sha256=sample_sha256.lower(),
            backend=backend,
            policy=policy,
        )
        self.jobs[job.job_id] = job
        return job

    def authorize_run(self, job_id: str) -> bool:
        job = self.jobs[job_id]
        return (
            job.policy.disposable
            and job.policy.automatic_rollback
            and not job.policy.shared_folders
            and not job.policy.clipboard
            and not job.policy.host_drives
            and job.policy.network_mode == "isolated"
        )

    def mark_started(self, job_id: str) -> None:
        if not self.authorize_run(job_id):
            raise PermissionError("Sandbox policy failed closed.")
        self.jobs[job_id].status = "RUNNING"

    def mark_finished(self, job_id: str, verified: bool) -> None:
        self.jobs[job_id].status = "VERIFIED" if verified else "REVIEW_REQUIRED"

    def rollback(self, job_id: str) -> None:
        job = self.jobs[job_id]
        if not job.policy.automatic_rollback:
            raise PermissionError("Automatic rollback is required.")
        job.status = "ROLLED_BACK"

    def job_manifest(self, job_id: str) -> Dict:
        return asdict(self.jobs[job_id])
