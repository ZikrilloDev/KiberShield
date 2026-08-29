# CyberShield AI Security Brain

This module is a defensive decision layer for CyberShield.

Pipeline:
Telemetry -> Evidence normalization -> Risk correlation -> Confidence -> Safe response -> Verification -> Audit

Safety boundaries:
- No arbitrary shell execution from AI output.
- Prefer containment/quarantine and rollback.
- Unknown or low-confidence samples are escalated.
- Malware samples are not executed on the Windows host.
- Dynamic analysis should use a disposable, isolated VM/sandbox controlled by explicit policy.
