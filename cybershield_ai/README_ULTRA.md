# CyberShield AI Ultra

This upgrade adds a context-aware Uzbek semantic front-end and defensive planner.

Examples:
- `qale+san` / `qale san` / `qalesan` -> GREETING
- `virus+ni+top` / `viruzni topvor` -> FIND_THREAT
- `shu papkani tekshir` -> SCAN_FOLDER
- `uni zararsizlantir` -> resolves the previous entity from context

Architecture:
language normalization -> intent/entity extraction -> context -> security plan -> explicit tools -> verification.

The planner never executes arbitrary shell commands. High-impact remediation is represented as a reversible, policy-gated plan.
