# CyberShield CIBER Upgrade

- Restored the full startup dashboard animation: shield, rotating render, system status, command panel, progress bar and boot stages.
- Startup animation is finite and never runs in the background after the prompt appears.
- Command input/output scrolls normally below the static header; no renderer repaints over history.
- Windows CMD ANSI/VT is enabled when available; ANSI-free fallback remains readable.
- Added safe defensive commands: `dns-resolve`, `port-check`, `listening-risk`, `security-baseline`, `process-network`.
- Arbitrary cmd.exe / PowerShell / shell execution remains blocked.
