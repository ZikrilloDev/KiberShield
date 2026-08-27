# CyberShield Security Terminal — fixed

## What was fixed

- `app/main.py` expected `TerminalWidget`, but `app/ui/terminal.py` did not define it.
- The old UI imported the non-existent `app.core.terminal_engine` module.
- The old terminal implementation had a simulated security scan that always returned `CLEAN`.
- The terminal page is now connected to `app.ai.cybershield_terminal.CyberShieldTerminal`.
- Security commands use the existing real CyberShield engines: static analysis, deep analysis, Defender/ClamAV/optional VirusTotal reputation, process telemetry, network telemetry, host inspection, quarantine, diagnostics, and database audit.
- Long-running terminal commands run in a Qt worker thread so the GUI is not blocked.
- Arbitrary CMD/PowerShell/shell execution remains disabled by design.

## Main terminal commands

- `yordam`
- `tekshir <file|folder>`
- `chuqur-tekshir <file>`
- `xesh <file>`
- `havola <https://example.com>`
- `tizim`
- `jarayonlar`
- `tarmoq`
- `xizmatlar`
- `vazifalar`
- `himoya`
- `xavfsiz-lab`
- `diagnostika`
- `hodisalar`
- `tarix`
- `karantin <file> --confirm`
- `holat`
- `toza`

## Important

This is a defensive security terminal, not a general-purpose shell. It reports `UNKNOWN`/`UNAVAILABLE` when an external engine is missing instead of pretending that a file is safe.
