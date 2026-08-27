# CyberShield REAL_FIXED — Terminal Audit

Audit scope: this ZIP only.

## Entry-point problem found

The ZIP contained **two different desktop entry points**:

- `main.py` — old GUI, no Security Terminal page.
- `app/main.py` — current GUI, includes `TerminalWidget`.

This could make `python main.py` start the wrong application. `main.py` is now a compatibility wrapper that always launches `app.main`.

## Terminal command audit

There are **17 built-in commands** in the current terminal help (including `toza`).

| Command | Implementation | Audit result |
|---|---|---|
| `tekshir` | `app.security.scanner.analyze_file/scan_directory` | REAL static analysis |
| `chuqur-tekshir` | static + Defender + optional VT/ClamAV | REAL when those engines are installed/configured; otherwise reports unavailable |
| `xesh` | real SHA-256/SHA-1/MD5 | PASS |
| `havola` | local URL heuristics + optional reputation | REAL analysis; does not open target page |
| `tizim` | host inventory | REAL; Windows services/tasks/Defender depend on Windows APIs/tools |
| `jarayonlar` | psutil | REAL |
| `tarmoq` | psutil | REAL |
| `xizmatlar` | Windows `sc.exe` | REAL on Windows; unavailable on non-Windows |
| `vazifalar` | Windows `schtasks.exe` | REAL on Windows; unavailable on non-Windows |
| `himoya` | fixed Defender status query | REAL on Windows with Defender/PowerShell available; otherwise unavailable |
| `xavfsiz-lab` | lab readiness policy | REAL readiness assessment; does not pretend a VM exists |
| `diagnostika` | imports core modules | REAL self-diagnostic |
| `hodisalar` | SQLite incident counts | REAL |
| `tarix` | terminal history | REAL |
| `karantin <file> --confirm` | copy/verify + atomic move | REAL reversible-isolation design; restore is handled outside this command |
| `holat` | diagnostics + DB + hostname | REAL |
| `toza` | terminal UI clear | REAL UI operation |

## Local execution test

The command layer was executed directly in the audit environment. The following worked:

- host inventory
- process telemetry
- network telemetry
- file hashing
- static file scan
- deep scan path
- URL analysis without opening the URL
- lab readiness
- self-diagnostics
- incidents/history/status/clear

Windows-only commands correctly returned `available: false` in the Linux audit environment rather than inventing results:

- `xizmatlar`
- `vazifalar`
- `himoya`

## Important real-world limitations

1. Microsoft Defender scanning requires `MpCmdRun.exe` on Windows.
2. VirusTotal requires `CYBERSHIELD_VIRUSTOTAL_API_KEY`.
3. Google Safe Browsing requires its configured API credentials.
4. ClamAV is optional and must be installed separately.
5. `xavfsiz-lab` intentionally refuses dynamic execution until a disposable isolated VM/snapshot is configured.
6. Static malware detection cannot honestly guarantee 100% detection.

The code uses `UNKNOWN/UNAVAILABLE` for missing engines instead of falsely reporting `CLEAN`.
