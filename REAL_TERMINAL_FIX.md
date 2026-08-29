# CyberShield Real Terminal Fix

- Fixed broken `app.core.terminal_engine` import.
- Replaced duplicate terminal UI with `app.ai.cybershield_terminal.CyberShieldTerminal`.
- Commands run in a QThread so host inspection/scanning does not freeze the GUI.
- `tizim`, `jarayonlar`, `tarmoq`, `xizmatlar`, `vazifalar`, `himoya`, `tekshir`, `chuqur-tekshir`, `xesh`, `havola`, `karantin`, `xavfsiz-lab`, `diagnostika`, `hodisalar`, `tarix`, `holat` are routed to the real CyberShield modules.
- Arbitrary CMD/PowerShell remains disabled by design.
- Fixed a responsive sidebar `setText()` bug in `app/main.py`.
