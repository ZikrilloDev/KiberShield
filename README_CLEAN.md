# CyberShield — CLEAN Desktop Project

Bu arxivdan ajratilgan asosiy Windows Desktop CyberShield loyihasi.

## Asosiy ishga tushirish
PowerShell:
```powershell
python main.py desktop
```
Yoki:
```powershell
python -m app.main
```

## Background protection
```powershell
python main.py background
```

## Kutubxonalar
```powershell
python -m pip install -r requirements-desktop.txt
```

## EXE
```powershell
.\BUILD_EXE_ONEFILE.ps1
```

## Tarkib
- `app/` — asosiy Desktop GUI, AI Copilot, scanner, phishing, sandbox, monitoring, database
- `cybershield_core/` — xavfsizlik core komponentlari
- `cybershield_ai/` — AI komponentlari
- `cybershield_autonomous/` — autonomous komponentlar
- `main.py` — asosiy launcher
- `background_service.py` — background protection
- `requirements-desktop.txt` — Desktop dependencylar

## Ataylab olib tashlangan
- `.git/` va `__pycache__/`
- `dist/` va `build/`
- tayyor `cybershield.db` runtime database
- web/server/Vercel qismi
- browser extension
- eski dokumentatsiya dump'lari
- test cache va testlar

Maqsad: Desktop CyberShield uchun keraksiz aralashmalarni ajratib, ishlash uchun kerakli source'ni bir joyga yig'ish.
