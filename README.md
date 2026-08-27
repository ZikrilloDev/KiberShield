# CyberShield — Modern Desktop Edition

Bu paket **faqat zamonaviy Windows Desktop/SOC CyberShield** uchun ajratilgan. Web/Vercel/serverless loyiha bu buildga kiritilmagan.

## Tuzatilgan muammolar
- Sandbox sahifasidagi boshlang'ich `PENDING` holatlar endi aniq `WAITING/READY` holatlar bilan ko'rsatiladi.
- Fayl tahlili GUI oynasini muzlatib qo'ymasligi uchun alohida Qt worker thread'da ishlaydi.
- Microsoft Defender tekshiruvi (mavjud bo'lsa) ham UI thread'ni bloklamaydi.
- Tahlil xatosi bo'lsa tugmalar va bosqichlar xavfsiz holatga qaytadi; sample hostda ishga tushirilmaydi.
- Standalone build'dagi eski `web/all` launcher rejimlari olib tashlandi; endi yo'q `server` modulini chaqirmaydi.
- Real-time file monitoring uchun `watchdog` dependency qo'shildi; u bo'lmasa polling fallback ishlaydi.
- Core scanner + AI + fail-closed lab smoke testlari qo'shildi.

## Nimalar saqlandi
- Premium CyberShield desktop UI
- AI Security Copilot
- File/static threat analysis
- AI Virus Neutralizer
- Phishing Analyzer
- Sandbox / Malware Lab / Forensics
- Live process va network monitoring
- Reversible quarantine va safety checks
- Windows background protection
- System tray: oynani `X` bilan yopganda protection davom etadi
- Uzbek-first localization (EN/RU ham mavjud)

## O'rnatish
Windows PowerShell/CMD:

```powershell
python -m pip install -r requirements-desktop.txt
```

## Ishga tushirish

```powershell
python -m app.main
```

Yoki `RUN_CYBERSHIELD.bat`.

## CyberShield Security Terminal

AI Copilot ichida va alohida konsolda **CyberShield uchun maxsus, real buyruq qatlami** mavjud. Buyruqlar bevosita CyberShield modullariga ulanadi: statik fayl skani, chuqur ko‘p-manbali tekshiruv, URL/fishing, hash, Defender, jarayonlar, tarmoq, xizmatlar, scheduled tasks, diagnostika, incidentlar va qaytariladigan karantin.

GUI ichida **AI ANALYST → SECURITY TERMINAL** tabini oching. Alohida terminal uchun:

```powershell
python main.py terminal
```

Misollar:

```text
CyberShield> status
CyberShield> tekshir "C:\Downloads\invoice.exe"
CyberShield> xesh "C:\Downloads\invoice.exe"
CyberShield> havola https://example.com
CyberShield> jarayonlar
CyberShield> tarmoq
CyberShield> diagnostika
CyberShield> karantin "C:\Downloads\bad.exe" --confirm
```

**UZ / EN / RU:** buyruqning o‘zbekcha, inglizcha yoki ruscha aliasi yozilsa, terminal javob tilini avtomatik moslaydi.

**Muhim:** CyberShield terminali `cmd.exe`, PowerShell yoki arbitrary shell'ni ishga tushirmaydi. Bu ataylab qilingan xavfsizlik chegarasi: terminal faqat ro‘yxatdan o‘tgan defensive security operatsiyalarini bajaradi.

## Background
Desktop ilova ishga tushganda `BackgroundProtection` avtomatik start oladi.
Oynani `X` bilan yopish ilovani darhol o'chirmaydi — System Trayga yashiradi va protection davom etadi.

Alohida background rejimi:

```powershell
python main.py background
```

## EXE

```powershell
.\BUILD_EXE.ps1
```

## Xavfsizlik modeli
Noma'lum sample hostda bajarilmaydi. Static analysis evidence-first ishlaydi. Yuqori ishonchli holatlarda containment/quarantine policy orqali qaytariladigan usulda qo'llanadi.

## Tekshiruv
Source compile-check va core smoke testlar o'tkazilgan. Ushbu Linux muhitida PySide6 o'rnatilmaganligi sabab Windows GUI runtime bu yerda ko'rsatilmagan; Windowsda dependency o'rnatilgach GUI ishga tushiriladi.

**Eslatma:** bu professional defensive platforma, sertifikatlangan commercial EDR/antivirus o'rnini bosmaydi.

## Multi-engine real detection

CyberShield uses layered evidence instead of a single AI score:
- local static analysis (PE/script/document/archive heuristics, hashes, entropy and masquerading checks);
- Windows Authenticode status when available;
- Microsoft Defender file scanning when available;
- optional ClamAV if `clamscan` is installed;
- optional VirusTotal hash/URL reputation via `CYBERSHIELD_VIRUSTOTAL_API_KEY`;
- optional Google Safe Browsing URL reputation via `CYBERSHIELD_GOOGLE_SAFE_BROWSING_KEY`;
- DNS intelligence for suspicious URLs;
- real-time file/process monitoring and evidence correlation.

No engine is treated as proof of safety when unavailable. Samples are never executed by the scanner, and URL analysis does not open a browser or execute JavaScript.

**Important:** no defensive product can truthfully guarantee detecting every threat before every other product. CyberShield is designed to detect early using multiple independent signals and to fail closed when evidence is insufficient.

## EXE yaratish

Windows PowerShell'da loyiha papkasida:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\BUILD_EXE_ONEFILE.ps1
```

Yoki `BUILD_EXE.bat` faylini ikki marta bosing.

Natija:

```text
dist\CyberShield.exe
```

Build one-file rejimida ishlaydi. Security engine natijalari evidence-first va deterministic formatda qaytariladi; AI matnni bezashi mumkin, ammo tasdiqlanmagan threat/verdictni o'ylab topmasligi kerak.
