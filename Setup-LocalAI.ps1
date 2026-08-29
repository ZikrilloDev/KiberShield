$ErrorActionPreference = 'Stop'
Write-Host 'CyberShield Local AI setup' -ForegroundColor Cyan

$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    Write-Host 'Ollama topilmadi.' -ForegroundColor Yellow
    Write-Host 'Ollama o‘rnatilgach ushbu skriptni qayta ishga tushiring.'
    Write-Host 'CyberShield internet search fallback bilan Ollama-siz ham ishlaydi.'
    exit 1
}

Write-Host 'Ollama topildi. Model tekshirilmoqda...' -ForegroundColor Green
& ollama pull qwen2.5:7b
if ($LASTEXITCODE -ne 0) { throw 'Modelni yuklash muvaffaqiyatsiz tugadi.' }

[Environment]::SetEnvironmentVariable('CYBERSHIELD_AI_PROVIDER','auto','User')
[Environment]::SetEnvironmentVariable('CYBERSHIELD_AI_MODEL','qwen2.5:7b','User')
Write-Host 'Tayyor: CyberShield AI local Qwen modelidan foydalanadi.' -ForegroundColor Green
Write-Host 'Yangi terminal ochib dasturni ishga tushiring.'
