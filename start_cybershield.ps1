$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$mode = if ($args.Count -gt 0) { $args[0].ToLower() } else { 'desktop' }

switch ($mode) {
    'desktop' { python .\launch_cybershield.py desktop }
    'web' { python .\launch_cybershield.py web }
    'all' { python .\launch_cybershield.py all }
    default {
        Write-Host 'Usage: .\start_cybershield.ps1 [desktop|web|all]'
        exit 2
    }
}
