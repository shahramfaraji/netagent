param(
    [switch]$Lan
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".\netagent\webapp.py")) {
    throw "Run this script from the netagent project root."
}

if (-not $env:NETAGENT_WEB_TOKEN) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $env:NETAGENT_WEB_TOKEN = ([BitConverter]::ToString($bytes)).Replace("-", "").ToLowerInvariant()
    Write-Host "Temporary operator token (copy into the UI when running backup/discovery):" -ForegroundColor Yellow
    Write-Host $env:NETAGENT_WEB_TOKEN -ForegroundColor Yellow
}

if ($Lan) {
    $env:NETAGENT_WEB_HOST = "0.0.0.0"
    Write-Host "LAN mode enabled. Use this computer's LAN IP and port 8765; Windows Firewall may need a rule." -ForegroundColor Yellow
} else {
    $env:NETAGENT_WEB_HOST = "127.0.0.1"
    Write-Host "Local-only mode. For LAN access, restart with: .\run-web.ps1 -Lan" -ForegroundColor Cyan
}

python -m netagent.webserver
