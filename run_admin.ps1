# Check for Administrator elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Set-Location -Path $PSScriptRoot
$host.UI.RawUI.WindowTitle = "VEYLIX - AI Insider Threat Detection (Administrator)"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Starting VEYLIX with Administrator Privileges (Scapy/Npcap enabled)  " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Start Frontend Dev Server if npm is installed
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "[*] Starting Vite Frontend dev server (http://localhost:5173)..." -ForegroundColor Green
    Start-Process cmd.exe -ArgumentList '/c "cd /d frontend && npm run dev"' -WindowStyle Minimized
}

# Run Flask Backend
Write-Host "[*] Starting Flask Backend (http://localhost:5000)..." -ForegroundColor Green
python app.py
