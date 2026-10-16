@echo off
:: Self-elevate to Administrator if not already elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title VEYLIX - Insider Threat Detection (Administrator)
echo ======================================================================
echo   Running VEYLIX with Administrator Privileges
echo   Zero Decryption Encrypted Traffic Analysis
echo ======================================================================
echo.

:: Start Frontend Vite dev server in background if npm available
where npm >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Starting Frontend dev server (http://localhost:5173) ...
    start /min "VEYLIX Frontend" cmd /c "cd /d \"%~dp0frontend\" && npm run dev"
)

:: Run Flask Backend on Port 5000
echo [*] Starting Flask Backend (http://localhost:5000) ...
python app.py
pause
