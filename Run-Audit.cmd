@echo off
REM Runs the share audit locally with UAC elevation (double-click). Arguments are passed to the script.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Elevation required...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ShareAudit.ps1" -OpenReport %*
echo.
pause
