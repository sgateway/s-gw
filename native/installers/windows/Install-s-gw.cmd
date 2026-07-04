@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-s-gw.ps1" %*
if errorlevel 1 (
  echo.
  echo s-gw installation failed.
  pause
  exit /b 1
)
echo.
echo s-gw installation completed.
pause
