@echo off
setlocal
cd /d "%~dp0"
echo Updating 31 ACTION photo folders...
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0update-images.ps1"
if errorlevel 1 (
  echo.
  echo ERROR: The image list was NOT replaced. The previous working list was kept.
  echo Please copy the error shown above and send it to me.
  echo.
  pause
  exit /b 1
)
echo.
echo Update complete.
pause
