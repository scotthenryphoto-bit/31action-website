@echo off
setlocal
cd /d "%~dp0"
call "%~dp0UPDATE_IMAGES.bat"
if errorlevel 1 exit /b 1
start "" "%~dp0index.html"
