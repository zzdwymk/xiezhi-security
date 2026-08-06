@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\package-desktop-release.ps1" %*
pause
