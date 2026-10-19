@echo off
chcp 65001 >nul
set "ELECTRON_RUN_AS_NODE="
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-desktop.ps1"
if errorlevel 1 pause
