@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul

rem Prefer PowerShell 7 when it is installed. pwsh decodes a BOM-less .ps1 as
rem UTF-8, while Windows PowerShell 5.1 falls back to the ANSI code page, which
rem corrupts non-ASCII text in the script. Fall back to 5.1 when 7 is absent.
set "PS_BIN="
for /f "delims=" %%I in ('where pwsh.exe 2^>nul') do (
    if not defined PS_BIN set "PS_BIN=%%I"
)
if not defined PS_BIN (
    for /f "delims=" %%I in ('where powershell.exe 2^>nul') do (
        if not defined PS_BIN set "PS_BIN=%%I"
    )
)
if not defined PS_BIN (
    echo [ERROR] Neither pwsh.exe nor powershell.exe was found on PATH.
    pause
    exit /b 1
)

echo Using PowerShell: %PS_BIN%
"%PS_BIN%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\package-desktop-release.ps1" %*
pause
