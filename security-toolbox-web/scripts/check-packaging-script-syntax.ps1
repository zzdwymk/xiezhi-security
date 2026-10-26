# 语法检查：确认 scripts/package-desktop-release.ps1 在 Windows PowerShell 5.1 下
# 能被完整解析（cmd 里的 package-desktop-release.cmd 调用的就是 powershell.exe）。
# 注意：用 -File 运行时 $PSScriptRoot 由 powershell.exe 传入，不要依赖 $MyInvocation.MyCommand。
# 输出保持 ASCII，避免 GBK 解码问题。
param([string]$RepoRoot = '')

if (-not $RepoRoot) {
    $RepoRoot = (Get-Location).Path
    if ((Split-Path $RepoRoot -Leaf) -eq 'security-toolbox-web') {
        $RepoRoot = Split-Path $RepoRoot -Parent
    }
}
$scriptPath = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'scripts\package-desktop-release.ps1'))
Write-Host ("checking: {0}" -f $scriptPath)
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    Write-Host 'script not found' -ForegroundColor Red
    exit 2
}
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
Write-Host ('PowerShell version: ' + $PSVersionTable.PSVersion.ToString())
if ($errors -and $errors.Count -gt 0) {
    Write-Host ('PARSE ERRORS: ' + $errors.Count) -ForegroundColor Red
    foreach ($errorItem in $errors) {
        Write-Host ('  line ' + $errorItem.Extent.StartLineNumber + ': ' + $errorItem.Message)
    }
    exit 1
}
Write-Host 'Parse OK' -ForegroundColor Green
