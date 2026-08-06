$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$backend = Join-Path $workspace 'security-toolbox-server'
$frontend = Join-Path $workspace 'security-toolbox-web'
$maven = (Get-Command mvn -ErrorAction Stop).Source
$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npmCommand) { $npmCommand = Get-Command npm -ErrorAction Stop }

Write-Host 'Building the local Spring Boot engine...' -ForegroundColor Cyan
& $maven -B -ntp -DskipTests package -f (Join-Path $backend 'pom.xml')
if ($LASTEXITCODE -ne 0) { throw 'Backend build failed.' }

Push-Location $frontend
try {
    Write-Host 'Opening Xiezhi desktop...' -ForegroundColor Cyan
    & $npmCommand.Source run desktop:dev
} finally {
    Pop-Location
}
