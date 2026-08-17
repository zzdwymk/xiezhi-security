$ErrorActionPreference = 'Stop'

$utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

function Add-ProcessJvmOptions([string]$Name, [string[]]$Options) {
    $existing = [Environment]::GetEnvironmentVariable($Name, 'Process')
    $parts = @()
    if (-not [string]::IsNullOrWhiteSpace($existing)) { $parts += $existing.Trim() }
    foreach ($option in $Options) {
        if ($existing -notlike "*$option*") { $parts += $option }
    }
    [Environment]::SetEnvironmentVariable($Name, ($parts -join ' '), 'Process')
}

Add-ProcessJvmOptions 'MAVEN_OPTS' @(
    '-Dfile.encoding=UTF-8',
    '-Dsun.stdout.encoding=UTF-8',
    '-Dsun.stderr.encoding=UTF-8'
)

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
