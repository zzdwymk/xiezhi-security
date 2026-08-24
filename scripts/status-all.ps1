$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pidFile = Join-Path $workspace '.run\processes.json'

function Get-PortStatus([int]$Port) {
    $connection = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($connection) { return "LISTENING (PID $($connection.OwningProcess))" }
    return 'STOPPED'
}

if (Test-Path -LiteralPath $pidFile) {
    $state = Get-Content -LiteralPath $pidFile -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host "Run record: $($state.startedAt)"
} else {
    Write-Host 'No run record.'
}

$rows = @(
    [pscustomobject]@{ Service = 'Spring Boot backend'; Address = 'http://127.0.0.1:8080'; Status = Get-PortStatus 8080 },
    [pscustomobject]@{ Service = 'Vue 3 frontend'; Address = 'http://127.0.0.1:5173'; Status = Get-PortStatus 5173 }
)
$rows | Format-Table -AutoSize
