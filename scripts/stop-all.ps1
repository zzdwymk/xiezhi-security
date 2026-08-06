$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pidFile = Join-Path $workspace '.run\processes.json'

function Stop-ProcessTree([int]$RootPid) {
    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        Stop-ProcessTree ([int]$child.ProcessId)
    }
    Stop-Process -Id $RootPid -Force -ErrorAction SilentlyContinue
}

function Test-StoredProcess($Stored) {
    $process = Get-Process -Id ([int]$Stored.pid) -ErrorAction SilentlyContinue
    if (-not $process) { return $false }
    try {
        $actual = $process.StartTime.ToUniversalTime()
        $expected = [DateTime]::Parse($Stored.startTime).ToUniversalTime()
        return [math]::Abs(($actual - $expected).TotalSeconds) -lt 2
    } catch {
        return $false
    }
}

if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Host 'No start-all run record was found. Services may already be stopped.' -ForegroundColor Yellow
    exit 0
}

$state = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
if ($state.workspace -ne $workspace) {
    throw 'The run record belongs to a different workspace.'
}

foreach ($name in @('frontend', 'backend')) {
    $stored = $state.$name
    if (Test-StoredProcess $stored) {
        Stop-ProcessTree ([int]$stored.pid)
        Write-Host "Stopped $name process tree." -ForegroundColor Green
    } else {
        Write-Host "$name process is missing or its PID was reused. No process was terminated." -ForegroundColor Yellow
    }
}

Remove-Item -LiteralPath $pidFile -Force
Write-Host 'Backend and frontend stopped successfully.' -ForegroundColor Green
