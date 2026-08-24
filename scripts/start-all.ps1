param(
    [switch]$NoBrowser,
    [ValidateRange(1, 3600)]
    [int]$BackendStartupTimeoutSeconds = 90,
    [ValidateRange(1, 3600)]
    [int]$FrontendStartupTimeoutSeconds = 60
)

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

$utf8JvmOptions = @(
    '-Dfile.encoding=UTF-8',
    '-Dsun.stdout.encoding=UTF-8',
    '-Dsun.stderr.encoding=UTF-8'
)
Add-ProcessJvmOptions 'MAVEN_OPTS' $utf8JvmOptions

$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$backendDir = Join-Path $workspace 'security-toolbox-server'
$frontendDir = Join-Path $workspace 'security-toolbox-web'
$runDir = Join-Path $workspace '.run'
$logDir = Join-Path $runDir 'logs'
$pidFile = Join-Path $runDir 'processes.json'
$developmentSecretsFile = Join-Path $runDir 'development-secrets.json'
$jar = Join-Path $backendDir 'target\security-toolbox-server-0.1.0.jar'

New-Item -ItemType Directory -Force -Path $runDir, $logDir | Out-Null

function Test-PortListening([int]$Port) {
    $listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return [bool]($listeners | Where-Object { $_.Port -eq $Port } | Select-Object -First 1)
}

function Stop-StartedProcessTree([System.Diagnostics.Process]$Process) {
    if (-not $Process) { return }
    $Process.Refresh()
    if ($Process.HasExited) { return }

    function Stop-ProcessTreeById([int]$RootPid) {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            Stop-ProcessTreeById ([int]$child.ProcessId)
        }
        Stop-Process -Id $RootPid -Force -ErrorAction SilentlyContinue
    }

    Stop-ProcessTreeById $Process.Id
}

function Wait-ProcessPort(
        [System.Diagnostics.Process]$Process,
        [int]$Port,
        [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { return $false }
        if (Test-PortListening $Port) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Wait-BackendAdminLogin(
        [System.Diagnostics.Process]$Process,
        [string]$Password,
        [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $body = @{ username = 'admin'; password = $Password } | ConvertTo-Json -Compress
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { return $false }
        try {
            $response = Invoke-RestMethod `
                -Uri 'http://127.0.0.1:8080/api/auth/login' `
                -Method Post `
                -ContentType 'application/json' `
                -Body $body `
                -TimeoutSec 2
            if ($response.token -and $response.user.username -eq 'admin') { return $true }
        } catch {
            # The web server can accept TCP connections before startup migrations commit.
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function New-DevelopmentSecret([int]$ByteCount = 48) {
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Protect-DevelopmentSecret([string]$Value) {
    $secure = ConvertTo-SecureString -String $Value -AsPlainText -Force
    return ConvertFrom-SecureString -SecureString $secure
}

function Unprotect-DevelopmentSecret([string]$Value) {
    $secure = ConvertTo-SecureString -String $Value
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Assert-StrongDevelopmentSecrets($Secrets) {
    if ([string]::IsNullOrWhiteSpace($Secrets.adminPassword) -or $Secrets.adminPassword.Length -lt 16) {
        throw 'ADMIN_PASSWORD must contain at least 16 characters for local development.'
    }
    if ([Text.Encoding]::UTF8.GetByteCount($Secrets.jwtSecret) -lt 32) {
        throw 'JWT_SECRET must contain at least 32 bytes for local development.'
    }
    if ([string]::IsNullOrWhiteSpace($Secrets.mitmCaPassword) -or $Secrets.mitmCaPassword.Length -lt 16) {
        throw 'TRAFFIC_MITM_CA_PASSWORD must contain at least 16 characters for local development.'
    }
    if ($Secrets.adminPassword -eq 'admin123' -or
        $Secrets.jwtSecret -eq 'development-only-jwt-secret-change-me-32-bytes' -or
        $Secrets.mitmCaPassword -eq 'change-this-development-password') {
        throw 'Fixed development credentials are disabled. Supply strong values; legacy defaults are accepted only by the protected one-click migration.'
    }
}

function Save-DevelopmentSecrets($Secrets) {
    $protected = [ordered]@{
        schemaVersion = 2
        adminPassword = Protect-DevelopmentSecret $Secrets.adminPassword
        jwtSecret = Protect-DevelopmentSecret $Secrets.jwtSecret
        mitmCaPassword = Protect-DevelopmentSecret $Secrets.mitmCaPassword
        legacyMigrationPending = [bool]$Secrets.legacyMigrationPending
    }
    $temporaryFile = Join-Path $runDir ('development-secrets.{0}.tmp' -f [Guid]::NewGuid())
    $backupFile = Join-Path $runDir ('development-secrets.{0}.bak' -f [Guid]::NewGuid())
    try {
        $protected | ConvertTo-Json | Set-Content -LiteralPath $temporaryFile -Encoding UTF8
        if ($env:OS -eq 'Windows_NT') {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls.exe $temporaryFile /inheritance:r /grant:r ('{0}:(F)' -f $identity) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict the development credential file ACL.' }
        }
        if (Test-Path -LiteralPath $developmentSecretsFile) {
            # Windows PowerShell/.NET Framework rejects a null backup path here.
            # A same-directory backup keeps the replacement atomic on both PS 5.1 and PS 7.
            [IO.File]::Replace($temporaryFile, $developmentSecretsFile, $backupFile)
        } else {
            [IO.File]::Move($temporaryFile, $developmentSecretsFile)
        }
    } finally {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-DevelopmentSecrets {
    if (Test-Path -LiteralPath $developmentSecretsFile) {
        try {
            $saved = Get-Content -Raw -LiteralPath $developmentSecretsFile -Encoding UTF8 | ConvertFrom-Json
            if ($saved.schemaVersion -ne 1 -and $saved.schemaVersion -ne 2) { throw 'unsupported schema' }
            if ($saved.schemaVersion -eq 2 -and $saved.legacyMigrationPending -isnot [bool]) {
                throw 'invalid migration state'
            }
            $secrets = [ordered]@{
                adminPassword = Unprotect-DevelopmentSecret $saved.adminPassword
                jwtSecret = Unprotect-DevelopmentSecret $saved.jwtSecret
                mitmCaPassword = Unprotect-DevelopmentSecret $saved.mitmCaPassword
                legacyMigrationPending = if ($saved.schemaVersion -eq 2) {
                    [bool]$saved.legacyMigrationPending
                } else {
                    $false
                }
            }
        } catch {
            throw 'The protected local development credential file cannot be decrypted by the current user.'
        }
        foreach ($entry in @(
            @('ADMIN_PASSWORD', 'adminPassword'),
            @('JWT_SECRET', 'jwtSecret'),
            @('TRAFFIC_MITM_CA_PASSWORD', 'mitmCaPassword'))) {
            $provided = [Environment]::GetEnvironmentVariable($entry[0], 'Process')
            if ($provided -and $provided -ne $secrets[$entry[1]]) {
                throw "$($entry[0]) differs from the protected development credential. Existing backend data was not changed; review $developmentSecretsFile before intentional credential rotation."
            }
        }
        Assert-StrongDevelopmentSecrets $secrets
        return $secrets
    }

    $dataDirectory = Join-Path $backendDir 'data'
    $existingDatabase = @(Get-ChildItem -LiteralPath $dataDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^security-toolbox.*\.(mv|h2|data)\.db$' })
    $existingCa = Test-Path -LiteralPath (Join-Path $dataDirectory 'traffic-mitm-ca.p12')
    $anyExistingData = $existingDatabase.Count -gt 0 -or $existingCa
    $allExplicit = $env:ADMIN_PASSWORD -and $env:JWT_SECRET -and $env:TRAFFIC_MITM_CA_PASSWORD
    $anyExplicit = $env:ADMIN_PASSWORD -or $env:JWT_SECRET -or $env:TRAFFIC_MITM_CA_PASSWORD
    $legacyMigrationPending = $false
    if ($existingDatabase.Count -gt 0 -and $existingCa) {
        if ($anyExplicit -and -not $allExplicit) {
            throw 'Existing backend data requires ADMIN_PASSWORD, JWT_SECRET, and TRAFFIC_MITM_CA_PASSWORD together; partial credential overrides were not applied.'
        }
        $legacyMigrationPending = $true
    } elseif ($anyExistingData -and -not $allExplicit) {
        throw 'Automatic legacy migration requires both the existing H2 database and traffic-mitm-ca.p12. Restore the missing file from backup or provide all three current strong credentials explicitly.'
    }

    $secrets = [ordered]@{
        adminPassword = if ($env:ADMIN_PASSWORD) { $env:ADMIN_PASSWORD } else { New-DevelopmentSecret 48 }
        jwtSecret = if ($env:JWT_SECRET) { $env:JWT_SECRET } else { New-DevelopmentSecret 64 }
        mitmCaPassword = if ($env:TRAFFIC_MITM_CA_PASSWORD) { $env:TRAFFIC_MITM_CA_PASSWORD } else { New-DevelopmentSecret 48 }
        legacyMigrationPending = $legacyMigrationPending
    }
    Assert-StrongDevelopmentSecrets $secrets
    Save-DevelopmentSecrets $secrets
    return $secrets
}

if (Test-Path -LiteralPath $pidFile) {
    & (Join-Path $PSScriptRoot 'status-all.ps1')
    throw 'An existing run record was found. Run scripts\stop-all.ps1 first.'
}

foreach ($port in @(8080, 5173)) {
    if (Test-PortListening $port) {
        throw "Port $port is already in use."
    }
}

$java = (Get-Command java -ErrorAction Stop).Source
$node = (Get-Command node -ErrorAction Stop).Source
$maven = (Get-Command mvn -ErrorAction Stop).Source
$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npmCommand) { $npmCommand = Get-Command npm -ErrorAction Stop }
$npm = $npmCommand.Source

$sourcePaths = @((Join-Path $backendDir 'src'), (Join-Path $backendDir 'pom.xml'))
$sourceLatest = Get-ChildItem -LiteralPath $sourcePaths -Recurse -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not (Test-Path -LiteralPath $jar) -or $sourceLatest.LastWriteTime -gt (Get-Item -LiteralPath $jar).LastWriteTime) {
    Write-Host 'Backend sources changed. Building the executable JAR...' -ForegroundColor Cyan
    & $maven -B -ntp -DskipTests package -f (Join-Path $backendDir 'pom.xml')
    if ($LASTEXITCODE -ne 0) { throw 'Backend Maven build failed.' }
}

if (-not (Test-Path -LiteralPath (Join-Path $frontendDir 'node_modules'))) {
    Write-Host 'Frontend dependencies are missing. Running npm install...' -ForegroundColor Cyan
    Push-Location $frontendDir
    try {
        & $npm install
        if ($LASTEXITCODE -ne 0) { throw 'Frontend npm install failed.' }
    } finally {
        Pop-Location
    }
}

$developmentSecrets = Get-DevelopmentSecrets
$previousAdminPassword = [Environment]::GetEnvironmentVariable('ADMIN_PASSWORD', 'Process')
$previousJwtSecret = [Environment]::GetEnvironmentVariable('JWT_SECRET', 'Process')
$previousMitmPassword = [Environment]::GetEnvironmentVariable('TRAFFIC_MITM_CA_PASSWORD', 'Process')
$previousInsecureGate = [Environment]::GetEnvironmentVariable('ALLOW_INSECURE_DEVELOPMENT_CREDENTIALS', 'Process')
$previousLegacyMigration = [Environment]::GetEnvironmentVariable('MIGRATE_LEGACY_DEVELOPMENT_CREDENTIALS', 'Process')
$backendOutLog = Join-Path $logDir 'backend.out.log'
$backendErrLog = Join-Path $logDir 'backend.err.log'
try {
    [Environment]::SetEnvironmentVariable('ADMIN_PASSWORD', $developmentSecrets.adminPassword, 'Process')
    [Environment]::SetEnvironmentVariable('JWT_SECRET', $developmentSecrets.jwtSecret, 'Process')
    [Environment]::SetEnvironmentVariable('TRAFFIC_MITM_CA_PASSWORD', $developmentSecrets.mitmCaPassword, 'Process')
    [Environment]::SetEnvironmentVariable('ALLOW_INSECURE_DEVELOPMENT_CREDENTIALS', 'false', 'Process')
    [Environment]::SetEnvironmentVariable(
        'MIGRATE_LEGACY_DEVELOPMENT_CREDENTIALS',
        $developmentSecrets.legacyMigrationPending.ToString().ToLowerInvariant(),
        'Process')
    $backendJavaArguments = (
        ($utf8JvmOptions + @('-jar', ('"{0}"' -f $jar))) -join ' '
    )
    $backend = Start-Process -FilePath $java `
        -ArgumentList $backendJavaArguments `
        -WorkingDirectory $backendDir `
        -RedirectStandardOutput $backendOutLog `
        -RedirectStandardError $backendErrLog `
        -WindowStyle Hidden `
        -PassThru
} finally {
    [Environment]::SetEnvironmentVariable('ADMIN_PASSWORD', $previousAdminPassword, 'Process')
    [Environment]::SetEnvironmentVariable('JWT_SECRET', $previousJwtSecret, 'Process')
    [Environment]::SetEnvironmentVariable('TRAFFIC_MITM_CA_PASSWORD', $previousMitmPassword, 'Process')
    [Environment]::SetEnvironmentVariable('ALLOW_INSECURE_DEVELOPMENT_CREDENTIALS', $previousInsecureGate, 'Process')
    [Environment]::SetEnvironmentVariable('MIGRATE_LEGACY_DEVELOPMENT_CREDENTIALS', $previousLegacyMigration, 'Process')
}

$backendReady = Wait-ProcessPort $backend 8080 $BackendStartupTimeoutSeconds
if (-not $backendReady) {
    $backend.Refresh()
    if ($backend.HasExited) {
        throw "Backend process exited before port 8080 became ready (exit code $($backend.ExitCode)). Logs: $backendOutLog and $backendErrLog."
    }
    Stop-StartedProcessTree $backend
    throw "Backend startup timed out after $BackendStartupTimeoutSeconds seconds. Logs: $backendOutLog and $backendErrLog."
}

if ($developmentSecrets.legacyMigrationPending) {
    if (-not (Wait-BackendAdminLogin $backend $developmentSecrets.adminPassword $BackendStartupTimeoutSeconds)) {
        $backend.Refresh()
        if ($backend.HasExited) {
            throw "Backend process exited during legacy credential migration (exit code $($backend.ExitCode)). Existing data was retained. Logs: $backendOutLog and $backendErrLog."
        }
        Stop-StartedProcessTree $backend
        throw "Legacy credential migration did not authenticate within $BackendStartupTimeoutSeconds seconds. Existing data was retained. Logs: $backendOutLog and $backendErrLog."
    }
    try {
        $developmentSecrets['legacyMigrationPending'] = $false
        Save-DevelopmentSecrets $developmentSecrets
    } catch {
        Stop-StartedProcessTree $backend
        throw
    }
    Write-Host 'Legacy development credentials migrated successfully.' -ForegroundColor Green
}

$frontendOutLog = Join-Path $logDir 'frontend.out.log'
$frontendErrLog = Join-Path $logDir 'frontend.err.log'
$viteCli = Join-Path $frontendDir 'node_modules\vite\bin\vite.js'
$frontend = $null
try {
    $frontend = Start-Process -FilePath $node `
        -ArgumentList ('"{0}" --host 127.0.0.1 --port 5173 --strictPort' -f $viteCli) `
        -WorkingDirectory $frontendDir `
        -RedirectStandardOutput $frontendOutLog `
        -RedirectStandardError $frontendErrLog `
        -WindowStyle Hidden `
        -PassThru

    $state = [ordered]@{
        workspace = $workspace
        startedAt = (Get-Date).ToUniversalTime().ToString('o')
        backend = [ordered]@{
            pid = $backend.Id
            startTime = $backend.StartTime.ToUniversalTime().ToString('o')
            port = 8080
        }
        frontend = [ordered]@{
            pid = $frontend.Id
            startTime = $frontend.StartTime.ToUniversalTime().ToString('o')
            port = 5173
        }
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $pidFile -Encoding UTF8
} catch {
    Stop-StartedProcessTree $frontend
    Stop-StartedProcessTree $backend
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    throw
}

$frontendReady = $false
try {
    $frontendReady = Wait-ProcessPort $frontend 5173 $FrontendStartupTimeoutSeconds
    if (-not $frontendReady) {
        $frontend.Refresh()
        $frontendExitCode = if ($frontend.HasExited) { $frontend.ExitCode } else { $null }
        if ($null -ne $frontendExitCode) {
            throw "Frontend process exited before port 5173 became ready (exit code $frontendExitCode). Logs: $frontendOutLog and $frontendErrLog."
        }
        throw "Frontend startup timed out after $FrontendStartupTimeoutSeconds seconds. Logs: $frontendOutLog and $frontendErrLog."
    }
} catch {
    & (Join-Path $PSScriptRoot 'stop-all.ps1')
    throw
}

Write-Host 'Backend and frontend started successfully.' -ForegroundColor Green
Write-Host 'Login username: admin'
Write-Host ("Login password: {0}" -f $developmentSecrets.adminPassword) -ForegroundColor Yellow
Write-Host 'Frontend: http://127.0.0.1:5173'
Write-Host 'Backend:  http://127.0.0.1:8080'
Write-Host "Logs:     $logDir"

if (-not $NoBrowser) {
    Start-Process 'http://127.0.0.1:5173'
}
