param(
    [switch]$SkipComponentBuild,
    [string]$Python
)

$ErrorActionPreference = 'Stop'

# Keep Windows PowerShell 5.1 and native build tools on the same UTF-8 channel.
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
$aiRuntime = Join-Path $workspace 'ai-runtime'
$releaseRoot = Join-Path $frontend 'desktop-release'
$maven = (Get-Command mvn -ErrorAction Stop).Source
$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npmCommand) { $npmCommand = Get-Command npm -ErrorAction Stop }
$buildOutput = $null

if (-not $SkipComponentBuild) {
    Write-Host 'Building and validating local AI Runtime...' -ForegroundColor Cyan
    $aiBuildArguments = @{ SkipInstall = $true }
    if ($Python) { $aiBuildArguments.Python = $Python }
    & (Join-Path $aiRuntime 'build-windows.ps1') @aiBuildArguments
    if ($LASTEXITCODE -ne 0) { throw 'AI Runtime build failed.' }
    $aiBuiltExe = Join-Path $aiRuntime 'dist\security-toolbox-ai-runtime\security-toolbox-ai-runtime.exe'
    if (-not (Test-Path -LiteralPath $aiBuiltExe -PathType Leaf)) { throw 'AI Runtime executable was not produced.' }
    $aiBuiltExeTime = (Get-Item -LiteralPath $aiBuiltExe).LastWriteTime
    $aiSourcePyFiles = @()
    $aiSourcePyFiles += Get-ChildItem -Path (Join-Path $aiRuntime 'app') -Recurse -File -Filter '*.py' -ErrorAction SilentlyContinue
    $runtimeServerPy = Join-Path $aiRuntime 'runtime_server.py'
    if (Test-Path -LiteralPath $runtimeServerPy -PathType Leaf) { $aiSourcePyFiles += Get-Item -LiteralPath $runtimeServerPy }
    $staleAiSource = $aiSourcePyFiles | Where-Object { $_.LastWriteTime -gt $aiBuiltExeTime } | Select-Object -First 1
    if ($staleAiSource) { throw ('AI Runtime 源码比已打包程序新，请重新构建：' + $staleAiSource.FullName) }

    Write-Host 'Building Spring Boot engine...' -ForegroundColor Cyan
    & $maven -B -ntp clean package -f (Join-Path $backend 'pom.xml')
    if ($LASTEXITCODE -ne 0) { throw 'Backend build failed.' }
    if (-not (Test-Path -LiteralPath (Join-Path $backend 'target\security-toolbox-server-0.1.0.jar') -PathType Leaf)) {
        throw 'Backend JAR was not produced by the build.'
    }
}
Push-Location $frontend
try {
    Write-Host 'Building Vue renderer...' -ForegroundColor Cyan
    & $npmCommand.Source run build:desktop
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }

    $buildOutput = Join-Path $env:LOCALAPPDATA ('Temp\security-toolbox-build-' + [Guid]::NewGuid().ToString('N'))
    Write-Host 'Packaging Electron unpacked application...' -ForegroundColor Cyan
    & $npmCommand.Source exec -- electron-builder --dir "--config.directories.output=$buildOutput"
    if ($LASTEXITCODE -ne 0) { throw 'Electron packaging failed.' }

    $source = Join-Path $buildOutput 'win-unpacked'
    $packagedExe = Get-ChildItem -LiteralPath $source -Filter '*.exe' -File | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $packagedExe -or $packagedExe.Length -lt 100MB) {
        throw 'Packaged executable was not created.'
    }
    $packagedServer = Join-Path $source 'resources\server\security-toolbox-server.jar'
    $packagedAiRuntime = Join-Path $source 'resources\ai-runtime\security-toolbox-ai-runtime.exe'
    if (-not (Test-Path -LiteralPath $packagedServer -PathType Leaf)) {
        throw 'Backend JAR is missing from the unpacked application.'
    }
    if (-not (Test-Path -LiteralPath $packagedAiRuntime -PathType Leaf)) {
        throw 'AI Runtime is missing from the unpacked application.'
    }

    New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
    $resolvedReleaseRoot = (Resolve-Path -LiteralPath $releaseRoot).Path.TrimEnd('\')
    if (-not $resolvedReleaseRoot.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release directory is outside the workspace: $resolvedReleaseRoot"
    }

    function ConvertTo-NormalizedPath([string]$value) {
        if ([string]::IsNullOrWhiteSpace($value)) { return $null }
        try {
            return [IO.Path]::GetFullPath($value.Trim().Trim('"')).TrimEnd('\')
        } catch {
            return $null
        }
    }

    function Test-ToolboxServerJarProcess($process, [string]$projectRoot, [string]$releaseDirectory, [string[]]$knownJarPaths) {
        $executableName = [IO.Path]::GetFileName([string]$process.ExecutablePath)
        if ($executableName -notin @('java.exe', 'javaw.exe')) { return $false }
        $commandLine = [string]$process.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) { return $false }
        $normalizedCommandLine = $commandLine.Replace('/', '\')
        $serverProjectRoot = (ConvertTo-NormalizedPath (Join-Path $projectRoot 'security-toolbox-server')).TrimEnd('\')
        foreach ($knownJarPath in $knownJarPaths) {
            if ($knownJarPath -and $normalizedCommandLine.IndexOf($knownJarPath.Replace('/', '\'), [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }

        $jarMatches = [regex]::Matches(
            $normalizedCommandLine,
            '(?i)"([^"\r\n]*security-toolbox-server[^"\r\n]*\.jar)"|(?<!\S)([^\s"\r\n]*security-toolbox-server[^\s"\r\n]*\.jar)(?!\S)'
        )
        foreach ($jarMatch in $jarMatches) {
            $jarPath = if ($jarMatch.Groups[1].Success) { $jarMatch.Groups[1].Value } else { $jarMatch.Groups[2].Value }
            if (-not [IO.Path]::IsPathRooted($jarPath)) {
                $workingDirectory = ConvertTo-NormalizedPath ([string]$process.WorkingDirectory)
                if (-not $workingDirectory) { continue }
                $jarPath = Join-Path $workingDirectory $jarPath
            }
            $normalizedJarPath = ConvertTo-NormalizedPath $jarPath
            if (-not $normalizedJarPath) { continue }
            $jarName = [IO.Path]::GetFileName($normalizedJarPath)
            $underProject = $normalizedJarPath.StartsWith($serverProjectRoot + '\', [StringComparison]::OrdinalIgnoreCase)
            $underRelease = $normalizedJarPath.StartsWith($releaseDirectory + '\', [StringComparison]::OrdinalIgnoreCase)
            if ($jarName -like 'security-toolbox-server*.jar' -and ($underProject -or $underRelease)) {
                return $true
            }
        }
        return $false
    }

    function Test-WindowsProcessAlive([int]$processId) {
        return $null -ne (Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue)
    }

    function Stop-ProcessTreeAndVerify([int]$processId, [string]$description) {
        $attempts = 0
        $taskkillOutput = @()
        do {
            $attempts++
            $previousErrorActionPreference = $ErrorActionPreference
            try {
                # A matching process can exit between CIM discovery and taskkill.
                # Capture that diagnostic and decide from the follow-up liveness check.
                $ErrorActionPreference = 'Continue'
                $taskkillOutput = @(& taskkill.exe /PID $processId /T /F 2>&1 | ForEach-Object { [string]$_ })
            } finally {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            $deadline = [DateTime]::UtcNow.AddSeconds(3)
            do {
                if (-not (Test-WindowsProcessAlive $processId)) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
        } while ((Test-WindowsProcessAlive $processId) -and $attempts -lt 2)

        $stillAlive = Test-WindowsProcessAlive $processId
        $output = ($taskkillOutput -join ' ').Trim()
        $context = "description=$description; pid=$processId; attempts=$attempts; alive=$stillAlive"
        if ($output) { $context += "; taskkill=$output" }
        if ($stillAlive) {
            throw "Unable to stop $description (PID $processId). $context"
        }
        Write-Host "Stopped $description (PID $processId); taskkill attempts: $attempts" -ForegroundColor DarkGray
    }

    # Match only Java processes whose command line references this project's server JAR.
    $projectRoot = (ConvertTo-NormalizedPath $workspace).TrimEnd('\')
    $releaseDirectory = (ConvertTo-NormalizedPath $resolvedReleaseRoot).TrimEnd('\')
    $serverProjectRoot = Join-Path $projectRoot 'security-toolbox-server'
    $knownServerJarPaths = @(
        Get-ChildItem -LiteralPath $serverProjectRoot -Filter 'security-toolbox-server*.jar' -File -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $releaseDirectory -Filter 'security-toolbox-server*.jar' -File -Recurse -ErrorAction SilentlyContinue
    ) | ForEach-Object { ConvertTo-NormalizedPath $_.FullName }
    Get-CimInstance Win32_Process | Where-Object {
        Test-ToolboxServerJarProcess $_ $projectRoot $releaseDirectory $knownServerJarPaths
    } | Sort-Object ProcessId -Unique | ForEach-Object {
        Stop-ProcessTreeAndVerify ([int]$_.ProcessId) "security-toolbox-server Java process"
    }

    # Stop any process still running from the previous release directory so its files can be replaced.
    Get-CimInstance Win32_Process | Where-Object {
        $exePath = ConvertTo-NormalizedPath ([string]$_.ExecutablePath)
        $exePath -and $exePath.StartsWith($releaseDirectory + '\', [StringComparison]::OrdinalIgnoreCase)
    } | Sort-Object ProcessId -Unique | ForEach-Object {
        Stop-ProcessTreeAndVerify ([int]$_.ProcessId) 'desktop release process'
    }

    $staging = Join-Path $resolvedReleaseRoot ('.next-' + [Guid]::NewGuid().ToString('N'))
    $unpackedStaging = Join-Path $staging 'win-unpacked'
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $unpackedStaging -Recurse

    # Preserve portable tools installed beside the previous executable.
    $previousTools = Get-ChildItem -Directory -LiteralPath $resolvedReleaseRoot | Where-Object {
        $_.FullName -ne $staging -and (Test-Path -LiteralPath (Join-Path $_.FullName 'tools'))
    } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($previousTools) {
        $toolsSource = Join-Path $previousTools.FullName 'tools'
        $toolsTarget = Join-Path $unpackedStaging 'tools'
        Copy-Item -LiteralPath $toolsSource -Destination $toolsTarget -Recurse -Force
        Remove-Item -LiteralPath (Join-Path $toolsTarget '.downloads') -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $toolsTarget '.staging') -Recurse -Force -ErrorAction SilentlyContinue
    }

    $packageJsonPath = Join-Path $frontend 'package.json'
    $packageVersion = ([IO.File]::ReadAllText($packageJsonPath, [Text.Encoding]::UTF8) | ConvertFrom-Json).version
    $portableArchiveName = "xiezhi-$packageVersion-portable.zip"
    $portableArchive = Join-Path $staging $portableArchiveName
    Write-Host 'Creating portable archive...' -ForegroundColor Cyan
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $unpackedStaging,
        $portableArchive,
        [IO.Compression.CompressionLevel]::Optimal,
        $false
    )
    $portableArchiveFile = Get-Item -LiteralPath $portableArchive
    if ($portableArchiveFile.Length -lt 100MB) {
        throw 'Portable archive was not created.'
    }

    function Get-FileSha256([string]$path) {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $stream = [IO.File]::OpenRead($path)
            try {
                return ([BitConverter]::ToString($sha256.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
            } finally {
                $stream.Dispose()
            }
        } finally {
            $sha256.Dispose()
        }
    }

    # Verify the packaged backend JAR is byte-identical to the freshly built JAR.
    $sourceBackendJar = Join-Path $backend 'target\security-toolbox-server-0.1.0.jar'
    $packagedJar = Join-Path $unpackedStaging 'resources\server\security-toolbox-server.jar'
    if (-not (Test-Path -LiteralPath $packagedJar -PathType Leaf)) { throw 'Packaged backend JAR is missing.' }
    if (-not (Test-Path -LiteralPath $sourceBackendJar -PathType Leaf)) { throw 'Source backend JAR is missing.' }
    if ((Get-FileSha256 $packagedJar) -ne (Get-FileSha256 $sourceBackendJar)) {
        throw 'Packaged backend JAR does not match the freshly built JAR.'
    }

    # Verify every packaged AI runtime file matches the freshly built onedir copy.
    $aiSourceDir = Join-Path $aiRuntime 'dist\security-toolbox-ai-runtime'
    $aiPackagedDir = Join-Path $unpackedStaging 'resources\ai-runtime'
    if (-not (Test-Path -LiteralPath $aiSourceDir -PathType Container)) { throw 'Source AI runtime directory is missing.' }
    if (-not (Test-Path -LiteralPath $aiPackagedDir -PathType Container)) { throw 'Packaged AI runtime directory is missing.' }
    foreach ($aiSourceFile in (Get-ChildItem -LiteralPath $aiSourceDir -Recurse -File)) {
        $aiRelative = $aiSourceFile.FullName.Substring($aiSourceDir.Length).TrimStart('\').Replace('\','/')
        $aiPackagedFile = Join-Path $aiPackagedDir $aiRelative.Replace('/','\')
        if (-not (Test-Path -LiteralPath $aiPackagedFile -PathType Leaf)) {
            throw 'Packaged AI runtime is missing file: ' + $aiRelative
        }
        if ((Get-FileSha256 $aiSourceFile.FullName) -ne (Get-FileSha256 $aiPackagedFile)) {
            throw 'Packaged AI runtime file mismatch: ' + $aiRelative
        }
    }

    $checksumEntries = @(
        @{ Path = $portableArchive; Name = $portableArchiveName },
        @{ Path = (Join-Path $unpackedStaging $packagedExe.Name); Name = ('win-unpacked/' + $packagedExe.Name) },
        @{ Path = (Join-Path $unpackedStaging 'resources\app.asar'); Name = 'win-unpacked/resources/app.asar' },
        @{ Path = $packagedJar; Name = 'win-unpacked/resources/server/security-toolbox-server.jar' }
    )
    # Hash every file inside the packaged AI runtime so the full onedir is covered.
    $checksumEntries += Get-ChildItem -LiteralPath $aiPackagedDir -Recurse -File | ForEach-Object {
        $aiRelative = $_.FullName.Substring($aiPackagedDir.Length).TrimStart('\').Replace('\','/')
        @{ Path = $_.FullName; Name = ('win-unpacked/resources/ai-runtime/' + $aiRelative) }
    }
    $checksumLines = foreach ($entry in $checksumEntries) {
        if (-not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) {
            throw "Release checksum target is missing: $($entry.Name)"
        }
        "$(Get-FileSha256 $entry.Path)  $($entry.Name)"
    }
    [IO.File]::WriteAllLines((Join-Path $staging 'SHA256SUMS.txt'), $checksumLines, [Text.UTF8Encoding]::new($false))
    Write-Host 'Swapping desktop release with rollback...' -ForegroundColor Cyan
    $backupDir = Join-Path $resolvedReleaseRoot ('.previous-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Get-ChildItem -Force -LiteralPath $resolvedReleaseRoot | Where-Object { $_.FullName -ne $staging -and $_.FullName -ne $backupDir } | ForEach-Object {
        $candidate = $_.FullName
        if (-not $candidate.StartsWith($resolvedReleaseRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to move path outside release directory: $candidate"
        }
        Move-Item -LiteralPath $candidate -Destination $backupDir
    }

    try {
        Get-ChildItem -Force -LiteralPath $staging | ForEach-Object {
            Move-Item -LiteralPath $_.FullName -Destination $resolvedReleaseRoot
        }
        Remove-Item -LiteralPath $staging -Force
    } catch {
        Get-ChildItem -Force -LiteralPath $backupDir | ForEach-Object {
            Move-Item -LiteralPath $_.FullName -Destination $resolvedReleaseRoot
        }
        throw
    }

    Remove-Item -LiteralPath $backupDir -Recurse -Force
    Remove-Item -LiteralPath $buildOutput -Recurse -Force
    Write-Host "Desktop unpacked release ready: $(Join-Path $resolvedReleaseRoot ('win-unpacked\' + $packagedExe.Name))" -ForegroundColor Green
    Write-Host "Desktop portable archive ready: $(Join-Path $resolvedReleaseRoot $portableArchiveName)" -ForegroundColor Green
    Write-Host "Release checksums ready: $(Join-Path $resolvedReleaseRoot 'SHA256SUMS.txt')" -ForegroundColor Green
} finally {
    if ($buildOutput -and (Test-Path -LiteralPath $buildOutput)) {
        $tempRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Temp')).TrimEnd('\')
        $resolvedBuildOutput = [IO.Path]::GetFullPath($buildOutput)
        if ($resolvedBuildOutput.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedBuildOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Pop-Location
}
