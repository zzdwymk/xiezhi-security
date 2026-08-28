param(
    [switch]$SkipComponentBuild,
    [switch]$Force,
    [string]$Python,
    # 'Fastest' cuts archive time roughly in half at the cost of a larger zip;
    # pass -ZipCompressionLevel Optimal for the smallest artifact.
    [ValidateSet('Optimal', 'Fastest')]
    [string]$ZipCompressionLevel = 'Fastest'
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
$staging = $null
$resolvedReleaseRoot = $null
$releaseSucceeded = $false

# Helper to find the newest LastWriteTimeUtc among files/directories
function Get-NewestFileTimeUtc([string[]]$Paths, [string[]]$ExcludePatterns = @()) {
    $newest = [DateTime]::MinValue
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path
            if ($item.LastWriteTimeUtc -gt $newest) { $newest = $item.LastWriteTimeUtc }
        } else {
            $files = Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $skip = $false
                foreach ($pattern in $ExcludePatterns) {
                    if ($file.FullName -like "*$pattern*") { $skip = $true; break }
                }
                if (-not $skip -and $file.LastWriteTimeUtc -gt $newest) {
                    $newest = $file.LastWriteTimeUtc
                }
            }
        }
    }
    return $newest
}

# 精确检测 target/classes 里是否存在“孤儿” .class —— 即不能被当前任一 .java 源派生出来的
# 已编译输出。派生关系：一个 X.java 对应顶层类 X，以及 X$<内部/匿名类> 这组 .class。
# 只要存在无法匹配到任何当前源的 .class，则说明有被删除源文件残留的旧 class，需要 clean 重建。
# 该方法对单个/内部/匿名/枚举类都成立，无数量阈值、无误报、无漏检。
function Test-StaleBackendClasses([string]$BackendDir) {
    $classesRoot = Join-Path $BackendDir 'target\classes'
    $javaRoot = Join-Path $BackendDir 'src\main\java'
    if (-not (Test-Path -LiteralPath $classesRoot -PathType Container)) { return $false }
    if (-not (Test-Path -LiteralPath $javaRoot -PathType Container)) { return $false }

    # 0) 兜底——读取 Maven 上次编译记录的源码清单 inputFiles.lst。只要上次参与编译的一个
    #    .java 现在已不存在于源码树，就说明发生了“源文件删除/改名”，增量构建无法自行清理，
    #    必须强制 clean 重建。这是对数量/前缀判据之外更硬、无漏检的判定。
    $inputList = Join-Path $BackendDir (
        'target\maven-status\maven-compiler-plugin\compile\default-compile\inputFiles.lst'
    )
    if (Test-Path -LiteralPath $inputList -PathType Leaf) {
        foreach ($prevSourcePath in (Get-Content -LiteralPath $inputList -ErrorAction SilentlyContinue)) {
            $prevSourcePath = $prevSourcePath.Trim()
            if ([string]::IsNullOrWhiteSpace($prevSourcePath)) { continue }
            if ($prevSourcePath.EndsWith('.java', [System.StringComparison]::OrdinalIgnoreCase) -and
                -not (Test-Path -LiteralPath $prevSourcePath -PathType Leaf)) {
                # 上次编译过、现在却找不到的源文件 → 一定有删除残留
                return $true
            }
        }
    }

    # 1) 收集所有当前 .java 对应的“外层类相对路径”（去掉 .java 后缀、统一成反斜杠）。
    $prefixes = [System.Collections.Generic.List[string]]::new()
    Get-ChildItem -LiteralPath $javaRoot -Recurse -Filter *.java -File |
        ForEach-Object {
            $rel = $_.FullName.Substring($javaRoot.Length).TrimStart('\', '/')
            if ($rel.EndsWith('.java', [System.StringComparison]::OrdinalIgnoreCase)) {
                $prefixes.Add($rel.Substring(0, $rel.Length - 5).Replace('/', '\'))
            }
        }
    if ($prefixes.Count -eq 0) { return $false }

    # 2) 对每个 .class：若 相对路径(去 .class，统一反斜杠) 恰好等于某前缀(顶层类)，
    #    或以 “前缀 + '$'” 开头(内部/匿名类)，则视为当前源可派生；否则就是孤儿(被删源的残留)。
    $stale = $false
    Get-ChildItem -LiteralPath $classesRoot -Recurse -Filter *.class -File |
        ForEach-Object {
            $relNoExt = $_.FullName.Substring($classesRoot.Length).TrimStart('\', '/')
            $relNoExt = $relNoExt.Substring(0, $relNoExt.Length - 6).Replace('/', '\')
            $derived = $false
            foreach ($p in $prefixes) {
                if ($relNoExt -eq $p -or $relNoExt.StartsWith($p + '$')) {
                    $derived = $true
                    break
                }
            }
            if (-not $derived) { $stale = $true }
        }
    return $stale
}

# 生成“源码树签名”：对目录下所有排除项之外的文件，按 相对路径|长度|最后修改时间 排序拼接。
# 只要任一文件被新增/删除/改名/内容(大小)变化/时间变化，签名必然改变。这是前端/AI 这类
# 没有构建清单产物判断“源被删除”的兜底：旧签名(上次成功构建)与当前签名不一致，就重建。
function Get-SourceSignature([string]$Root, [string[]]$ExcludePatterns) {
    $lines = [System.Collections.Generic.List[string]]::new()
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $skip = $false
            foreach ($pat in $ExcludePatterns) {
                if ($_.FullName -like "*$pat*") { $skip = $true; break }
            }
            -not $skip
        } |
        ForEach-Object {
            $rel = $_.FullName.Substring($Root.Length).TrimStart('\', '/').Replace('/', '\')
            $lines.Add(('{0}|{1}|{2}' -f $rel, $_.Length, $_.LastWriteTimeUtc.Ticks))
        }
    $lines.Sort()
    return ($lines -join "`n")
}

# 判断某产物是否需要根据源码状态重建：清单缺失 or 签名与上次成功构建记录的清单不一致。
# manifest 文件自身在 ExcludePatterns 里，避免被计入签名造成自循环。
function Test-ProduceNeedsRebuild(
    [string]$Root,
    [string]$ManifestPath,
    [string[]]$ExcludePatterns
) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $true }
    $last = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($last)) { return $true }
    return $last -ne (Get-SourceSignature $Root $ExcludePatterns)
}

# 在成功构建后写入/更新源码清单，供下一次增量判断使用。
function Write-SourceManifest([string]$Root, [string]$ManifestPath, [string[]]$ExcludePatterns) {
    $signature = Get-SourceSignature $Root $ExcludePatterns
    [IO.File]::WriteAllText($ManifestPath, $signature, [Text.UTF8Encoding]::new($false))
}

# Per-stage timing: each stage logs its own duration as it finishes, and a
# summary table with the total is printed at the end of a successful run.
$stageTimings = [System.Collections.Generic.List[pscustomobject]]::new()
$totalStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Format-StageDuration([TimeSpan]$Duration) {
    if ($Duration.TotalMinutes -ge 1) {
        return ('{0}m {1:D2}s' -f [int]$Duration.TotalMinutes, $Duration.Seconds)
    }
    return ('{0:N1}s' -f $Duration.TotalSeconds)
}

function Start-Stage {
    return [System.Diagnostics.Stopwatch]::StartNew()
}

function Stop-Stage([string]$Name, [System.Diagnostics.Stopwatch]$Watch) {
    $Watch.Stop()
    $stageTimings.Add([pscustomobject]@{ Stage = $Name; Elapsed = $Watch.Elapsed })
    Write-Host ("{0} took {1}." -f $Name, (Format-StageDuration $Watch.Elapsed)) -ForegroundColor DarkGray
}

if (-not $SkipComponentBuild) {
    # 1. AI Runtime delta check
    $aiBuiltExe = Join-Path $aiRuntime 'dist\security-toolbox-ai-runtime\security-toolbox-ai-runtime.exe'
    # Watch entire ai-runtime tree (covers app/**/*.py, spec, requirements, etc.) excluding build artefacts
    # 和构建产物自身(.manifest 用于记录上次成功构建的源码签名，必须排除以免自循环)。
    $aiExcludes = @('__pycache__', '.pytest_cache', 'build', 'dist', '.venv', 'venv', '.git',
        'tests/__pycache__', '.toolbox-build-manifest.json')
    $aiManifest = Join-Path $aiRuntime '.toolbox-build-manifest.json'
    $needAiBuild = $Force -or (-not (Test-Path -LiteralPath $aiBuiltExe -PathType Leaf)) `
        -or (Test-ProduceNeedsRebuild $aiRuntime $aiManifest $aiExcludes)

    $stageWatch = Start-Stage
    if ($needAiBuild) {
        Write-Host 'Building and validating local AI Runtime...' -ForegroundColor Cyan
        $aiBuildArguments = @{ SkipInstall = $true }
        if ($Python) { $aiBuildArguments.Python = $Python }
        & (Join-Path $aiRuntime 'build-windows.ps1') @aiBuildArguments
        if ($LASTEXITCODE -ne 0) { throw 'AI Runtime build failed.' }
        if (-not (Test-Path -LiteralPath $aiBuiltExe -PathType Leaf)) { throw 'AI Runtime executable was not produced.' }
        Write-SourceManifest $aiRuntime $aiManifest $aiExcludes
        Stop-Stage 'AI Runtime build' $stageWatch
    } else {
        Write-Host 'AI Runtime is up-to-date (reusing existing binary).' -ForegroundColor Green
        Stop-Stage 'AI Runtime build (cached)' $stageWatch
    }

    # 2. Spring Boot backend delta check - watch entire module excluding build output
    $backendJar = Join-Path $backend 'target\security-toolbox-server-0.1.0.jar'
    $backendSources = @((Join-Path $backend '.'))
    $needBackendBuild = $Force -or (-not (Test-Path -LiteralPath $backendJar -PathType Leaf))
    if (-not $needBackendBuild) {
        $backendJarTime = (Get-Item -LiteralPath $backendJar).LastWriteTimeUtc
        $backendSourceNewest = Get-NewestFileTimeUtc $backendSources @('target', '.git', '.idea', '.mvn/wrapper')
        if ($backendSourceNewest -gt $backendJarTime) {
            $needBackendBuild = $true
        }
        # 判断 target/classes 里是否有“孤儿 .class”（源文件被删除后残留的旧编译输出）。
        # 若存在，说明增量构建已把已删代码打进过 jar，必须 clean 重建。
        if (-not $needBackendBuild) {
            # Maven 增量打包在源文件被删除后，target/classes 仍会残留旧 .class（会把已删代码打进包）。
            # 不能用“class 数 > 源数×倍数”这种启发式（一个 .java 会生成顶层/内部/匿名多个 .class，
            # 这里 224 个源对应 392 个 class，必然误报）。改为精确判断：只要 target/classes 里存在
            # 一个不能由当前任一 .java 派生出来的 .class，就视为有删除残留，强制 clean 重建。
            if (Test-StaleBackendClasses $backend) {
                Write-Host 'Backend class output looks stale (orphaned classes from deleted sources), forcing clean build...' -ForegroundColor Yellow
                $needBackendBuild = $true
                $Force = $true
            }
        }
    }

    $stageWatch = Start-Stage
    if ($needBackendBuild) {
        Write-Host 'Building Spring Boot engine...' -ForegroundColor Cyan
        # Always use clean for correctness; -DskipTests keeps it fast (~8-12s vs 20s+ with tests)
        & $maven -B -ntp clean package -DskipTests -f (Join-Path $backend 'pom.xml')
        if ($LASTEXITCODE -ne 0) { throw 'Backend build failed.' }
        if (-not (Test-Path -LiteralPath $backendJar -PathType Leaf)) {
            throw 'Backend JAR was not produced by the build.'
        }
        Stop-Stage 'Spring Boot backend build' $stageWatch
    } else {
        Write-Host 'Spring Boot engine is up-to-date (reusing existing JAR).' -ForegroundColor Green
        Stop-Stage 'Spring Boot backend build (cached)' $stageWatch
    }
}
Push-Location $frontend
try {
    # 3. Vue renderer frontend delta check - watch entire web tree excluding build artefacts and deps
    $frontendDistIndex = Join-Path $frontend 'dist\index.html'
    $frontendExcludes = @('dist', 'node_modules', 'desktop-release', '.git', 'target', '.next', '.toolbox-build-manifest.json')
    $frontendManifest = Join-Path $frontend '.toolbox-build-manifest.json'
    $needFrontendBuild = $Force -or (-not (Test-Path -LiteralPath $frontendDistIndex -PathType Leaf))
    if (-not $needFrontendBuild) {
        # Verify that the existing dist is a desktop build (base './'), not a web build (base '/').
        # A web build contains href="/assets or src="/assets which fails under file:// in Electron (blank window).
        try {
            $indexContent = [IO.File]::ReadAllText($frontendDistIndex, [Text.Encoding]::UTF8)
            $isDesktopBase = $indexContent -match 'src="\./assets/' -or $indexContent -match 'href="\./assets/'
            $isWebBase = $indexContent -match 'src="/assets/' -or $indexContent -match 'href="/assets/'
            if ($isWebBase -and -not $isDesktopBase) {
                Write-Host 'Existing dist is a web build (base "/"), forcing desktop rebuild...' -ForegroundColor Yellow
                $needFrontendBuild = $true
            }
        } catch {
            $needFrontendBuild = $true
        }
    }
    if (-not $needFrontendBuild) {
        if (Test-ProduceNeedsRebuild $frontend $frontendManifest $frontendExcludes) {
            $needFrontendBuild = $true
        }
    }

    $stageWatch = Start-Stage
    if ($needFrontendBuild) {
        Write-Host 'Building Vue renderer (desktop mode)...' -ForegroundColor Cyan
        & $npmCommand.Source run build:desktop
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
        Write-SourceManifest $frontend $frontendManifest $frontendExcludes
        Stop-Stage 'Vue renderer build' $stageWatch
    } else {
        Write-Host 'Vue renderer is up-to-date (reusing existing dist).' -ForegroundColor Green
        Stop-Stage 'Vue renderer build (cached)' $stageWatch
    }

    # Stage inside the release directory so electron-builder writes the
    # unpacked app exactly where it will ship, instead of building in %TEMP%
    # and copying the whole tree a second time.
    New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
    $resolvedReleaseRoot = (Resolve-Path -LiteralPath $releaseRoot).Path.TrimEnd('\')
    if (-not $resolvedReleaseRoot.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release directory is outside the workspace: $resolvedReleaseRoot"
    }
    $staging = Join-Path $resolvedReleaseRoot ('.next-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null

    $stageWatch = Start-Stage
    Write-Host 'Packaging Electron unpacked application...' -ForegroundColor Cyan
    & $npmCommand.Source exec -- electron-builder --dir "--config.directories.output=$staging"
    if ($LASTEXITCODE -ne 0) { throw 'Electron packaging failed.' }
    # electron-builder drops its debug log next to win-unpacked; it is not a release artifact.
    Remove-Item -LiteralPath (Join-Path $staging 'builder-debug.yml') -Force -ErrorAction SilentlyContinue

    $source = Join-Path $staging 'win-unpacked'
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
    Stop-Stage 'Electron packaging' $stageWatch

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
    $stageWatch = Start-Stage
    $projectRoot = (ConvertTo-NormalizedPath $workspace).TrimEnd('\')
    $releaseDirectory = (ConvertTo-NormalizedPath $resolvedReleaseRoot).TrimEnd('\')
    $serverProjectRoot = Join-Path $projectRoot 'security-toolbox-server'
    # Only the build output and the packaged resources can hold the JAR; the
    # regex fallback in Test-ToolboxServerJarProcess still covers other paths.
    $knownServerJarPaths = @(
        Get-ChildItem -LiteralPath (Join-Path $serverProjectRoot 'target') -Filter 'security-toolbox-server*.jar' -File -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath (Join-Path $releaseDirectory 'win-unpacked\resources\server') -Filter 'security-toolbox-server*.jar' -File -ErrorAction SilentlyContinue
    ) | ForEach-Object { ConvertTo-NormalizedPath $_.FullName }

    # Snapshot the process table once and reuse it for both sweeps.
    $runningProcesses = @(Get-CimInstance Win32_Process -Property ProcessId, ExecutablePath, CommandLine)
    $runningProcesses | Where-Object {
        Test-ToolboxServerJarProcess $_ $projectRoot $releaseDirectory $knownServerJarPaths
    } | Sort-Object ProcessId -Unique | ForEach-Object {
        Stop-ProcessTreeAndVerify ([int]$_.ProcessId) "security-toolbox-server Java process"
    }

    # Stop any process still running from the previous release directory so its files can be replaced.
    $runningProcesses | Where-Object {
        $exePath = ConvertTo-NormalizedPath ([string]$_.ExecutablePath)
        $exePath -and $exePath.StartsWith($releaseDirectory + '\', [StringComparison]::OrdinalIgnoreCase)
    } | Sort-Object ProcessId -Unique | ForEach-Object {
        # The Java sweep above may have already killed some of these.
        if (Test-WindowsProcessAlive ([int]$_.ProcessId)) {
            Stop-ProcessTreeAndVerify ([int]$_.ProcessId) 'desktop release process'
        }
    }
    Stop-Stage 'Stop running release processes' $stageWatch

    $unpackedStaging = Join-Path $staging 'win-unpacked'

    # Preserve portable tools installed beside the previous executable.
    $previousTools = Get-ChildItem -Directory -LiteralPath $resolvedReleaseRoot | Where-Object {
        $_.FullName -ne $staging -and (Test-Path -LiteralPath (Join-Path $_.FullName 'tools'))
    } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($previousTools) {
        $stageWatch = Start-Stage
        $toolsSource = Join-Path $previousTools.FullName 'tools'
        $toolsTarget = Join-Path $unpackedStaging 'tools'
        # robocopy's multi-threaded copy is several times faster than Copy-Item
        # for the many small files under tools; /XD skips transient state dirs.
        & robocopy.exe $toolsSource $toolsTarget /E /MT:16 /NFL /NDL /NJH /NJS /NP /R:2 /W:1 `
            /XD (Join-Path $toolsSource '.downloads') (Join-Path $toolsSource '.staging') | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Failed to preserve portable tools (robocopy exit code $LASTEXITCODE)." }
        $global:LASTEXITCODE = 0
        Stop-Stage 'Preserve portable tools' $stageWatch
    }

    $packageJsonPath = Join-Path $frontend 'package.json'
    $packageVersion = ([IO.File]::ReadAllText($packageJsonPath, [Text.Encoding]::UTF8) | ConvertFrom-Json).version
    $portableArchiveName = "xiezhi-$packageVersion-portable.zip"
    $portableArchive = Join-Path $staging $portableArchiveName
    $stageWatch = Start-Stage
    Write-Host "Creating portable archive ($ZipCompressionLevel compression)..." -ForegroundColor Cyan
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $unpackedStaging,
        $portableArchive,
        [IO.Compression.CompressionLevel]::$ZipCompressionLevel,
        $false
    )
    $portableArchiveFile = Get-Item -LiteralPath $portableArchive
    if ($portableArchiveFile.Length -lt 100MB) {
        throw 'Portable archive was not created.'
    }
    Stop-Stage 'Portable archive (zip)' $stageWatch

    # Release files are immutable during a run, so each path is hashed once and
    # the verification and SHA256SUMS passes share the cached digests.
    $script:sha256Cache = @{}
    function Get-FileSha256([string]$path) {
        $key = [IO.Path]::GetFullPath($path)
        if ($script:sha256Cache.ContainsKey($key)) { return $script:sha256Cache[$key] }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $stream = [IO.File]::OpenRead($path)
            try {
                $buffered = [IO.BufferedStream]::new($stream, 4MB)
                try {
                    $hash = ([BitConverter]::ToString($sha256.ComputeHash($buffered)) -replace '-', '').ToLowerInvariant()
                } finally {
                    $buffered.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        } finally {
            $sha256.Dispose()
        }
        $script:sha256Cache[$key] = $hash
        return $hash
    }

    # Verify the packaged backend JAR is byte-identical to the freshly built JAR.
    $stageWatch = Start-Stage
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
    Stop-Stage 'Verify packaged artifacts (SHA256)' $stageWatch

    $stageWatch = Start-Stage
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
    Stop-Stage 'Write SHA256SUMS' $stageWatch

    $stageWatch = Start-Stage
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
    Stop-Stage 'Swap release with rollback' $stageWatch

    $totalStopwatch.Stop()
    Write-Host ''
    Write-Host 'Release timing summary:' -ForegroundColor Cyan
    foreach ($timing in $stageTimings) {
        Write-Host ('  {0,-36} {1,10}' -f $timing.Stage, (Format-StageDuration $timing.Elapsed))
    }
    Write-Host ('  {0,-36} {1,10}' -f 'Total', (Format-StageDuration $totalStopwatch.Elapsed)) -ForegroundColor Cyan
    Write-Host ''

    Write-Host "Desktop unpacked release ready: $(Join-Path $resolvedReleaseRoot ('win-unpacked\' + $packagedExe.Name))" -ForegroundColor Green
    Write-Host "Desktop portable archive ready: $(Join-Path $resolvedReleaseRoot $portableArchiveName)" -ForegroundColor Green
    Write-Host "Release checksums ready: $(Join-Path $resolvedReleaseRoot 'SHA256SUMS.txt')" -ForegroundColor Green
    $releaseSucceeded = $true
} finally {
    # A failed run leaves the staging tree behind; only ever remove the GUID
    # directory this run created inside the validated release root.
    if ($staging -and $resolvedReleaseRoot -and
        $staging.StartsWith($resolvedReleaseRoot + '\', [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $staging)) {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not $releaseSucceeded) {
        Write-Host ("Release run aborted after {0}." -f (Format-StageDuration $totalStopwatch.Elapsed)) -ForegroundColor Yellow
    }
    Pop-Location
}
