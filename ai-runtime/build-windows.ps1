param(
  [string]$Python,
 [ValidatePattern('^\d+\.\d+$')]
  [string]$MinPythonVersion = '3.11',
  [switch]$SkipInstall,
  [switch]$SkipBuild,
  [switch]$SkipHealthCheck
)
$ErrorActionPreference = 'Stop'

# Python may emit Chinese paths through the native Windows pipe. Keep the
# parent PowerShell stream UTF-8 after that child process returns as well.
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

# Keep Windows PowerShell 5.1 and native build tools on the same UTF-8 channel.
$utf8 = [System.Text.UTF8Encoding]::new($false)
function Set-Utf8ConsoleEncoding {
  [Console]::InputEncoding = $utf8
  [Console]::OutputEncoding = $utf8
  $global:OutputEncoding = $utf8
}
Set-Utf8ConsoleEncoding

$root = (Resolve-Path $PSScriptRoot).Path

function Resolve-ExecutableReference {
  param([Parameter(Mandatory = $true)][string]$Reference)

  if (Test-Path -LiteralPath $Reference -PathType Leaf) {
    return (Resolve-Path -LiteralPath $Reference).Path
  }

  if (-not [System.IO.Path]::IsPathRooted($Reference)) {
    $scriptRelative = Join-Path $root $Reference
    if (Test-Path -LiteralPath $scriptRelative -PathType Leaf) {
      return (Resolve-Path -LiteralPath $scriptRelative).Path
    }
  }

  $command = Get-Command $Reference -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($command -and $command.Source -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
    return (Resolve-Path -LiteralPath $command.Source).Path
  }

  return $null
}

function Get-PythonInfo {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$DiscoveredBy
  )

  if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { return $null }

  try {
    # Windows PowerShell 5.1 strips the double quotes embedded in a native
    # command argument. Use Python single-quoted literals so the probe works
    # both in powershell.exe and pwsh.
    $probeScript = "import json,struct,sys; print(json.dumps({'bits':struct.calcsize('P')*8,'executable':sys.executable,'implementation':sys.implementation.name,'version':'.'.join(map(str,sys.version_info[:2]))}))"
    $probeOutput = @(
      & $Executable -c $probeScript 2>$null
    )
    if ($LASTEXITCODE -ne 0 -or $probeOutput.Count -eq 0) { return $null }

    $probe = $probeOutput[-1] | ConvertFrom-Json
    if (-not $probe.executable -or -not $probe.version) { return $null }
    if (-not (Test-Path -LiteralPath $probe.executable -PathType Leaf)) { return $null }

    return [pscustomobject]@{
      Path = (Resolve-Path -LiteralPath $probe.executable).Path
      Version = [string]$probe.version
      Implementation = [string]$probe.implementation
      Bits = [int]$probe.bits
      DiscoveredBy = $DiscoveredBy
    }
  } catch {
    return $null
  }
}

function Test-PackagingPythonCompatibility {
  param([Parameter(Mandatory = $true)]$Info)

  return (
    $Info.Implementation -eq 'cpython' -and
    ([Version]$Info.Version) -ge ([Version]$MinPythonVersion) -and
    $Info.Bits -eq 64
  )
}

function Format-PythonDescription {
  param([Parameter(Mandatory = $true)]$Info)
  return "$($Info.Implementation) $($Info.Version) $($Info.Bits)-bit at $($Info.Path)"
}

function Get-PathPythonInfo {
  $command = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $command -or -not $command.Source) { return $null }
  return Get-PythonInfo -Executable $command.Source -DiscoveredBy 'PATH'
}

function Get-PyLauncherPythonCandidates {
  param([string[]]$Versions)

  $launcher = Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $launcher -or -not $launcher.Source) { return @() }

  $results = @()
  foreach ($candidateVersion in $Versions) {
    try {
      $pathOutput = @(& $launcher.Source "-$candidateVersion" -c 'import sys; print(sys.executable)' 2>$null)
      if ($LASTEXITCODE -ne 0 -or $pathOutput.Count -eq 0) { continue }
      $resolved = Resolve-ExecutableReference -Reference ([string]$pathOutput[-1]).Trim()
      if (-not $resolved) { continue }
      $info = Get-PythonInfo -Executable $resolved -DiscoveredBy "py -$candidateVersion"
      if ($info) { $results += $info }
    } catch {
      continue
    }
  }
  return $results
}

function Get-CondaPythonCandidates {
  $conda = Get-Command conda -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $conda -or -not $conda.Source) { return @() }

  try {
    $jsonOutput = @(& $conda.Source env list --json 2>$null)
    if ($LASTEXITCODE -ne 0 -or $jsonOutput.Count -eq 0) { return @() }
    $environmentList = ($jsonOutput -join [Environment]::NewLine) | ConvertFrom-Json
  } catch {
    return @()
  }

  $results = @()
  foreach ($environmentRoot in @($environmentList.envs)) {
    if (-not $environmentRoot) { continue }
    $candidate = Join-Path ([string]$environmentRoot) 'python.exe'
    $info = Get-PythonInfo -Executable $candidate -DiscoveredBy 'Conda environment'
    if ($info) { $results += $info }
  }
  return $results
}

function Resolve-PackagingPython {
  if ($Python) {
    $requested = Resolve-ExecutableReference -Reference $Python
    if (-not $requested) { throw "The requested Python executable could not be resolved: $Python" }
    $requestedInfo = Get-PythonInfo -Executable $requested -DiscoveredBy '-Python parameter'
    if (-not $requestedInfo) { throw "The requested Python executable could not be started: $requested" }
    if (-not (Test-PackagingPythonCompatibility -Info $requestedInfo)) {
      throw "The requested interpreter is $(Format-PythonDescription -Info $requestedInfo); CPython $MinPythonVersion+ 64-bit is required."
    }
    return $requestedInfo
  }

  $projectPython = Join-Path $root '.venv\Scripts\python.exe'
  $projectInfo = Get-PythonInfo -Executable $projectPython -DiscoveredBy 'ai-runtime\.venv'
  if ($projectInfo -and (Test-PackagingPythonCompatibility -Info $projectInfo)) { return $projectInfo }

  $discovered = @()
  foreach ($activeEnvironment in @(
    @{ Name = 'VIRTUAL_ENV'; Root = $env:VIRTUAL_ENV },
    @{ Name = 'CONDA_PREFIX'; Root = $env:CONDA_PREFIX }
  )) {
    if (-not $activeEnvironment.Root) { continue }
    $activePython = Join-Path ([string]$activeEnvironment.Root) 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $activePython -PathType Leaf)) {
      $activePython = Join-Path ([string]$activeEnvironment.Root) 'python.exe'
    }
    $activeInfo = Get-PythonInfo -Executable $activePython -DiscoveredBy $activeEnvironment.Name
    if ($activeInfo) { $discovered += $activeInfo }
  }

  $pathInfo = Get-PathPythonInfo
  if ($env:GITHUB_ACTIONS -eq 'true') {
    if ($pathInfo -and (Test-PackagingPythonCompatibility -Info $pathInfo)) { return $pathInfo }
    if ($pathInfo) {
      throw "GitHub Actions provided $(Format-PythonDescription -Info $pathInfo); configure actions/setup-python for CPython $MinPythonVersion+ x64."
    }
    throw 'GitHub Actions did not provide Python on PATH. Run actions/setup-python before this script.'
  }

  if ($pathInfo) { $discovered += $pathInfo }
  $minimum = [Version]$MinPythonVersion
  $launcherVersions = $minimum.Minor..($minimum.Minor + 9) |
    ForEach-Object { "$($minimum.Major).$_" }
  $discovered += @(Get-PyLauncherPythonCandidates -Versions $launcherVersions)
  $discovered += @(Get-CondaPythonCandidates)
  $match = $discovered |
    Where-Object { Test-PackagingPythonCompatibility -Info $_ } |
    Sort-Object @{ Expression = { [Version]$_.Version } }, Path -Unique |
    Select-Object -First 1
  if ($match) { return $match }

  $pathHint = if ($pathInfo) { " PATH currently resolves to $(Format-PythonDescription -Info $pathInfo)." } else { '' }
  throw "No compatible Python was found. Install CPython $MinPythonVersion+ 64-bit, create ai-runtime\.venv, activate a matching environment, or pass -Python <path-or-command>.$pathHint"
}

$pythonInfo = Resolve-PackagingPython
$pythonExe = $pythonInfo.Path
$version = (& $pythonExe -c 'import sys; print(sys.version_info.major,sys.version_info.minor,sep=chr(46))').Trim()
Set-Utf8ConsoleEncoding
if ($LASTEXITCODE -ne 0) { throw 'Unable to determine the Python version.' }
Write-Host "Packaging AI Runtime with Python $version at $pythonExe ($($pythonInfo.DiscoveredBy))" -ForegroundColor Cyan

if (-not $SkipInstall) {
  $requirements = Join-Path $root 'requirements-build.txt'
  & $pythonExe -m pip install -r $requirements
  Set-Utf8ConsoleEncoding
  if ($LASTEXITCODE -ne 0) { throw 'AI Runtime dependency installation failed.' }
}

if (-not $SkipBuild) {
  Push-Location $root
  try {
    $pytestTemp = Join-Path $root ('.pytest-package-' + [Guid]::NewGuid().ToString('N'))
    & $pythonExe -m pytest -q -p no:cacheprovider --basetemp $pytestTemp
    Set-Utf8ConsoleEncoding
    if ($LASTEXITCODE -ne 0) { throw 'AI Runtime tests failed.' }
    $spec = Join-Path $root 'ai-runtime.spec'
    & $pythonExe -m PyInstaller --noconfirm --clean $spec
    Set-Utf8ConsoleEncoding
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
  } finally {
    if ($pytestTemp -and (Test-Path -LiteralPath $pytestTemp)) {
      $resolvedPytestTemp = [System.IO.Path]::GetFullPath($pytestTemp)
      if ($resolvedPytestTemp.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedPytestTemp -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
    Pop-Location
  }
}

$exe = Join-Path $root 'dist\security-toolbox-ai-runtime\security-toolbox-ai-runtime.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Runtime executable was not generated: $exe" }

if (-not $SkipHealthCheck) {
  $testRoot = Join-Path $root ("build\health-test-{0}" -f $PID)
  $testData = Join-Path $testRoot 'data'
  $tokenFile = Join-Path $testRoot 'runtime-token.txt'
  New-Item -ItemType Directory -Force -Path $testData | Out-Null
  $token = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
  Set-Content -LiteralPath $tokenFile -Value $token -Encoding UTF8 -NoNewline
  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  $testPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
  $listener.Stop()
  $runtimeArguments = @(
    '--port', $testPort,
    '--data-dir', ('"{0}"' -f $testData),
    '--token-file', ('"{0}"' -f $tokenFile),
    '--log-level', 'warning'
  )
  # Keep stdout/stderr detached here. The packaged windowed executable has no
  # console in production, and redirecting streams would hide startup bugs.
  $runtime = Start-Process -FilePath $exe -ArgumentList $runtimeArguments -WindowStyle Hidden -PassThru
  $healthPassed = $false
  try {
    $deadline = (Get-Date).AddSeconds(45)
    $health = $null
    while ((Get-Date) -lt $deadline -and -not $health -and -not $runtime.HasExited) {
      try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$testPort/health" -TimeoutSec 2 } catch { Start-Sleep -Milliseconds 400 }
    }
    if (-not $health) {
      $startupError = Join-Path $testData 'runtime-startup-error.log'
      if (Test-Path -LiteralPath $startupError) { Get-Content -LiteralPath $startupError | Write-Error }
      throw "The packaged AI Runtime health check failed. Diagnostics: $testRoot"
    }
    if (-not $health.agent.graphCompiled) { throw 'LangGraph did not compile in the packaged runtime.' }
    if (-not ($health.components.langchain -and $health.components.langgraph -and $health.components.retrieval -and $health.components.langchainTools)) {
      throw 'The packaged LangChain/LangGraph/retrieval components are incomplete.'
    }
    Write-Host "Packaged Runtime health check passed: $($health.status)" -ForegroundColor Green
    $healthPassed = $true
  } finally {
    if ($runtime -and -not $runtime.HasExited) { Stop-Process -Id $runtime.Id -Force -ErrorAction SilentlyContinue }
    $resolvedTestRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedBuildRoot = [System.IO.Path]::GetFullPath((Join-Path $root 'build'))
    if ($healthPassed -and $resolvedTestRoot.StartsWith($resolvedBuildRoot, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTestRoot)) {
      Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
  }
}

Set-Utf8ConsoleEncoding
Write-Host "AI Runtime Windows package generated: $exe" -ForegroundColor Green
