param([string]$Python = 'python', [switch]$FullRegression, [string]$OcrModels)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$run = Join-Path $root ('reports\runtime-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run | Out-Null
$runtimeProcess = $null
$mockProcess = $null
try {
  foreach ($port in @(18091,18092)) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
    try { $listener.Start() } finally { $listener.Stop() }
  }
  if ($FullRegression) {
    $env:ICP_OCR_MODELS = if ($OcrModels) { (Resolve-Path $OcrModels).Path } else { Join-Path $root 'security-toolbox-server\data\models\icp' }
    foreach ($asset in @('det.onnx','rec.onnx','ppocr_keys_v1.txt')) {
      if (!(Test-Path -LiteralPath (Join-Path $env:ICP_OCR_MODELS $asset) -PathType Leaf)) { throw 'Full regression requires real OCR assets; run fetch-ocr-e2e-models.py first' }
    }
  }
  $env:AI_RUNTIME_E2E = 'true'
  $env:AI_RUNTIME_URL = 'http://127.0.0.1:18092'
  $env:AI_RUNTIME_TOKEN = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
  $env:AI_RUNTIME_PROJECT_SIGNING_SECRET = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
  $env:AI_RUNTIME_LLM_ENABLED = 'true'
  $env:AI_RUNTIME_BASE_URL = 'http://127.0.0.1:18091/v1'
  $env:AI_RUNTIME_API_KEY = 'mock-key'
  $env:AI_RUNTIME_MODEL = 'mock-harness-model'
  $mockProcess = Start-Process $Python -ArgumentList @('tests/mock_openai_server.py','--port','18091') -WorkingDirectory (Join-Path $root 'ai-runtime') -RedirectStandardOutput (Join-Path $run 'mock.stdout.log') -RedirectStandardError (Join-Path $run 'mock.stderr.log') -PassThru
  $runtimeProcess = Start-Process $Python -ArgumentList @('runtime_server.py','--port','18092','--data-dir',(Join-Path $run 'data')) -WorkingDirectory (Join-Path $root 'ai-runtime') -RedirectStandardOutput (Join-Path $run 'runtime.stdout.log') -RedirectStandardError (Join-Path $run 'runtime.stderr.log') -PassThru
  $ready = $false
  for ($i=0; $i -lt 60; $i++) {
    if ($runtimeProcess.HasExited) { throw 'Isolated Python runtime exited; inspect runtime.stderr.log' }
    try { $h=Invoke-RestMethod ($env:AI_RUNTIME_URL + '/health') -TimeoutSec 2; $ready=$true; break } catch { Start-Sleep -Milliseconds 500 }
  }
  if (!$ready) { throw 'Isolated runtime did not become ready' }
  Write-Output ('Evidence: ' + $run)
  Write-Output ('Runtime ready, PID ' + $runtimeProcess.Id + '; deterministic LLM fixture PID ' + $mockProcess.Id)
  $arguments = @('-B','-ntp','-f',(Join-Path $root 'security-toolbox-server\pom.xml'),'test')
  if (!$FullRegression) { $arguments += '-Dtest=AiPythonAgentRouteEndToEndTests,AiPythonRuntimeEndToEndTests' }
  & mvn @arguments *> (Join-Path $run 'maven.log')
  $result = $LASTEXITCODE
  Write-Output ('Maven exit: ' + $result)
  exit $result
} finally {
  foreach ($process in @($runtimeProcess,$mockProcess)) {
    if ($null -ne $process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
  }
}
