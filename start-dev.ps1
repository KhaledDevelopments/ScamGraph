param(
    [switch]$Install,
    [ValidateRange(1024, 65535)]
    [int]$BackendPort = 8001,
    [ValidateSet('backend', 'frontend')]
    [string]$Server
)

$ErrorActionPreference = 'Stop'
$backendPath = Join-Path $PSScriptRoot 'backend'
$frontendPath = Join-Path $PSScriptRoot 'frontend'
$pythonPath = Join-Path $backendPath '.venv\Scripts\python.exe'

# Each server runs in its own terminal so its logs and Ctrl+C stay accessible.
if ($Server -eq 'backend') {
    Set-Location $backendPath
    & $pythonPath -m uvicorn main:app --reload --host 127.0.0.1 --port $BackendPort
    exit $LASTEXITCODE
}
if ($Server -eq 'frontend') {
    Set-Location $frontendPath
    $env:VITE_API_BASE_URL = "http://127.0.0.1:$BackendPort"
    & npm.cmd run dev -- --port 5173 --strictPort
    exit $LASTEXITCODE
}

foreach ($command in @('uv', 'node', 'npm.cmd')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' is missing. Install uv and Node.js, then reopen your terminal."
    }
}

Push-Location $backendPath
try {
    if (-not (Test-Path -LiteralPath $pythonPath)) {
        & uv venv --python 3.12
        if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
    }
    & uv pip install --python $pythonPath -r requirements-dev.txt
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
}
finally {
    Pop-Location
}

if ($Install -or -not (Test-Path -LiteralPath (Join-Path $frontendPath 'node_modules'))) {
    Push-Location $frontendPath
    try {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    }
    finally {
        Pop-Location
    }
}

$scriptPath = $PSCommandPath
foreach ($serverName in @('backend', 'frontend')) {
    Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$scriptPath`"", '-Server', $serverName,
        '-BackendPort', $BackendPort
    )
}

Write-Host 'Server terminals opened. Once Vite is ready, open http://localhost:5173'
Write-Host "API docs: http://127.0.0.1:$BackendPort/docs"
Write-Host 'Stop each server with Ctrl+C in its terminal, then close the windows.'
