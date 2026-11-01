# Run Sentinel-Graph on this machine only (Windows PowerShell 5.1+).
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_local.ps1 [-Python <path>]
#
# Starts the Vite dev server (frontend, http://localhost:5173, live reload) in the
# background and the FastAPI backend (http://127.0.0.1:8000) in this window, then
# opens the browser. Nothing is reachable from outside this computer.
# Ctrl-C stops both. Run setup.bat once first on a fresh clone.
param(
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Frontend = Join-Path $Root 'frontend'

foreach ($port in 5173, 8000) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Stop whatever is running there first."
    }
}
if (-not (Test-Path (Join-Path $Frontend 'node_modules'))) {
    throw 'frontend\node_modules is missing. Run setup.bat once first.'
}

$Logs = Join-Path $env:TEMP 'sentinel-graph-local'
New-Item -ItemType Directory -Force $Logs | Out-Null

$frontendProc = $null
try {
    Write-Host '== Starting the frontend on http://localhost:5173' -ForegroundColor Cyan
    $frontendProc = Start-Process -PassThru -WindowStyle Hidden -FilePath 'cmd.exe' `
        -ArgumentList '/c', "npm --prefix `"$Frontend`" run dev -- --port 5173 --strictPort" `
        -RedirectStandardOutput (Join-Path $Logs 'frontend.log') -RedirectStandardError (Join-Path $Logs 'frontend.err.log')

    Write-Host ''
    Write-Host '  Open:  http://localhost:5173' -ForegroundColor Green
    Write-Host "  Frontend log: $Logs\frontend.log"
    Write-Host '  Ctrl-C stops both.'
    Write-Host ''
    Start-Process 'http://localhost:5173'

    Write-Host '== Starting the backend on http://127.0.0.1:8000 (loading models takes ~30 s)' -ForegroundColor Cyan
    Set-Location $Root
    & $Python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
}
finally {
    Write-Host '== Stopping the frontend' -ForegroundColor Cyan
    if ($frontendProc -and -not $frontendProc.HasExited) { & taskkill /PID $frontendProc.Id /T /F | Out-Null }
}
