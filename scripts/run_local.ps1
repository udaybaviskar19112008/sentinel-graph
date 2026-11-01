# Run Sentinel-Graph on this machine only (Windows PowerShell 5.1+).
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_local.ps1 [-Python <path>]
#
# Starts the Vite dev server (frontend, http://localhost:5173, live reload) and the
# FastAPI backend (http://127.0.0.1:8000) in this window, and opens the browser once
# the backend has loaded its models. Nothing is reachable from outside this computer.
# Ctrl-C, or closing the window, stops both. Run setup.bat once first on a fresh clone;
# the Python it recorded in .sentinel-python is used unless -Python is given.
param(
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Frontend = Join-Path $Root 'frontend'
$Url = 'http://localhost:5173'

# Covers IPv6 too: Vite often listens on ::1 only.
function Test-Listening([int]$Port) {
    [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners().Port -contains $Port
}

function Get-PortOwner([int]$Port) {
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($conn) { Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue }
    }
    catch { $null }
}

function Show-Log([string]$Path, [switch]$Head) {
    if (-not (Test-Path -LiteralPath $Path) -or (Get-Item -LiteralPath $Path).Length -eq 0) { return }
    Write-Host "-- $Path" -ForegroundColor DarkGray
    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    $lines = if ($Head) { $lines | Select-Object -First 15 } else { $lines | Select-Object -Last 10 }
    # rolldown colours its errors even in a file (it ignores NO_COLOR).
    $lines | ForEach-Object { Write-Host ('   ' + ($_ -replace '\x1b\[[0-9;]*m', '')) }
}

# Vite's error comes first in its stderr log, ahead of the stack trace.
function Show-FrontendLog { Show-Log $FrontendLog; Show-Log $FrontendErr -Head }

$Logs = Join-Path $env:TEMP 'sentinel-graph-local'
$FrontendLog = Join-Path $Logs 'frontend.log'
$FrontendErr = Join-Path $Logs 'frontend.err.log'
$frontendProc = $null
$backendProc = $null
$failed = $false
try {
    if (-not $Python) {
        $Python = 'python'
        $recorded = Join-Path $Root '.sentinel-python'
        if (Test-Path -LiteralPath $recorded) {
            $path = "$(Get-Content -LiteralPath $recorded -TotalCount 1)".Trim()
            if ($path -and (Test-Path -LiteralPath $path)) { $Python = $path }
            else { Write-Host "  setup.bat recorded '$path', which is gone; trying 'python' from PATH." -ForegroundColor Yellow }
        }
    }
    if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
        throw "Python ('$Python') was not found. Run setup.bat first."
    }
    & $Python -c 'import fastapi, uvicorn'
    if ($LASTEXITCODE -ne 0) {
        throw "The backend's packages are not installed for $Python. Run setup.bat first, or pass the Python you installed them into: run.bat C:\path\to\python.exe"
    }
    $node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $node) { throw 'Node.js was not found. Install it from https://nodejs.org, then run setup.bat.' }
    if (-not (Test-Path -LiteralPath (Join-Path $Frontend 'node_modules\vite\bin\vite.js'))) {
        throw 'frontend\node_modules is missing or incomplete. Run setup.bat first.'
    }
    foreach ($port in 5173, 8000) {
        if (Test-Listening $port) {
            $owner = Get-PortOwner $port
            $who = if ($owner) { "$($owner.ProcessName).exe (PID $($owner.Id))" } else { 'another program' }
            $hint = if ($owner) { " If it is an earlier run.bat, close that window or run: taskkill /PID $($owner.Id) /T /F" } else { '' }
            throw "Port $port is already in use by $who.$hint"
        }
    }

    New-Item -ItemType Directory -Force $Logs | Out-Null
    $noInput = Join-Path $Logs 'no-input.txt'
    [IO.File]::WriteAllText($noInput, '')

    Write-Host '== Starting the frontend on http://localhost:5173' -ForegroundColor Cyan
    # Attached to this console, so closing the window stops it too (a hidden window would
    # outlive this one and hold the port). Stdin is an empty file: on the console, Vite's
    # keyboard shortcuts would switch it to raw mode and Ctrl-C would stop reaching uvicorn.
    $frontendProc = Start-Process -PassThru -NoNewWindow -FilePath $node.Source -WorkingDirectory $Frontend `
        -ArgumentList 'node_modules\vite\bin\vite.js', '--port', '5173', '--strictPort' `
        -RedirectStandardInput $noInput -RedirectStandardOutput $FrontendLog -RedirectStandardError $FrontendErr
    $null = $frontendProc.Handle  # without a cached handle, ExitCode reads as empty
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Listening 5173)) {
        if ($frontendProc.HasExited) {
            Show-FrontendLog
            throw "The frontend stopped during startup (exit code $($frontendProc.ExitCode)); its log is above."
        }
        if ((Get-Date) -gt $deadline) { Show-FrontendLog; throw 'The frontend did not start within 60 s; its log is above.' }
        Start-Sleep -Milliseconds 500
    }

    Write-Host '== Starting the backend on http://127.0.0.1:8000 (loading the models takes about 30 s)' -ForegroundColor Cyan
    # uvicorn listens only after the app's startup (model loading) has finished, so a
    # listening port means the dashboard can scan. Its output goes to this window.
    $backendProc = Start-Process -PassThru -NoNewWindow -FilePath $Python -WorkingDirectory $Root `
        -ArgumentList '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'
    $null = $backendProc.Handle
    while (-not (Test-Listening 8000)) {
        if ($backendProc.HasExited) { throw "The backend stopped during startup (exit code $($backendProc.ExitCode)); its error is above." }
        Start-Sleep -Milliseconds 500
    }

    Write-Host ''
    Write-Host "  Ready:  $Url" -ForegroundColor Green
    Write-Host "  Frontend log: $FrontendLog"
    Write-Host '  Ctrl-C (or closing this window) stops both.'
    Write-Host ''
    # Opening the browser is a convenience; a broken default-browser association
    # must not take the servers down with it.
    try { Start-Process $Url }
    catch { Write-Host '  (Could not open the browser automatically - open the link above yourself.)' -ForegroundColor Yellow }

    while (-not $backendProc.HasExited) {
        if ($frontendProc.HasExited) {
            Show-FrontendLog
            throw "The frontend stopped (exit code $($frontendProc.ExitCode)); its log is above."
        }
        Start-Sleep -Milliseconds 500
    }
    # Ctrl-C never gets here (it stops the script), so the backend exited on its own.
    throw "The backend stopped (exit code $($backendProc.ExitCode)); its error is above."
}
catch {
    Write-Host ''
    Write-Host $_.Exception.Message -ForegroundColor Red
    $failed = $true
}
finally {
    if ($frontendProc -or $backendProc) { Write-Host '== Stopping Sentinel-Graph' -ForegroundColor Cyan }
    # After Ctrl-C uvicorn is already shutting down; give it a moment to close the database.
    $grace = if ($failed) { 0 } else { 5000 }
    if ($backendProc -and -not $backendProc.WaitForExit($grace)) { & taskkill /PID $backendProc.Id /T /F | Out-Null }
    if ($frontendProc -and -not $frontendProc.HasExited) { & taskkill /PID $frontendProc.Id /T /F | Out-Null }
}
if ($failed) { exit 1 }
