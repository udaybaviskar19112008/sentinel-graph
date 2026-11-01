# Host Sentinel-Graph on a public Cloudflare quick tunnel (Windows PowerShell 5.1+).
#
#   powershell -ExecutionPolicy Bypass -File scripts\host_tunnel.ps1 [-SkipBuild] [-Python <path>]
#
# 1. Builds the frontend and serves the production build with `vite preview` on :5173
#    (the dev server is too slow through a tunnel).
# 2. Opens `cloudflared tunnel --url http://localhost:5173` and reads its random
#    https://<words>.trycloudflare.com address from the log.
# 3. Starts the backend on :8000 with that address added to SOC_CORS_ALLOW_ORIGINS:
#    the analysis WebSocket checks the browser's Origin, so without it every scan
#    through the tunnel is refused (close code 1006).
#
# Ctrl-C stops the backend, the tunnel and the preview server together. The address
# changes on every run. Anyone with it can see the scan history and submit emails.
param(
    [switch]$SkipBuild,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Port = 5173

if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    throw 'cloudflared is not on PATH. Install it: winget install --id Cloudflare.cloudflared'
}
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is already in use (a dev server?). Stop it first."
}
if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) {
    throw 'Port 8000 is already in use. Stop the other backend first.'
}

$Frontend = Join-Path $Root 'frontend'
if (-not $SkipBuild) {
    Write-Host '== Building the frontend' -ForegroundColor Cyan
    npm --prefix $Frontend run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
}

$Logs = Join-Path $env:TEMP 'sentinel-graph-tunnel'
New-Item -ItemType Directory -Force $Logs | Out-Null
$TunnelLog = Join-Path $Logs 'cloudflared.log'
Remove-Item $TunnelLog -ErrorAction SilentlyContinue

$preview = $null
$tunnel = $null
try {
    Write-Host "== Serving the build on http://localhost:$Port" -ForegroundColor Cyan
    $preview = Start-Process -PassThru -WindowStyle Hidden -FilePath 'cmd.exe' `
        -ArgumentList '/c', "npm --prefix `"$Frontend`" run preview -- --port $Port --strictPort" `
        -RedirectStandardOutput (Join-Path $Logs 'preview.log') -RedirectStandardError (Join-Path $Logs 'preview.err.log')

    Write-Host '== Opening the Cloudflare quick tunnel' -ForegroundColor Cyan
    $tunnel = Start-Process -PassThru -WindowStyle Hidden -FilePath 'cloudflared' `
        -ArgumentList 'tunnel', '--url', "http://localhost:$Port", '--logfile', $TunnelLog

    $url = $null
    for ($i = 0; $i -lt 60 -and -not $url; $i++) {
        Start-Sleep -Seconds 1
        if (Test-Path $TunnelLog) {
            $hit = Select-String -Path $TunnelLog -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' | Select-Object -First 1
            if ($hit) { $url = $hit.Matches[0].Value }
        }
        if ($tunnel.HasExited) { throw "cloudflared exited early; see $TunnelLog" }
    }
    if (-not $url) { throw "No tunnel address after 60 s; see $TunnelLog" }

    $env:SOC_CORS_ALLOW_ORIGINS = "[`"http://localhost:$Port`",`"http://127.0.0.1:$Port`",`"$url`"]"
    Write-Host ''
    Write-Host "  Public URL:  $url" -ForegroundColor Green
    Write-Host "  Local URL:   http://localhost:$Port"
    Write-Host '  Ctrl-C stops everything.'
    Write-Host ''

    Set-Location $Root
    & $Python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
}
finally {
    Write-Host '== Stopping the tunnel and the preview server' -ForegroundColor Cyan
    foreach ($p in @($tunnel, $preview)) {
        if ($p -and -not $p.HasExited) { & taskkill /PID $p.Id /T /F | Out-Null }
    }
}
