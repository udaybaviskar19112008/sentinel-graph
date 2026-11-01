# One-shot setup for a fresh clone or ZIP download (Windows PowerShell 5.1+).
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup_local.ps1 [-Python <path>]
#
# setup.bat runs this. It picks a Python the pinned wheels exist for (64-bit CPython
# 3.12-3.14), checks Node.js against Vite 8, installs the pip packages, Playwright's
# Chromium and the frontend's node_modules, checks that the backend imports, and
# records the interpreter in .sentinel-python so run.bat uses the same one.
param(
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Prints: executable, major.minor, pointer size in bits, 1 if the GIL is enabled.
# Single quotes only: Windows PowerShell does not escape embedded double quotes for native commands.
$Probe = "import struct, sys; print(sys.executable); print('%d.%d' % sys.version_info[:2]); print(struct.calcsize('P') * 8); print(int(getattr(sys, '_is_gil_enabled', lambda: True)()))"

function Get-PythonInfo([string]$Exe) {
    # Native stderr (the Microsoft Store "python" stub's message, say) must not trip 'Stop'.
    $ErrorActionPreference = 'Continue'
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return $null }
    $out = @(& $Exe -c $Probe 2>$null)
    if ($LASTEXITCODE -ne 0 -or $out.Count -lt 4) { return $null }
    $path = "$($out[0])".Trim()
    # A path with characters outside the console code page comes back mangled.
    if (-not (Test-Path -LiteralPath $path)) { $path = (Get-Command $Exe).Source }
    [pscustomobject]@{
        Path         = $path
        Version      = [version]("$($out[1])".Trim())
        Bits         = [int]("$($out[2])".Trim())
        FreeThreaded = "$($out[3])".Trim() -eq '0'
    }
}

function Get-PythonProblem($Info) {
    if ($Info.Version -lt [version]'3.12') { return "Python $($Info.Version) is too old" }
    if ($Info.Version -gt [version]'3.14') {
        return "Python $($Info.Version) is too new: the pinned onnxruntime, numpy and scikit-learn have no wheels for it yet"
    }
    if ($Info.Bits -ne 64) { return "this is a $($Info.Bits)-bit Python; torch only ships 64-bit wheels" }
    if ($Info.FreeThreaded) { return 'this is a free-threaded build; onnxruntime has no wheels for it' }
    $null
}

function Get-LauncherPythons {
    # "py -0p" lists every python.org install with its path.
    $ErrorActionPreference = 'Continue'
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) { return @() }
    @(& py -0p 2>$null) | ForEach-Object { if ("$_" -match '([A-Za-z]:\\.*?\.exe)') { $Matches[1] } }
}

function Test-Listening([int]$Port) {
    [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners().Port -contains $Port
}

function Write-Step([string]$Text) { Write-Host "== $Text" -ForegroundColor Cyan }

try {
    $oneDrive = @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) |
        Where-Object { $_ -and $Root.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }
    if ($oneDrive) {
        Write-Host '  Note: this folder is synced by OneDrive, which can lock files while npm, pip and the scan' -ForegroundColor Yellow
        Write-Host '  database write them. If anything fails with EPERM, EBUSY or "database is locked", move the' -ForegroundColor Yellow
        Write-Host '  folder out of OneDrive (for example to C:\sentinel-graph) and run setup.bat again.' -ForegroundColor Yellow
    }

    Write-Step 'Looking for Python 3.12-3.14 (64-bit)'
    if ($Python) {
        $candidates = @($Python)
    }
    else {
        $candidates = @('python') + @(Get-LauncherPythons) +
            @("$env:USERPROFILE\anaconda3\python.exe", "$env:USERPROFILE\miniconda3\python.exe")
    }
    $chosen = $null
    $rejected = @()
    $seen = @{}
    foreach ($candidate in $candidates) {
        $info = Get-PythonInfo $candidate
        if (-not $info -or $seen.ContainsKey($info.Path)) { continue }
        $seen[$info.Path] = $true
        $problem = Get-PythonProblem $info
        if (-not $problem) { $chosen = $info; break }
        $rejected += "    $($info.Path): $problem"
    }
    if (-not $chosen) {
        $found = if ($rejected) { "Found:`n" + ($rejected -join "`n") } else { 'No working Python was found.' }
        if ($Python -and -not $rejected) { $found = "'$Python' does not run." }
        throw ("Sentinel-Graph needs 64-bit Python 3.12, 3.13 or 3.14. $found`n" +
            "Install Python 3.14 from https://www.python.org/downloads/windows/ (tick 'Add python.exe to PATH'),`n" +
            'then run setup.bat again, or pass an interpreter: setup.bat C:\path\to\python.exe')
    }
    Write-Host "  Python $($chosen.Version) at $($chosen.Path)"

    Write-Step 'Checking Node.js'
    $node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $node) {
        throw 'Node.js was not found. Install the LTS from https://nodejs.org, then open a new window and run setup.bat again.'
    }
    $nodeVersion = [version]("$(& $node.Source -v)".Trim().TrimStart('v'))
    # Vite 8 supports ^20.19.0 || >=22.12.0. npm ci only warns on older versions, and the
    # dev server then dies at start, which run.bat would show as a page that never loads.
    if (-not (($nodeVersion.Major -eq 20 -and $nodeVersion.Minor -ge 19) -or $nodeVersion -ge [version]'22.12')) {
        throw "Node.js $nodeVersion is too old for Vite 8, which needs 20.19+ or 22.12+. Install the LTS from https://nodejs.org and run setup.bat again."
    }
    Write-Host "  Node.js $nodeVersion"
    if (Test-Listening 5173) {
        Write-Host '  Note: something is serving port 5173. If it is an earlier run.bat, close it first: npm ci' -ForegroundColor Yellow
        Write-Host '  replaces frontend\node_modules and fails on files that are still in use.' -ForegroundColor Yellow
    }

    Write-Step 'Installing the Python packages (the first run downloads several hundred MB)'
    & $chosen.Path -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        throw ("pip install failed (see the error above). Common causes: no internet access, or Windows' 260-character`n" +
            "path limit (errors naming a long path): enable long paths, e.g. with the python.org installer's`n" +
            "'Disable path length limit' button, and run setup.bat again.")
    }

    Write-Step 'Installing the Playwright Chromium sandbox'
    & $chosen.Path -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { throw 'Playwright could not install Chromium (see the error above).' }

    Write-Step 'Installing the frontend packages'
    Push-Location (Join-Path $Root 'frontend')
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) {
            throw 'npm ci failed (see the error above). EPERM or EBUSY means a file is in use: close run.bat and editors, and run setup.bat again.'
        }
    }
    finally { Pop-Location }

    Write-Step 'Checking that the backend imports (about 20 s)'
    & $chosen.Path -c 'import app.main'
    if ($LASTEXITCODE -ne 0) {
        throw ("The backend does not import (see the error above). 'DLL load failed' from torch or onnxruntime means the`n" +
            'Microsoft Visual C++ Redistributable is missing: install https://aka.ms/vs/17/release/vc_redist.x64.exe and run setup.bat again.')
    }

    Set-Content -LiteralPath (Join-Path $Root '.sentinel-python') -Value $chosen.Path -Encoding UTF8
    Write-Host ''
    Write-Host 'Setup complete. Start Sentinel-Graph with run.bat.' -ForegroundColor Green
}
catch {
    Write-Host ''
    Write-Host "Setup FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
