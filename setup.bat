@echo off
rem One-shot setup for a fresh clone or ZIP download (Windows). Checks Python and Node.js,
rem installs the pip packages, Playwright Chromium and the frontend node_modules, and
rem records the Python it used for run.bat. Pass a Python path to use a specific one:
rem   setup.bat C:\Users\you\anaconda3\python.exe
setlocal
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup_local.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup_local.ps1" -Python "%~1"
)
set "RC=%errorlevel%"
rem Started by double-click, the window would close before the result can be read.
pause
exit /b %RC%
