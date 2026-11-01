@echo off
rem Run Sentinel-Graph locally: frontend on http://localhost:5173, backend on :8000.
rem Ctrl-C (or closing the window) stops both. Uses the Python setup.bat recorded;
rem pass a path to use a specific interpreter:
rem   run.bat C:\Users\you\anaconda3\python.exe
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run_local.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run_local.ps1" -Python "%~1"
)
set "RC=%errorlevel%"
rem Started by double-click, the window would close before an error can be read.
if not "%RC%"=="0" pause
exit /b %RC%
