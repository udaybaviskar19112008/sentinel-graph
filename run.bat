@echo off
rem Run Sentinel-Graph locally: frontend on http://localhost:5173, backend on :8000.
rem Ctrl-C stops both. Pass a Python path to use a specific interpreter:
rem   run.bat C:\Users\you\anaconda3\python.exe
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run_local.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run_local.ps1" -Python "%~1"
)
