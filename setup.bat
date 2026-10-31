@echo off
rem One-shot setup for a fresh clone (Windows). Run from the repository root.
setlocal
cd /d "%~dp0"

echo Installing Python dependencies...
python -m pip install -r requirements.txt || goto :fail

echo Installing Playwright Chromium sandbox...
python -m playwright install chromium || goto :fail

echo Installing Frontend dependencies...
pushd frontend
call npm ci || (popd & goto :fail)
popd

echo Setup Complete!
exit /b 0

:fail
echo Setup FAILED - see the error above.
exit /b 1
