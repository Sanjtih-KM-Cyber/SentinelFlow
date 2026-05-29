@echo off
title SentinelFlow
echo.
echo  ============================================
echo   SentinelFlow - Starting...
echo  ============================================
echo.

:: Find Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Python not found in PATH.
    echo  Please install Python 3.10+ from https://python.org
    echo.
    pause
    exit /b 1
)

:: Check version
python -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Python 3.10 or newer required.
    pause
    exit /b 1
)

:: Install deps silently if needed
echo  Checking dependencies...
python -m pip install -r requirements.txt -q --no-warn-script-location 2>nul

:: Launch desktop app (windowed - no console flicker)
echo  Launching SentinelFlow...
start /B pythonw desktop\app.py

:: If pythonw fails, fall back to python
if %errorlevel% neq 0 (
    python desktop\app.py
)
