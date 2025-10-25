@echo off
title Aegis Cloud Security Scanner - Development Mode
color 0E

echo.
echo ========================================
echo   AEGIS CLOUD SECURITY SCANNER
echo   Version 0.9.1 - DEVELOPMENT MODE
echo ========================================
echo.
echo   WARNING: This uses Flask's development
echo   server with debug mode enabled.
echo.
echo   DO NOT use in production!
echo ========================================
echo.

REM Set the application directory (where the script is located)
set "APP_DIR=%~dp0"
cd /d "%APP_DIR%"

REM Set virtual environment in user's AppData (avoids permission issues)
set "VENV_DIR=%LOCALAPPDATA%\AegisCloudScanner\venv"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo.
    echo Please install Python 3.8 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

echo [1/4] Checking Python installation...
python --version

REM Create virtual environment if it doesn't exist
if not exist "%VENV_DIR%\" (
    echo.
    echo [2/4] Creating virtual environment...
    echo Location: %VENV_DIR%

    REM Create parent directory
    if not exist "%LOCALAPPDATA%\AegisCloudScanner" mkdir "%LOCALAPPDATA%\AegisCloudScanner"

    REM Create virtual environment
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment!
        echo.
        echo This might be a permissions issue. Try running as Administrator.
        pause
        exit /b 1
    )
    echo Virtual environment created successfully!
) else (
    echo [2/4] Virtual environment already exists
)

REM Activate virtual environment
echo [3/4] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment!
    pause
    exit /b 1
)

REM Install/update requirements
echo [4/4] Installing dependencies (this may take a few minutes on first run)...
pip install -r "%APP_DIR%requirements.txt" --quiet --upgrade
if errorlevel 1 (
    echo [WARNING] Some dependencies failed to install. Trying without upgrade...
    pip install -r "%APP_DIR%requirements.txt" --quiet
)

REM Clear screen and show startup message
cls
echo.
echo ========================================
echo   AEGIS CLOUD SECURITY SCANNER
echo   Development Server (Flask Debug)
echo ========================================
echo.
echo   Status: STARTING...
echo   Access URL: http://localhost:5000
echo   Debug Mode: ENABLED
echo.
echo   Features:
echo   - Auto-reload on code changes
echo   - Detailed error messages
echo   - Debug toolbar
echo.
echo   Opening browser in 5 seconds...
echo   Press Ctrl+C to stop the server
echo ========================================
echo.

REM Set Flask environment variables for development
set FLASK_ENV=development
set FLASK_DEBUG=1

REM Open browser after 5 seconds delay (in background)
start "" cmd /c "timeout /t 5 /nobreak >nul && start http://localhost:5000"

REM Start the application with Flask development server
python "%APP_DIR%app.py"

REM Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo [ERROR] Application crashed! Check error messages above.
    echo.
    pause
)
