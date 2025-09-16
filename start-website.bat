@echo off
echo.
echo 🌐 Starting ForTAI Landing Website...
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
) else (
    python3 --version >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_CMD=python3
    ) else (
        echo ❌ Python is not installed or not in PATH
        echo Please install Python 3.x to run the website server
        pause
        exit /b 1
    )
)

echo ✅ Using Python: %PYTHON_CMD%
echo.

REM Navigate to website directory
cd /d "%~dp0website"

REM Start the server
echo 🚀 Starting website server...
echo 📱 Open your browser and go to: http://localhost:8080
echo.
echo Press Ctrl+C to stop the server
echo.

%PYTHON_CMD% server.py

pause