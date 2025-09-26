@echo off
echo CVE-2023-45612 XXE Vulnerability Test - Windows Edition
echo ======================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python and try again
    pause
    exit /b 1
)

REM Install requirements if needed
if not exist "venv\" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

echo [INFO] Installing requirements...
pip install -r requirements.txt

echo.
echo [INFO] Starting Ktor server in background...
start /B "Ktor Server" cmd /c "gradlew.bat run"

REM Wait a bit for server to start
echo [INFO] Waiting for server to start...
timeout /t 10 /nobreak >nul

echo.
echo [INFO] Testing server connectivity...
python test_server.py
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Server is not responding
    echo Please check if the Ktor server started correctly
    pause
    exit /b 1
)

echo.
echo [INFO] Running Windows-specific XXE vulnerability test...
echo ======================================================
python xxe_poc_windows.py --full-test

echo.
echo [INFO] Test completed. Check the output above for results.
pause
