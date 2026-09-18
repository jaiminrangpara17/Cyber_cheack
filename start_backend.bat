@echo off
setlocal
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
  echo Creating Python virtual environment...
  python -m venv venv
)
echo Installing/updating backend dependencies...
venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
echo Starting CyberCheck backend on http://127.0.0.1:5000
venv\Scripts\python.exe backend\app.py
pause
