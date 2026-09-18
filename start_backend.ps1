$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path "venv\Scripts\python.exe")) {
    Write-Host "Creating Python virtual environment..."
    python -m venv venv
}
Write-Host "Installing/updating backend dependencies..."
& ".\venv\Scripts\python.exe" -m pip install -r requirements.txt
Write-Host "Starting CyberCheck backend on http://127.0.0.1:5000"
& ".\venv\Scripts\python.exe" "backend\app.py"
