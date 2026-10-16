# scripts/init_env.ps1
# Idempotent environment initialization for Windows PowerShell

$ErrorActionPreference = "Stop"

Write-Host "=== Initializing Developer Sandbox Bootstrapper Environment ===" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = "python"
if (Get-Command "py" -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
}

# 2. Virtual environment
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment in .venv..." -ForegroundColor Yellow
    Invoke-Expression "$pythonCmd -m venv .venv"
} else {
    Write-Host "Virtual environment .venv already exists." -ForegroundColor Green
}

$venvPython = ".\.venv\Scripts\python.exe"

# 3. Upgrade pip and install dependencies
Write-Host "Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r requirements.txt --quiet

# 4. Copy .env if not exists
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
} else {
    Write-Host ".env configuration already exists." -ForegroundColor Green
}

# 5. Initialize SQLite Database
Write-Host "Initializing SQLite database schema..." -ForegroundColor Yellow
& $venvPython -m src.storage.db_init

Write-Host "=== Initialization Complete! ===" -ForegroundColor Green
Write-Host "Start the API with: .\\scripts\\start_api.ps1"
Write-Host "Start the UI with:  .\\scripts\\start_ui.ps1"
Write-Host "Run tests with:     .\\scripts\\run_tests.ps1"
