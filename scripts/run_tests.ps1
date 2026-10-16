# scripts/run_tests.ps1
# Execute the complete automated test suite with coverage reporting

$ErrorActionPreference = "Stop"

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Virtual environment not found. Please run .\\scripts\\init_env.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "Running automated test suite with coverage..." -ForegroundColor Cyan
& $venvPython -m pytest -v --cov=src --cov-report=term-missing $args
