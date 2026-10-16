# scripts/start_api.ps1
# Start the local FastAPI development server bound strictly to 127.0.0.1

$ErrorActionPreference = "Stop"

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Virtual environment not found. Please run .\\scripts\\init_env.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "Starting Developer Sandbox Bootstrapper API on http://127.0.0.1:8000..." -ForegroundColor Cyan
Write-Host "API docs available at: http://127.0.0.1:8000/docs" -ForegroundColor Yellow
& $venvPython -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
