# scripts/start_ui.ps1
# Start the local Streamlit Web Console

$ErrorActionPreference = "Stop"

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Virtual environment not found. Please run .\\scripts\\init_env.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "Starting Developer Sandbox Bootstrapper Web Console on http://localhost:8501..." -ForegroundColor Cyan
& $venvPython -m streamlit run src/ui/app.py
