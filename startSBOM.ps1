# startAll.ps1
$ErrorActionPreference = "Stop"

# --- Config ---
$WORKDIR = "temp_repo_dir"
$VENV = ".venv"

# --- Check Python ---
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python is not installed or not in PATH. Please install Python 3 first."
    exit 1
}

# --- Setup ---
Write-Host "Creating virtual environment..."
python -m venv $VENV

# Activate venv
Write-Host "Activating virtual environment..."
& "$VENV\Scripts\Activate.ps1"

# Upgrade pip and install dependencies
Write-Host "Installing Python dependencies..."
python -m pip install --upgrade pip
python -m pip install cyclonedx-python-lib

# --- Prepare working directory ---
Write-Host "Cloning repository..."
if (Test-Path $WORKDIR) { Remove-Item -Recurse -Force $WORKDIR }
git clone https://gitlab.cern.ch/atlas/StatAnalysis $WORKDIR

# --- Run Python script ---
Write-Host "Running Python script..."
Set-Location $WORKDIR
python ..\generate_sbom.py

# --- Cleanup ---
Set-Location ..
Start-Sleep -Seconds 2
Remove-Item -Recurse -Force $WORKDIR
Start-Sleep -Seconds 1
Remove-Item -Recurse -Force $VENV

Write-Host "Done - repository cloned, script executed, and cleaned up."
