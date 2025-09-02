set -e

WORKDIR="temp_repo_dir"
VENV=".venv"

# --- Setup ---
# Ensure python3-venv is installed
sudo dnf install python3

python3 -m venv "$VENV"

# Activate venv (Linux)
source "$VENV/bin/activate"

mkdir -p "$WORKDIR"
git clone https://gitlab.cern.ch/atlas/StatAnalysis "$WORKDIR"

# --- Run script ---
cd "$WORKDIR"
pip install --upgrade pip
pip install cyclonedx-python-lib
python3 ../generate_sbom.py

# --- Cleanup ---
cd ..
deactivate || true
sleep 2

# Remove dirs safely
rm -rf "$WORKDIR"
sleep 1
rm -rf "$VENV"
echo "Done - repo cloned, script executed, everything cleaned up."