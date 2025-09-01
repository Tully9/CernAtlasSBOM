set -e

WORKDIR="temp_repo_dir"
VENV=".venv"

# --- Setup ---
echo "Creating Virtual Environment..."
python3 -m venv "$VENV"

# activate venv (Windows Git Bash)
source "$VENV/Scripts/activate"

mkdir -p "$WORKDIR"
git clone https://gitlab.cern.ch/atlas/StatAnalysis "$WORKDIR"

# --- Run script ---
cd "$WORKDIR"
echo "Installing Python dependancies in temporarily VE..."
pip install cyclonedx-python-lib
echo "Running Python Script..."
python3 ../generate_sbom.py

# --- Cleanup ---
cd ..
deactivate || true
sleep 2

# remove dirs safely
rm -rf "$WORKDIR"
sleep 1
rm -rf "$VENV"

echo "Done - repo cloned, script executed, everything cleaned up."