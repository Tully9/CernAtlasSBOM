#!/bin/bash
set -e

# --- Cleanup ---
rm -f cppDep.txt pyDep.txt stat-analysis-sbom.json stat-analysis-sbom.md

echo "Sourcing ATLAS environment..."
set +e
source /cvmfs/atlas.cern.ch/repo/ATLASLocalRootBase/user/atlasLocalSetup.sh
set -e

echo "Setting up StatAnalysis..."
asetup StatAnalysis,0.6.3 > cppDep.txt || { echo "asetup failed"; exit 1; }

# --- Capture dependencies ---
echo "Freezing Python dependencies..."
pip freeze > pyDep.txt

echo "Ensuring pip + cyclonedx are available..."
pip install --upgrade pip
pip install cyclonedx-python-lib

# --- Run SBOM generator ---
echo "Generating SBOM..."
python3 sbomGenerator.py

echo "SBOM generation complete!"