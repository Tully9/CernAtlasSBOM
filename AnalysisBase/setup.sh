#!/bin/bash
set -e

# --- Cleanup ---
rm -f cppDep.txt stat-analysis-sbom.json stat-analysis-sbom.md
rm -rf AtlasExternals

# --- Clone Atlas Externals at version 2.1.16.7 ---
echo "Cloning AtlasExternals..."
git clone --branch 2.1.16.7 --depth 1 https://gitlab.cern.ch/atlas/atlasexternals.git AtlasExternals

# --- Parse CMakeLists.txt for dependency versions ---
echo "Parsing CMakeLists.txt for C++ dependencies..."
cd AtlasExternals/External
python3 ../../sbomGenerator.py --parse-cmakelists
cd ..

# --- Remove cloned repo ---
echo "Removing AtlasExternals clone..."

# --- Setup ATLAS environment and AnalysisBase ---
echo "Setting up ATLAS and AnalysisBase..."
set +e
source /cvmfs/atlas.cern.ch/repo/ATLASLocalRootBase/user/atlasLocalSetup.sh
set -e
python -v -c "quit()" > pyDep.txt 2>&1
python3 sbomGenerator.py --parse-cpp

# --- Ensure pip + cyclonedx are available ---
echo "Ensuring pip + cyclonedx are available..."
pip install --upgrade pip
pip install cyclonedx-python-lib

# --- Generate SBOM and Markdown report ---
echo "Generating SBOM and Markdown report..."
cd ..
python3 sbomGenerator.py --parse-cpp

echo "SBOM generation complete!"