#!/bin/bash
set -e

# --- Cleanup ---
rm -f cppDep.txt stat-analysis-sbom.json stat-analysis-sbom.md
rm -rf AtlasExternals

# --- Clone Atlas Externals ---
echo "Cloning AtlasExternals..."
git clone https://gitlab.cern.ch/atlas/atlasexternals.git AtlasExternals

# --- Parse CMakeLists.txt for dependency versions ---
echo "Parsing CMakeLists.txt for C++ dependencies..."
cd AtlasExternals/External
python3 ../../sbomGenerator.py --parse-cmakelists
cd ..

# It's not pretty, but it's 5pm and it works
cd Projects/AnalysisBaseExternals
python3 ../../../sbomGenerator.py --parse-package-filter
cd ..
cd ..
cd ..

# --- Gather PyPi packages ---
echo "Gathering Python Packages"
cd AtlasExternals/External/PyModules
python3 ../../../sbomGenerator.py --parse-python-packages-1 # Opens requirements_analysisbase.txt.in and requirements.txt.in
cd ..
cd PyAnalysis
python3 ../../../sbomGenerator.py --parse-python-packages-2 # Parses CMakeLists.txt, setuptools : 75.8.0, Cython : 3.0.12, numpy : 2.1.3, PyYAML : 6.0.2, wheel : 0.45.0, pip : 32.3.1
cd ..
cd ..
cd ..

# --- Remove cloned repo ---
echo "Removing AtlasExternals clone..."
rm -rf AtlasExternals

# --- Ensure pip + cyclonedx are available ---
echo "Ensuring pip + cyclonedx are available..."
pip install --upgrade pip
pip install cyclonedx-python-lib

# --- Generate SBOM and Markdown report ---
echo "Generating SBOM and Markdown report..."
python3 sbomGenerator.py --parse-cpp

# --- Version and save SBOM ---
echo "Versioning and saving SBOM..."
python3 version_sbom.py

# Clean up temporary files
rm -f cppDep.txt pyDep.txt package_filters.txt 

echo "SBOM generation complete!"