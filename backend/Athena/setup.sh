#!/bin/bash
set -e

# --- Cleanup ---
echo "Cleaning up old files..."
rm -f cppDep.txt athena-sbom.json athena-sbom.md
rm -rf AtlasExternals

# --- Clone Atlas Externals (needed for parsing missing packages) ---
echo "Cloning AtlasExternals..."
git clone https://gitlab.cern.ch/atlas/atlasexternals.git AtlasExternals

# --- Ensure pip + cyclonedx are available ---
echo "Ensuring pip + cyclonedx are available..."
pip install --upgrade pip
pip install cyclonedx-python-lib

# --- Generate SBOM and Markdown report ---
# This will:
# 1. Parse externalBuild.txt to get LCG version, platform, and package list
# 2. Fetch and parse LCG website HTML for package versions
# 3. Compare packages and find missing ones
# 4. Parse AtlasExternals CMakeLists.txt for missing packages
# 5. Generate CycloneDX JSON and Markdown reports
echo "Generating SBOM and Markdown report..."
python3 sbomGenerator.py --parse-cpp

# --- Version and save SBOM ---
echo "Versioning and saving SBOM..."
python3 version_sbom.py

# --- Remove cloned repo ---
echo "Removing AtlasExternals clone..."
rm -rf AtlasExternals

# Clean up temporary files
rm -f cppDep.txt

echo "SBOM generation complete!"
