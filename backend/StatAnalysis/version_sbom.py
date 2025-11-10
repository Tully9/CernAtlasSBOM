#!/usr/bin/env python3
"""
Script to version and save SBOM files for StatAnalysis.
Checks if the new SBOM is different from the most recent one,
and creates a new versioned directory if needed.
"""

import json
import os
import sys
from pathlib import Path

def get_sbom_signature(sbom_data, build_info=None):
    """Generate a signature for an SBOM to compare if it's identical
    Includes all data except generation timestamp"""
    signature_parts = []
    
    # 1. Components (dependencies) - sorted by name and version
    components = sbom_data.get('components', [])
    normalized_components = sorted([
        (comp.get('name', ''), comp.get('version', ''))
        for comp in components
    ])
    signature_parts.append(('components', tuple(normalized_components)))
    
    # 2. Metadata properties (excluding timestamp)
    metadata = sbom_data.get('metadata', {})
    properties = metadata.get('properties', [])
    # Convert properties list to sorted dict for consistent comparison
    props_dict = {}
    for prop in properties:
        props_dict[prop.get('name', '')] = prop.get('value', '')
    normalized_props = tuple(sorted(props_dict.items()))
    signature_parts.append(('properties', normalized_props))
    
    # 3. Build information (if provided) - StatAnalysis typically doesn't have this
    if build_info:
        normalized_build = tuple(sorted(build_info.items()))
        signature_parts.append(('build_info', normalized_build))
    
    return tuple(signature_parts)

def get_next_version_number(sboms_dir='SBOMs'):
    """Get the next version number by checking existing version directories"""
    sboms_path = Path(sboms_dir)
    
    if not sboms_path.exists():
        return 1
    
    # Find all version directories (v1, v2, v3, etc.)
    version_dirs = []
    for item in sboms_path.iterdir():
        if item.is_dir() and item.name.startswith('v'):
            try:
                version_num = int(item.name[1:])  # Extract number after 'v'
                version_dirs.append(version_num)
            except ValueError:
                continue
    
    if not version_dirs:
        return 1
    
    return max(version_dirs) + 1

def main():
    json_file = Path('stat-analysis-sbom.json')
    md_file = Path('stat-analysis-sbom.md')
    
    if not json_file.exists():
        print("Error: stat-analysis-sbom.json not found")
        sys.exit(1)
    
    # Load the newly generated SBOM
    with open(json_file, 'r', encoding='utf-8') as f:
        new_sbom_data = json.load(f)
    
    # StatAnalysis doesn't have build info from externalBuild.txt
    new_signature = get_sbom_signature(new_sbom_data, None)
    
    # Check SBOMs directory
    sboms_dir = Path('SBOMs')
    sboms_dir.mkdir(exist_ok=True)
    
    # Find most recent version
    max_version = 0
    most_recent_dir = None
    
    for item in sboms_dir.iterdir():
        if item.is_dir() and item.name.startswith('v'):
            try:
                version_num = int(item.name[1:])
                if version_num > max_version:
                    max_version = version_num
                    most_recent_dir = item
            except ValueError:
                continue
    
    # Check if we need a new version
    is_duplicate = False
    
    if most_recent_dir:
        recent_json = most_recent_dir / 'stat-analysis-sbom.json'
        if recent_json.exists():
            with open(recent_json, 'r', encoding='utf-8') as f:
                recent_sbom_data = json.load(f)
            
            # StatAnalysis doesn't have build info
            recent_signature = get_sbom_signature(recent_sbom_data, None)
            
            if recent_signature == new_signature:
                is_duplicate = True
                print(f"SBOM is identical to most recent version (v{max_version}). No new version created.")
                json_file.unlink()
                if md_file.exists():
                    md_file.unlink()
                sys.exit(0)
    
    # Create new version directory
    next_version = max_version + 1
    version_dir = sboms_dir / f'v{next_version}'
    version_dir.mkdir(exist_ok=True)
    
    # Move files to version directory
    json_file.rename(version_dir / 'stat-analysis-sbom.json')
    if md_file.exists():
        md_file.rename(version_dir / 'stat-analysis-sbom.md')
    
    print(f"SBOM saved to {version_dir}/ (version {next_version})")

if __name__ == '__main__':
    main()

