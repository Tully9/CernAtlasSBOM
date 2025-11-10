#!/usr/bin/env python3
"""
Script to version and save SBOM files.
Checks if the new SBOM is different from the most recent one,
and creates a new versioned directory if needed.
"""

import json
import os
import sys
import re
from pathlib import Path

def parse_build_info_from_markdown(md_file):
    """Parse build information from markdown file"""
    build_info = {}
    if not md_file.exists():
        return build_info
    
    try:
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse C Compiler
        c_match = re.search(r'\|\s*C Compiler\s*\|\s*(.+?)\s*\|', content)
        if c_match:
            build_info['C Compiler'] = c_match.group(1).strip()
        
        # Parse CXX Compiler
        cxx_match = re.search(r'\|\s*CXX Compiler\s*\|\s*(.+?)\s*\|', content)
        if cxx_match:
            build_info['CXX Compiler'] = cxx_match.group(1).strip()
        
        # Parse Platform
        platform_match = re.search(r'\|\s*Platform\s*\|\s*(.+?)\s*\|', content)
        if platform_match:
            build_info['Platform'] = platform_match.group(1).strip()
        
        # Parse LCG Version
        lcg_match = re.search(r'\|\s*LCG Version\s*\|\s*(.+?)\s*\|', content)
        if lcg_match:
            build_info['lcg_version'] = lcg_match.group(1).strip()
    except Exception as e:
        print(f"Warning: Could not parse build info from markdown: {e}", file=sys.stderr)
    
    return build_info

def parse_build_info_from_file(build_txt_path="externalBuild.txt"):
    """Parse compiler and platform information from externalBuild.txt"""
    compiler_info = {}
    
    if not os.path.exists(build_txt_path):
        return compiler_info
    
    try:
        with open(build_txt_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
            # Parse line 1: C compiler
            if len(lines) > 0:
                c_line = lines[0].strip()
                c_match = re.search(r'The C compiler identification is (.+)', c_line)
                if c_match:
                    compiler_info['C Compiler'] = c_match.group(1)
            
            # Parse line 2: CXX compiler
            if len(lines) > 1:
                cxx_line = lines[1].strip()
                cxx_match = re.search(r'The CXX compiler identification is (.+)', cxx_line)
                if cxx_match:
                    compiler_info['CXX Compiler'] = cxx_match.group(1)
            
            # Parse line 25 (index 24): Platform name
            if len(lines) > 24:
                platform_line = lines[24].strip()
                platform_match = re.search(r'Using platform name: (.+)', platform_line)
                if platform_match:
                    compiler_info['Platform'] = platform_match.group(1)
            
            # Parse LCG version and platform
            for line in lines:
                line = line.strip()
                # Pattern: LCG release "LCG_106b_ATLAS_1" for platform: x86_64-el9-gcc13-opt
                lcg_match = re.search(r'LCG release "LCG_([^"]+)" for platform: (.+)', line)
                if lcg_match:
                    compiler_info['lcg_version'] = lcg_match.group(1)
                    compiler_info['platform'] = lcg_match.group(2)
                    break
                    
    except Exception as e:
        print(f"Warning: Failed to parse build info: {e}", file=sys.stderr)
    
    return compiler_info

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
    
    # 3. Build information (if provided)
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
    json_file = Path('athena-sbom.json')
    md_file = Path('athena-sbom.md')
    
    if not json_file.exists():
        print("Error: athena-sbom.json not found")
        sys.exit(1)
    
    # Load the newly generated SBOM
    with open(json_file, 'r', encoding='utf-8') as f:
        new_sbom_data = json.load(f)
    
    # Parse build info from externalBuild.txt for new SBOM
    new_build_info = parse_build_info_from_file()
    new_signature = get_sbom_signature(new_sbom_data, new_build_info)
    
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
        recent_json = most_recent_dir / 'athena-sbom.json'
        recent_md = most_recent_dir / 'athena-sbom.md'
        
        if recent_json.exists():
            with open(recent_json, 'r', encoding='utf-8') as f:
                recent_sbom_data = json.load(f)
            
            # Parse build info from markdown for existing SBOM
            recent_build_info = parse_build_info_from_markdown(recent_md)
            recent_signature = get_sbom_signature(recent_sbom_data, recent_build_info)
            
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
    json_file.rename(version_dir / 'athena-sbom.json')
    if md_file.exists():
        md_file.rename(version_dir / 'athena-sbom.md')
    
    print(f"SBOM saved to {version_dir}/ (version {next_version})")

if __name__ == '__main__':
    main()

