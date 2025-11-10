"""
SBOM Generator for Athena
"""

import re
import os
from pathlib import Path
from typing import Optional, Set, List, Dict
from dataclasses import dataclass
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import Property
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion
from datetime import datetime
import argparse
import urllib.request
import urllib.error

@dataclass
class Dependency:
    name: str
    version: Optional[str] = None
    source: str = ""
    file_path: str = ""

    def __hash__(self):
        return hash((self.name, self.version))

    def __eq__(self, other):
        return isinstance(other, Dependency) and (self.name, self.version) == (other.name, other.version)


class SBOMGenerator:
    def __init__(self):
        base = os.path.dirname(__file__)
        self.cpp_file = Path(os.path.join(base, "cppDep.txt"))
        self.dependencies: Set[Dependency] = set()
        self.build_info = {}

    def parse_build_info(self, build_txt_path="externalBuild.txt") -> Dict:
        """Parse externalBuild.txt to extract LCG version, platform, package list, and compiler info"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        build_txt_path = os.path.join(base_dir, build_txt_path)
        
        result = {
            'lcg_version': None,
            'platform': None,
            'packages': [],
            'C Compiler': None,
            'CXX Compiler': None,
            'Platform': None
        }
        
        if not os.path.exists(build_txt_path):
            print(f"Build log not found: {build_txt_path}")
            return result
        
        try:
            with open(build_txt_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
                # Parse line 1: C compiler
                if len(lines) > 0:
                    c_line = lines[0].strip()
                    c_match = re.search(r'The C compiler identification is (.+)', c_line)
                    if c_match:
                        result['C Compiler'] = c_match.group(1)
                
                # Parse line 2: CXX compiler
                if len(lines) > 1:
                    cxx_line = lines[1].strip()
                    cxx_match = re.search(r'The CXX compiler identification is (.+)', cxx_line)
                    if cxx_match:
                        result['CXX Compiler'] = cxx_match.group(1)
                
                # Parse LCG version and platform
                for line in lines:
                    line = line.strip()
                    # Pattern: LCG release "LCG_106b_ATLAS_1" for platform: x86_64-el9-gcc13-opt
                    lcg_match = re.search(r'LCG release "LCG_([^"]+)" for platform: (.+)', line)
                    if lcg_match:
                        result['lcg_version'] = lcg_match.group(1)
                        result['platform'] = lcg_match.group(2)
                        break
                
                # Parse platform name - search for "Using platform name:" line
                for line in lines:
                    line = line.strip()
                    platform_match = re.search(r'Using platform name: (.+)', line)
                    if platform_match:
                        result['Platform'] = platform_match.group(1)
                        break
                
                # Parse package filtering rules
                in_package_section = False
                for line in lines:
                    line = line.strip()
                    if 'Package filtering rules read:' in line:
                        in_package_section = True
                        continue
                    if in_package_section:
                        # Stop at the next section or empty line after packages
                        if line.startswith('-- Configuring') or (line == '' and result['packages']):
                            break
                        # Extract package names from lines like: "--   + External/Acts"
                        pkg_match = re.search(r'--\s+\+\s+External/(.+)', line)
                        if pkg_match:
                            pkg_name = pkg_match.group(1).strip()
                            result['packages'].append(pkg_name)
                        elif line.startswith('--   -'):
                            # End of package list
                            break
                            
        except Exception as e:
            print(f"Failed to parse build info: {e}")
        
        self.build_info = result
        return result

    def fetch_and_parse_lcg_packages(self, lcg_version: str, platform: str, 
                                     fallback_html_path: Optional[str] = None) -> Dict[str, str]:
        """Fetch HTML from LCG website and parse package/version pairs"""
        url = f"https://lcginfo.cern.ch/release_packages/{lcg_version}/{platform}/"
        html_content = None
        
        # Try to fetch from URL
        try:
            print(f"Fetching LCG packages from: {url}")
            with urllib.request.urlopen(url, timeout=30) as response:
                html_content = response.read().decode('utf-8')
                print(f"Successfully fetched HTML from LCG website")
        except urllib.error.URLError as e:
            print(f"Failed to fetch from URL: {e}")
            # Try fallback to local file
            if fallback_html_path:
                fallback_path = os.path.join(os.path.dirname(__file__), fallback_html_path)
                if os.path.exists(fallback_path):
                    print(f"Using fallback HTML file: {fallback_path}")
                    try:
                        with open(fallback_path, "r", encoding="utf-8") as f:
                            html_content = f.read()
                    except Exception as e2:
                        print(f"Failed to read fallback file: {e2}")
        
        if not html_content:
            print("Warning: No HTML content available for parsing")
            return {}
        
        # Parse HTML using regex (simpler than BeautifulSoup)
        packages = {}
        
        # Find the table with id="release"
        table_match = re.search(r'<table[^>]*id="release"[^>]*>(.*?)</table>', html_content, re.DOTALL)
        if not table_match:
            print("Warning: Could not find release table in HTML")
            return packages
        
        table_content = table_match.group(1)
        
        # Extract package rows - each row has two <td> elements:
        # First <td>: <a href="/pkg/{name}/">{name}</a>
        # Second <td>: <a href="/pkgver/{name}/{version}/">{version}</a>
        # We need to match pairs within the same <tr>
        row_pattern = r'<tr[^>]*>\s*<td[^>]*>\s*<a[^>]*href="/pkg/([^/]+)/"[^>]*>\s*([^<]+?)\s*</a>\s*</td>\s*<td[^>]*>.*?<a[^>]*href="/pkgver/[^/]+/([^/]+)/"[^>]*>\s*([^<]+?)\s*</a>.*?</td>\s*</tr>'
        
        for match in re.finditer(row_pattern, table_content, re.DOTALL | re.IGNORECASE):
            pkg_name_from_href = match.group(1).strip()
            pkg_name_from_text = match.group(2).strip()
            version_from_href = match.group(3).strip()
            version_from_text = match.group(4).strip()
            
            # Prefer text content over href, but fallback to href if text is empty
            pkg_name = pkg_name_from_text or pkg_name_from_href
            version = version_from_text or version_from_href
            
            if pkg_name and version:
                packages[pkg_name] = version
        
        # Alternative pattern if the above doesn't work - match links separately and pair them
        if not packages:
            # Find all package name links
            pkg_matches = list(re.finditer(r'<a[^>]*href="/pkg/([^/]+)/"[^>]*>([^<]+)</a>', table_content, re.IGNORECASE))
            # Find all version links
            ver_matches = list(re.finditer(r'<a[^>]*href="/pkgver/[^/]+/([^/]+)/"[^>]*>([^<]+)</a>', table_content, re.IGNORECASE))
            
            # Match them up by position (they should be in the same rows)
            for i, pkg_match in enumerate(pkg_matches):
                if i < len(ver_matches):
                    ver_match = ver_matches[i]
                    pkg_name = (pkg_match.group(2) or pkg_match.group(1)).strip()
                    version = (ver_match.group(2) or ver_match.group(1)).strip()
                    if pkg_name and version:
                        packages[pkg_name] = version
        
        print(f"Parsed {len(packages)} packages from LCG website")
        return packages

    def find_missing_packages(self, build_packages: List[str], lcg_packages: Dict[str, str]) -> List[str]:
        """Compare build log packages with LCG website packages and return missing ones"""
        missing = []
        
        # Known name mappings between build log and LCG website
        name_mappings = {
            'nlohmann_json': 'jsonmcpp',  # nlohmann_json in build log is jsonmcpp on LCG
        }
        
        # Normalize package names for comparison (case-insensitive)
        lcg_packages_lower = {k.lower(): v for k, v in lcg_packages.items()}
        
        for pkg in build_packages:
            found = False
            
            # Try exact match first
            if pkg in lcg_packages:
                found = True
                continue
            
            # Try case-insensitive match
            if pkg.lower() in lcg_packages_lower:
                found = True
                continue
            
            # Try with known name mappings
            if pkg in name_mappings:
                mapped_name = name_mappings[pkg]
                if mapped_name in lcg_packages or mapped_name.lower() in lcg_packages_lower:
                    found = True
                    continue
            
            if not found:
                missing.append(pkg)
        
        print(f"Found {len(missing)} packages not in LCG website: {missing}")
        return missing

    def parse_atlasexternals_packages(self, missing_packages: List[str], 
                                      atlasexternals_path: str = "AtlasExternals") -> Dict[str, str]:
        """Parse CMakeLists.txt files from AtlasExternals repo for missing packages"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        atlasexternals_path = os.path.join(base_dir, atlasexternals_path)
        
        packages = {}
        
        if not os.path.isdir(atlasexternals_path):
            print(f"AtlasExternals directory not found: {atlasexternals_path}")
            return packages
        
        # Patterns similar to AnalysisBase
        patterns = {
            "Acts": [r'Acts[-_/]?([0-9.]+)\.tar\.gz', r'acts[-_/]?([0-9.]+)\.tar\.gz'],
            "CLHEP": [r'CLHEP[-_/]?([0-9.]+)\.tar\.gz', r'clhep[-_/]?([0-9.]+)\.tar\.gz'],
            "Coin3D": [r'Coin3D[-_/]?([0-9.]+)\.tar\.gz', r'coin3d[-_/]?([0-9.]+)\.tar\.gz'],
            "COOL": [r'COOL[-_/]?([0-9.]+)\.tar\.gz', r'cool[-_/]?([0-9.]+)\.tar\.gz'],
            "CORAL": [r'CORAL[-_/]?([0-9.]+)\.tar\.gz', r'coral[-_/]?([0-9.]+)\.tar\.gz'],
            "Gaudi": [r'Gaudi[-_/]?([0-9.]+)\.tar\.gz', r'gaudi[-_/]?([0-9.]+)\.tar\.gz'],
            "Geant4": [r'Geant4[-_/]?([0-9.]+)\.tar\.gz', r'geant4[-_/]?([0-9.]+)\.tar\.gz'],
            "GeoModel": [r'GeoModel[-_/]?([0-9.]+)\.tar\.gz', r'geomodel[-_/]?([0-9.]+)\.tar\.gz'],
            "GoogleTest": [r'googletest-([0-9.]+)\.tar\.gz', r'GoogleTest[-_/]?([0-9.]+)\.tar\.gz'],
            "lwtnn": [r'lwtnn[/\\]v?([0-9.]+)\.tar\.gz', r'externals/lwtnn/v?([0-9.]+)\.tar\.gz'],
            "onnxruntime": [r'onnxruntime[-\w]*-([0-9.]+)\.(?:tgz|tar\.gz)'],
            "nlohmann_json": [r'json-([0-9.]+)\.tar\.gz', r'nlohmann_json[-_/]?([0-9.]+)\.tar\.gz'],
            "PyModules": [],  # Special handling
        }
        
        external_dir = os.path.join(atlasexternals_path, "External")
        if not os.path.isdir(external_dir):
            print(f"External directory not found: {external_dir}")
            return packages
        
        for pkg in missing_packages:
            pkg_dir = os.path.join(external_dir, pkg)
            if not os.path.isdir(pkg_dir):
                print(f"Package directory not found: {pkg_dir}")
                continue
            
            cmake_path = os.path.join(pkg_dir, "CMakeLists.txt")
            if not os.path.isfile(cmake_path):
                alt_path = os.path.join(pkg_dir, "cmake", "CMakeLists.txt")
                if os.path.isfile(alt_path):
                    cmake_path = alt_path
                else:
                    print(f"CMakeLists.txt not found for {pkg}")
                    continue
            
            # Read CMakeLists.txt
            try:
                with open(cmake_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                print(f"Failed to read {cmake_path}: {e}")
                continue
            
            # Special handling for PyModules
            if pkg == "PyModules":
                req_files = ["requirements.txt.in", "requirements_athena.txt.in"]
                for rf in req_files:
                    rfpath = os.path.join(pkg_dir, rf)
                    if os.path.isfile(rfpath):
                        try:
                            with open(rfpath, "r", encoding="utf-8") as rfh:
                                for line in rfh:
                                    line = line.strip()
                                    if not line or line.startswith("#"):
                                        continue
                                    m = re.match(r'^([A-Za-z0-9_\-]+)==([^\s]+)', line)
                                    if m:
                                        pkgname, pkgver = m.groups()
                                        # Add to dependencies set
                                        self.dependencies.add(Dependency(
                                            name=pkgname,
                                            version=pkgver,
                                            source="PyModules",
                                            file_path=rfpath
                                        ))
                        except Exception as e:
                            print(f"Failed to parse {rfpath}: {e}")
                continue
            
            # Generic version extraction
            found_version = None
            regex_list = patterns.get(pkg, [])
            
            for rx in regex_list:
                m = re.search(rx, content)
                if m:
                    found_version = m.group(1)
                    break
            
            # Fallback to generic patterns
            if not found_version:
                generic_patterns = [
                    r'/sources/[^/]+-([0-9A-Za-z\._\-]+)\.tar\.gz',
                    r'[-_/]v?([0-9]+\.[0-9]+\.[0-9A-Za-z\._\-]+)\.tar\.gz',
                    r'[-_/]v?([0-9]+\.[0-9A-Za-z\._\-]+)\.tar\.gz',
                    r'([0-9]{6,})\.tar\.gz'
                ]
                for rx in generic_patterns:
                    m = re.search(rx, content)
                    if m:
                        found_version = m.group(1)
                        break
            
            if found_version:
                packages[pkg] = found_version
                print(f"Discovered {pkg}: {found_version} from AtlasExternals")
            else:
                print(f"Could not find version for {pkg}")
        
        return packages

    def parse_cpp_deps(self):
        """Parse C++ dependencies from cppDep.txt"""
        if not self.cpp_file.exists():
            print(f"C++ dependency file not found: {self.cpp_file}")
            return

        pattern = r"^([A-Za-z0-9_\-]+)\s*:\s*(.*)$"

        with open(self.cpp_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = re.match(pattern, line)
                if not m:
                    continue
                name, version_raw = m.groups()
                version = version_raw.split()[0] if version_raw else "undefined"
                self.dependencies.add(Dependency(name=name, version=version, source=str(self.cpp_file)))

    def generate_cyclonedx_sbom(self, athena_version="24.0") -> str:
        """Generate CycloneDX SBOM"""
        metadata = BomMetaData(
            properties=[
                Property(name="Athena", value=athena_version),
            ]
        )
        bom = Bom(metadata=metadata)
        for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
            component = Component(
                name=dep.name,
                version=dep.version or "undefined",
                type=ComponentType.LIBRARY
            )
            bom.components.add(component)
        outputter = make_outputter(
            bom=bom,
            output_format=OutputFormat.JSON,
            schema_version=SchemaVersion.V1_4
        )
        return outputter.output_as_string()

    def save_sbom(self, output_path="athena-sbom.json"):
        """Save SBOM to JSON file"""
        sbom_json = self.generate_cyclonedx_sbom()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sbom_json)
        print(f"SBOM saved to {output_path}")

    def generate_markdown_report(self, athena_version="24.0", build_info=None) -> str:
        """Generate Markdown report"""
        md = []
        md.append("# Athena SBOM Report\n")
        md.append(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Total dependencies:** {len(self.dependencies)}\n")
        
        # Build Information section
        if build_info:
            md.append("## Build Information\n")
            md.append("| Component | Version/Specification |")
            md.append("|-----------|-----------------------|")
            if 'C Compiler' in build_info:
                md.append(f"| C Compiler | {build_info['C Compiler']} |")
            if 'CXX Compiler' in build_info:
                md.append(f"| CXX Compiler | {build_info['CXX Compiler']} |")
            if 'Platform' in build_info:
                md.append(f"| Platform | {build_info['Platform']} |")
            if 'lcg_version' in build_info:
                md.append(f"| LCG Version | {build_info['lcg_version']} |")
            md.append("")
        
        md.append("## Source Versions\n")
        md.append("| Source | Version |")
        md.append("|--------|---------|")
        md.append(f"| Athena | {athena_version} |\n")
        
        if self.dependencies:
            md.append("## All Dependencies\n")
            md.append("| Package | Version |")
            md.append("|---------|---------|")
            for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
                md.append(f"| {dep.name} | {dep.version or 'undefined'} |")
            md.append("")
        return "\n".join(md)

    def save_markdown_report(self, output_path="athena-sbom.md", build_info=None):
        """Save Markdown report"""
        md_content = self.generate_markdown_report(build_info=build_info)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {output_path}")

    def generate(self, output_json="athena-sbom.json", output_md="athena-sbom.md"):
        """Main generation method"""
        print("Parsing build log...")
        build_info = self.parse_build_info()
        
        if not build_info.get('lcg_version') or not build_info.get('platform'):
            print("Error: Could not extract LCG version or platform from build log")
            return
        
        print(f"LCG Version: {build_info['lcg_version']}")
        print(f"Platform: {build_info['platform']}")
        print(f"Packages from build log: {len(build_info['packages'])}")
        
        # Fetch and parse LCG packages
        print("Fetching and parsing LCG website packages...")
        lcg_packages = self.fetch_and_parse_lcg_packages(
            build_info['lcg_version'],
            build_info['platform'],
            fallback_html_path="ExampleLcgInfoWebsiteHtmlCode.html"
        )
        
        # Add LCG packages to dependencies
        for pkg_name, version in lcg_packages.items():
            self.dependencies.add(Dependency(
                name=pkg_name,
                version=version,
                source="LCG Website"
            ))
        
        # Find missing packages
        print("Comparing packages...")
        missing_packages = self.find_missing_packages(build_info['packages'], lcg_packages)
        
        # Parse AtlasExternals for missing packages
        if missing_packages:
            print(f"Parsing AtlasExternals for {len(missing_packages)} missing packages...")
            atlasexternals_packages = self.parse_atlasexternals_packages(missing_packages)
            
            # Add AtlasExternals packages to dependencies
            for pkg_name, version in atlasexternals_packages.items():
                self.dependencies.add(Dependency(
                    name=pkg_name,
                    version=version,
                    source="AtlasExternals"
                ))
        
        # Parse any additional dependencies from cppDep.txt
        print("Parsing C++ dependencies from cppDep.txt...")
        self.parse_cpp_deps()
        
        print(f"Found {len(self.dependencies)} dependencies total.")
        
        # Generate reports
        self.save_sbom(output_json)
        self.save_markdown_report(output_md, build_info=build_info)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parse-cpp', action='store_true', help='Parse dependencies and generate SBOM')
    args = parser.parse_args()

    generator = SBOMGenerator()

    if args.parse_cpp:
        generator.generate()
        print("SBOM generation complete.")


if __name__ == "__main__":
    main()

