"""
Software Bill of Materials (SBOM) Generator for StatAnalysis Repository

This script recursively scans CMakeLists.txt files and Python requirements files
to generate a CycloneDX SBOM in JSON format.
"""

import json
import re
import sys
from pathlib import Path
from typing import Set, Optional
from dataclasses import dataclass
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.tool import Tool
from cyclonedx.model import Property
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion


@dataclass
class Dependency:
    """Represents a dependency found in the project."""
    name: str
    version: Optional[str] = None
    source: str = ""  # CMakeLists.txt or requirements.txt
    file_path: str = ""
    
    def __post_init__(self):
        if self.version:
            self.version = self.version.strip()
    
    def __hash__(self):
        return hash((self.name, self.version))
    
    def __eq__(self, other):
        if not isinstance(other, Dependency):
            return False
        return (self.name, self.version) == (other.name, other.version)
    
    def __str__(self):
        if self.version:
            return f"{self.name}@{self.version}"
        return self.name


class SBOMGenerator:
    """Generates Software Bill of Materials for the StatAnalysis repository."""
    
    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir).resolve()
        self.dependencies: Set[Dependency] = set()
        self.cmake_files_scanned = 0
        self.python_files_scanned = 0
        

    def scan_cmake_files(self) -> None:
        """Recursively scan all CMakeLists.txt files for dependencies."""
        print(f"Scanning CMakeLists.txt files in: {self.root_dir}")
        
        for cmake_file in self.root_dir.rglob("CMakeLists.txt"):
            self.cmake_files_scanned += 1
            self.parse_cmake_file(cmake_file)
    
    def parse_cmake_file(self, file_path: Path) -> None:
        """Parse a single CMakeLists.txt file for find_package calls."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find all find_package calls
            find_package_pattern = r'find_package\s*\(\s*([A-Za-z0-9_]+)\s*(?:([^\s)]+)\s*)?(?:REQUIRED|QUIET|EXACT|NO_MODULE|GLOBAL|CONFIG|MODULE|COMPONENTS|OPTIONAL_COMPONENTS|NAMES|NAMES_PER_DIR|PATHS|PATH_SUFFIXES|HINTS|NO_DEFAULT_PATH|NO_CMAKE_ENVIRONMENT_PATH|NO_SYSTEM_ENVIRONMENT_PATH|NO_CMAKE_PACKAGE_REGISTRY|NO_CMAKE_BUILDS_PATH|NO_CMAKE_SYSTEM_PATH|NO_CMAKE_SYSTEM_PACKAGE_REGISTRY|CMAKE_FIND_ROOT_PATH_BOTH|ONLY_CMAKE_FIND_ROOT_PATH|NO_CMAKE_FIND_ROOT_PATH)?\s*\)'
            
            matches = re.finditer(find_package_pattern, content, re.IGNORECASE)
            
            for match in matches:
                package_name = match.group(1).strip()
                version_spec = match.group(2).strip() if match.group(2) else None
                
                # Skip if it's just a flag like REQUIRED
                if version_spec and version_spec.upper() in ['REQUIRED', 'QUIET', 'EXACT']:
                    version_spec = None
                
                # Clean up version specification
                if version_spec:
                    # Remove common flags and clean up
                    version_spec = re.sub(r'\s+(REQUIRED|QUIET|EXACT|NO_MODULE|GLOBAL|CONFIG|MODULE)', '', version_spec, flags=re.IGNORECASE)
                    version_spec = version_spec.strip()
                
                # Create dependency object
                dep = Dependency(
                    name=package_name,
                    version=version_spec,
                    source="CMakeLists.txt",
                    file_path=str(file_path.relative_to(self.root_dir))
                )
                
                self.dependencies.add(dep)
                
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
    
    def scan_python_requirements(self) -> None:
        """Scan Python requirements.txt files for dependencies."""
        print(f"Scanning Python requirements files in: {self.root_dir}")
        
        for req_file in self.root_dir.rglob("requirements.txt"):
            self.python_files_scanned += 1
            self.parse_requirements_file(req_file)
    
    def parse_requirements_file(self, file_path: Path) -> None:
        """Parse a single requirements.txt file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse requirements.txt format
            # Handle various formats: package==version, package>=version, package~=version, etc.
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse package specification
                # Pattern: package[extras]==version, package>=version, package~=version, etc.
                package_pattern = r'^([A-Za-z0-9_-]+)(?:\[[^\]]*\])?([=~<>!]+)(.+)$'
                match = re.match(package_pattern, line)
                
                if match:
                    package_name = match.group(1)
                    operator = match.group(2)
                    version_spec = match.group(3).strip()
                    
                    # Clean up version specification
                    if version_spec:
                        # Remove trailing comments
                        version_spec = re.sub(r'\s*#.*$', '', version_spec)
                        version_spec = version_spec.strip()
                    
                    # Create dependency object
                    dep = Dependency(
                        name=package_name,
                        version=f"{operator}{version_spec}" if version_spec else None,
                        source="requirements.txt",
                        file_path=str(file_path.relative_to(self.root_dir))
                    )
                    
                    self.dependencies.add(dep)
                else:
                    # Simple package name without version
                    package_name = line.split('#')[0].strip()
                    if package_name:
                        dep = Dependency(
                            name=package_name,
                            version=None,
                            source="requirements.txt",
                            file_path=str(file_path.relative_to(self.root_dir))
                        )
                        self.dependencies.add(dep)
                        
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")

    def generate_cyclonedx_sbom(self) -> str:
        """Generate CycloneDX SBOM in JSON format (v11.0.0)."""
        # Create BOM with metadata
        bom = Bom(
            metadata=BomMetaData(
                tools=[Tool(name="StatAnalysis SBOM Generator", version="1.0.0")]
            )
        )

        # Add components
        for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
            component = Component(
                name=dep.name,
                version=dep.version or "unknown",
                type=ComponentType.LIBRARY
            )

            if dep.source:
                component.properties.add(Property(name="source", value=dep.source))
            if dep.file_path:
                component.properties.add(Property(name="file_path", value=dep.file_path))

            bom.components.add(component)

        # Generate JSON output
        outputter = make_outputter(
            bom=bom,
            output_format=OutputFormat.JSON,
            schema_version=SchemaVersion.V1_4
        )
        raw_json = outputter.output_as_string()

        # Reorder top-level
        desired_order = [
            "$schema",
            "bomFormat",
            "specVersion",
            "serialNumber",
            "version",
            "metadata",
            "components",
        ]

        try:
            data = json.loads(raw_json)
            ordered = {}

            for key in desired_order:
                if key in data:
                    ordered[key] = data[key]

            for key, value in data.items():
                if key not in ordered:
                    ordered[key] = value

            return json.dumps(ordered, indent=2)
        except Exception:
            # If any issue occurs, fall back to original output
            return raw_json


    def print_summary(self) -> None:
        """Print a summary of found dependencies to stdout."""
        print("\n" + "="*60)
        print("SBOM GENERATION SUMMARY")
        print("="*60)
        print(f"Root directory: {self.root_dir}")
        print(f"CMakeLists.txt files scanned: {self.cmake_files_scanned}")
        print(f"Python requirements files scanned: {self.python_files_scanned}")
        print(f"Total unique dependencies found: {len(self.dependencies)}")
        
        if self.dependencies:
            print("\nDependencies by source:")
            
            # Group by source
            by_source = {}
            for dep in self.dependencies:
                if dep.source not in by_source:
                    by_source[dep.source] = []
                by_source[dep.source].append(dep)
            
            for source, deps in sorted(by_source.items()):
                print(f"\n{source} ({len(deps)} dependencies):")
                for dep in sorted(deps, key=lambda x: x.name.lower()):
                    print(f"  - {dep}")
        
        print("\n" + "="*60)
    
    def save_sbom(self, output_path: str) -> None:
        """Save the SBOM to the specified path."""
        # Create output directory if it doesn't exist
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate SBOM content
        sbom_content = self.generate_cyclonedx_sbom()
        
        # Save to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sbom_content)
        
        print(f"SBOM saved to: {output_path}")
    
    def generate_markdown_report(self) -> str:
        """Generate a markdown report of the dependencies."""
        markdown_content = []
        
        # Header
        markdown_content.append("# StatAnalysis Software Bill of Materials (SBOM)")
        markdown_content.append("")
        markdown_content.append(f"**Generated on:** {self._get_current_timestamp()}")
        markdown_content.append(f"**Root directory:** `{self.root_dir}`")
        markdown_content.append("")
        
        # Summary
        markdown_content.append("## Summary")
        markdown_content.append("")
        markdown_content.append(f"- **CMakeLists.txt files scanned:** {self.cmake_files_scanned}")
        markdown_content.append(f"- **Python requirements files scanned:** {self.python_files_scanned}")
        markdown_content.append(f"- **Total unique dependencies:** {len(self.dependencies)}")
        markdown_content.append("")
        
        # Dependencies by source
        if self.dependencies:
            # Group by source
            by_source = {}
            for dep in self.dependencies:
                if dep.source not in by_source:
                    by_source[dep.source] = []
                by_source[dep.source].append(dep)
            
            for source, deps in sorted(by_source.items()):
                markdown_content.append(f"## {source} Dependencies ({len(deps)})")
                markdown_content.append("")
                
                markdown_content.append("| Package Name | Version | File Path |")
                markdown_content.append("|--------------|---------|-----------|")
                
                for dep in sorted(deps, key=lambda x: x.name.lower()):
                    version = dep.version or "unknown"
                    file_path = dep.file_path or "N/A"
                    markdown_content.append(f"| {dep.name} | {version} | {file_path} |")
                
                markdown_content.append("")
        
        # Version analysis
        markdown_content.append("## Version Analysis")
        markdown_content.append("")
        
        # Count dependencies with known vs unknown versions
        known_versions = [dep for dep in self.dependencies if dep.version and dep.version != "unknown"]
        unknown_versions = [dep for dep in self.dependencies if not dep.version or dep.version == "unknown"]
        
        markdown_content.append(f"- **Dependencies with known versions:** {len(known_versions)}")
        markdown_content.append(f"- **Dependencies with unknown versions:** {len(unknown_versions)}")
        markdown_content.append("")
        
        if unknown_versions:
            markdown_content.append("### Dependencies with Unknown Versions")
            markdown_content.append("")
            markdown_content.append("The following dependencies have unknown or unspecified versions:")
            markdown_content.append("")
            for dep in sorted(unknown_versions, key=lambda x: x.name.lower()):
                file_info = f" in `{dep.file_path}`" if dep.file_path else ""
                markdown_content.append(f"- **{dep.name}**{file_info}")
            markdown_content.append("")
        
        # Footer
        markdown_content.append("---")
        markdown_content.append("*This report was automatically generated by the [StatAnalysis SBOM Generator](https://github.com/Tully9/AtlasStatAnalysis)*")
        
        return "\n".join(markdown_content)
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in a readable format."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def save_markdown_report(self, output_path: str) -> None:
        """Save the markdown report to the specified path."""
        # Create output directory if it doesn't exist
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate markdown content
        markdown_content = self.generate_markdown_report()
        
        # Save to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        print(f"Markdown report saved to: {output_path}")

    def generate(self, output_path: str = "../stat-analysis-sbom.json") -> None:
        """Main function to generate the complete SBOM."""
        print("Starting SBOM generation...")
        
        # Scan for dependencies
        self.scan_cmake_files()
        self.scan_python_requirements()
        
        # Print summary
        self.print_summary()
        
        # Save SBOM
        self.save_sbom(output_path)
        
        # Generate and save markdown report
        markdown_path = str(Path(output_path).with_suffix('.md'))
        self.save_markdown_report(markdown_path)
        
        print("SBOM generation completed successfully!")


def main():
    directory = "."
    output_path = "../stat-analysis-sbom.json"

    try:
        generator = SBOMGenerator(directory)
        generator.generate(output_path)

    except KeyboardInterrupt:
        print("\nSBOM generation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error generating SBOM: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()