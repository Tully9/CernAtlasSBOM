"""
SBOM Generator for StatAnalysis using pip freeze (pyDep.txt) and asetup output (cppDep.txt).
"""

import json
import re
import sys
from pathlib import Path
from typing import Optional, Set
from dataclasses import dataclass
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.tool import Tool
from cyclonedx.model import Property
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion
from datetime import datetime


@dataclass
class Dependency:
    name: str
    version: Optional[str] = None
    source: str = ""  # pyDep.txt or cppDep.txt
    file_path: str = ""

    def __hash__(self):
        return hash((self.name, self.version))

    def __eq__(self, other):
        return isinstance(other, Dependency) and (self.name, self.version) == (other.name, other.version)


class SBOMGenerator:
    def __init__(self, py_file="pyDep.txt", cpp_file="cppDep.txt"):
        self.py_file = Path(py_file)
        self.cpp_file = Path(cpp_file)
        self.dependencies: Set[Dependency] = set()

    # --- Python dependencies ---
    def parse_py_deps(self):
        if not self.py_file.exists():
            print(f"Python dependency file not found: {self.py_file}")
            return

        with open(self.py_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if "==" in line:
                    name, version = line.split("==", 1)
                    self.dependencies.add(
                        Dependency(name=name.strip(), version=version.strip(), source="pyDep.txt")
                    )
                else:
                    self.dependencies.add(Dependency(name=line.strip(), source="pyDep.txt"))

    # --- C++ dependencies ---
    def parse_cpp_deps(self):
        if not self.cpp_file.exists():
            print(f"C++ dependency file not found: {self.cpp_file}")
            return

        pattern = r"^([A-Za-z0-9_]+)\s*:\s*(.*)$"

        with open(self.cpp_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                match = re.match(pattern, line)
                if not match:
                    continue
                name, version_raw = match.groups()
                version_raw = version_raw.strip()

                # Extract version as everything before the first whitespace (timestamp) or empty -> undefined
                version = version_raw.split()[0] if version_raw else "undefined"

                self.dependencies.add(Dependency(name=name, version=version, source="cppDep.txt"))


    # --- CycloneDX SBOM JSON ---
    def generate_cyclonedx_sbom(self) -> str:
        bom = Bom(
            metadata=BomMetaData(
                tools=[Tool(name="StatAnalysis SBOM Generator", version="2.0.0")]
            )
        )

        for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
            component = Component(
                name=dep.name,
                version=dep.version or "unknown",
                type=ComponentType.LIBRARY
            )
            if dep.source:
                component.properties.add(Property(name="source", value=dep.source))
            bom.components.add(component)

        outputter = make_outputter(
            bom=bom,
            output_format=OutputFormat.JSON,
            schema_version=SchemaVersion.V1_4
        )
        return outputter.output_as_string()

    def save_sbom(self, output_path="stat-analysis-sbom.json"):
        sbom_json = self.generate_cyclonedx_sbom()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sbom_json)
        print(f"SBOM saved to {output_path}")

    # --- Markdown report ---
    def generate_markdown_report(self) -> str:
        md = []
        md.append("# StatAnalysis SBOM Report\n")
        md.append(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Total dependencies:** {len(self.dependencies)}\n")

        if self.dependencies:
            by_source = {}
            for dep in self.dependencies:
                by_source.setdefault(dep.source, []).append(dep)

            for source, deps in sorted(by_source.items()):
                md.append(f"## {source} Dependencies ({len(deps)})\n")
                md.append("| Package | Version |")
                md.append("|---------|---------|")
                for dep in sorted(deps, key=lambda x: x.name.lower()):
                    md.append(f"| {dep.name} | {dep.version or 'unknown'} |")
                md.append("")

        return "\n".join(md)

    def save_markdown_report(self, output_path="stat-analysis-sbom.md"):
        md_content = self.generate_markdown_report()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {output_path}")

    # --- Main generate ---
    def generate(self, output_json="stat-analysis-sbom.json", output_md="stat-analysis-sbom.md"):
        print("Parsing Python dependencies...")
        self.parse_py_deps()
        print("Parsing C++ dependencies...")
        self.parse_cpp_deps()
        print(f"Found {len(self.dependencies)} dependencies total.")

        self.save_sbom(output_json)
        self.save_markdown_report(output_md)


def main():
    try:
        generator = SBOMGenerator()
        generator.generate()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
