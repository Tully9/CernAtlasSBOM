"""
SBOM Generator for AnalysisBase
"""

import json
import re
import sys
import os
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
import argparse

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
    def __init__(self, py_file="pyDep.txt", cpp_file="cppDep.txt"):
        self.py_file = Path(py_file)
        self.cpp_file = Path(cpp_file)
        self.dependencies: Set[Dependency] = set()

    # --- Python dependencies ---
    def parse_py_deps(self):
        if not self.py_file.exists():
            print(f"Python dependency file not found: {self.py_file}")
            return

        pattern = r"^([A-Za-z0-9_]+)\s*:\s*(.*)$"

        with open(self.py_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                match = re.match(pattern, line)
                if not match:
                    continue
                name, version_raw = match.groups()
                version = version_raw.split()[0] if version_raw else "undefined"
                self.dependencies.add(Dependency(name=name, version=version, source="pyDep.txt"))

    # --- C++ dependencies ---
    # Use to parce CMakeLists.txt files to extract dependency versions
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

    def parse_cmakelists(self):
        print(f"Entering parse_cmakelists() - Current directory: {os.getcwd()}")
        deps = [
            ("Boost", "boost_", r"/sources/boost_([0-9_]+)\.tar\.gz;"),
            ("Eigen", "eigen-", r"/sources/eigen-([0-9.]+)\.tar\.gz;"),
            ("Root", "root_v", r"/ROOT/root_v([0-9.]+)\.source\.tar\.gz;"),
            ("XRootD", "xrootd-", r"/sources/xrootd-([0-9.]+)\.tar\.gz;"),
            ("dcap", "dcap-", r"/sources/dcap-([0-9.]+)-"),
            ("Davix", "davix-", r"/sources/davix-([0-9.]+)\.tar\.gz;"),
            ("TBB", "oneTBB-", r"/sources/oneTBB-([0-9.]+)\.tar\.gz;"),
            ("nlohmann_json", "json-", r"/sources/json-([0-9.]+)\.tar\.gz;"),
        ]
        cppdep_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "cppDep.txt"))
        with open(cppdep_path, "a", encoding="utf-8") as outf:
            for dep, prefix, regex in deps:
                cmake_path = os.path.join(os.getcwd(), dep, "CMakeLists.txt")
                if not os.path.isfile(cmake_path):
                    continue
                with open(cmake_path, "r", encoding="utf-8") as f:
                    for line in f:
                        match = re.search(regex, line)
                        if match:
                            version = match.group(1)
                            if dep == "Boost":
                                version = version.replace("_", ".")
                            outf.write(f"{dep}: {version}\n")
                            print(f"Discovered {dep}: {version}")
                            break
        print(f"Exiting parse_cmakelists() - Current directory: {os.getcwd()}")

    # --- CycloneDX SBOM JSON ---
    def generate_cyclonedx_sbom(self) -> str:
        bom = Bom(
            metadata=BomMetaData(
                tools=[Tool(name="AnalysisBase SBOM Generator", version="2.1.16.7")]
            )
        )

        for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
            component = Component(
                name=dep.name,
                version=dep.version or "undefined",
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

    def save_sbom(self, output_path="analysis-base-sbom.json"):
        sbom_json = self.generate_cyclonedx_sbom()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sbom_json)
        print(f"SBOM saved to {output_path}")

    # --- Markdown report ---
    def generate_markdown_report(self) -> str:
        md = []
        md.append("# AnalysisBase SBOM Report\n")
        md.append(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Total dependencies:** {len(self.dependencies)}\n")

        if self.dependencies:
            md.append("## All Dependencies\n")
            md.append("| Package | Version |")
            md.append("|---------|---------|")
            for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
                md.append(f"| {dep.name} | {dep.version or 'undefined'} |")
            md.append("")

        return "\n".join(md)

    def save_markdown_report(self, output_path="analysis-base-sbom.md"):
        md_content = self.generate_markdown_report()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {output_path}")

    # --- Main generate ---
    def generate(self, output_json="analysis-base-sbom.json", output_md="analysis-base-sbom.md"):
        print("Parsing Python dependencies...")
        self.parse_py_deps()
        print("Parsing C++ dependencies...")
        self.parse_cpp_deps()
        print(f"Found {len(self.dependencies)} dependencies total.")

        self.save_sbom(output_json)
        self.save_markdown_report(output_md)

    def extract_python_version_and_update_cppdep(self, pydep_path="pyDep.txt", cppdep_path="cppDep.txt"):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        pydep_path = os.path.join(base_dir, pydep_path)
        cppdep_path = os.path.join(base_dir, cppdep_path)

        # Parse pyDep.txt for Python version
        version = None
        if not os.path.exists(pydep_path):
            print(f"Python dependency file not found: {pydep_path}")
            return
        with open(pydep_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Python 3."):
                    m = re.search(r'Python (\d+\.\d+\.\d+)', line)
                    if m:
                        version = m.group(1)
                        print(f"Discovered Python: {version}")
                        break
        if version:
            already_present = False
            if os.path.exists(cppdep_path):
                with open(cppdep_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith(f"Python: {version}"):
                            already_present = True
                            break
            if not already_present:
                with open(cppdep_path, "a", encoding="utf-8") as out:
                    out.write(f"Python: {version}\n")


def main():
    print(f"Script started in directory: {os.getcwd()}")
    parser = argparse.ArgumentParser()
    parser.add_argument('--parse-gitlab', action='store_true')
    parser.add_argument('--parse-cpp', action='store_true')
    parser.add_argument('--parse-terminal', nargs='?', const='cppDep.txt')
    parser.add_argument('--parse-cmakelists', action='store_true')
    parser.add_argument('--extract-python-version', action='store_true')
    args = parser.parse_args()

    generator = SBOMGenerator()

    if args.parse_gitlab:
        generator.parse_py_deps()
        print("Parsed GitLab dependencies.")
    if args.parse_cpp:
        generator.extract_python_version_and_update_cppdep()
        generator.generate()
        print("Parsed dependencies and generated SBOM.")
    if args.parse_terminal:
        generator.parse_terminal_output(args.parse_terminal)
        print(f"Parsed terminal output from {args.parse_terminal}.")
    if args.parse_cmakelists:
        generator.parse_cmakelists()
        print("Parsed CMakeLists.txt for dependencies.")
    if args.extract_python_version:
        generator.extract_python_version_and_update_cppdep()
        print("Extracted Python version and updated cppDep.txt.")
    print(f"Script finished in directory: {os.getcwd()}")

if __name__ == "__main__":
    main()