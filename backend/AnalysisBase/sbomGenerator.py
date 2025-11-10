"""
SBOM Generator for AnalysisBase
"""

import re
import os
from pathlib import Path
from typing import Optional, Set, List
from dataclasses import dataclass
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
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
    def __init__(self):
        base = os.path.dirname(__file__)
        self.py_file = Path(os.path.join(base, "pyDep.txt"))
        self.cpp_file = Path(os.path.join(base, "cppDep.txt"))
        self.dependencies: Set[Dependency] = set()

    def parse_py_deps(self):
        if not self.py_file.exists():
            print(f"Python dependency file not found: {self.py_file}")
            return

        pattern = r"^([A-Za-z0-9_\-]+)\s*:\s*(.*)$"

        with open(self.py_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = re.match(pattern, line)
                if not m:
                    continue
                name, version_raw = m.groups()
                version = version_raw.split()[0] if version_raw else "undefined"
                self.dependencies.add(Dependency(name=name, version=version, source=str(self.py_file)))

    def parse_cpp_deps(self):
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
                version_raw = version_raw.strip()
                version = version_raw.split()[0] if version_raw else "undefined"
                self.dependencies.add(Dependency(name=name, version=version, source=str(self.cpp_file)))

    def _load_package_filters(self, filters_path: Optional[str] = None) -> List[str]:
        candidates = []
        if filters_path:
            candidates.append(filters_path)
        candidates.append(os.path.join(os.getcwd(), "package_filters.txt"))
        candidates.append(os.path.join(os.getcwd(), "..", "Projects", "AnalysisBaseExternals", "package_filters.txt"))
        candidates.append(os.path.join(os.path.dirname(__file__), "package_filters.txt"))

        chosen = None
        for c in candidates:
            try:
                if os.path.isfile(os.path.abspath(c)):
                    chosen = os.path.abspath(c)
                    break
            except Exception:
                continue

        if not chosen:
            # fallback conservative list
            return [
                "HDF5", "BAT", "Blas", "Boost", "Davix", "dcap", "Eigen", "lwtnn",
                "FastJet", "FastJetContrib", "GoogleTest", "KLFitter", "Lhapdf",
                "LibXml2", "onnxruntime", "nlohmann_json", "PyAnalysis", "PyModules",
                "Python", "ROOT", "SQLite", "TBB", "XRootD"
            ]

        deps: List[str] = []
        try:
            with open(chosen, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith("+") and "External/" in line:
                        after = line.split("External/", 1)[1].strip()
                        pkg = after.split()[0]
                        if pkg:
                            deps.append(pkg)
        except Exception:
            # on failure return fallback
            return [
                "HDF5", "BAT", "Blas", "Boost", "Davix", "dcap", "Eigen", "lwtnn",
                "FastJet", "FastJetContrib", "GoogleTest", "KLFitter", "Lhapdf",
                "LibXml2", "onnxruntime", "nlohmann_json", "PyAnalysis", "PyModules",
                "Python", "ROOT", "SQLite", "TBB", "XRootD"
            ]
        return deps

    def export_package_filters(self, dest_dir: Optional[str] = None) -> Optional[str]:
        src = os.path.join(os.getcwd(), "package_filters.txt")
        if not os.path.isfile(src):
            print(f"package_filters.txt not found in current directory: {os.getcwd()}")
            return None
        dest_dir = dest_dir or os.path.dirname(__file__)
        dest = os.path.join(dest_dir, "package_filters.txt")
        try:
            with open(src, "r", encoding="utf-8") as fsrc, open(dest, "w", encoding="utf-8") as fdst:
                fdst.write(fsrc.read())
            print(f"Copied package_filters.txt to {dest}")
            return dest
        except Exception as e:
            print(f"Failed to copy package_filters.txt: {e}")
            return None

    def parse_cmakelists(self):
        print(f"Entering parse_cmakelists() - Current directory: {os.getcwd()}")
        deps = self._load_package_filters()

        patterns = {
            "HDF5": [r'ATLAS_HDF5_VERSION\s*"([^"]+)"', r'HDF5[-_]?([0-9.]+)\.tar\.gz'],
            "BAT": [r'BAT[-_/]?([0-9]+(?:\.[0-9]+){1,})\.tar\.gz', r'/v[0-9]+/BAT-([0-9.]+)\.tar\.gz'],
            "Blas": [r'OpenBLAS-([0-9.]+)\.tar\.gz'],
            "Boost": [r'boost_([0-9_]+)\.tar\.gz'],
            "Davix": [r'davix-([0-9.]+)\.tar\.gz'],
            "dcap": [r'dcap-([0-9.]+)-', r'dcap-([0-9.]+)\.tar'],
            "Eigen": [r'eigen-([0-9.]+)\.tar\.gz'],
            "lwtnn": [r'lwtnn[/\\]v?([0-9.]+)\.tar\.gz', r'externals/lwtnn/v?([0-9.]+)\.tar\.gz', r'v([0-9.]+)\.tar\.gz'],
            "FastJet": [r'fastjet-([0-9.]+)\.tar\.gz'],
            "FastJetContrib": [r'fjcontrib-([0-9.]+)\.tar\.gz', r'fastjetcontrib-([0-9.]+)\.tar\.gz'],
            "GoogleTest": [r'googletest-([0-9.]+)\.tar\.gz'],
            "KLFitter": [r'KLFitter[/\\]v?([0-9.]+)\.tar\.gz', r'KLFitter-([0-9.]+)\.tar\.gz'],
            "Lhapdf": [r'LHAPDF-([0-9.]+)\.tar\.gz'],
            "LibXml2": [r'libxml2-([0-9.]+)\.tar\.gz'],
            "onnxruntime": [r'onnxruntime[-\w]*-([0-9.]+)\.(?:tgz|tar\.gz)'],
            "nlohmann_json": [r'json-([0-9.]+)\.tar\.gz'],
            "Python": [r'libffi-([0-9.]+)\.tar\.gz', r'Python\s+([0-9.]+)'],
            "ROOT": [r'root_v([0-9.]+)\.source\.tar\.gz', r'ROOT[/\\]root_v([0-9.]+)\.source\.tar\.gz'],
            "SQLite": [r'sqlite-autoconf-([0-9]+)\.tar\.gz'],
            "TBB": [r'oneTBB-([0-9.]+)\.tar\.gz'],
            "XRootD": [r'xrootd-([0-9.]+)\.tar\.gz'],
        }

        cppdep_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "cppDep.txt"))

        existing_entries = set()
        if os.path.isfile(cppdep_path):
            try:
                with open(cppdep_path, "r", encoding="utf-8") as ef:
                    for l in ef:
                        existing_entries.add(l.strip())
            except Exception:
                pass

        with open(cppdep_path, "a", encoding="utf-8") as outf:
            for dep in deps:
                dep_key = dep
                if dep.lower() == "root":
                    dep_key = "ROOT"
                elif dep.lower() in ("nlohmann_json", "nlohmann-json"):
                    dep_key = "nlohmann_json"
                elif dep.lower() == "blas":
                    dep_key = "Blas"

                pkg_dir = os.path.join(os.getcwd(), dep)
                cmake_path = os.path.join(pkg_dir, "CMakeLists.txt")
                if not os.path.isfile(cmake_path):
                    alt_path = os.path.join(pkg_dir, "cmake", "CMakeLists.txt")
                    if os.path.isfile(alt_path):
                        cmake_path = alt_path
                    else:
                        if dep in ("PyModules", "PyAnalysis") and os.path.isdir(pkg_dir):
                            cmake_path = None
                        else:
                            continue

                content = ""
                if cmake_path and os.path.isfile(cmake_path):
                    try:
                        with open(cmake_path, "r", encoding="utf-8") as f:
                            content = f.read()
                    except Exception:
                        content = ""

                # PyModules: extract python packages from requirements files inside the package dir
                if dep == "PyModules" and os.path.isdir(pkg_dir):
                    req_files = ["requirements_analysisbase.txt.in", "requirements.txt.in"]
                    for rf in req_files:
                        rfpath = os.path.join(pkg_dir, rf)
                        if not os.path.isfile(rfpath):
                            continue
                        try:
                            with open(rfpath, "r", encoding="utf-8") as rfh:
                                for line in rfh:
                                    line = line.strip()
                                    if not line or line.startswith("#"):
                                        continue
                                    m = re.match(r'^([A-Za-z0-9_\-]+)==([^\s]+)', line)
                                    if not m:
                                        continue
                                    pkgname, pkgver = m.groups()
                                    entry = f"{pkgname}: {pkgver}"
                                    if entry not in existing_entries:
                                        outf.write(entry + "\n")
                                        existing_entries.add(entry)
                                        print(f"Discovered Python package from PyModules: {pkgname}: {pkgver}")
                        except Exception:
                            continue
                    continue

                # PyAnalysis: multiple python packages declared in its CMakeLists.txt
                if dep == "PyAnalysis":
                    if content:
                        for name, ver in re.findall(r'sources/([A-Za-z0-9_\-]+)-([0-9][0-9A-Za-z\._\-]+)\.tar\.gz', content):
                            entry = f"{name}: {ver}"
                            if entry not in existing_entries:
                                outf.write(entry + "\n")
                                existing_entries.add(entry)
                                print(f"Discovered {name}: {ver} (from PyAnalysis)")
                        for name, ver in re.findall(r'([A-Za-z0-9_\-]+)\s*=\s*sources/[A-Za-z0-9_\-]+-([0-9][0-9A-Za-z\._\-]+)\.tar\.gz', content):
                            entry = f"{name}: {ver}"
                            if entry not in existing_entries:
                                outf.write(entry + "\n")
                                existing_entries.add(entry)
                                print(f"Discovered {name}: {ver} (from PyAnalysis)")
                    continue

                # Generic per-package parsing
                found_version = None
                regex_list = patterns.get(dep_key, [])
                for rx in regex_list:
                    if content:
                        m = re.search(rx, content)
                        if m:
                            found_version = m.group(1)
                            break

                if not found_version and content:
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
                    if dep_key == "Boost":
                        found_version = found_version.replace("_", ".")
                    entry = f"{dep}: {found_version}"
                    if entry not in existing_entries:
                        outf.write(entry + "\n")
                        existing_entries.add(entry)
                        print(f"Discovered {dep}: {found_version}")
        print(f"Exiting parse_cmakelists() - Current directory: {os.getcwd()}")

    def parse_python_packages_1(self):
        base = os.path.dirname(__file__)
        outpath = os.path.join(base, "pyDep.txt")
        found = set()
        req_files = ["requirements_analysisbase.txt.in", "requirements.txt.in"]
        for rf in req_files:
            if not os.path.isfile(rf):
                continue
            try:
                with open(rf, "r", encoding="utf-8") as rfh:
                    for line in rfh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        m = re.match(r'^([A-Za-z0-9_\-]+)==([^\s]+)', line)
                        if not m:
                            continue
                        pkgname, pkgver = m.groups()
                        found.add((pkgname, pkgver))
            except Exception:
                continue
        if found:
            with open(outpath, "a", encoding="utf-8") as out:
                for pkgname, pkgver in sorted(found):
                    out.write(f"{pkgname}: {pkgver}\n")
            print(f"Wrote {len(found)} python package(s) to {outpath}")

    def parse_python_packages_2(self):
        cmake = "CMakeLists.txt"
        if not os.path.isfile(cmake):
            print(f"CMakeLists.txt not found in {os.getcwd()}")
            return
        outpath = os.path.join(os.path.dirname(__file__), "pyDep.txt")
        found = set()
        try:
            with open(cmake, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            content = ""

        for name, ver in re.findall(r'sources/([A-Za-z0-9_\-]+)-([0-9][0-9A-Za-z\._\-]+)\.tar\.gz', content):
            found.add((name, ver))
        for name, ver in re.findall(r'([A-Za-z0-9_\-]+)\s*=\s*sources/[A-Za-z0-9_\-]+-([0-9][0-9A-Za-z\._\-]+)\.tar\.gz', content):
            found.add((name, ver))

        if found:
            with open(outpath, "a", encoding="utf-8") as out:
                for name, ver in sorted(found):
                    out.write(f"{name}: {ver}\n")
            print(f"Wrote {len(found)} python package(s) to {outpath}")

    def generate_cyclonedx_sbom(self, analysisbase_version="24.0", externals_version="24.2.42") -> str:
        metadata = BomMetaData(
            properties=[
                Property(name="AnalysisBase", value=analysisbase_version),
                Property(name="AnalysisBaseExternals", value=externals_version)
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

    def save_sbom(self, output_path="analysis-base-sbom.json"):
        sbom_json = self.generate_cyclonedx_sbom()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sbom_json)
        print(f"SBOM saved to {output_path}")

    def generate_markdown_report(self, analysisbase_version="24.0", externals_version="24.2.42", build_info=None) -> str:
        md = []
        md.append("# AnalysisBase SBOM Report\n")
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
            md.append("")
        
        md.append("## Source Versions\n")
        md.append("| Source | Version |")
        md.append("|--------|---------|")
        md.append(f"| AnalysisBase | {analysisbase_version} |")
        md.append(f"| AnalysisBaseExternals | {externals_version} |\n")
        if self.dependencies:
            md.append("## All Dependencies\n")
            md.append("| Package | Version |")
            md.append("|---------|---------|")
            for dep in sorted(self.dependencies, key=lambda x: x.name.lower()):
                md.append(f"| {dep.name} | {dep.version or 'undefined'} |")
            md.append("")
        return "\n".join(md)

    def save_markdown_report(self, output_path="analysis-base-sbom.md", build_info=None):
        md_content = self.generate_markdown_report(build_info=build_info)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {output_path}")

    def generate(self, output_json="analysis-base-sbom.json", output_md="analysis-base-sbom.md"):
        print("Parsing Python dependencies...")
        self.parse_py_deps()
        print("Parsing C++ dependencies...")
        self.parse_cpp_deps()
        print(f"Found {len(self.dependencies)} dependencies total.")
        self.save_sbom(output_json)
        
        # Parse build information
        print("Parsing build information...")
        build_info = self.parse_build_info()
        self.save_markdown_report(output_md, build_info=build_info)

    def extract_python_version_and_update_cppdep(self, pydep_path="pyDep.txt", cppdep_path="cppDep.txt"):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        pydep_path = os.path.join(base_dir, pydep_path)
        cppdep_path = os.path.join(base_dir, cppdep_path)

        version = None
        if not os.path.exists(pydep_path):
            return
        with open(pydep_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.lower().startswith("python"):
                    m = re.search(r'([Pp]ython)\s*[:\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', line)
                    if m:
                        version = m.group(2)
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

    def parse_build_info(self, build_txt_path="externalBuild.txt"):
        """Parse compiler and platform information from externalBuild.txt"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        build_txt_path = os.path.join(base_dir, build_txt_path)
        
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
                        
        except Exception as e:
            print(f"Failed to parse build info: {e}")
        
        return compiler_info


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parse-cmakelists', action='store_true')
    parser.add_argument('--parse-package-filter', action='store_true')
    parser.add_argument('--parse-python-packages-1', action='store_true')
    parser.add_argument('--parse-python-packages-2', action='store_true')
    parser.add_argument('--parse-cpp', action='store_true')
    args = parser.parse_args()

    generator = SBOMGenerator()

    if args.parse_cmakelists:
        generator.parse_cmakelists()
        print("Parsed CMakeLists.txt for dependencies.")
    if args.parse_package_filter:
        generator.export_package_filters()
        print("Exported package_filters.txt (if present).")
    if args.parse_python_packages_1:
        generator.parse_python_packages_1()
    if args.parse_python_packages_2:
        generator.parse_python_packages_2()
    if args.parse_cpp:
        generator.extract_python_version_and_update_cppdep()
        generator.generate()
        print("Parsed dependencies and generated SBOM.")

if __name__ == "__main__":
    main()