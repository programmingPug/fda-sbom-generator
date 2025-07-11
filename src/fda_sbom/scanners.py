"""
Base scanner interface and implementations for different package managers.
"""

import json
import os
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import Component, ComponentType, License


class BaseScanner(ABC):
    """Base class for all package scanners."""
    
    def __init__(self, project_path: Path):
        self.project_path = Path(project_path)
        self.components: List[Component] = []
    
    @abstractmethod
    def can_scan(self) -> bool:
        """Check if this scanner can handle the project."""
        pass
    
    @abstractmethod
    def scan(self) -> List[Component]:
        """Scan the project and return components."""
        pass
    
    def _run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        if cwd is None:
            cwd = self.project_path
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False
            )
            return result
        except FileNotFoundError:
            raise FileNotFoundError(f"Command not found: {cmd[0]}")
    
    def _normalize_license(self, license_text: str) -> License:
        """Normalize license text to License object."""
        if not license_text:
            return License(name="Unknown")
        
        # Clean up the license text
        license_text = license_text.strip()
        
        # Common SPDX license mappings
        spdx_mappings = {
            "MIT": "MIT",
            "Apache-2.0": "Apache-2.0",
            "GPL-3.0": "GPL-3.0-only",
            "BSD-3-Clause": "BSD-3-Clause",
            "ISC": "ISC",
            "LGPL-2.1": "LGPL-2.1-only",
        }
        
        # Check for direct match first
        if license_text in spdx_mappings:
            return License(
                spdx_id=spdx_mappings[license_text],
                name=license_text
            )
        
        # Check for partial matches
        for pattern, spdx_id in spdx_mappings.items():
            if pattern.lower() in license_text.lower():
                return License(
                    spdx_id=spdx_id,
                    name=license_text
                )
        
        return License(name=license_text)


class PythonScanner(BaseScanner):
    """Scanner for Python projects using pip."""
    
    def can_scan(self) -> bool:
        """Check if this is a Python project."""
        indicators = [
            "requirements.txt",
            "setup.py",
            "pyproject.toml",
            "Pipfile",
            "conda.yaml",
            "environment.yml"
        ]
        
        for indicator in indicators:
            if (self.project_path / indicator).exists():
                return True
        
        # Check for Python files
        for py_file in self.project_path.rglob("*.py"):
            return True
        
        return False
    
    def scan(self) -> List[Component]:
        """Scan Python project for dependencies."""
        components = []
        
        # Parse requirements.txt
        requirements_file = self.project_path / "requirements.txt"
        if requirements_file.exists():
            components.extend(self._parse_requirements_txt(requirements_file))
        
        # Parse pyproject.toml
        pyproject_file = self.project_path / "pyproject.toml"
        if pyproject_file.exists():
            components.extend(self._parse_pyproject_toml(pyproject_file))
        
        return components
    
    def _create_python_component(self, package_info: Dict) -> Optional[Component]:
        """Create a Component from pip package info."""
        try:
            name = package_info.get("name", "")
            version = package_info.get("version", "")
            
            if not name:
                return None
            
            # Get additional package info
            try:
                result = self._run_command([
                    sys.executable, "-m", "pip", "show", name
                ])
                
                description = ""
                homepage = ""
                license_text = ""
                
                if result.returncode == 0:
                    # Handle both regular newlines and escaped newlines in the output
                    lines = result.stdout.replace('\\n', '\n').split('\n')
                    for line in lines:
                        if line.startswith("Summary:"):
                            description = line.split(":", 1)[1].strip()
                        elif line.startswith("Home-page:"):
                            homepage = line.split(":", 1)[1].strip()
                        elif line.startswith("License:"):
                            license_text = line.split(":", 1)[1].strip()
            except:
                description = ""
                homepage = ""
                license_text = ""
            
            licenses = [self._normalize_license(license_text)] if license_text else []
            
            return Component(
                name=name,
                version=version,
                type=ComponentType.LIBRARY,
                package_manager="pip",
                description=description,
                homepage=homepage,
                licenses=licenses,
                package_url=f"pkg:pypi/{name}@{version}"
            )
        except Exception as e:
            print(f"Warning: Could not process package {package_info}: {e}")
            return None
    
    def _parse_requirements_txt(self, requirements_file: Path) -> List[Component]:
        """Parse requirements.txt file."""
        components = []
        
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        component = self._parse_requirement_line(line)
                        if component:
                            components.append(component)
        except Exception as e:
            print(f"Warning: Could not parse requirements.txt: {e}")
        
        return components
    
    def _parse_requirement_line(self, line: str) -> Optional[Component]:
        """Parse a single requirement line."""
        # Simple regex for package==version
        match = re.match(r'^([a-zA-Z0-9_-]+)([>=<~!]+)([0-9.]+)', line)
        if match:
            name, operator, version = match.groups()
            return Component(
                name=name,
                version=version,
                type=ComponentType.LIBRARY,
                package_manager="pip",
                package_url=f"pkg:pypi/{name}@{version}"
            )
        
        # Just package name
        match = re.match(r'^([a-zA-Z0-9_-]+)$', line)
        if match:
            name = match.group(1)
            return Component(
                name=name,
                type=ComponentType.LIBRARY,
                package_manager="pip",
                package_url=f"pkg:pypi/{name}"
            )
        
        return None
    
    def _parse_pyproject_toml(self, pyproject_file: Path) -> List[Component]:
        """Parse pyproject.toml file."""
        components = []
        
        try:
            import toml
            with open(pyproject_file, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            # Check for dependencies
            project = data.get('project', {})
            dependencies = project.get('dependencies', [])
            
            for dep in dependencies:
                component = self._parse_requirement_line(dep)
                if component:
                    components.append(component)
        except Exception as e:
            print(f"Warning: Could not parse pyproject.toml: {e}")
        
        return components


class JavaScriptScanner(BaseScanner):
    """Scanner for JavaScript/Node.js projects."""
    
    def can_scan(self) -> bool:
        """Check if this is a JavaScript project."""
        indicators = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml"
        ]
        
        for indicator in indicators:
            if (self.project_path / indicator).exists():
                return True
        
        return False
    
    def scan(self) -> List[Component]:
        """Scan JavaScript project for dependencies."""
        components = []
        
        package_json = self.project_path / "package.json"
        if package_json.exists():
            components.extend(self._parse_package_json(package_json))
        
        return components
    
    def _parse_package_json(self, package_json: Path) -> List[Component]:
        """Parse package.json file."""
        components = []
        
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse dependencies
            dependencies = data.get('dependencies', {})
            dev_dependencies = data.get('devDependencies', {})
            
            for name, version in dependencies.items():
                component = Component(
                    name=name,
                    version=version.lstrip('^~>=<'),
                    type=ComponentType.LIBRARY,
                    package_manager="npm",
                    package_url=f"pkg:npm/{name}@{version.lstrip('^~>=<')}"
                )
                components.append(component)
            
            for name, version in dev_dependencies.items():
                component = Component(
                    name=name,
                    version=version.lstrip('^~>=<'),
                    type=ComponentType.LIBRARY,
                    package_manager="npm",
                    package_url=f"pkg:npm/{name}@{version.lstrip('^~>=<')}"
                )
                components.append(component)
        
        except Exception as e:
            print(f"Warning: Could not parse package.json: {e}")
        
        return components


class JavaScanner(BaseScanner):
    """Scanner for Java projects using Maven or Gradle."""
    
    def can_scan(self) -> bool:
        """Check if this is a Java project."""
        indicators = [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "gradle.properties"
        ]
        
        for indicator in indicators:
            if (self.project_path / indicator).exists():
                return True
        
        return False
    
    def scan(self) -> List[Component]:
        """Scan Java project for dependencies."""
        components = []
        
        # Try Maven first
        pom_xml = self.project_path / "pom.xml"
        if pom_xml.exists():
            components.extend(self._parse_maven_pom(pom_xml))
        
        # Try Gradle
        build_gradle = self.project_path / "build.gradle"
        if build_gradle.exists():
            components.extend(self._parse_gradle_build(build_gradle))
        
        return components
    
    def _parse_maven_pom(self, pom_file: Path) -> List[Component]:
        """Parse Maven pom.xml file."""
        components = []
        
        try:
            import xml.etree.ElementTree as ET
            
            with open(pom_file, 'r', encoding='utf-8') as f:
                tree = ET.parse(f)
                root = tree.getroot()
            
            # Handle Maven namespace
            namespaces = {}
            if root.tag.startswith('{'):
                namespace = root.tag[1:root.tag.index('}')]
                namespaces['mvn'] = namespace
                dependency_xpath = './/mvn:dependency'
                group_xpath = 'mvn:groupId'
                artifact_xpath = 'mvn:artifactId' 
                version_xpath = 'mvn:version'
            else:
                dependency_xpath = './/dependency'
                group_xpath = 'groupId'
                artifact_xpath = 'artifactId'
                version_xpath = 'version'
            
            # Find dependencies
            dependencies = root.findall(dependency_xpath, namespaces)
            
            for dep in dependencies:
                group_id_elem = dep.find(group_xpath, namespaces)
                artifact_id_elem = dep.find(artifact_xpath, namespaces)
                version_elem = dep.find(version_xpath, namespaces)
                
                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text
                    version_text = version_elem.text if version_elem is not None else "unknown"
                    
                    if group_id and artifact_id:  # Ensure we have valid text
                        name = f"{group_id}:{artifact_id}"
                        
                        component = Component(
                            name=name,
                            version=version_text,
                            type=ComponentType.LIBRARY,
                            package_manager="maven",
                            namespace=group_id,
                            package_url=f"pkg:maven/{group_id}/{artifact_id}@{version_text}"
                        )
                        components.append(component)
        
        except Exception as e:
            print(f"Warning: Could not parse pom.xml: {e}")
        
        return components
    
    def _parse_gradle_build(self, build_file: Path) -> List[Component]:
        """Parse Gradle build.gradle file."""
        components = []
        
        try:
            with open(build_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple regex to find dependencies
            patterns = [
                r'implementation\s+["\']([^:]+):([^:]+):([^"\']*)["\']*',
                r'compile\s+["\']([^:]+):([^:]+):([^"\']*)["\']*',
                r'api\s+["\']([^:]+):([^:]+):([^"\']*)["\']*'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    group_id, artifact_id, version = match
                    name = f"{group_id}:{artifact_id}"
                    
                    component = Component(
                        name=name,
                        version=version or "unknown",
                        type=ComponentType.LIBRARY,
                        package_manager="gradle",
                        namespace=group_id,
                        package_url=f"pkg:maven/{group_id}/{artifact_id}@{version}"
                    )
                    components.append(component)
        
        except Exception as e:
            print(f"Warning: Could not parse build.gradle: {e}")
        
        return components


class DotNetScanner(BaseScanner):
    """Scanner for .NET/C# projects."""
    
    def can_scan(self) -> bool:
        """Check if this is a .NET project."""
        indicators = [
            "*.csproj",
            "*.vbproj", 
            "*.fsproj",
            "packages.config",
            "*.sln"
        ]
        
        for indicator in indicators:
            if list(self.project_path.glob(indicator)):
                return True
        
        return False
    
    def scan(self) -> List[Component]:
        """Scan .NET project for dependencies."""
        components = []
        
        # Find project files
        project_files = []
        for pattern in ["*.csproj", "*.vbproj", "*.fsproj"]:
            project_files.extend(self.project_path.rglob(pattern))
        
        for project_file in project_files:
            components.extend(self._scan_project_file(project_file))
        
        # Also check for packages.config files
        packages_configs = list(self.project_path.rglob("packages.config"))
        for packages_file in packages_configs:
            components.extend(self._scan_packages_config(packages_file))
        
        return components
    
    def _scan_project_file(self, project_file: Path) -> List[Component]:
        """Scan a project file for dependencies."""
        components = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(project_file)
            root = tree.getroot()
            
            # Handle MSBuild namespace
            namespaces = {}
            if root.tag.startswith('{'):
                namespace = root.tag[1:root.tag.index('}')]
                namespaces['msbuild'] = namespace
                package_xpath = './/msbuild:PackageReference'
                framework_xpath = './/msbuild:TargetFramework'
                frameworks_xpath = './/msbuild:TargetFrameworks'
            else:
                package_xpath = './/PackageReference'
                framework_xpath = './/TargetFramework'
                frameworks_xpath = './/TargetFrameworks'
            
            # Find PackageReference elements
            package_references = root.findall(package_xpath, namespaces)
            for pkg_ref in package_references:
                package_id = pkg_ref.get("Include")
                version = pkg_ref.get("Version")
                
                if package_id:
                    component = Component(
                        name=package_id,
                        version=version or "unknown",
                        type=ComponentType.LIBRARY,
                        package_manager="nuget",
                        package_url=f"pkg:nuget/{package_id}@{version or 'unknown'}"
                    )
                    components.append(component)
            
            # Find TargetFramework and add .NET runtime component
            target_frameworks = root.findall(framework_xpath, namespaces)
            if not target_frameworks:
                target_frameworks = root.findall(frameworks_xpath, namespaces)
            
            for tf_elem in target_frameworks:
                framework_text = tf_elem.text
                if framework_text:
                    runtime_info = self._parse_target_framework(framework_text)
                    if runtime_info:
                        runtime_component = Component(
                            name=runtime_info["name"],
                            version=runtime_info["version"],
                            type=ComponentType.FRAMEWORK,
                            description=f"{runtime_info['name']} Runtime"
                        )
                        components.append(runtime_component)
                    break  # Only process first target framework
        
        except Exception as e:
            print(f"Warning: Could not parse project file {project_file}: {e}")
        
        return components
    
    def _scan_packages_config(self, packages_file: Path) -> List[Component]:
        """Scan packages.config file for legacy .NET Framework projects."""
        components = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(packages_file)
            root = tree.getroot()
            
            # Find package elements
            for package in root.findall('package'):
                package_id = package.get('id')
                version = package.get('version')
                target_framework = package.get('targetFramework')
                
                if package_id and version:
                    component = Component(
                        name=package_id,
                        version=version,
                        type=ComponentType.LIBRARY,
                        package_manager="nuget",
                        package_url=f"pkg:nuget/{package_id}@{version}"
                    )
                    components.append(component)
        
        except Exception as e:
            print(f"Warning: Could not parse packages.config file {packages_file}: {e}")
        
        return components
    
    def _parse_target_framework(self, framework: str) -> Optional[Dict]:
        """Parse target framework string to extract .NET version info."""
        if not framework:
            return None
        
        framework = framework.lower().strip()
        
        # .NET 5+ (net5.0, net6.0, net7.0, net8.0)
        if framework.startswith('net') and '.' in framework:
            version_part = framework[3:]  # Remove 'net' prefix
            if version_part.replace('.', '').isdigit():
                return {
                    "name": ".NET",
                    "version": version_part
                }
        
        # .NET Framework (net45, net48, etc.)
        if framework.startswith('net') and framework[3:].isdigit():
            version_code = framework[3:]
            version_mapping = {
                "45": "4.5",
                "451": "4.5.1",
                "452": "4.5.2",
                "46": "4.6",
                "461": "4.6.1",
                "462": "4.6.2",
                "47": "4.7",
                "471": "4.7.1",
                "472": "4.7.2",
                "48": "4.8"
            }
            version = version_mapping.get(version_code, f"4.{version_code[0]}.{version_code[1:]}")
            return {
                "name": ".NET Framework",
                "version": version
            }
        
        # .NET Core (netcoreapp2.1, netcoreapp3.1)
        if framework.startswith('netcoreapp'):
            version = framework.replace('netcoreapp', '')
            return {
                "name": ".NET Core",
                "version": version
            }
        
        # .NET Standard (netstandard2.0, netstandard2.1)
        if framework.startswith('netstandard'):
            version = framework.replace('netstandard', '')
            return {
                "name": ".NET Standard",
                "version": version
            }
        
        return None


class FileScanner(BaseScanner):
    """Scanner for individual files and generic components."""
    
    def can_scan(self) -> bool:
        """Can always scan for files."""
        return True
    
    def scan(self) -> List[Component]:
        """Scan for important files and create file components."""
        components = []
        
        # Important file patterns to track
        important_patterns = [
            "*.so",
            "*.dll", 
            "*.dylib",
            "*.exe",
            "*.jar"
        ]
        
        for pattern in important_patterns:
            for file_path in self.project_path.rglob(pattern):
                if file_path.is_file():
                    component = self._create_file_component(file_path)
                    if component:
                        components.append(component)
        
        return components
    
    def _create_file_component(self, file_path: Path) -> Optional[Component]:
        """Create a Component from a file."""
        try:
            import hashlib
            
            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            file_hash = sha256_hash.hexdigest()
            relative_path = file_path.relative_to(self.project_path)
            
            return Component(
                name=file_path.name,
                version="unknown",
                type=ComponentType.FILE,
                file_path=str(relative_path),
                file_hash=file_hash,
                description=f"Binary file: {file_path.suffix}"
            )
        
        except Exception as e:
            print(f"Warning: Could not process file {file_path}: {e}")
            return None


class ScannerRegistry:
    """Registry for managing available scanners."""
    
    def __init__(self):
        self.scanners = [
            PythonScanner,
            JavaScriptScanner,
            JavaScanner,
            DotNetScanner,
            FileScanner,  # Always last as fallback
        ]
    
    def get_applicable_scanners(self, project_path: Path) -> List[BaseScanner]:
        """Get all scanners that can handle the project."""
        applicable = []
        
        for scanner_class in self.scanners:
            scanner = scanner_class(project_path)
            if scanner.can_scan():
                applicable.append(scanner)
        
        return applicable
    
    def register_scanner(self, scanner_class):
        """Register a new scanner class."""
        if scanner_class not in self.scanners:
            # Insert before FileScanner (which should always be last)
            self.scanners.insert(-1, scanner_class)
