"""
Unit tests for scanners.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from fda_sbom.scanners import (
    BaseScanner, PythonScanner, JavaScriptScanner, JavaScanner, 
    DotNetScanner, FileScanner, ScannerRegistry
)
from fda_sbom.models import Component, ComponentType, License


class TestBaseScanner:
    """Test BaseScanner abstract class."""
    
    def test_base_scanner_instantiation(self):
        """Test base scanner cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseScanner(Path("."))
    
    def test_normalize_license(self):
        """Test license normalization."""
        # Create a concrete scanner for testing
        class TestScanner(BaseScanner):
            def can_scan(self): return True
            def scan(self): return []
        
        scanner = TestScanner(Path("."))
        
        # Test known license mappings
        mit_license = scanner._normalize_license("MIT")
        assert mit_license.spdx_id == "MIT"
        assert mit_license.name == "MIT"
        
        apache_license = scanner._normalize_license("Apache-2.0")
        assert apache_license.spdx_id == "Apache-2.0"
        
        # Test unknown license
        unknown_license = scanner._normalize_license("Custom License")
        assert unknown_license.name == "Custom License"
        assert unknown_license.spdx_id is None
        
        # Test empty license
        empty_license = scanner._normalize_license("")
        assert empty_license.name == "Unknown"


class TestPythonScanner:
    """Test PythonScanner."""
    
    def test_can_scan_with_requirements_txt(self, sample_python_project):
        """Test scanner detection with requirements.txt."""
        scanner = PythonScanner(sample_python_project)
        assert scanner.can_scan() is True
    
    def test_can_scan_with_pyproject_toml(self, temp_project_dir):
        """Test scanner detection with pyproject.toml only."""
        project_path = temp_project_dir / "pyproject_only"
        project_path.mkdir()
        
        pyproject = """
[project]
name = "test-project"
dependencies = ["requests>=2.0"]
"""
        (project_path / "pyproject.toml").write_text(pyproject.strip())
        
        scanner = PythonScanner(project_path)
        assert scanner.can_scan() is True
    
    def test_can_scan_with_python_files(self, temp_project_dir):
        """Test scanner detection with Python files."""
        project_path = temp_project_dir / "python_files_only"
        project_path.mkdir()
        (project_path / "main.py").write_text("print('hello')")
        
        scanner = PythonScanner(project_path)
        assert scanner.can_scan() is True
    
    def test_cannot_scan_non_python_project(self, temp_project_dir):
        """Test scanner rejection of non-Python project."""
        project_path = temp_project_dir / "not_python"
        project_path.mkdir()
        (project_path / "index.js").write_text("console.log('hello')")
        
        scanner = PythonScanner(project_path)
        assert scanner.can_scan() is False
    
    def test_parse_requirements_txt(self, sample_python_project):
        """Test parsing requirements.txt."""
        scanner = PythonScanner(sample_python_project)
        requirements_file = sample_python_project / "requirements.txt"
        
        components = scanner._parse_requirements_txt(requirements_file)
        
        # Should find multiple components
        assert len(components) > 0
        
        # Check specific components
        component_names = [c.name for c in components]
        assert "requests" in component_names
        assert "click" in component_names
        assert "pytest" in component_names
        
        # Check component details
        requests_comp = next(c for c in components if c.name == "requests")
        assert requests_comp.version == "2.28.0"
        assert requests_comp.package_manager == "pip"
        assert requests_comp.type == ComponentType.LIBRARY
    
    def test_parse_requirement_line_with_version(self):
        """Test parsing requirement line with exact version."""
        scanner = PythonScanner(Path("."))
        
        component = scanner._parse_requirement_line("requests==2.28.0")
        assert component is not None
        assert component.name == "requests"
        assert component.version == "2.28.0"
        assert component.package_url == "pkg:pypi/requests@2.28.0"
    
    def test_parse_requirement_line_without_version(self):
        """Test parsing requirement line without version."""
        scanner = PythonScanner(Path("."))
        
        component = scanner._parse_requirement_line("requests")
        assert component is not None
        assert component.name == "requests"
        assert component.version is None
    
    def test_parse_requirement_line_invalid(self):
        """Test parsing invalid requirement line."""
        scanner = PythonScanner(Path("."))
        
        component = scanner._parse_requirement_line("# This is a comment")
        assert component is None
    
    @patch('subprocess.run')
    def test_create_python_component_with_pip_show(self, mock_run):
        """Test creating component with pip show data."""
        # Mock pip show output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Summary: HTTP library\\nHome-page: https://requests.readthedocs.io\\nLicense: Apache 2.0"
        )
        
        scanner = PythonScanner(Path("."))
        package_info = {"name": "requests", "version": "2.28.0"}
        
        component = scanner._create_python_component(package_info)
        
        assert component is not None
        assert component.name == "requests"
        assert component.version == "2.28.0"
        assert component.description == "HTTP library"
        assert component.homepage == "https://requests.readthedocs.io"
        assert len(component.licenses) == 1
    
    def test_full_scan(self, sample_python_project):
        """Test full project scan."""
        scanner = PythonScanner(sample_python_project)
        components = scanner.scan()
        
        # Should find components from both requirements.txt and pyproject.toml
        assert len(components) > 0
        
        # Check for components from requirements.txt
        component_names = [c.name for c in components]
        assert any("requests" in name for name in component_names)


class TestJavaScriptScanner:
    """Test JavaScriptScanner."""
    
    def test_can_scan_with_package_json(self, sample_nodejs_project):
        """Test scanner detection with package.json."""
        scanner = JavaScriptScanner(sample_nodejs_project)
        assert scanner.can_scan() is True
    
    def test_cannot_scan_without_js_indicators(self, temp_project_dir):
        """Test scanner rejection without JS indicators."""
        project_path = temp_project_dir / "not_js"
        project_path.mkdir()
        (project_path / "main.py").write_text("print('hello')")
        
        scanner = JavaScriptScanner(project_path)
        assert scanner.can_scan() is False
    
    def test_parse_package_json(self, sample_nodejs_project):
        """Test parsing package.json."""
        scanner = JavaScriptScanner(sample_nodejs_project)
        package_json = sample_nodejs_project / "package.json"
        
        components = scanner._parse_package_json(package_json)
        
        assert len(components) > 0
        
        # Check for production dependencies
        component_names = [c.name for c in components]
        assert "react" in component_names
        assert "axios" in component_names
        assert "lodash" in component_names
        
        # Check for dev dependencies
        assert "webpack" in component_names
        assert "eslint" in component_names
        
        # Check component details
        react_comp = next(c for c in components if c.name == "react")
        assert react_comp.package_manager == "npm"
        assert react_comp.type == ComponentType.LIBRARY


class TestJavaScanner:
    """Test JavaScanner."""
    
    def test_can_scan_with_pom_xml(self, sample_java_project):
        """Test scanner detection with pom.xml."""
        scanner = JavaScanner(sample_java_project)
        assert scanner.can_scan() is True
    
    def test_cannot_scan_without_java_indicators(self, temp_project_dir):
        """Test scanner rejection without Java indicators."""
        project_path = temp_project_dir / "not_java"
        project_path.mkdir()
        (project_path / "main.py").write_text("print('hello')")
        
        scanner = JavaScanner(project_path)
        assert scanner.can_scan() is False
    
    def test_parse_maven_pom(self, sample_java_project):
        """Test parsing Maven pom.xml."""
        scanner = JavaScanner(sample_java_project)
        pom_file = sample_java_project / "pom.xml"
        
        components = scanner._parse_maven_pom(pom_file)
        
        assert len(components) > 0
        
        # Check for specific dependencies
        component_names = [c.name for c in components]
        assert any("spring-boot-starter-web" in name for name in component_names)
        assert any("jackson-databind" in name for name in component_names)
        
        # Check component details
        spring_comp = next(c for c in components if "spring-boot" in c.name)
        assert spring_comp.package_manager == "maven"
        assert spring_comp.type == ComponentType.LIBRARY
        assert spring_comp.namespace == "org.springframework.boot"


class TestDotNetScanner:
    """Test DotNetScanner."""
    
    def test_can_scan_with_csproj(self, sample_dotnet_project):
        """Test scanner detection with .csproj file."""
        scanner = DotNetScanner(sample_dotnet_project)
        assert scanner.can_scan() is True
    
    def test_can_scan_with_packages_config(self, sample_dotnet_project):
        """Test scanner detection with packages.config."""
        scanner = DotNetScanner(sample_dotnet_project)
        assert scanner.can_scan() is True
    
    def test_cannot_scan_without_dotnet_indicators(self, temp_project_dir):
        """Test scanner rejection without .NET indicators."""
        project_path = temp_project_dir / "not_dotnet"
        project_path.mkdir()
        (project_path / "main.py").write_text("print('hello')")
        
        scanner = DotNetScanner(project_path)
        assert scanner.can_scan() is False
    
    def test_scan_project_file(self, sample_dotnet_project):
        """Test scanning .csproj file."""
        scanner = DotNetScanner(sample_dotnet_project)
        csproj_file = sample_dotnet_project / "MedicalDevice.Api.csproj"
        
        components = scanner._scan_project_file(csproj_file)
        
        assert len(components) > 0
        
        # Check for NuGet packages
        package_names = [c.name for c in components]
        assert "Microsoft.AspNetCore.OpenApi" in package_names
        assert "Swashbuckle.AspNetCore" in package_names
        assert "Newtonsoft.Json" in package_names
        
        # Check for .NET runtime
        assert any(".NET" in c.name for c in components)
        
        # Check component details
        openapi_comp = next(c for c in components if c.name == "Microsoft.AspNetCore.OpenApi")
        assert openapi_comp.version == "8.0.0"
        assert openapi_comp.package_manager == "nuget"
    
    def test_scan_packages_config(self, sample_dotnet_project):
        """Test scanning packages.config file."""
        scanner = DotNetScanner(sample_dotnet_project)
        packages_file = sample_dotnet_project / "packages.config"
        
        components = scanner._scan_packages_config(packages_file)
        
        assert len(components) > 0
        
        # Check for legacy packages
        package_names = [c.name for c in components]
        assert "EntityFramework" in package_names
        assert "log4net" in package_names
        
        # Check component details
        ef_comp = next(c for c in components if c.name == "EntityFramework")
        assert ef_comp.version == "6.4.4"
        assert ef_comp.package_manager == "nuget"
    
    def test_parse_target_framework(self):
        """Test parsing target framework versions."""
        scanner = DotNetScanner(Path("."))
        
        # Test .NET 8
        result = scanner._parse_target_framework("net8.0")
        assert result["name"] == ".NET"
        assert result["version"] == "8.0"
        
        # Test .NET Framework
        result = scanner._parse_target_framework("net48")
        assert result["name"] == ".NET Framework"
        assert "4.8" in result["version"]
        
        # Test .NET Standard
        result = scanner._parse_target_framework("netstandard2.1")
        assert result["name"] == ".NET Standard"
        assert result["version"] == "2.1"
        
        # Test unknown framework
        result = scanner._parse_target_framework("unknown")
        assert result is None


class TestFileScanner:
    """Test FileScanner."""
    
    def test_can_scan_always_true(self, temp_project_dir):
        """Test that FileScanner can always scan."""
        scanner = FileScanner(temp_project_dir)
        assert scanner.can_scan() is True
    
    def test_scan_binary_files(self, temp_project_dir):
        """Test scanning for binary files."""
        # Create some binary files
        (temp_project_dir / "library.dll").write_bytes(b"fake dll content")
        (temp_project_dir / "library.so").write_bytes(b"fake so content")
        (temp_project_dir / "app.exe").write_bytes(b"fake exe content")
        
        scanner = FileScanner(temp_project_dir)
        components = scanner.scan()
        
        # Should find binary files
        assert len(components) > 0
        
        file_names = [c.name for c in components]
        assert "library.dll" in file_names
        assert "library.so" in file_names
        assert "app.exe" in file_names
        
        # Check component details
        dll_comp = next(c for c in components if c.name == "library.dll")
        assert dll_comp.type == ComponentType.FILE
        assert dll_comp.file_hash is not None
        assert dll_comp.file_path is not None


class TestScannerRegistry:
    """Test ScannerRegistry."""
    
    def test_registry_initialization(self):
        """Test scanner registry initialization."""
        registry = ScannerRegistry()
        
        # Should have all built-in scanners
        scanner_names = [s.__name__ for s in registry.scanners]
        assert "PythonScanner" in scanner_names
        assert "JavaScriptScanner" in scanner_names
        assert "JavaScanner" in scanner_names
        assert "DotNetScanner" in scanner_names
        assert "FileScanner" in scanner_names
        
        # FileScanner should be last
        assert registry.scanners[-1].__name__ == "FileScanner"
    
    def test_get_applicable_scanners_python(self, sample_python_project):
        """Test getting applicable scanners for Python project."""
        registry = ScannerRegistry()
        scanners = registry.get_applicable_scanners(sample_python_project)
        
        # Should include PythonScanner and FileScanner
        scanner_names = [s.__class__.__name__ for s in scanners]
        assert "PythonScanner" in scanner_names
        assert "FileScanner" in scanner_names
    
    def test_get_applicable_scanners_nodejs(self, sample_nodejs_project):
        """Test getting applicable scanners for Node.js project."""
        registry = ScannerRegistry()
        scanners = registry.get_applicable_scanners(sample_nodejs_project)
        
        # Should include JavaScriptScanner and FileScanner
        scanner_names = [s.__class__.__name__ for s in scanners]
        assert "JavaScriptScanner" in scanner_names
        assert "FileScanner" in scanner_names
    
    def test_get_applicable_scanners_multi_language(self, sample_multi_project_solution):
        """Test getting applicable scanners for multi-language project."""
        registry = ScannerRegistry()
        scanners = registry.get_applicable_scanners(sample_multi_project_solution)
        
        # Should include multiple scanners
        scanner_names = [s.__class__.__name__ for s in scanners]
        assert "DotNetScanner" in scanner_names  # .csproj files
        assert "JavaScriptScanner" in scanner_names  # package.json
        assert "PythonScanner" in scanner_names  # requirements.txt
        assert "FileScanner" in scanner_names
    
    def test_register_custom_scanner(self):
        """Test registering custom scanner."""
        class CustomScanner(BaseScanner):
            def can_scan(self): return True
            def scan(self): return []
        
        registry = ScannerRegistry()
        initial_count = len(registry.scanners)
        
        registry.register_scanner(CustomScanner)
        
        # Should add the scanner before FileScanner
        assert len(registry.scanners) == initial_count + 1
        assert CustomScanner in registry.scanners
        assert registry.scanners[-1].__name__ == "FileScanner"  # FileScanner still last


if __name__ == "__main__":
    pytest.main([__file__])
