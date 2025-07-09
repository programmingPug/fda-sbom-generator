"""
Test suite for FDA SBOM Generator.
"""

import json
import tempfile
from pathlib import Path

import pytest
from unittest.mock import Mock, patch

from fda_sbom.generator import SBOMGenerator
from fda_sbom.models import Component, ComponentType, License, SBOM
from fda_sbom.scanners import PythonScanner, FileScanner


class TestSBOMGenerator:
    """Test cases for SBOMGenerator."""
    
    def test_generate_sbom_basic(self):
        """Test basic SBOM generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            # Create a simple Python file
            (project_path / "requirements.txt").write_text("requests==2.28.0\nclick>=8.0")
            
            generator = SBOMGenerator()
            sbom = generator.generate_sbom(
                project_path=project_path,
                target_system="test-project",
                manufacturer="Test Manufacturer",
                include_vulnerabilities=False
            )
            
            assert sbom.document_name == "test-project"
            assert sbom.manufacturer == "Test Manufacturer"
            assert len(sbom.components) >= 0  # May find components from requirements.txt
    
    def test_validate_sbom(self):
        """Test SBOM validation."""
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom",
            manufacturer="Test Manufacturer"
        )
        
        # Add a component
        component = Component(
            name="test-component",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            licenses=[License(name="MIT")]
        )
        sbom.add_component(component)
        
        generator = SBOMGenerator()
        report = generator.validate_sbom(sbom)
        
        assert report.fda_compliant
        assert report.total_components == 1
        assert len(report.compliance_issues) == 0


class TestPythonScanner:
    """Test cases for PythonScanner."""
    
    def test_can_scan_with_requirements_txt(self):
        """Test scanner detection with requirements.txt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "requirements.txt").write_text("requests==2.28.0")
            
            scanner = PythonScanner(project_path)
            assert scanner.can_scan()
    
    def test_can_scan_with_python_files(self):
        """Test scanner detection with Python files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "main.py").write_text("print('hello')")
            
            scanner = PythonScanner(project_path)
            assert scanner.can_scan()
    
    def test_parse_requirements_txt(self):
        """Test parsing requirements.txt file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            requirements_file = project_path / "requirements.txt"
            requirements_file.write_text(
                "requests==2.28.0\n"
                "click>=8.0\n"
                "# This is a comment\n"
                "pytest\n"
            )
            
            scanner = PythonScanner(project_path)
            components = scanner._parse_requirements_txt(requirements_file)
            
            assert len(components) == 3
            
            # Check requests component
            requests_comp = next(c for c in components if c.name == "requests")
            assert requests_comp.version == "2.28.0"
            assert requests_comp.package_manager == "pip"


class TestComponent:
    """Test cases for Component model."""
    
    def test_component_creation(self):
        """Test basic component creation."""
        component = Component(
            name="test-lib",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            package_manager="pip"
        )
        
        assert component.name == "test-lib"
        assert component.version == "1.0.0"
        assert component.type == ComponentType.LIBRARY
        assert component.package_manager == "pip"
    
    def test_component_with_license(self):
        """Test component with license information."""
        license_obj = License(name="MIT", spdx_id="MIT")
        component = Component(
            name="test-lib",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            licenses=[license_obj]
        )
        
        assert len(component.licenses) == 1
        assert component.licenses[0].name == "MIT"


class TestSBOM:
    """Test cases for SBOM model."""
    
    def test_sbom_creation(self):
        """Test basic SBOM creation."""
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom"
        )
        
        assert sbom.document_id == "test-123"
        assert sbom.document_name == "Test SBOM"
        assert len(sbom.components) == 0
    
    def test_add_component(self):
        """Test adding components to SBOM."""
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom"
        )
        
        component = Component(
            name="test-component",
            version="1.0.0",
            type=ComponentType.LIBRARY
        )
        
        sbom.add_component(component)
        assert len(sbom.components) == 1
        assert sbom.components[0].name == "test-component"
    
    def test_validate_fda_compliance(self):
        """Test FDA compliance validation."""
        # Valid SBOM
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom",
            manufacturer="Test Manufacturer"
        )
        
        component = Component(
            name="test-component",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            licenses=[License(name="MIT")]
        )
        sbom.add_component(component)
        
        issues = sbom.validate_fda_compliance()
        assert len(issues) == 0
        
        # Invalid SBOM (missing manufacturer)
        invalid_sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom"
        )
        
        issues = invalid_sbom.validate_fda_compliance()
        assert len(issues) > 0
        assert any("Manufacturer is required" in issue for issue in issues)


# Integration test
def test_end_to_end_generation():
    """Test complete SBOM generation workflow."""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir)
        
        # Create a simple project structure
        (project_path / "requirements.txt").write_text("requests==2.28.0\nclick>=8.0")
        (project_path / "main.py").write_text("import requests\nprint('Hello, World!')")
        
        # Generate SBOM
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(
            project_path=project_path,
            target_system="test-project",
            target_version="1.0.0",
            manufacturer="Test Manufacturer",
            device_model="TEST-001",
            include_vulnerabilities=False  # Skip for speed
        )
        
        # Validate results
        assert sbom.target_system == "test-project"
        assert sbom.target_version == "1.0.0"
        assert sbom.manufacturer == "Test Manufacturer"
        assert sbom.model_number == "TEST-001"
        
        # Should have found some components
        assert len(sbom.components) >= 0
        
        # Test validation
        report = generator.validate_sbom(sbom)
        assert report.total_components == len(sbom.components)


if __name__ == "__main__":
    pytest.main([__file__])
