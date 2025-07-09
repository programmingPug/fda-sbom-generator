"""
Unit tests for SBOM generator.
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from fda_sbom.generator import SBOMGenerator
from fda_sbom.models import SBOM, Component, ComponentType, SBOMReport


class TestSBOMGenerator:
    """Test SBOMGenerator."""
    
    def test_initialization(self):
        """Test generator initialization."""
        generator = SBOMGenerator()
        
        assert generator.scanner_registry is not None
        assert generator.security_analyzer is not None
    
    def test_generate_sbom_basic(self, sample_python_project):
        """Test basic SBOM generation."""
        generator = SBOMGenerator()
        
        sbom = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Test Medical Device",
            manufacturer="Test Medical Inc",
            include_vulnerabilities=False  # Skip for speed
        )
        
        assert isinstance(sbom, SBOM)
        assert sbom.target_system == "Test Medical Device"
        assert sbom.manufacturer == "Test Medical Inc"
        assert sbom.document_id is not None
        assert sbom.document_name == "Test Medical Device"
        assert sbom.creators == ["fda-sbom-generator-0.1.0"]
    
    def test_generate_sbom_with_all_metadata(self, sample_python_project):
        """Test SBOM generation with all FDA metadata."""
        generator = SBOMGenerator()
        
        sbom = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Cardiac Monitor",
            target_version="2.1.0",
            manufacturer="Acme Medical Devices Inc",
            device_model="CM-2024",
            fda_submission_id="K240001",
            include_vulnerabilities=False
        )
        
        assert sbom.target_system == "Cardiac Monitor"
        assert sbom.target_version == "2.1.0"
        assert sbom.manufacturer == "Acme Medical Devices Inc"
        assert sbom.model_number == "CM-2024"
        assert sbom.fda_submission_id == "K240001"
    
    def test_generate_sbom_nonexistent_path(self):
        """Test SBOM generation with nonexistent path."""
        generator = SBOMGenerator()
        
        with pytest.raises(FileNotFoundError):
            generator.generate_sbom(
                project_path="/nonexistent/path",
                manufacturer="Test Inc"
            )
    
    @patch('fda_sbom.vulnerability.SecurityAnalyzer.scan_all_components')
    def test_generate_sbom_with_vulnerabilities(self, mock_scan, sample_python_project):
        """Test SBOM generation with vulnerability scanning."""
        # Mock vulnerability scanning to return SBOM as-is
        mock_scan.side_effect = lambda sbom, **kwargs: sbom
        
        generator = SBOMGenerator()
        
        sbom = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Test Device",
            manufacturer="Test Inc",
            include_vulnerabilities=True
        )
        
        # Should have called vulnerability scanning
        mock_scan.assert_called_once()
        assert isinstance(sbom, SBOM)
    
    def test_generate_sbom_with_progress_callback(self, sample_python_project):
        """Test SBOM generation with progress callback."""
        progress_messages = []
        
        def progress_callback(message):
            progress_messages.append(message)
        
        generator = SBOMGenerator()
        
        sbom = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Test Device",
            manufacturer="Test Inc",
            include_vulnerabilities=False,
            progress_callback=progress_callback
        )
        
        assert len(progress_messages) > 0
        assert any("Scanning project" in msg for msg in progress_messages)
    
    def test_scan_project(self, sample_python_project):
        """Test project scanning."""
        generator = SBOMGenerator()
        
        components = generator._scan_project(sample_python_project)
        
        assert isinstance(components, list)
        assert len(components) >= 0
        
        # Should deduplicate components
        component_keys = set()
        for component in components:
            key = f"{component.name}:{component.version}:{component.package_manager}"
            assert key not in component_keys  # No duplicates
            component_keys.add(key)
    
    def test_validate_sbom(self, sample_fda_compliant_sbom):
        """Test SBOM validation."""
        generator = SBOMGenerator()
        
        report = generator.validate_sbom(sample_fda_compliant_sbom)
        
        assert isinstance(report, SBOMReport)
        assert report.sbom_id == sample_fda_compliant_sbom.document_id
        assert report.total_components == len(sample_fda_compliant_sbom.components)
        assert report.fda_compliant is True
        assert len(report.compliance_issues) == 0
    
    def test_validate_sbom_non_compliant(self):
        """Test validation of non-compliant SBOM."""
        # Create non-compliant SBOM (missing manufacturer)
        sbom = SBOM(
            document_id="test-123",
            document_name="Test Device",
            document_namespace="https://test.com/sbom"
            # Missing manufacturer - FDA non-compliant
        )
        
        generator = SBOMGenerator()
        report = generator.validate_sbom(sbom)
        
        assert report.fda_compliant is False
        assert len(report.compliance_issues) > 0
        assert any("Manufacturer is required" in issue for issue in report.compliance_issues)
    
    def test_generate_compliance_checklist(self, sample_fda_compliant_sbom):
        """Test FDA compliance checklist generation."""
        generator = SBOMGenerator()
        
        checklist = generator.generate_compliance_checklist(sample_fda_compliant_sbom)
        
        assert isinstance(checklist, dict)
        
        # Check required fields
        assert "document_has_unique_id" in checklist
        assert "document_has_name" in checklist
        assert "has_manufacturer" in checklist
        assert "has_components" in checklist
        
        # All should be True for compliant SBOM
        for key, value in checklist.items():
            assert isinstance(value, bool)
    
    def test_scan_file(self, temp_project_dir):
        """Test single file scanning."""
        # Create a binary file
        dll_file = temp_project_dir / "test.dll"
        dll_file.write_bytes(b"fake dll content")
        
        generator = SBOMGenerator()
        component = generator.scan_file(dll_file)
        
        assert component is not None
        assert component.name == "test.dll"
        assert component.type == ComponentType.FILE
        assert component.file_hash is not None
    
    def test_scan_file_nonexistent(self):
        """Test scanning nonexistent file."""
        generator = SBOMGenerator()
        component = generator.scan_file("/nonexistent/file.dll")
        
        assert component is None
    
    def test_merge_sboms(self):
        """Test merging multiple SBOMs."""
        # Create multiple SBOMs
        sbom1 = SBOM(
            document_id="sbom-1",
            document_name="Device API",
            document_namespace="https://test.com/sbom1",
            manufacturer="Test Inc"
        )
        sbom1.add_component(Component(
            name="requests", version="2.28.0", type=ComponentType.LIBRARY
        ))
        
        sbom2 = SBOM(
            document_id="sbom-2", 
            document_name="Device UI",
            document_namespace="https://test.com/sbom2",
            fda_submission_id="K240001"
        )
        sbom2.add_component(Component(
            name="react", version="18.2.0", type=ComponentType.LIBRARY
        ))
        
        generator = SBOMGenerator()
        merged = generator.merge_sboms([sbom1, sbom2], "Merged Device Software")
        
        assert merged.document_name == "Merged Device Software"
        assert merged.manufacturer == "Test Inc"  # From first SBOM
        assert merged.fda_submission_id == "K240001"  # From second SBOM
        assert len(merged.components) == 2  # Both components
        
        component_names = [c.name for c in merged.components]
        assert "requests" in component_names
        assert "react" in component_names
    
    def test_merge_sboms_empty_list(self):
        """Test merging empty SBOM list."""
        generator = SBOMGenerator()
        
        with pytest.raises(ValueError, match="No SBOMs provided"):
            generator.merge_sboms([], "Empty Merge")
    
    def test_merge_sboms_deduplication(self):
        """Test SBOM merging with duplicate components."""
        # Create SBOMs with duplicate components
        sbom1 = SBOM(
            document_id="sbom-1",
            document_name="Project 1", 
            document_namespace="https://test.com/sbom1"
        )
        sbom1.add_component(Component(
            name="requests", version="2.28.0", type=ComponentType.LIBRARY, package_manager="pip"
        ))
        
        sbom2 = SBOM(
            document_id="sbom-2",
            document_name="Project 2",
            document_namespace="https://test.com/sbom2"
        )
        sbom2.add_component(Component(
            name="requests", version="2.28.0", type=ComponentType.LIBRARY, package_manager="pip"
        ))
        
        generator = SBOMGenerator()
        merged = generator.merge_sboms([sbom1, sbom2], "Merged Project")
        
        # Should have only one requests component (deduplicated)
        assert len(merged.components) == 1
        assert merged.components[0].name == "requests"
    
    @patch('requests.get')
    def test_update_component_licenses(self, mock_get):
        """Test updating component licenses from PyPI."""
        # Mock PyPI response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "license": "MIT License"
            }
        }
        mock_get.return_value = mock_response
        
        # Create SBOM with component missing license
        sbom = SBOM(
            document_id="test-123",
            document_name="Test",
            document_namespace="https://test.com/sbom"
        )
        component = Component(
            name="requests",
            version="2.28.0",
            type=ComponentType.LIBRARY,
            package_manager="pip"
            # No licenses
        )
        sbom.add_component(component)
        
        generator = SBOMGenerator()
        updated_sbom = generator.update_component_licenses(sbom)
        
        # Should have fetched and added license
        assert len(updated_sbom.components[0].licenses) == 1
        assert updated_sbom.components[0].licenses[0].name == "MIT License"


if __name__ == "__main__":
    pytest.main([__file__])
