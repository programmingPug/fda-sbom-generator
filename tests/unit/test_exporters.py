"""
Unit tests for SBOM exporters.
"""

import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import pytest

from fda_sbom.exporters import (
    SPDXExporter, CycloneDXExporter, SWIDExporter, JSONExporter,
    export_sbom, get_exporter, EXPORTERS
)
from fda_sbom.models import SBOM, Component, ComponentType, License, Vulnerability, VulnerabilitySeverity, SBOMFormat


class TestSPDXExporter:
    """Test SPDX exporter."""
    
    def test_basic_export(self, sample_fda_compliant_sbom):
        """Test basic SPDX export."""
        exporter = SPDXExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test.spdx.json"
            exporter.export(sample_fda_compliant_sbom, output_file)
            
            assert output_file.exists()
            
            # Verify SPDX structure
            with open(output_file) as f:
                spdx_data = json.load(f)
            
            assert spdx_data["spdxVersion"] == "SPDX-2.3"
            assert spdx_data["dataLicense"] == "CC0-1.0"
            assert "SPDXID" in spdx_data
            assert spdx_data["name"] == sample_fda_compliant_sbom.document_name
            assert spdx_data["documentNamespace"] == sample_fda_compliant_sbom.document_namespace
            
            # Check creation info
            assert "creationInfo" in spdx_data
            creation_info = spdx_data["creationInfo"]
            assert "created" in creation_info
            assert "creators" in creation_info
            
            # Check packages
            assert "packages" in spdx_data
            packages = spdx_data["packages"]
            
            # Should have root package + component packages
            expected_packages = 1 + len(sample_fda_compliant_sbom.components)
            assert len(packages) == expected_packages
            
            # Check root package
            root_package = packages[0]
            assert root_package["SPDXID"] == "SPDXRef-Package"
            assert root_package["name"] == sample_fda_compliant_sbom.target_system
            assert root_package["supplier"] == f"Organization: {sample_fda_compliant_sbom.manufacturer}"
    
    def test_export_with_vulnerabilities(self, sample_sbom):
        """Test SPDX export with vulnerability annotations."""
        exporter = SPDXExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "vuln.spdx.json"
            exporter.export(sample_sbom, output_file)
            
            with open(output_file) as f:
                spdx_data = json.load(f)
            
            # Find component with vulnerabilities
            packages = spdx_data["packages"]
            vulnerable_package = None
            
            for package in packages:
                if "annotations" in package:
                    vulnerable_package = package
                    break
            
            assert vulnerable_package is not None
            annotations = vulnerable_package["annotations"]
            assert len(annotations) > 0
            
            # Check annotation structure
            annotation = annotations[0]
            assert annotation["annotationType"] == "REVIEW"
            assert "Vulnerability" in annotation["annotationComment"]
    
    def test_export_with_licenses(self, temp_project_dir):
        """Test SPDX export with license information."""
        sbom = SBOM(
            document_id="test-licenses",
            document_name="License Test",
            document_namespace="https://test.com/licenses"
        )
        
        # Add component with multiple licenses
        component = Component(
            name="multi-license-lib",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            licenses=[
                License(name="MIT", spdx_id="MIT"),
                License(name="Apache-2.0", spdx_id="Apache-2.0")
            ]
        )
        sbom.add_component(component)
        
        exporter = SPDXExporter()
        output_file = temp_project_dir / "licenses.spdx.json"
        exporter.export(sbom, output_file)
        
        with open(output_file) as f:
            spdx_data = json.load(f)
        
        # Find the component package
        component_package = spdx_data["packages"][1]  # First is root
        assert "licenseConcluded" in component_package
        assert "MIT AND Apache-2.0" in component_package["licenseConcluded"]


class TestCycloneDXExporter:
    """Test CycloneDX exporter."""
    
    def test_basic_export(self, sample_fda_compliant_sbom):
        """Test basic CycloneDX export."""
        exporter = CycloneDXExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test.cyclonedx.json"
            exporter.export(sample_fda_compliant_sbom, output_file)
            
            assert output_file.exists()
            
            # Verify CycloneDX structure
            with open(output_file) as f:
                cdx_data = json.load(f)
            
            assert cdx_data["bomFormat"] == "CycloneDX"
            assert cdx_data["specVersion"] == "1.4"
            assert "serialNumber" in cdx_data
            assert cdx_data["version"] == 1
            
            # Check metadata
            assert "metadata" in cdx_data
            metadata = cdx_data["metadata"]
            assert "timestamp" in metadata
            assert "tools" in metadata
            
            # Check components
            assert "components" in cdx_data
            components = cdx_data["components"]
            assert len(components) == len(sample_fda_compliant_sbom.components)
            
            # Check component structure
            if components:
                component = components[0]
                assert "type" in component
                assert "name" in component
                assert "bom-ref" in component
    
    def test_component_type_mapping(self):
        """Test component type mapping to CycloneDX format."""
        exporter = CycloneDXExporter()
        
        # Test all component type mappings
        test_cases = [
            ("library", "library"),
            ("framework", "framework"),
            ("application", "application"),
            ("firmware", "firmware"),
            ("unknown", "library")  # Default fallback
        ]
        
        for internal_type, expected_cdx_type in test_cases:
            result = exporter._map_component_type(internal_type)
            assert result == expected_cdx_type
    
    def test_export_with_vulnerabilities(self, sample_sbom):
        """Test CycloneDX export with vulnerabilities."""
        exporter = CycloneDXExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "vuln.cyclonedx.json"
            exporter.export(sample_sbom, output_file)
            
            with open(output_file) as f:
                cdx_data = json.load(f)
            
            # Find component with vulnerabilities
            components = cdx_data["components"]
            vulnerable_component = None
            
            for component in components:
                if "vulnerabilities" in component:
                    vulnerable_component = component
                    break
            
            assert vulnerable_component is not None
            vulnerabilities = vulnerable_component["vulnerabilities"]
            assert len(vulnerabilities) > 0
            
            # Check vulnerability structure
            vuln = vulnerabilities[0]
            assert "id" in vuln
            assert "source" in vuln


class TestSWIDExporter:
    """Test SWID exporter."""
    
    def test_basic_export(self, sample_fda_compliant_sbom):
        """Test basic SWID export."""
        exporter = SWIDExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test.swid.xml"
            exporter.export(sample_fda_compliant_sbom, output_file)
            
            assert output_file.exists()
            
            # Parse and verify XML structure
            tree = ET.parse(output_file)
            root = tree.getroot()
            
            # Handle XML namespace - get local name only
            tag_name = root.tag.split('}')[-1] if '}' in root.tag else root.tag
            assert tag_name == "SoftwareIdentity"
            assert root.get("tagId") == sample_fda_compliant_sbom.document_id
            assert root.get("name") == sample_fda_compliant_sbom.document_name
            assert root.get("version") == sample_fda_compliant_sbom.target_version
            
            # Check for Entity element - handle namespace
            # Try with namespace first
            ns = {'': 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd'}
            entity = root.find(".//{{{}}}Entity".format(ns['']))
            if entity is None:
                # Try without namespace
                entity = root.find("Entity")
            assert entity is not None
            assert entity.get("name") == sample_fda_compliant_sbom.manufacturer
    
    def test_export_with_components(self, sample_fda_compliant_sbom):
        """Test SWID export with component payload."""
        exporter = SWIDExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "components.swid.xml"
            exporter.export(sample_fda_compliant_sbom, output_file)
            
            tree = ET.parse(output_file)
            root = tree.getroot()
            
            # Check for Payload - handle namespace
            ns = {'': 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd'}
            payload = root.find(".//{{{}}}Payload".format(ns['']))
            if payload is None:
                payload = root.find("Payload")
            if sample_fda_compliant_sbom.components:
                assert payload is not None
                
                # Check directories for each component
                directories = payload.findall(".//{{{}}}Directory".format(ns['']))
                if not directories:
                    directories = payload.findall("Directory")
                assert len(directories) == len(sample_fda_compliant_sbom.components)
            
            # Check for Link elements - handle namespace
            links = root.findall(".//{{{}}}Link".format(ns['']))
            if not links:
                links = root.findall("Link")
            assert len(links) == len(sample_fda_compliant_sbom.components)


class TestJSONExporter:
    """Test native JSON exporter."""
    
    def test_basic_export(self, sample_fda_compliant_sbom):
        """Test basic JSON export."""
        exporter = JSONExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test.json"
            exporter.export(sample_fda_compliant_sbom, output_file)
            
            assert output_file.exists()
            
            # Verify JSON structure
            with open(output_file) as f:
                json_data = json.load(f)
            
            # Should be the SBOM dict representation
            assert json_data["document_id"] == sample_fda_compliant_sbom.document_id
            assert json_data["document_name"] == sample_fda_compliant_sbom.document_name
            assert json_data["manufacturer"] == sample_fda_compliant_sbom.manufacturer
            assert "components" in json_data
            assert len(json_data["components"]) == len(sample_fda_compliant_sbom.components)
    
    def test_json_serialization(self, sample_sbom):
        """Test JSON serialization of complex objects."""
        exporter = JSONExporter()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "complex.json"
            exporter.export(sample_sbom, output_file)
            
            # Should handle datetime and complex objects
            with open(output_file) as f:
                json_data = json.load(f)
            
            # Check that dates are serialized
            assert "created" in json_data
            assert isinstance(json_data["created"], str)
            
            # Check components with vulnerabilities
            if json_data["components"]:
                component = json_data["components"][0]
                if "vulnerabilities" in component and component["vulnerabilities"]:
                    vuln = component["vulnerabilities"][0]
                    assert "id" in vuln
                    assert "severity" in vuln


class TestExporterRegistry:
    """Test exporter registry and utility functions."""
    
    def test_get_exporter_valid_formats(self):
        """Test getting exporters for valid formats."""
        # Test enum formats
        for format_enum in SBOMFormat:
            exporter = get_exporter(format_enum.value)
            assert exporter is not None
        
        # Test string format
        json_exporter = get_exporter("json")
        assert isinstance(json_exporter, JSONExporter)
    
    def test_get_exporter_invalid_format(self):
        """Test getting exporter for invalid format."""
        with pytest.raises(ValueError, match="Unsupported format"):
            get_exporter("invalid_format")
    
    def test_exporters_registry(self):
        """Test the EXPORTERS registry."""
        assert SBOMFormat.SPDX in EXPORTERS
        assert SBOMFormat.CYCLONEDX in EXPORTERS
        assert SBOMFormat.SWID in EXPORTERS
        assert "json" in EXPORTERS
        
        # Check exporter types
        assert isinstance(EXPORTERS[SBOMFormat.SPDX], SPDXExporter)
        assert isinstance(EXPORTERS[SBOMFormat.CYCLONEDX], CycloneDXExporter)
        assert isinstance(EXPORTERS[SBOMFormat.SWID], SWIDExporter)
        assert isinstance(EXPORTERS["json"], JSONExporter)
    
    def test_export_sbom_function(self, sample_fda_compliant_sbom):
        """Test the export_sbom convenience function."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "function_test.spdx.json"
            
            # Should work with the convenience function
            export_sbom(sample_fda_compliant_sbom, output_file, "spdx")
            assert output_file.exists()
            
            # Verify it's valid SPDX
            with open(output_file) as f:
                spdx_data = json.load(f)
            assert spdx_data["spdxVersion"] == "SPDX-2.3"


class TestExportValidation:
    """Test export validation and error handling."""
    
    def test_export_invalid_path(self, sample_fda_compliant_sbom):
        """Test export to invalid path."""
        exporter = SPDXExporter()
        
        # Try to export to a directory that doesn't exist
        invalid_path = Path("/nonexistent/directory/file.spdx.json")
        
        with pytest.raises(FileNotFoundError):
            exporter.export(sample_fda_compliant_sbom, invalid_path)
    
    def test_export_readonly_path(self, sample_fda_compliant_sbom):
        """Test export to read-only location."""
        exporter = SPDXExporter()
        
        # This test is platform-dependent, so we'll skip detailed implementation
        # In a real scenario, you'd test with a read-only directory
        pass
    
    def test_export_empty_sbom(self):
        """Test export of SBOM with no components."""
        empty_sbom = SBOM(
            document_id="empty-test",
            document_name="Empty SBOM",
            document_namespace="https://test.com/empty"
        )
        
        # Should still export successfully
        exporter = SPDXExporter()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "empty.spdx.json"
            exporter.export(empty_sbom, output_file)
            
            assert output_file.exists()
            
            with open(output_file) as f:
                spdx_data = json.load(f)
            
            # Should have root package but no component packages
            assert len(spdx_data["packages"]) == 1
            assert spdx_data["packages"][0]["SPDXID"] == "SPDXRef-Package"


class TestFormatSpecificFeatures:
    """Test format-specific features and edge cases."""
    
    def test_spdx_package_urls(self, temp_project_dir):
        """Test SPDX export with package URLs."""
        sbom = SBOM(
            document_id="purl-test",
            document_name="Package URL Test",
            document_namespace="https://test.com/purl"
        )
        
        component = Component(
            name="test-package",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            package_url="pkg:pypi/test-package@1.0.0"
        )
        sbom.add_component(component)
        
        exporter = SPDXExporter()
        output_file = temp_project_dir / "purl.spdx.json"
        exporter.export(sbom, output_file)
        
        with open(output_file) as f:
            spdx_data = json.load(f)
        
        component_package = spdx_data["packages"][1]  # First is root
        assert "externalRefs" in component_package
        
        external_refs = component_package["externalRefs"]
        assert len(external_refs) == 1
        assert external_refs[0]["referenceType"] == "purl"
        assert external_refs[0]["referenceLocator"] == "pkg:pypi/test-package@1.0.0"
    
    def test_cyclonedx_bom_ref_generation(self, temp_project_dir):
        """Test CycloneDX BOM reference generation."""
        sbom = SBOM(
            document_id="bomref-test",
            document_name="BOM Ref Test",
            document_namespace="https://test.com/bomref"
        )
        
        # Add component without version
        component1 = Component(
            name="no-version-package",
            type=ComponentType.LIBRARY
        )
        
        # Add component with version
        component2 = Component(
            name="versioned-package",
            version="2.1.0",
            type=ComponentType.LIBRARY
        )
        
        sbom.add_component(component1)
        sbom.add_component(component2)
        
        exporter = CycloneDXExporter()
        output_file = temp_project_dir / "bomref.cyclonedx.json"
        exporter.export(sbom, output_file)
        
        with open(output_file) as f:
            cdx_data = json.load(f)
        
        components = cdx_data["components"]
        assert len(components) == 2
        
        # Check BOM references
        bom_refs = [c["bom-ref"] for c in components]
        assert "no-version-package@unknown" in bom_refs
        assert "versioned-package@2.1.0" in bom_refs


if __name__ == "__main__":
    pytest.main([__file__])
