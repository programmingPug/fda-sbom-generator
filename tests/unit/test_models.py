"""
Unit tests for data models.
"""

import json
from datetime import datetime
from pathlib import Path
import pytest
from pydantic import ValidationError

from fda_sbom.models import (
    License, Vulnerability, Component, SBOM, SBOMReport,
    ComponentType, VulnerabilitySeverity, SBOMFormat
)


class TestLicense:
    """Test License model."""
    
    def test_license_creation_basic(self):
        """Test basic license creation."""
        license_obj = License(name="MIT")
        
        assert license_obj.name == "MIT"
        assert license_obj.spdx_id is None
        assert license_obj.text is None
        assert license_obj.url is None
    
    def test_license_creation_full(self):
        """Test license creation with all fields."""
        license_obj = License(
            name="Apache License 2.0",
            spdx_id="Apache-2.0",
            text="Licensed under the Apache License, Version 2.0",
            url="https://www.apache.org/licenses/LICENSE-2.0"
        )
        
        assert license_obj.name == "Apache License 2.0"
        assert license_obj.spdx_id == "SPDX-License-Identifier: Apache-2.0"
        assert "Apache License" in license_obj.text
        assert license_obj.url == "https://www.apache.org/licenses/LICENSE-2.0"
    
    def test_spdx_id_validation(self):
        """Test SPDX ID validation and formatting."""
        # Should add prefix if not present
        license_obj = License(spdx_id="MIT")
        assert license_obj.spdx_id == "SPDX-License-Identifier: MIT"
        
        # Should not double-prefix
        license_obj2 = License(spdx_id="SPDX-License-Identifier: GPL-3.0")
        assert license_obj2.spdx_id == "SPDX-License-Identifier: GPL-3.0"


class TestVulnerability:
    """Test Vulnerability model."""
    
    def test_vulnerability_creation_minimal(self):
        """Test minimal vulnerability creation."""
        vuln = Vulnerability(
            id="CVE-2023-12345",
            severity=VulnerabilitySeverity.HIGH
        )
        
        assert vuln.id == "CVE-2023-12345"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.score is None
        assert vuln.description is None
        assert vuln.published is None
        assert vuln.modified is None
        assert len(vuln.references) == 0
    
    def test_vulnerability_creation_full(self):
        """Test vulnerability creation with all fields."""
        published_date = datetime(2023, 6, 1, 10, 0, 0)
        modified_date = datetime(2023, 6, 2, 14, 30, 0)
        
        vuln = Vulnerability(
            id="CVE-2023-54321",
            severity=VulnerabilitySeverity.CRITICAL,
            score=9.8,
            description="Critical remote code execution vulnerability",
            published=published_date,
            modified=modified_date,
            references=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-54321",
                "https://example.com/security-advisory"
            ]
        )
        
        assert vuln.id == "CVE-2023-54321"
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert vuln.score == 9.8
        assert "remote code execution" in vuln.description
        assert vuln.published == published_date
        assert vuln.modified == modified_date
        assert len(vuln.references) == 2
    
    def test_vulnerability_score_validation(self):
        """Test CVSS score validation."""
        # Valid scores
        vuln1 = Vulnerability(id="TEST-1", severity=VulnerabilitySeverity.LOW, score=0.0)
        assert vuln1.score == 0.0
        
        vuln2 = Vulnerability(id="TEST-2", severity=VulnerabilitySeverity.CRITICAL, score=10.0)
        assert vuln2.score == 10.0
        
        # Invalid scores should raise validation error
        with pytest.raises(ValidationError):
            Vulnerability(id="TEST-3", severity=VulnerabilitySeverity.HIGH, score=-1.0)
        
        with pytest.raises(ValidationError):
            Vulnerability(id="TEST-4", severity=VulnerabilitySeverity.HIGH, score=11.0)


class TestComponent:
    """Test Component model."""
    
    def test_component_creation_minimal(self):
        """Test minimal component creation."""
        component = Component(name="test-library")
        
        assert component.name == "test-library"
        assert component.version is None
        assert component.type == ComponentType.LIBRARY  # Default
        assert component.namespace is None
        assert component.description is None
        assert component.package_manager is None
        assert component.package_url is None
        assert len(component.licenses) == 0
        assert len(component.dependencies) == 0
        assert len(component.vulnerabilities) == 0


class TestSBOM:
    """Test SBOM model."""
    
    def test_sbom_creation_minimal(self):
        """Test minimal SBOM creation."""
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom"
        )
        
        assert sbom.document_id == "test-123"
        assert sbom.document_name == "Test SBOM"
        assert sbom.document_namespace == "https://test.com/sbom"
        assert isinstance(sbom.created, datetime)
        assert len(sbom.creators) == 0
        assert sbom.target_system is None
        assert sbom.target_version is None
        assert len(sbom.components) == 0
        assert len(sbom.relationships) == 0
    
    def test_add_component(self):
        """Test adding components to SBOM."""
        sbom = SBOM(
            document_id="test",
            document_name="Test",
            document_namespace="https://test.com"
        )
        
        component1 = Component(name="lib1", version="1.0.0")
        component2 = Component(name="lib2", version="2.0.0")
        
        sbom.add_component(component1)
        assert len(sbom.components) == 1
        
        sbom.add_component(component2)
        assert len(sbom.components) == 2
        
        assert sbom.components[0].name == "lib1"
        assert sbom.components[1].name == "lib2"
    
    def test_validate_fda_compliance(self):
        """Test FDA compliance validation."""
        # Non-compliant SBOM (missing required fields)
        non_compliant_sbom = SBOM(
            document_id="",  # Empty ID
            document_name="Test",
            document_namespace="https://test.com"
            # Missing manufacturer
        )
        
        issues = non_compliant_sbom.validate_fda_compliance()
        assert len(issues) > 0
        assert any("Document ID is required" in issue for issue in issues)
        assert any("Manufacturer is required" in issue for issue in issues)
        assert any("must contain at least one component" in issue for issue in issues)
        
        # Compliant SBOM
        compliant_sbom = SBOM(
            document_id="fda-compliant-001",
            document_name="FDA Compliant Device",
            document_namespace="https://medical.device/sbom",
            manufacturer="Medical Device Corp"
        )
        
        # Add component with required information
        license_obj = License(name="MIT")
        component = Component(
            name="medical-lib",
            version="1.0.0",
            licenses=[license_obj]
        )
        compliant_sbom.add_component(component)
        
        issues = compliant_sbom.validate_fda_compliance()
        assert len(issues) == 0


class TestSBOMReport:
    """Test SBOMReport model."""
    
    def test_report_creation_basic(self):
        """Test basic SBOM report creation."""
        report = SBOMReport(sbom_id="test-sbom-123")
        
        assert report.sbom_id == "test-sbom-123"
        assert isinstance(report.generated_at, datetime)
        assert report.total_components == 0
        assert report.total_vulnerabilities == 0
        assert len(report.vulnerability_counts) == 0
        assert report.fda_compliant is False
        assert len(report.compliance_issues) == 0
        assert len(report.recommendations) == 0


class TestEnumerations:
    """Test enumeration classes."""
    
    def test_sbom_format_enum(self):
        """Test SBOMFormat enumeration."""
        assert SBOMFormat.SPDX == "spdx"
        assert SBOMFormat.CYCLONEDX == "cyclonedx"
        assert SBOMFormat.SWID == "swid"
        
        # Should be able to use in comparisons
        assert SBOMFormat.SPDX.value == "spdx"
        
        # Should be iterable
        formats = list(SBOMFormat)
        assert len(formats) == 3
    
    def test_component_type_enum(self):
        """Test ComponentType enumeration."""
        assert ComponentType.LIBRARY == "library"
        assert ComponentType.FRAMEWORK == "framework"
        assert ComponentType.APPLICATION == "application"
        assert ComponentType.OPERATING_SYSTEM == "operating-system"
        assert ComponentType.DEVICE == "device"
        assert ComponentType.FIRMWARE == "firmware"
        assert ComponentType.FILE == "file"
        assert ComponentType.CONTAINER == "container"
        
        # Should be iterable
        types = list(ComponentType)
        assert len(types) == 8
    
    def test_vulnerability_severity_enum(self):
        """Test VulnerabilitySeverity enumeration."""
        assert VulnerabilitySeverity.CRITICAL == "critical"
        assert VulnerabilitySeverity.HIGH == "high"
        assert VulnerabilitySeverity.MEDIUM == "medium"
        assert VulnerabilitySeverity.LOW == "low"
        assert VulnerabilitySeverity.INFO == "info"
        
        # Should be iterable
        severities = list(VulnerabilitySeverity)
        assert len(severities) == 5


class TestModelValidation:
    """Test model validation and error handling."""
    
    def test_component_validation_errors(self):
        """Test component validation errors."""
        # Missing required name field
        with pytest.raises(ValidationError):
            Component()
        
        # Test that valid data passes
        component = Component(name="valid-component")
        assert component.name == "valid-component"
    
    def test_sbom_validation_errors(self):
        """Test SBOM validation errors."""
        # Missing required fields
        with pytest.raises(ValidationError):
            SBOM()  # Missing all required fields
        
        with pytest.raises(ValidationError):
            SBOM(document_id="test")  # Missing document_name and namespace
        
        # Valid SBOM should pass
        sbom = SBOM(
            document_id="valid-test",
            document_name="Valid Test",
            document_namespace="https://test.com/valid"
        )
        assert sbom.document_id == "valid-test"
    
    def test_vulnerability_validation_errors(self):
        """Test vulnerability validation errors."""
        # Missing required fields
        with pytest.raises(ValidationError):
            Vulnerability()  # Missing id and severity
        
        with pytest.raises(ValidationError):
            Vulnerability(id="test")  # Missing severity
        
        # Valid vulnerability should pass
        vuln = Vulnerability(
            id="valid-test",
            severity=VulnerabilitySeverity.MEDIUM
        )
        assert vuln.id == "valid-test"


if __name__ == "__main__":
    pytest.main([__file__])
