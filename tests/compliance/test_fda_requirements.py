"""
FDA compliance-specific tests.
"""

import json
from datetime import datetime
from pathlib import Path
import tempfile

import pytest

from fda_sbom.generator import SBOMGenerator
from fda_sbom.models import SBOM, Component, ComponentType, License, Vulnerability, VulnerabilitySeverity
from fda_sbom.exporters import export_sbom


class TestFDAComplianceRequirements:
    """Test specific FDA compliance requirements."""
    
    def test_required_sbom_metadata(self):
        """Test that SBOM contains all FDA-required metadata."""
        sbom = SBOM(
            document_id="FDA-TEST-001",
            document_name="Cardiac Monitor Software",
            document_namespace="https://medical.device/sbom/cardiac-monitor",
            target_system="Cardiac Monitor Pro",
            target_version="2.1.0",
            manufacturer="CardioTech Medical Devices Inc",
            model_number="CM-PRO-2024",
            fda_submission_id="K240156",
            device_identification="UDI-DI-CARDIAC123456789"
        )
        
        # Test required fields are present
        assert sbom.document_id is not None
        assert sbom.document_name is not None
        assert sbom.document_namespace is not None
        assert sbom.manufacturer is not None
        assert sbom.created is not None
        assert isinstance(sbom.created, datetime)
        
        # Test FDA-specific fields
        assert sbom.fda_submission_id == "K240156"
        assert sbom.model_number == "CM-PRO-2024" 
        assert sbom.device_identification == "UDI-DI-CARDIAC123456789"
    
    def test_component_completeness_requirements(self):
        """Test that components meet FDA completeness requirements."""
        # Create component with all required FDA data
        component = Component(
            name="medical-core-library",
            version="3.2.1",
            type=ComponentType.LIBRARY,
            package_manager="pip",
            description="Core medical device library for patient monitoring",
            package_url="pkg:pypi/medical-core-library@3.2.1",
            supplier="MedSoft Solutions Inc",
            originator="Dr. Jane Smith, MedSoft Solutions",
            download_location="https://pypi.org/project/medical-core-library/3.2.1/",
            homepage="https://github.com/medsoft/medical-core",
            licenses=[
                License(
                    name="MIT License",
                    spdx_id="MIT",
                    url="https://opensource.org/licenses/MIT"
                )
            ],
            medical_device_class="Class II",
            regulatory_status="FDA Cleared"
        )
        
        # Verify all required component data is present
        assert component.name is not None
        assert component.version is not None
        assert component.type is not None
        assert len(component.licenses) > 0
        assert component.licenses[0].name is not None
        
        # Verify FDA-specific component metadata
        assert component.medical_device_class == "Class II"
        assert component.regulatory_status == "FDA Cleared"
        assert component.supplier is not None
    
    def test_complete_fda_sbom_validation(self):
        """Test complete SBOM validation against FDA requirements."""
        # Create fully FDA-compliant SBOM
        sbom = SBOM(
            document_id="FDA-COMPLIANT-TEST-001",
            document_name="Surgical Robot Control System",
            document_namespace="https://robotics.medical/sbom/surgical-robot-v3",
            target_system="Surgical Robot Control System",
            target_version="3.1.2",
            manufacturer="Advanced Surgical Robotics Inc",
            model_number="ASR-3000",
            fda_submission_id="K240789",
            device_identification="UDI-DI-ASR3000123456789",
            creators=["FDA-SBOM-Generator-v1.0", "ASR Compliance Team"]
        )
        
        # Add FDA-compliant components
        components = [
            Component(
                name="surgical-precision-lib",
                version="2.1.0",
                type=ComponentType.LIBRARY,
                package_manager="pip",
                description="High-precision surgical movement library",
                supplier="Precision Medical Software Corp",
                licenses=[License(name="Commercial Medical License", 
                                text="Licensed for use in FDA-approved medical devices")],
                medical_device_class="Class II",
                regulatory_status="FDA Cleared"
            ),
            Component(
                name="robot-control-firmware",
                version="1.5.3",
                type=ComponentType.FIRMWARE,
                description="Robot arm control firmware",
                supplier="Advanced Surgical Robotics Inc",
                licenses=[License(name="Proprietary", 
                                text="Proprietary firmware, all rights reserved")],
                medical_device_class="Class II",
                regulatory_status="FDA Cleared"
            )
        ]
        
        for component in components:
            sbom.add_component(component)
        
        # Validate FDA compliance
        compliance_issues = sbom.validate_fda_compliance()
        
        # Should have no compliance issues
        assert len(compliance_issues) == 0, f"FDA compliance issues found: {compliance_issues}"
        
        # Verify SBOM completeness
        assert sbom.document_id is not None
        assert sbom.manufacturer is not None
        assert len(sbom.components) > 0
        
        # All components should have required information
        for component in sbom.components:
            assert component.name is not None
            assert component.version is not None
            assert len(component.licenses) > 0
    
    def test_fda_submission_format_compliance(self):
        """Test SBOM export formats meet FDA submission requirements."""
        # Create FDA-compliant SBOM
        sbom = SBOM(
            document_id="FDA-SUBMISSION-TEST",
            document_name="Insulin Pump Software",
            document_namespace="https://diabetic.care/sbom/insulin-pump",
            manufacturer="DiabeTech Medical Devices",
            fda_submission_id="K240456",
            model_number="DT-PUMP-2024"
        )
        
        # Add sample component
        sbom.add_component(Component(
            name="insulin-delivery-controller",
            version="4.2.1",
            type=ComponentType.APPLICATION,
            description="Insulin delivery control algorithm",
            licenses=[License(name="Commercial Medical License")],
            supplier="DiabeTech Medical Devices"
        ))
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Test SPDX format (FDA recommended)
            spdx_file = temp_path / "insulin-pump.spdx.json"
            export_sbom(sbom, spdx_file, "spdx")
            
            # Verify SPDX file meets FDA requirements
            with open(spdx_file) as f:
                spdx_data = json.load(f)
            
            # Check required SPDX fields
            assert spdx_data["spdxVersion"] == "SPDX-2.3"
            assert spdx_data["dataLicense"] == "CC0-1.0"
            assert "SPDXID" in spdx_data
            assert "name" in spdx_data
            assert "documentNamespace" in spdx_data
            assert "creationInfo" in spdx_data
            assert "packages" in spdx_data
            
            # Verify creation info
            creation_info = spdx_data["creationInfo"]
            assert "created" in creation_info
            assert "creators" in creation_info
            
            # Should have at least one package (root + components)
            assert len(spdx_data["packages"]) >= 1


class TestFDAReportingRequirements:
    """Test FDA reporting and documentation requirements."""
    
    def test_sbom_report_generation(self):
        """Test SBOM report generation for FDA submission."""
        generator = SBOMGenerator()
        
        # Create comprehensive SBOM
        sbom = SBOM(
            document_id="FDA-REPORT-TEST",
            document_name="Defibrillator Software Suite",
            document_namespace="https://defib.medical/sbom/suite",
            manufacturer="DefibTech Medical Systems",
            fda_submission_id="K240678",
            model_number="DT-DEFIB-PRO"
        )
        
        # Add various components
        components = [
            Component(name="emergency-protocol", version="1.0.0", type=ComponentType.APPLICATION,
                     licenses=[License(name="Proprietary")]),
            Component(name="patient-data-manager", version="2.1.0", type=ComponentType.LIBRARY,
                     licenses=[License(name="MIT")]),
            Component(name="device-driver", version="3.0.1", type=ComponentType.FIRMWARE,
                     licenses=[License(name="Commercial")])
        ]
        
        for component in components:
            sbom.add_component(component)
        
        # Generate compliance report
        report = generator.validate_sbom(sbom)
        
        # Verify report contains FDA-required information
        assert report.sbom_id == sbom.document_id
        assert report.total_components == len(sbom.components)
        assert isinstance(report.fda_compliant, bool)
        assert isinstance(report.compliance_issues, list)
        assert isinstance(report.recommendations, list)
        
        # Report should have timestamp
        assert report.generated_at is not None
        assert isinstance(report.generated_at, datetime)


if __name__ == "__main__":
    pytest.main([__file__])
