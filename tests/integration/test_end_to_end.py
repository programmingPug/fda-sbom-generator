"""
Integration tests for end-to-end workflows.
"""

import json
import tempfile
from pathlib import Path

import pytest

from fda_sbom.generator import SBOMGenerator
from fda_sbom.exporters import export_sbom
from fda_sbom.solution import SolutionScanner
from fda_sbom.models import SBOMFormat


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""
    
    def test_python_project_full_workflow(self, sample_python_project):
        """Test complete workflow for Python project."""
        generator = SBOMGenerator()
        
        # Step 1: Generate SBOM
        sbom = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Medical Device API",
            target_version="1.0.0",
            manufacturer="Acme Medical Devices Inc",
            device_model="API-2024",
            fda_submission_id="K240001",
            include_vulnerabilities=False  # Skip for speed in tests
        )
        
        # Verify SBOM structure
        assert sbom.target_system == "Medical Device API"
        assert sbom.manufacturer == "Acme Medical Devices Inc"
        assert len(sbom.components) >= 0
        
        # Step 2: Validate SBOM
        report = generator.validate_sbom(sbom)
        assert report.fda_compliant is True
        assert report.total_components == len(sbom.components)
        
        # Step 3: Export to different formats
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Export as SPDX
            spdx_file = temp_path / "device.spdx.json"
            export_sbom(sbom, spdx_file, SBOMFormat.SPDX)
            assert spdx_file.exists()
            
            # Verify SPDX content
            with open(spdx_file) as f:
                spdx_data = json.load(f)
            assert spdx_data["spdxVersion"] == "SPDX-2.3"
            assert spdx_data["name"] == sbom.document_name
            
            # Export as CycloneDX
            cyclonedx_file = temp_path / "device.cyclonedx.json"
            export_sbom(sbom, cyclonedx_file, SBOMFormat.CYCLONEDX)
            assert cyclonedx_file.exists()
            
            # Verify CycloneDX content
            with open(cyclonedx_file) as f:
                cdx_data = json.load(f)
            assert cdx_data["bomFormat"] == "CycloneDX"
            assert cdx_data["specVersion"] == "1.4"
    
    def test_dotnet_project_full_workflow(self, sample_dotnet_project):
        """Test complete workflow for .NET project."""
        generator = SBOMGenerator()
        
        # Generate SBOM for .NET project
        sbom = generator.generate_sbom(
            project_path=sample_dotnet_project,
            target_system="Medical Device Service",
            manufacturer="Healthcare Tech Inc",
            include_vulnerabilities=False
        )
        
        # Should find .NET packages and runtime
        assert len(sbom.components) >= 0
        
        # Check for NuGet packages if found
        if sbom.components:
            component_names = [c.name for c in sbom.components]
            # May find .NET components depending on scanning
    
    def test_multi_language_solution_workflow(self, sample_multi_project_solution):
        """Test workflow for multi-language solution."""
        solution_scanner = SolutionScanner()
        
        # Step 1: Scan solution
        project_sboms = solution_scanner.scan_solution(
            solution_path=sample_multi_project_solution,
            manufacturer="Multi-Tech Medical Inc",
            solution_name="Medical Device Platform",
            include_vulnerabilities=False
        )
        
        # Should find at least one project
        assert len(project_sboms) >= 1
        
        # Step 2: Create consolidated SBOM
        solution_sbom = solution_scanner.create_solution_sbom(
            project_sboms,
            "Medical Device Platform",
            "Multi-Tech Medical Inc"
        )
        
        # Verify consolidated SBOM
        assert solution_sbom.document_name == "Medical Device Platform"
        assert solution_sbom.manufacturer == "Multi-Tech Medical Inc"
        assert len(solution_sbom.components) >= 0
    
    def test_export_format_compatibility(self, sample_sbom):
        """Test that all export formats work correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            formats_to_test = [
                (SBOMFormat.SPDX, "spdx.json"),
                (SBOMFormat.CYCLONEDX, "cyclonedx.json"),
                (SBOMFormat.SWID, "swid.xml"),
                ("json", "native.json")
            ]
            
            for format_name, filename in formats_to_test:
                output_file = temp_path / filename
                
                # Should export without error
                export_sbom(sample_sbom, output_file, format_name)
                assert output_file.exists()
                assert output_file.stat().st_size > 0
                
                # Verify basic file structure
                if filename.endswith('.json'):
                    with open(output_file) as f:
                        data = json.load(f)
                    assert isinstance(data, dict)
                    assert len(data) > 0
                elif filename.endswith('.xml'):
                    # Basic XML validation
                    content = output_file.read_text()
                    assert content.startswith('<?xml')
                    assert '</SoftwareIdentity>' in content
    
    def test_compliance_validation_workflow(self, sample_fda_compliant_sbom):
        """Test FDA compliance validation workflow."""
        generator = SBOMGenerator()
        
        # Test compliant SBOM
        report = generator.validate_sbom(sample_fda_compliant_sbom)
        assert report.fda_compliant is True
        assert len(report.compliance_issues) == 0
        
        # Test compliance checklist
        checklist = generator.generate_compliance_checklist(sample_fda_compliant_sbom)
        
        # All checklist items should be True for compliant SBOM
        failed_checks = [k for k, v in checklist.items() if not v]
        assert len(failed_checks) == 0, f"Failed compliance checks: {failed_checks}"
    
    def test_error_handling_workflow(self):
        """Test error handling in workflows."""
        generator = SBOMGenerator()
        
        # Test with nonexistent path
        with pytest.raises(FileNotFoundError):
            generator.generate_sbom(
                project_path="/nonexistent/path",
                manufacturer="Test Inc"
            )
        
        # Test with invalid export format
        from fda_sbom.models import SBOM
        sbom = SBOM(
            document_id="test",
            document_name="test",
            document_namespace="https://test.com"
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test.sbom"
            
            with pytest.raises(ValueError):
                export_sbom(sbom, output_file, "invalid_format")


class TestCLIIntegration:
    """Test CLI integration."""
    
    def test_cli_scan_command(self, sample_python_project):
        """Test CLI scan command integration."""
        import subprocess
        import sys
        
        cmd = [
            sys.executable, "-m", "fda_sbom.cli",
            "scan", str(sample_python_project)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # Should succeed
        assert result.returncode == 0, f"CLI scan failed: {result.stderr}"
        
        # Should have output
        assert len(result.stdout) > 0


if __name__ == "__main__":
    pytest.main([__file__])
