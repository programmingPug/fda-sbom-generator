#!/usr/bin/env python3
"""Quick test to verify the fixes work correctly."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from fda_sbom.models import License, SBOM, Component, ComponentType
from fda_sbom.exporters import SPDXExporter, CycloneDXExporter, SWIDExporter
from fda_sbom.scanners import BaseScanner, ScannerRegistry

def test_license_model():
    """Test that License model works without the validator."""
    print("Testing License model...")
    
    # Create license with SPDX ID
    license1 = License(name="MIT", spdx_id="MIT")
    assert license1.spdx_id == "MIT"
    assert license1.name == "MIT"
    
    # Create license without SPDX ID
    license2 = License(name="Custom License")
    assert license2.spdx_id is None
    assert license2.name == "Custom License"
    
    print("✓ License model works correctly")

def test_exporters():
    """Test that exporters work with the fixed license handling."""
    print("\nTesting exporters...")
    
    # Create test SBOM
    sbom = SBOM(
        document_id="test-123",
        document_name="Test SBOM",
        document_namespace="https://test.com/sbom",
        manufacturer="Test Corp",
        target_system="Test System",
        target_version="1.0.0"
    )
    
    # Add component with license
    component = Component(
        name="test-lib",
        version="1.0.0",
        type=ComponentType.LIBRARY,
        licenses=[License(name="MIT", spdx_id="MIT")]
    )
    sbom.add_component(component)
    
    import tempfile
    import json
    import xml.etree.ElementTree as ET
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        # Test SPDX export
        spdx_file = tmppath / "test.spdx.json"
        SPDXExporter().export(sbom, spdx_file)
        with open(spdx_file) as f:
            spdx_data = json.load(f)
        assert "MIT" in spdx_data["packages"][1]["licenseConcluded"]
        print("✓ SPDX export works")
        
        # Test CycloneDX export
        cdx_file = tmppath / "test.cdx.json"
        CycloneDXExporter().export(sbom, cdx_file)
        with open(cdx_file) as f:
            cdx_data = json.load(f)
        assert cdx_data["components"][0]["licenses"][0]["id"] == "MIT"
        print("✓ CycloneDX export works")
        
        # Test SWID export
        swid_file = tmppath / "test.swid.xml"
        SWIDExporter().export(sbom, swid_file)
        tree = ET.parse(swid_file)
        root = tree.getroot()
        # Check it's valid XML with expected root
        assert "SoftwareIdentity" in root.tag
        print("✓ SWID export works")

def test_scanner_registry():
    """Test scanner registry."""
    print("\nTesting scanner registry...")
    
    registry = ScannerRegistry()
    
    # Test with empty directory
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        scanners = registry.get_applicable_scanners(Path(tmpdir))
        # Should at least have FileScanner
        assert len(scanners) >= 1
        assert any(s.__class__.__name__ == "FileScanner" for s in scanners)
    
    print("✓ Scanner registry works")

def main():
    """Run all verification tests."""
    print("Verifying FDA SBOM Generator fixes...")
    print("=" * 50)
    
    try:
        test_license_model()
        test_exporters()
        test_scanner_registry()
        
        print("\n" + "=" * 50)
        print("✓ All verifications passed!")
        print("\nThe fixes have been successfully applied.")
        print("You can now run the full test suite with: python -m pytest")
        return 0
    except Exception as e:
        print(f"\n✗ Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
