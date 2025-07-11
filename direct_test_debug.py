#!/usr/bin/env python3
"""
Debug specific test issues by running them individually.
"""

import sys
import os
from pathlib import Path
import tempfile

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_license_normalization():
    """Test the license normalization directly."""
    print("Testing license normalization...")
    
    from fda_sbom.scanners import BaseScanner
    from fda_sbom.models import License
    
    # Create a concrete scanner for testing
    class TestScanner(BaseScanner):
        def can_scan(self): 
            return True
        def scan(self): 
            return []
    
    scanner = TestScanner(Path("."))
    
    # Test license normalization
    mit_license = scanner._normalize_license("MIT")
    print(f"MIT License spdx_id: '{mit_license.spdx_id}'")
    print(f"MIT License name: '{mit_license.name}'")
    print(f"Expected: spdx_id='MIT', name='MIT'")
    
    # Check what the test expects
    if mit_license.spdx_id == "MIT":
        print("✅ License test should PASS")
    else:
        print(f"❌ License test FAILS: expected 'MIT', got '{mit_license.spdx_id}'")

def test_swid_export():
    """Test SWID export directly."""
    print("\nTesting SWID export...")
    
    from fda_sbom.exporters import SWIDExporter
    from fda_sbom.models import SBOM
    import xml.etree.ElementTree as ET
    
    # Create a test SBOM
    sbom = SBOM(
        document_id="test-123",
        document_name="Test SBOM",
        document_namespace="https://test.com/test",
        manufacturer="Test Corp"
    )
    
    exporter = SWIDExporter()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        output_file = Path(temp_dir) / "test.swid.xml"
        exporter.export(sbom, output_file)
        
        if output_file.exists():
            # Parse and check
            tree = ET.parse(output_file)
            root = tree.getroot()
            
            print(f"Root tag: {root.tag}")
            print(f"Root attributes: {root.attrib}")
            
            # Check for Entity element
            entity = root.find("Entity")
            print(f"Entity element: {entity}")
            
            if entity is not None:
                print(f"Entity attributes: {entity.attrib}")
                print("✅ SWID test should PASS")
            else:
                print("❌ SWID test FAILS: Entity element not found")
                
                # Print all child elements
                print("All child elements:")
                for child in root:
                    print(f"  - {child.tag}: {child.attrib}")
        else:
            print("❌ SWID export failed - no file created")

def test_javascript_scanner_detection():
    """Test JavaScript scanner detection."""
    print("\nTesting JavaScript scanner detection...")
    
    from fda_sbom.scanners import ScannerRegistry, JavaScriptScanner
    import json
    
    with tempfile.TemporaryDirectory() as temp_dir:
        solution_path = Path(temp_dir) / "test_solution"
        solution_path.mkdir()
        
        # Create a package.json file
        package_json = {
            "name": "test-project",
            "dependencies": {"react": "^18.0.0"}
        }
        (solution_path / "package.json").write_text(json.dumps(package_json))
        (solution_path / "index.js").write_text("console.log('test');")
        
        # Test individual scanner
        js_scanner = JavaScriptScanner(solution_path)
        can_scan = js_scanner.can_scan()
        print(f"JavaScriptScanner can_scan: {can_scan}")
        
        # Test registry
        registry = ScannerRegistry()
        scanners = registry.get_applicable_scanners(solution_path)
        scanner_names = [s.__class__.__name__ for s in scanners]
        print(f"Detected scanners: {scanner_names}")
        
        if "JavaScriptScanner" in scanner_names:
            print("✅ JavaScript scanner detection should PASS")
        else:
            print("❌ JavaScript scanner detection FAILS")

def main():
    os.chdir(Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator"))
    
    print("Direct testing of failing components...")
    print("="*80)
    
    try:
        test_license_normalization()
    except Exception as e:
        print(f"License test error: {e}")
    
    try:
        test_swid_export()
    except Exception as e:
        print(f"SWID test error: {e}")
    
    try:
        test_javascript_scanner_detection()
    except Exception as e:
        print(f"JS scanner test error: {e}")

if __name__ == "__main__":
    main()
