#!/usr/bin/env python3
"""
Simple test to check current behavior vs expected.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_individual_components():
    """Test each component individually."""
    
    print("1. Testing License Creation...")
    from fda_sbom.models import License
    
    # Test what happens when we create a license with spdx_id
    license1 = License(name="MIT", spdx_id="MIT")
    print(f"License with spdx_id='MIT': {license1.spdx_id}")
    
    # Test if model validation is adding prefix
    if license1.spdx_id == "MIT":
        print("✅ Model stores raw SPDX ID")
    elif license1.spdx_id == "SPDX-License-Identifier: MIT":
        print("❌ Model auto-prefixes SPDX ID")
    else:
        print(f"❓ Unexpected result: {license1.spdx_id}")
    
    print("\n2. Testing Scanner License Normalization...")
    from fda_sbom.scanners import BaseScanner
    
    class TestScanner(BaseScanner):
        def can_scan(self): return True
        def scan(self): return []
    
    scanner = TestScanner(Path("."))
    mit_license = scanner._normalize_license("MIT")
    
    print(f"Scanner normalized MIT: spdx_id='{mit_license.spdx_id}', name='{mit_license.name}'")
    
    print("\n3. Testing SWID Export...")
    from fda_sbom.exporters import SWIDExporter
    from fda_sbom.models import SBOM
    import tempfile
    import xml.etree.ElementTree as ET
    
    sbom = SBOM(
        document_id="test-123",
        document_name="Test",
        document_namespace="https://test.com",
        manufacturer="Test Corp"
    )
    
    exporter = SWIDExporter()
    with tempfile.TemporaryDirectory() as temp_dir:
        output_file = Path(temp_dir) / "test.xml"
        exporter.export(sbom, output_file)
        
        # Read and parse the file
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"SWID XML content preview:")
        print(content[:500])
        
        # Parse with ElementTree
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        print(f"Root tag: {root.tag}")
        entity = root.find("Entity")
        print(f"Entity found: {entity is not None}")
        
        if entity is not None:
            print(f"Entity name: {entity.get('name')}")
        else:
            print("Child elements:")
            for child in root:
                print(f"  {child.tag}: {child.attrib}")
    
    print("\n4. Testing JavaScript Scanner...")
    from fda_sbom.scanners import JavaScriptScanner
    import json
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_path = Path(temp_dir)
        
        # Create package.json
        package_json = {"name": "test", "dependencies": {"react": "^18.0.0"}}
        (test_path / "package.json").write_text(json.dumps(package_json))
        
        scanner = JavaScriptScanner(test_path)
        can_scan = scanner.can_scan()
        print(f"JavaScript scanner can_scan: {can_scan}")

if __name__ == "__main__":
    os.chdir(Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator"))
    test_individual_components()
