#!/usr/bin/env python3
"""
Test the BaseScanner license normalization fix.
"""

import sys
sys.path.insert(0, 'src')

def test_base_scanner_fix():
    """Test that BaseScanner returns raw SPDX IDs."""
    from pathlib import Path
    from fda_sbom.scanners import BaseScanner
    
    # Create a concrete scanner for testing
    class TestScanner(BaseScanner):
        def can_scan(self): return True
        def scan(self): return []
    
    scanner = TestScanner(Path("."))
    
    # Test MIT license - should return raw "MIT"
    mit_license = scanner._normalize_license("MIT")
    print(f"MIT license - spdx_id: '{mit_license.spdx_id}', name: '{mit_license.name}'")
    
    # Test Apache license - should return raw "Apache-2.0"
    apache_license = scanner._normalize_license("Apache-2.0")
    print(f"Apache license - spdx_id: '{apache_license.spdx_id}', name: '{apache_license.name}'")
    
    # Test unknown license - should have None spdx_id
    custom_license = scanner._normalize_license("Custom License")
    print(f"Custom license - spdx_id: '{custom_license.spdx_id}', name: '{custom_license.name}'")
    
    # Test empty license - should be "Unknown"
    empty_license = scanner._normalize_license("")
    print(f"Empty license - spdx_id: '{empty_license.spdx_id}', name: '{empty_license.name}'")
    
    # Verify the test expectations
    assert mit_license.spdx_id == "MIT", f"Expected 'MIT', got '{mit_license.spdx_id}'"
    assert mit_license.name == "MIT", f"Expected 'MIT', got '{mit_license.name}'"
    
    assert apache_license.spdx_id == "Apache-2.0", f"Expected 'Apache-2.0', got '{apache_license.spdx_id}'"
    
    assert custom_license.name == "Custom License"
    assert custom_license.spdx_id is None
    
    assert empty_license.name == "Unknown"
    
    print("✅ BaseScanner license normalization test passed!")

if __name__ == "__main__":
    try:
        test_base_scanner_fix()
        print("\n🎉 BaseScanner fix verified!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
