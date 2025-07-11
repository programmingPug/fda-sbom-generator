#!/usr/bin/env python3
"""Run the 3 remaining failing tests."""

import subprocess
import sys

def main():
    """Run the specific failing tests."""
    tests = [
        "tests/unit/test_models.py::TestLicense::test_license_creation_full",
        "tests/unit/test_models.py::TestLicense::test_spdx_id_validation",
        "tests/unit/test_scanners.py::TestBaseScanner::test_normalize_license"
    ]
    
    print("Running remaining failing tests...")
    print("=" * 60)
    
    for test in tests:
        cmd = [sys.executable, "-m", "pytest", test, "-xvs"]
        print(f"\nRunning: {' '.join(cmd)}")
        print("-" * 60)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ PASSED")
        else:
            print("✗ FAILED")
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
    
    print("\n" + "=" * 60)
    print("Done! Run 'python -m pytest' to verify all tests pass.")

if __name__ == "__main__":
    main()
