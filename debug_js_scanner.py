#!/usr/bin/env python3
"""
Quick test to debug the JavaScript scanner detection issue.
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    # Change to project directory
    project_dir = Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    os.chdir(project_dir)
    
    print(f"Working directory: {os.getcwd()}")
    
    # Test the multi-language scanner detection specifically
    test_path = "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language"
    
    print(f"Testing: {test_path}")
    
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v", "-s"],
        capture_output=True,
        text=True
    )
    
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    
    print(f"\nReturn code: {result.returncode}")
    
    # Also test a working JavaScript scanner test
    test_path2 = "tests/unit/test_scanners.py::TestJavaScriptScanner::test_can_scan_with_package_json"
    print(f"\nTesting: {test_path2}")
    
    result2 = subprocess.run(
        [sys.executable, "-m", "pytest", test_path2, "-v", "-s"],
        capture_output=True,
        text=True
    )
    
    print("STDOUT:")
    print(result2.stdout)
    
    return result.returncode == 0 and result2.returncode == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
