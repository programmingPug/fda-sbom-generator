#!/usr/bin/env python3
"""
Test the specific failing tests one by one to see current status.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_single_test(test_path):
    """Run a single test and return success/failure."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v"],
        capture_output=True,
        text=True
    )
    
    success = result.returncode == 0
    print(f"{'✅ PASS' if success else '❌ FAIL'}: {test_path.split('::')[-1]}")
    
    if not success:
        print("Error details:")
        print(result.stdout[-1000:])  # Last 1000 chars
        print("---")
    
    return success

def main():
    # Change to project directory
    project_dir = Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    os.chdir(project_dir)
    
    print(f"Working directory: {os.getcwd()}")
    print("="*80)
    
    # List of the originally failing tests
    failing_tests = [
        "tests/unit/test_models.py::TestLicense::test_license_creation_full",
        "tests/unit/test_models.py::TestLicense::test_spdx_id_validation",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_basic_export",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_export_with_components",
        "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_compliance_validation_workflow",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_python_project_full_workflow"
    ]
    
    results = []
    
    for test in failing_tests:
        success = run_single_test(test)
        results.append((test, success))
    
    print("="*80)
    print("SUMMARY:")
    passed = sum(1 for _, success in results if success)
    failed = len(results) - passed
    
    print(f"PASSED: {passed}")
    print(f"FAILED: {failed}")
    
    if failed > 0:
        print("\nStill failing:")
        for test, success in results:
            if not success:
                print(f"  - {test.split('::')[-1]}")
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
