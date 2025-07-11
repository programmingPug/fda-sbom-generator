#!/usr/bin/env python3
"""
Diagnostic script to understand specific test failures.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_single_test_detailed(test_path):
    """Run a single test and return detailed output."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v", "-s", "--tb=short"],
        capture_output=True,
        text=True
    )
    
    return result.returncode == 0, result.stdout, result.stderr

def main():
    # Change to project directory
    project_dir = Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    os.chdir(project_dir)
    
    print(f"Working directory: {os.getcwd()}")
    print("="*80)
    
    # Test each failing test individually with detailed output
    failing_tests = [
        "tests/unit/test_scanners.py::TestBaseScanner::test_normalize_license",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_basic_export", 
        "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_python_project_full_workflow"
    ]
    
    for test in failing_tests:
        print(f"\n{'='*80}")
        print(f"DETAILED ANALYSIS: {test.split('::')[-1]}")
        print('='*80)
        
        success, stdout, stderr = run_single_test_detailed(test)
        
        print(f"SUCCESS: {success}")
        if not success:
            print("\nSTDOUT OUTPUT:")
            print(stdout[-2000:])  # Last 2000 chars to see key info
            if stderr:
                print("\nSTDERR OUTPUT:")
                print(stderr)
        else:
            print("✅ This test is now PASSING!")
    
    # Quick check of a basic test that should work
    print(f"\n{'='*80}")
    print("CONTROL TEST - Basic SBOM creation")
    print('='*80)
    
    control_test = "tests/unit/test_models.py::TestSBOM::test_sbom_creation_minimal"
    success, stdout, stderr = run_single_test_detailed(control_test)
    print(f"Control test success: {success}")
    
    return True

if __name__ == "__main__":
    main()
