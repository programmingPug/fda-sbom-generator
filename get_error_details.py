#!/usr/bin/env python3
"""
Get specific error details for each failing test.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_test_with_full_output(test_path):
    """Run a test and get the actual error message."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-vvs", "--tb=long", "--no-cov"],
        capture_output=True,
        text=True
    )
    
    return result.returncode == 0, result.stdout, result.stderr

def main():
    # Change to project directory
    project_dir = Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    os.chdir(project_dir)
    
    # Test each failing test to get exact error details
    failing_tests = [
        "tests/unit/test_scanners.py::TestBaseScanner::test_normalize_license",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_basic_export",
        "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_python_project_full_workflow"
    ]
    
    for test in failing_tests:
        print(f"\n{'='*100}")
        print(f"DETAILED ERROR FOR: {test}")
        print('='*100)
        
        success, stdout, stderr = run_test_with_full_output(test)
        
        if not success:
            # Extract the actual failure message
            lines = stdout.split('\n')
            in_failure_section = False
            
            for line in lines:
                if "FAILURES" in line or "AssertionError" in line or "assert" in line:
                    in_failure_section = True
                
                if in_failure_section:
                    print(line)
                    
                if line.strip() == "" and in_failure_section and "assert" in stdout:
                    break
        else:
            print("✅ TEST IS NOW PASSING!")

if __name__ == "__main__":
    main()
