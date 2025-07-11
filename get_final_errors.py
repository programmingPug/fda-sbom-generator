#!/usr/bin/env python3
"""
Final targeted fixes for the specific test failures.
"""

import os
import sys
from pathlib import Path
import subprocess

def run_single_test_and_show_error(test_path):
    """Run one test and show the exact assertion error."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v", "--tb=line", "--no-header"],
        capture_output=True,
        text=True,
        cwd=Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    )
    
    # Extract just the assertion error
    lines = result.stdout.split('\n')
    for line in lines:
        if 'AssertionError' in line or 'assert' in line:
            return line.strip()
    return "No clear assertion error found"

def main():
    os.chdir(Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator"))
    
    failing_tests = [
        "tests/unit/test_scanners.py::TestBaseScanner::test_normalize_license",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_basic_export",
        "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_python_project_full_workflow"
    ]
    
    print("Getting exact assertion errors for each test:")
    print("="*80)
    
    for test in failing_tests:
        print(f"\n{test.split('::')[-1]}:")
        error = run_single_test_and_show_error(test)
        print(f"  {error}")
    
    # Based on what we see, we can make the final fixes

if __name__ == "__main__":
    main()
