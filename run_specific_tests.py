#!/usr/bin/env python3
"""Run the specific failing tests to verify fixes."""

import subprocess
import sys

def run_test(test_path):
    """Run a single test and return result."""
    cmd = [sys.executable, "-m", "pytest", test_path, "-xvs"]
    print(f"\nRunning: {' '.join(cmd)}")
    print("-" * 60)
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✓ PASSED")
        return True
    else:
        print("✗ FAILED")
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        return False

def main():
    """Run all the failing tests."""
    tests = [
        "tests/unit/test_exporters.py::TestSWIDExporter::test_basic_export",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_export_with_components",
        "tests/unit/test_scanners.py::TestBaseScanner::test_normalize_license",
        "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_python_project_full_workflow"
    ]
    
    passed = 0
    failed = 0
    
    print("Testing fixes for FDA SBOM Generator")
    print("=" * 60)
    
    for test in tests:
        if run_test(test):
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Summary: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n✓ All tests fixed successfully!")
        return 0
    else:
        print(f"\n✗ {failed} tests still failing")
        return 1

if __name__ == "__main__":
    sys.exit(main())
