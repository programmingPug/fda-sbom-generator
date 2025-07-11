#!/usr/bin/env python3
"""
Comprehensive test runner to verify all the failing tests are now fixed.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_test(test_path):
    """Run a specific test and return result."""
    print(f"\n{'='*80}")
    print(f"Running: {test_path}")
    print('='*80)
    
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v", "-x"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print("✅ PASSED")
    else:
        print("❌ FAILED")
        print("\nSTDOUT:")
        print(result.stdout)
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
    
    return result.returncode == 0

def main():
    # Change to project directory
    project_dir = Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    os.chdir(project_dir)
    
    print(f"Working directory: {os.getcwd()}")
    
    # List of previously failing tests
    failing_tests = [
        "tests/unit/test_scanners.py::TestJavaScanner::test_parse_maven_pom",
        "tests/unit/test_scanners.py::TestScannerRegistry::test_get_applicable_scanners_multi_language",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_basic_export",
        "tests/unit/test_exporters.py::TestSWIDExporter::test_export_with_components", 
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_compliance_validation_workflow",
        "tests/integration/test_end_to_end.py::TestEndToEndWorkflows::test_python_project_full_workflow"
    ]
    
    print("Testing previously failing tests...")
    
    results = {}
    
    for test in failing_tests:
        success = run_test(test)
        results[test] = success
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print('='*80)
    
    passed = 0
    failed = 0
    
    for test, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{status}: {test.split('::')[-1]}")
        if success:
            passed += 1
        else:
            failed += 1
    
    print(f"\nTotal: {len(results)} tests")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 All previously failing tests are now PASSING!")
        
        # Run a broader test to make sure we didn't break anything
        print(f"\n{'='*80}")
        print("Running broader test suite to check for regressions...")
        print('='*80)
        
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("✅ All tests are passing!")
        else:
            print("⚠️ Some other tests may have issues:")
            print(result.stdout[-2000:])  # Last 2000 chars to see recent output
        
        return True
    else:
        print(f"\n⚠️ {failed} tests still failing")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
