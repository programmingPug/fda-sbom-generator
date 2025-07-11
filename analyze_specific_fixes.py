#!/usr/bin/env python3
"""
Quick fixes for remaining test issues.
"""

import sys
import os
from pathlib import Path

def apply_fixes():
    """Apply targeted fixes for the remaining test failures."""
    
    # Change to project directory
    project_dir = Path(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")
    os.chdir(project_dir)
    
    print("Applying fixes for remaining test issues...")
    
    # Fix 1: Update the license test expectations
    print("1. Checking license test expectations...")
    test_scanners_file = project_dir / "tests" / "unit" / "test_scanners.py"
    
    if test_scanners_file.exists():
        content = test_scanners_file.read_text()
        
        # The test expects the scanner to return licenses with raw SPDX IDs
        # but our current implementation via the model auto-prefixes them
        # Let's check what the test actually expects
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'mit_license.spdx_id == "MIT"' in line:
                print(f"Found test expectation at line {i+1}: {line.strip()}")
                print("Test expects raw SPDX ID 'MIT'")
                break
    
    # Fix 2: Debug SWID export issue
    print("\n2. Debugging SWID export...")
    
    # The issue might be that the test is trying to find "Entity" without namespace
    # but our XML might have namespaces that affect the search
    
    # Let's look at the specific test
    test_exporters_file = project_dir / "tests" / "unit" / "test_exporters.py"
    if test_exporters_file.exists():
        content = test_exporters_file.read_text()
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            if 'entity = root.find("Entity")' in line:
                print(f"Found SWID test at line {i+1}: {line.strip()}")
                print("Test uses root.find('Entity') - needs exact element name")
                break
    
    # Fix 3: Check JavaScript scanner logic
    print("\n3. Checking JavaScript scanner detection...")
    
    scanners_file = project_dir / "src" / "fda_sbom" / "scanners.py"
    if scanners_file.exists():
        content = scanners_file.read_text()
        
        # Find the JavaScriptScanner can_scan method
        lines = content.split('\n')
        in_js_scanner = False
        in_can_scan = False
        
        for i, line in enumerate(lines):
            if 'class JavaScriptScanner' in line:
                in_js_scanner = True
                print(f"Found JavaScriptScanner at line {i+1}")
            elif in_js_scanner and 'def can_scan' in line:
                in_can_scan = True
                print(f"Found can_scan method at line {i+1}")
            elif in_can_scan and 'return' in line:
                print(f"Scanner detection logic: {line.strip()}")
                in_can_scan = False
                break
    
    print("\n4. Summary of issues to fix:")
    print("- License test expects raw SPDX IDs from scanner")
    print("- SWID test needs Entity element to be found correctly")
    print("- JavaScript scanner detection in multi-project might need enhancement")

if __name__ == "__main__":
    apply_fixes()
