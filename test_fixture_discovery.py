#!/usr/bin/env python3
"""
Test fixture availability and imports.
"""

import sys
import os

# Change to project directory
os.chdir('C:/Users/ckoch/OneDrive/Documents/GitHub/fda-sbom-generator')
sys.path.insert(0, 'src')

def test_fixture_discovery():
    """Test that pytest can discover our fixtures."""
    try:
        import subprocess
        
        # Run pytest with --fixtures to see available fixtures
        result = subprocess.run([
            sys.executable, "-m", "pytest", "--fixtures", "tests/unit/test_exporters.py"
        ], capture_output=True, text=True, timeout=30)
        
        print("=== Pytest Fixtures Output ===")
        print(result.stdout)
        
        if result.stderr:
            print("=== Stderr ===")
            print(result.stderr)
        
        # Check if our custom fixtures are found
        fixtures_output = result.stdout
        
        missing_fixtures = []
        required_fixtures = [
            'sample_python_project',
            'sample_fda_compliant_sbom',
            'sample_sbom',
            'sample_dotnet_project',
            'sample_nodejs_project',
            'sample_multi_project_solution',
            'test_data_generator'
        ]
        
        for fixture in required_fixtures:
            if fixture not in fixtures_output:
                missing_fixtures.append(fixture)
        
        if missing_fixtures:
            print(f"❌ Missing fixtures: {missing_fixtures}")
            return False
        else:
            print("✅ All required fixtures found!")
            return True
            
    except Exception as e:
        print(f"❌ Error testing fixtures: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_simple_import():
    """Test basic imports work."""
    try:
        from fda_sbom.models import SBOM, Component
        from fda_sbom.exporters import JSONExporter
        print("✅ Basic imports work")
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def test_one_simple_test():
    """Try to run one simple test."""
    try:
        import subprocess
        
        # Try to run a very simple test
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            "tests/unit/test_models.py::TestLicense::test_license_creation_full",
            "-v", "-s"
        ], capture_output=True, text=True, timeout=60)
        
        print("=== Simple Test Output ===")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        print("Return Code:", result.returncode)
        
        if result.returncode == 0:
            print("✅ Simple test passed!")
            return True
        else:
            print("❌ Simple test failed")
            return False
            
    except Exception as e:
        print(f"❌ Error running simple test: {e}")
        return False

if __name__ == "__main__":
    print("Testing fixture discovery and basic functionality...\n")
    
    # Test 1: Basic imports
    import_success = test_simple_import()
    
    # Test 2: Fixture discovery
    if import_success:
        fixture_success = test_fixture_discovery()
        
        # Test 3: Try running one test
        if fixture_success:
            test_success = test_one_simple_test()
            
            if test_success:
                print("\n🎉 All tests successful! Ready to run full test suite.")
            else:
                print("\n❌ Individual test failed - check test logic")
        else:
            print("\n❌ Fixture discovery failed - need to fix fixture imports")
    else:
        print("\n❌ Basic imports failed - install dependencies first")
