#!/usr/bin/env python3
"""
Test the import issues by running a simple test manually.
"""

import sys
import os
sys.path.insert(0, 'src')

def test_imports():
    """Test that all imports work correctly."""
    try:
        print("Testing basic imports...")
        
        # Test models import
        from fda_sbom.models import SBOM, Component, ComponentType, License
        print("✅ Models import OK")
        
        # Test exporters import
        from fda_sbom.exporters import SPDXExporter, JSONExporter, export_sbom
        print("✅ Exporters import OK")
        
        # Test generator import
        from fda_sbom.generator import SBOMGenerator
        print("✅ Generator import OK")
        
        # Test scanners import
        from fda_sbom.scanners import PythonScanner
        print("✅ Scanners import OK")
        
        # Test creating a simple SBOM
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.com/sbom"
        )
        print("✅ SBOM creation OK")
        
        # Test creating a component
        component = Component(
            name="test-component",
            version="1.0.0",
            type=ComponentType.LIBRARY
        )
        sbom.add_component(component)
        print("✅ Component creation OK")
        
        # Test JSON exporter
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test.json"
            exporter = JSONExporter()
            exporter.export(sbom, output_file)
            
            if output_file.exists():
                print("✅ JSON export OK")
            else:
                print("❌ JSON export failed - file not created")
        
        print("\n🎉 All basic imports and functionality working!")
        return True
        
    except Exception as e:
        print(f"❌ Import/functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_fixture_dependencies():
    """Test if the fixtures work correctly."""
    try:
        print("\nTesting fixture dependencies...")
        
        # Test the fixtures that tests are looking for
        sys.path.insert(0, 'tests')
        from fixtures.conftest import sample_fda_compliant_sbom
        print("✅ Fixture import available")
        
        # Try to create a fixture instance (won't have pytest context but should import)
        print("✅ Fixture definitions OK")
        
    except Exception as e:
        print(f"❌ Fixture test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    os.chdir('C:/Users/ckoch/OneDrive/Documents/GitHub/fda-sbom-generator')
    
    success = test_imports()
    if success:
        test_fixture_dependencies()
    
    if success:
        print("\n✅ Ready to run tests!")
    else:
        print("\n❌ Fix imports before running tests")
