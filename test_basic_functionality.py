#!/usr/bin/env python3
"""
Simple test runner to check core functionality.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_basic_imports():
    """Test that basic imports work."""
    try:
        from fda_sbom.models import SBOM, Component, ComponentType
        from fda_sbom.generator import SBOMGenerator
        from fda_sbom.scanners import ScannerRegistry
        from fda_sbom.vulnerability import SecurityAnalyzer
        from fda_sbom.solution import SolutionScanner
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_scanner_registry():
    """Test scanner registry functionality."""
    try:
        from fda_sbom.scanners import ScannerRegistry
        registry = ScannerRegistry()
        scanners = registry.get_applicable_scanners(Path("."))
        print(f"✓ Scanner registry works, found {len(scanners)} applicable scanners")
        return True
    except Exception as e:
        print(f"✗ Scanner registry failed: {e}")
        return False

def test_sbom_generator():
    """Test basic SBOM generator functionality."""
    try:
        from fda_sbom.generator import SBOMGenerator
        generator = SBOMGenerator()
        
        # Test with current directory
        sbom = generator.generate_sbom(
            project_path=".",
            target_system="Test System",
            manufacturer="Test Manufacturer",
            include_vulnerabilities=False
        )
        
        print(f"✓ SBOM generator works, found {len(sbom.components)} components")
        return True
    except Exception as e:
        print(f"✗ SBOM generator failed: {e}")
        return False

def test_models():
    """Test basic model functionality."""
    try:
        from fda_sbom.models import SBOM, Component, ComponentType, License
        
        # Test component creation
        component = Component(
            name="test-component",
            version="1.0.0",
            type=ComponentType.LIBRARY,
            package_manager="pip"
        )
        
        # Test SBOM creation
        sbom = SBOM(
            document_id="test-123",
            document_name="Test SBOM",
            document_namespace="https://test.example.com/sbom/123",
            manufacturer="Test Manufacturer"
        )
        
        sbom.add_component(component)
        
        print(f"✓ Models work, SBOM has {len(sbom.components)} components")
        return True
    except Exception as e:
        print(f"✗ Models failed: {e}")
        return False

def main():
    """Run basic tests."""
    print("Running basic functionality tests...")
    print("=" * 50)
    
    tests = [
        test_basic_imports,
        test_models,
        test_scanner_registry,
        test_sbom_generator,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} crashed: {e}")
            failed += 1
        print()
    
    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All basic tests passed! The core functionality is working.")
        return 0
    else:
        print("⚠️ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
