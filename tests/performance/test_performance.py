"""
Performance tests for FDA SBOM Generator.
"""

import time
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

import pytest

from fda_sbom.generator import SBOMGenerator
from fda_sbom.models import Component, ComponentType, SBOM
from fda_sbom.scanners import ScannerRegistry


class TestPerformance:
    """Performance tests for SBOM generation."""
    
    def test_large_project_scanning_performance(self, test_data_generator, temp_project_dir):
        """Test performance with large number of dependencies."""
        # Create large project
        large_project = test_data_generator.create_large_project(
            temp_project_dir, 
            num_dependencies=500
        )
        
        generator = SBOMGenerator()
        
        # Measure scanning time
        start_time = time.time()
        
        sbom = generator.generate_sbom(
            project_path=large_project,
            target_system="Large Performance Test",
            manufacturer="Performance Test Inc",
            include_vulnerabilities=False  # Skip vulnerability scanning for performance
        )
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Performance assertions
        assert scan_duration < 30.0  # Should complete within 30 seconds
        assert len(sbom.components) > 0
        
        # Should handle large number of components efficiently
        components_per_second = len(sbom.components) / scan_duration
        assert components_per_second > 10  # At least 10 components per second
    
    def test_scanner_registry_performance(self, temp_project_dir):
        """Test scanner registry performance with many scanners."""
        registry = ScannerRegistry()
        
        # Create project with multiple technology indicators
        mixed_project = temp_project_dir / "mixed_tech_project"
        mixed_project.mkdir()
        
        # Add files for different technologies
        (mixed_project / "requirements.txt").write_text("requests==2.28.0")
        (mixed_project / "package.json").write_text('{"name": "test"}')
        (mixed_project / "pom.xml").write_text("<project></project>")
        (mixed_project / "project.csproj").write_text("<Project />")
        (mixed_project / "Cargo.toml").write_text("[package]")
        
        # Measure scanner detection time
        start_time = time.time()
        
        applicable_scanners = registry.get_applicable_scanners(mixed_project)
        
        end_time = time.time()
        detection_duration = end_time - start_time
        
        # Should detect scanners quickly
        assert detection_duration < 1.0  # Less than 1 second
        assert len(applicable_scanners) >= 2  # Should find multiple scanners
    
    @pytest.mark.slow
    def test_vulnerability_scanning_performance(self, sample_python_project):
        """Test vulnerability scanning performance."""
        generator = SBOMGenerator()
        
        # First generate SBOM without vulnerabilities
        sbom_without_vulns = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Performance Test",
            manufacturer="Test Inc",
            include_vulnerabilities=False
        )
        
        # Measure vulnerability scanning time
        start_time = time.time()
        
        sbom_with_vulns = generator.generate_sbom(
            project_path=sample_python_project,
            target_system="Performance Test with Vulns",
            manufacturer="Test Inc",
            include_vulnerabilities=True
        )
        
        end_time = time.time()
        vuln_scan_duration = end_time - start_time
        
        # Vulnerability scanning should complete in reasonable time
        assert vuln_scan_duration < 60.0  # Less than 1 minute
        
        # Should have same number of components
        assert len(sbom_with_vulns.components) == len(sbom_without_vulns.components)
    
    def test_memory_usage_large_sbom(self, temp_project_dir):
        """Test memory usage with large SBOM."""
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create SBOM with many components
        sbom = SBOM(
            document_id="memory-test",
            document_name="Memory Test SBOM",
            document_namespace="https://test.com/memory"
        )
        
        # Add 1000 components
        for i in range(1000):
            component = Component(
                name=f"component-{i:04d}",
                version=f"1.{i % 100}.{i % 10}",
                type=ComponentType.LIBRARY,
                description=f"Test component number {i} for memory testing"
            )
            sbom.add_component(component)
        
        # Get memory usage after creating large SBOM
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB for 1000 components)
        assert memory_increase < 100.0
        
        # Verify SBOM is functional
        assert len(sbom.components) == 1000
        assert sbom.get_component_by_name("component-0500") is not None


class TestMemoryLeaks:
    """Test for memory leaks and resource management."""
    
    def test_repeated_sbom_generation_memory_stability(self, sample_python_project):
        """Test that repeated SBOM generation doesn't leak memory."""
        import psutil
        import os
        import gc
        
        process = psutil.Process(os.getpid())
        generator = SBOMGenerator()
        
        # Get baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate SBOMs repeatedly
        for i in range(10):
            sbom = generator.generate_sbom(
                project_path=sample_python_project,
                target_system=f"Memory Test {i}",
                manufacturer="Memory Test Inc",
                include_vulnerabilities=False
            )
            
            # Verify SBOM is valid
            assert sbom.document_name == f"Memory Test {i}"
            
            # Clear reference
            del sbom
            
            # Force garbage collection every few iterations
            if i % 3 == 0:
                gc.collect()
        
        # Final garbage collection
        gc.collect()
        
        # Check final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - baseline_memory
        
        # Memory increase should be minimal (less than 50MB)
        assert memory_increase < 50.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not slow"])
