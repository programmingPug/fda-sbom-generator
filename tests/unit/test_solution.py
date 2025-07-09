"""
Unit tests for solution scanning functionality.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from fda_sbom.solution import SolutionScanner
from fda_sbom.models import SBOM, Component, ComponentType
from fda_sbom.generator import SBOMGenerator


class TestSolutionScanner:
    """Test SolutionScanner."""
    
    def test_scanner_initialization(self):
        """Test solution scanner initialization."""
        scanner = SolutionScanner()
        
        assert scanner.generator is not None
        assert isinstance(scanner.generator, SBOMGenerator)
        assert scanner.project_patterns is not None
        assert len(scanner.project_patterns) > 0
    
    @patch.object(SBOMGenerator, 'generate_sbom')
    def test_scan_solution_basic(self, mock_generate, sample_multi_project_solution):
        """Test basic solution scanning."""
        # Mock SBOM generation
        mock_sbom = SBOM(
            document_id="test-project",
            document_name="Test Project",
            document_namespace="https://test.com/project"
        )
        mock_generate.return_value = mock_sbom
        
        scanner = SolutionScanner()
        
        project_sboms = scanner.scan_solution(
            solution_path=sample_multi_project_solution,
            manufacturer="Test Inc",
            include_vulnerabilities=False
        )
        
        # Should find at least one project
        assert len(project_sboms) >= 1
        assert isinstance(project_sboms, dict)
        
        # Each value should be an SBOM
        for project_name, sbom in project_sboms.items():
            assert isinstance(project_name, str)
            assert isinstance(sbom, SBOM)
    
    def test_scan_solution_nonexistent_path(self):
        """Test scanning nonexistent solution path."""
        scanner = SolutionScanner()
        
        with pytest.raises(FileNotFoundError):
            scanner.scan_solution("/nonexistent/path")
    
    @patch.object(SBOMGenerator, 'generate_sbom')
    def test_scan_solution_with_progress_callback(self, mock_generate, sample_multi_project_solution):
        """Test solution scanning with progress callback."""
        mock_sbom = SBOM(
            document_id="test",
            document_name="Test",
            document_namespace="https://test.com"
        )
        mock_generate.return_value = mock_sbom
        
        progress_messages = []
        def progress_callback(message):
            progress_messages.append(message)
        
        scanner = SolutionScanner()
        project_sboms = scanner.scan_solution(
            solution_path=sample_multi_project_solution,
            progress_callback=progress_callback
        )
        
        # Should have received progress updates
        assert len(progress_messages) > 0
        assert any("Found" in msg and "projects" in msg for msg in progress_messages)
    
    def test_create_solution_sbom(self):
        """Test creating consolidated solution SBOM."""
        # Create sample project SBOMs
        project1_sbom = SBOM(
            document_id="project1",
            document_name="Project 1",
            document_namespace="https://test.com/project1",
            manufacturer="Test Inc"
        )
        project1_sbom.add_component(Component(
            name="lib1", version="1.0.0", type=ComponentType.LIBRARY
        ))
        
        project2_sbom = SBOM(
            document_id="project2",
            document_name="Project 2", 
            document_namespace="https://test.com/project2"
        )
        project2_sbom.add_component(Component(
            name="lib2", version="2.0.0", type=ComponentType.LIBRARY
        ))
        
        project_sboms = {
            "Project 1": project1_sbom,
            "Project 2": project2_sbom
        }
        
        scanner = SolutionScanner()
        solution_sbom = scanner.create_solution_sbom(
            project_sboms, "Test Solution", "Solution Inc"
        )
        
        assert solution_sbom.target_system == "Test Solution"
        assert solution_sbom.manufacturer == "Solution Inc"
        assert len(solution_sbom.components) == 2
        
        # Should have relationships
        assert "Project 1" in solution_sbom.relationships
        assert "Project 2" in solution_sbom.relationships
        
        component_names = [c.name for c in solution_sbom.components]
        assert "lib1" in component_names
        assert "lib2" in component_names
    
    def test_create_solution_sbom_empty_projects(self):
        """Test creating solution SBOM with no projects."""
        scanner = SolutionScanner()
        
        with pytest.raises(ValueError, match="No project SBOMs provided"):
            scanner.create_solution_sbom({}, "Empty Solution")


if __name__ == "__main__":
    pytest.main([__file__])
