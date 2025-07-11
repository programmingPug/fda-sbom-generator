"""
Multi-project and solution scanning capabilities.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from .generator import SBOMGenerator
from .models import SBOM, Component


class SolutionScanner:
    """Scanner for multi-project solutions."""
    
    def __init__(self):
        self.generator = SBOMGenerator()
        self.project_patterns = {
            # .NET Solutions
            '*.sln': self._scan_dotnet_solution,
            # Node.js workspaces
            'package.json': self._scan_npm_workspace,
            # Python projects
            'pyproject.toml': self._scan_python_workspace,
            # Java multi-module
            'pom.xml': self._scan_maven_multimodule,
            # Generic project detection
            '*': self._scan_generic_projects
        }
    
    def scan_solution(
        self, 
        solution_path: Union[str, Path],
        manufacturer: Optional[str] = None,
        solution_name: Optional[str] = None,
        include_vulnerabilities: bool = True,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, SBOM]:
        """Scan an entire solution with multiple projects."""
        
        solution_path = Path(solution_path)
        if not solution_path.exists():
            raise FileNotFoundError(f"Solution path does not exist: {solution_path}")
        
        # Auto-detect solution type and projects
        projects = self._detect_projects(solution_path)
        
        if progress_callback:
            progress_callback(f"Found {len(projects)} projects in solution")
        
        # Generate SBOM for each project
        project_sboms = {}
        
        for i, (project_name, project_path) in enumerate(projects.items()):
            if progress_callback:
                progress_callback(f"Scanning project {i+1}/{len(projects)}: {project_name}")
            
            try:
                sbom = self.generator.generate_sbom(
                    project_path=project_path,
                    target_system=project_name,
                    manufacturer=manufacturer,
                    include_vulnerabilities=include_vulnerabilities,
                    progress_callback=None  # Avoid nested progress
                )
                project_sboms[project_name] = sbom
                
            except Exception as e:
                print(f"Warning: Failed to scan project {project_name}: {e}")
        
        return project_sboms
    
    def create_solution_sbom(
        self,
        project_sboms: Dict[str, SBOM],
        solution_name: str,
        manufacturer: Optional[str] = None
    ) -> SBOM:
        """Create a consolidated SBOM for the entire solution."""
        
        if not project_sboms:
            raise ValueError("No project SBOMs provided")
        
        # Merge all project SBOMs
        sbom_list = list(project_sboms.values())
        merged_sbom = self.generator.merge_sboms(sbom_list, solution_name)
        
        # Add solution-level metadata
        merged_sbom.target_system = solution_name
        if manufacturer:
            merged_sbom.manufacturer = manufacturer
        
        # Add project relationships
        merged_sbom.relationships = {}
        for project_name, project_sbom in project_sboms.items():
            component_names = [c.name for c in project_sbom.components]
            merged_sbom.relationships[project_name] = component_names
        
        return merged_sbom
    
    def _detect_projects(self, solution_path: Path) -> Dict[str, Path]:
        """Detect all projects in a solution."""
        projects = {}
        
        # Check for specific solution types first
        if self._is_dotnet_solution(solution_path):
            projects.update(self._scan_dotnet_solution(solution_path))
        elif self._is_npm_workspace(solution_path):
            projects.update(self._scan_npm_workspace(solution_path))
        elif self._is_maven_multimodule(solution_path):
            projects.update(self._scan_maven_multimodule(solution_path))
        else:
            # Generic project detection
            projects.update(self._scan_generic_projects(solution_path))
        
        return projects
    
    def _is_dotnet_solution(self, path: Path) -> bool:
        """Check if this is a .NET solution."""
        return any(path.glob('*.sln'))
    
    def _is_npm_workspace(self, path: Path) -> bool:
        """Check if this is an npm workspace."""
        package_json = path / 'package.json'
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                return 'workspaces' in data
            except:
                pass
        return False
    
    def _is_maven_multimodule(self, path: Path) -> bool:
        """Check if this is a Maven multi-module project."""
        pom_xml = path / 'pom.xml'
        if pom_xml.exists():
            try:
                content = pom_xml.read_text()
                return '<modules>' in content
            except:
                pass
        return False
    
    def _scan_dotnet_solution(self, solution_path: Path) -> Dict[str, Path]:
        """Scan .NET solution for projects."""
        projects = {}
        
        # Find .sln files
        for sln_file in solution_path.glob('*.sln'):
            try:
                content = sln_file.read_text(encoding='utf-8')
                
                # Parse project paths from .sln file
                import re
                project_pattern = r'Project\(".*?"\) = "(.*?)", "(.*?)"'
                matches = re.findall(project_pattern, content)
                
                for project_name, project_path in matches:
                    if project_path.endswith('.csproj') or project_path.endswith('.vbproj'):
                        full_path = (sln_file.parent / project_path).parent
                        if full_path.exists():
                            projects[project_name] = full_path
            
            except Exception as e:
                print(f"Warning: Could not parse .sln file {sln_file}: {e}")
        
        return projects
    
    def _scan_npm_workspace(self, solution_path: Path) -> Dict[str, Path]:
        """Scan npm workspace for projects."""
        projects = {}
        
        package_json = solution_path / 'package.json'
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                
                workspaces = data.get('workspaces', [])
                if isinstance(workspaces, dict):
                    workspaces = workspaces.get('packages', [])
                
                for workspace_pattern in workspaces:
                    # Handle glob patterns
                    if '*' in workspace_pattern:
                        for workspace_path in solution_path.glob(workspace_pattern):
                            if workspace_path.is_dir() and (workspace_path / 'package.json').exists():
                                projects[workspace_path.name] = workspace_path
                    else:
                        workspace_path = solution_path / workspace_pattern
                        if workspace_path.exists() and (workspace_path / 'package.json').exists():
                            projects[workspace_path.name] = workspace_path
            
            except Exception as e:
                print(f"Warning: Could not parse package.json workspace: {e}")
        
        return projects
    
    def _scan_maven_multimodule(self, solution_path: Path) -> Dict[str, Path]:
        """Scan Maven multi-module project."""
        projects = {}
        
        pom_xml = solution_path / 'pom.xml'
        if pom_xml.exists():
            try:
                from lxml import etree
                
                with open(pom_xml, 'r', encoding='utf-8') as f:
                    root = etree.parse(f)
                
                # Find modules
                ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
                modules = root.xpath('//maven:module', namespaces=ns)
                
                for module in modules:
                    module_name = module.text
                    module_path = solution_path / module_name
                    if module_path.exists() and (module_path / 'pom.xml').exists():
                        projects[module_name] = module_path
            
            except Exception as e:
                print(f"Warning: Could not parse Maven multi-module: {e}")
        
        return projects
    
    def _scan_python_workspace(self, solution_path: Path) -> Dict[str, Path]:
        """Scan Python workspace for projects."""
        projects = {}
        
        # Look for pyproject.toml files with workspace definitions
        pyproject_file = solution_path / 'pyproject.toml'
        if pyproject_file.exists():
            try:
                import toml
                with open(pyproject_file, 'r', encoding='utf-8') as f:
                    data = toml.load(f)
                
                # Check for workspace in tool.setuptools or similar
                # This is a basic implementation
                projects[solution_path.name] = solution_path
            except Exception as e:
                print(f"Warning: Could not parse Python workspace: {e}")
        
        return projects
    
    def _scan_generic_projects(self, solution_path: Path) -> Dict[str, Path]:
        """Generic project detection by scanning for project indicators."""
        projects = {}
        
        # Project indicators
        indicators = [
            'package.json',      # Node.js
            'requirements.txt',  # Python
            'pyproject.toml',   # Python
            'pom.xml',          # Java/Maven
            'build.gradle',     # Java/Gradle
            '*.csproj',         # .NET
            'Cargo.toml',       # Rust
            'go.mod',           # Go
        ]
        
        # Scan directories up to 3 levels deep
        for level in range(1, 4):
            pattern = '/'.join(['*'] * level)
            
            for dir_path in solution_path.glob(pattern):
                if not dir_path.is_dir():
                    continue
                
                # Skip common non-project directories
                if dir_path.name.startswith('.') or dir_path.name in ['node_modules', 'target', 'build', '__pycache__']:
                    continue
                
                # Check for project indicators
                for indicator in indicators:
                    if list(dir_path.glob(indicator)):
                        project_name = self._get_relative_name(dir_path, solution_path)
                        projects[project_name] = dir_path
                        break
        
        # If no sub-projects found, treat the root as a project
        if not projects:
            for indicator in indicators:
                if list(solution_path.glob(indicator)):
                    projects[solution_path.name] = solution_path
                    break
        
        return projects
    
    def _get_relative_name(self, project_path: Path, solution_path: Path) -> str:
        """Get a relative name for the project."""
        try:
            rel_path = project_path.relative_to(solution_path)
            return str(rel_path).replace('/', '-').replace('\\', '-')
        except ValueError:
            return project_path.name
    
    def export_solution_report(
        self,
        project_sboms: Dict[str, SBOM],
        solution_sbom: SBOM,
        output_path: Path
    ) -> None:
        """Export a comprehensive solution report."""
        
        report = {
            'solution_name': solution_sbom.target_system,
            'generated_at': solution_sbom.created.isoformat(),
            'total_projects': len(project_sboms),
            'total_components': len(solution_sbom.components),
            'projects': {}
        }
        
        # Add project details
        for project_name, project_sbom in project_sboms.items():
            vuln_counts = project_sbom.get_vulnerability_count_by_severity()
            
            report['projects'][project_name] = {
                'component_count': len(project_sbom.components),
                'vulnerability_count': len(project_sbom.get_vulnerabilities()),
                'vulnerability_breakdown': {k.value: v for k, v in vuln_counts.items()},
                'package_managers': list(set(c.package_manager for c in project_sbom.components if c.package_manager))
            }
        
        # Add solution-level summary
        all_vulns = solution_sbom.get_vulnerability_count_by_severity()
        report['solution_summary'] = {
            'total_vulnerabilities': len(solution_sbom.get_vulnerabilities()),
            'vulnerability_breakdown': {k.value: v for k, v in all_vulns.items()},
            'risk_assessment': self._assess_solution_risk(solution_sbom)
        }
        
        # Write report
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _assess_solution_risk(self, sbom: SBOM) -> str:
        """Assess overall solution risk level."""
        vuln_counts = sbom.get_vulnerability_count_by_severity()
        
        if vuln_counts.get('critical', 0) > 0:
            return "HIGH"
        elif vuln_counts.get('high', 0) > 5:
            return "HIGH" 
        elif vuln_counts.get('high', 0) > 0 or vuln_counts.get('medium', 0) > 10:
            return "MEDIUM"
        else:
            return "LOW"
