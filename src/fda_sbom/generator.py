"""
Main SBOM generator implementation.
"""

import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from .models import SBOM, Component, SBOMFormat, SBOMReport
from .scanners import ScannerRegistry
from .vulnerability import SecurityAnalyzer


class SBOMGenerator:
    """Main class for generating FDA-compliant SBOMs."""
    
    def __init__(self):
        self.scanner_registry = ScannerRegistry()
        self.security_analyzer = SecurityAnalyzer()
    
    def generate_sbom(
        self,
        project_path: Union[str, Path],
        target_system: Optional[str] = None,
        target_version: Optional[str] = None,
        include_vulnerabilities: bool = True,
        manufacturer: Optional[str] = None,
        device_model: Optional[str] = None,
        fda_submission_id: Optional[str] = None,
        progress_callback: Optional[callable] = None
    ) -> SBOM:
        """Generate an SBOM for the given project."""
        
        project_path = Path(project_path)
        if not project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")
        
        # Create SBOM document
        document_id = str(uuid.uuid4())
        document_name = target_system or project_path.name
        document_namespace = f"https://sbom.example.com/{document_id}"
        
        sbom = SBOM(
            document_id=document_id,
            document_name=document_name,
            document_namespace=document_namespace,
            target_system=target_system or project_path.name,
            target_version=target_version,
            creators=[f"fda-sbom-generator-0.1.0"],
            manufacturer=manufacturer,
            model_number=device_model,
            fda_submission_id=fda_submission_id
        )
        
        # Scan for components
        if progress_callback:
            progress_callback("Scanning project for components...")
        
        components = self._scan_project(project_path)
        
        # Add components to SBOM
        for component in components:
            sbom.add_component(component)
        
        # Scan for vulnerabilities if requested
        if include_vulnerabilities:
            if progress_callback:
                progress_callback("Scanning for vulnerabilities...")
            
            sbom = self.security_analyzer.scan_all_components(
                sbom, 
                progress_callback=self._create_vuln_progress_callback(progress_callback)
            )
        
        return sbom
    
    def _scan_project(self, project_path: Path) -> List[Component]:
        """Scan project using all applicable scanners."""
        all_components = []
        components_seen = set()  # Track to avoid duplicates
        
        # Get applicable scanners
        scanners = self.scanner_registry.get_applicable_scanners(project_path)
        
        # Run each scanner
        for scanner in scanners:
            try:
                components = scanner.scan()
                
                # Deduplicate components
                for component in components:
                    component_key = f"{component.name}:{component.version}:{component.package_manager}"
                    if component_key not in components_seen:
                        components_seen.add(component_key)
                        all_components.append(component)
            
            except Exception as e:
                print(f"Warning: Scanner {scanner.__class__.__name__} failed: {e}")
        
        return all_components
    
    def _create_vuln_progress_callback(self, main_callback):
        """Create a progress callback for vulnerability scanning."""
        if not main_callback:
            return None
        
        def vuln_progress(current, total, component_name):
            message = f"Scanning vulnerabilities ({current}/{total}): {component_name}"
            main_callback(message)
        
        return vuln_progress
    
    def validate_sbom(self, sbom: SBOM) -> SBOMReport:
        """Validate SBOM for FDA compliance and generate report."""
        
        # Validate FDA compliance
        compliance_issues = sbom.validate_fda_compliance()
        
        # Generate security analysis
        security_analysis = self.security_analyzer.analyze_sbom(sbom)
        
        # Create report
        report = SBOMReport(
            sbom_id=sbom.document_id,
            total_components=len(sbom.components),
            total_vulnerabilities=security_analysis['total_vulnerabilities'],
            vulnerability_counts=security_analysis['vulnerability_by_severity'],
            fda_compliant=len(compliance_issues) == 0,
            compliance_issues=compliance_issues,
            recommendations=security_analysis.get('recommendations', [])
        )
        
        # Add FDA-specific recommendations
        if not report.fda_compliant:
            report.recommendations.insert(0, 
                "Address FDA compliance issues before submission"
            )
        
        if report.total_vulnerabilities > 0:
            report.recommendations.append(
                "Document risk assessment for all identified vulnerabilities"
            )
        
        return report
    
    def generate_compliance_checklist(self, sbom: SBOM) -> Dict[str, bool]:
        """Generate FDA compliance checklist."""
        
        checklist = {
            "document_has_unique_id": bool(sbom.document_id),
            "document_has_name": bool(sbom.document_name),
            "document_has_namespace": bool(sbom.document_namespace),
            "document_has_creation_date": bool(sbom.created),
            "document_has_creator": bool(sbom.creators and len(sbom.creators) > 0),
            "has_target_system": bool(sbom.target_system),
            "has_manufacturer": bool(sbom.manufacturer),
            "has_components": len(sbom.components) > 0,
            "all_components_have_names": len(sbom.components) == 0 or all(c.name for c in sbom.components),
            "all_components_have_versions": len(sbom.components) == 0 or all(c.version for c in sbom.components),
            "all_components_have_licenses": len(sbom.components) == 0 or all(c.licenses for c in sbom.components),
            "has_vulnerability_scan": len(sbom.components) == 0 or any(hasattr(c, 'vulnerabilities') for c in sbom.components),
            "has_package_urls": len(sbom.components) == 0 or all(c.package_url for c in sbom.components if c.package_manager),
        }
        
        return checklist
    
    def scan_file(self, file_path: Union[str, Path]) -> Optional[Component]:
        """Scan a single file and return component information."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            return None
        
        # Use FileScanner to analyze the file
        from .scanners import FileScanner
        scanner = FileScanner(file_path.parent)
        
        try:
            component = scanner._create_file_component(file_path)
            return component
        except Exception as e:
            print(f"Warning: Could not scan file {file_path}: {e}")
            return None
    
    def merge_sboms(self, sboms: List[SBOM], merged_name: str) -> SBOM:
        """Merge multiple SBOMs into one."""
        
        if not sboms:
            raise ValueError("No SBOMs provided for merging")
        
        # Create new merged SBOM
        merged_sbom = SBOM(
            document_id=str(uuid.uuid4()),
            document_name=merged_name,
            document_namespace=f"https://sbom.example.com/merged/{uuid.uuid4()}",
            target_system=merged_name,
            creators=[f"fda-sbom-generator-0.1.0-merged"]
        )
        
        # Collect all components
        seen_components = set()
        
        for sbom in sboms:
            # Copy metadata from first SBOM if not set
            if not merged_sbom.manufacturer and sbom.manufacturer:
                merged_sbom.manufacturer = sbom.manufacturer
            if not merged_sbom.fda_submission_id and sbom.fda_submission_id:
                merged_sbom.fda_submission_id = sbom.fda_submission_id
            
            # Add components
            for component in sbom.components:
                component_key = f"{component.name}:{component.version}:{component.package_manager}"
                if component_key not in seen_components:
                    seen_components.add(component_key)
                    merged_sbom.add_component(component)
        
        return merged_sbom
    
    def update_component_licenses(self, sbom: SBOM) -> SBOM:
        """Update license information for all components."""
        
        for component in sbom.components:
            if not component.licenses and component.package_manager == "pip":
                # Try to get license info from PyPI
                try:
                    import requests
                    url = f"https://pypi.org/pypi/{component.name}/json"
                    response = requests.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        license_text = data.get('info', {}).get('license', '')
                        
                        if license_text:
                            license_obj = self._normalize_license(license_text)
                            component.licenses = [license_obj]
                
                except Exception as e:
                    print(f"Warning: Could not fetch license for {component.name}: {e}")
        
        return sbom
    
    def _normalize_license(self, license_text: str) -> 'License':
        """Normalize license text to License object."""
        from .models import License
        
        if not license_text:
            return License(name="Unknown")
        
        # Clean up the license text
        license_text = license_text.strip()
        
        # Common SPDX license mappings
        spdx_mappings = {
            "MIT": "MIT",
            "MIT License": "MIT",
            "Apache-2.0": "Apache-2.0",
            "Apache License 2.0": "Apache-2.0",
            "Apache 2.0": "Apache-2.0",
            "GPL-3.0": "GPL-3.0-only",
            "BSD-3-Clause": "BSD-3-Clause",
            "ISC": "ISC",
            "LGPL-2.1": "LGPL-2.1-only",
        }
        
        # Check for direct match first
        if license_text in spdx_mappings:
            return License(spdx_id=spdx_mappings[license_text], name=license_text)
        
        # Check for partial matches
        for pattern, spdx_id in spdx_mappings.items():
            if pattern.lower() in license_text.lower():
                return License(spdx_id=spdx_id, name=license_text)
        
        return License(name=license_text)
