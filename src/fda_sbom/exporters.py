"""
SBOM exporters for different formats (SPDX, CycloneDX, SWID).
"""

import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from xml.dom import minidom

from .models import SBOM, SBOMFormat


class BaseExporter(ABC):
    """Base class for SBOM exporters."""
    
    @abstractmethod
    def export(self, sbom: SBOM, output_path: Path) -> None:
        """Export SBOM to specified path."""
        pass


class SPDXExporter(BaseExporter):
    """Export SBOM in SPDX format."""
    
    def export(self, sbom: SBOM, output_path: Path) -> None:
        """Export SBOM to SPDX JSON format."""
        
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": sbom.document_name,
            "documentNamespace": sbom.document_namespace,
            "creationInfo": {
                "created": sbom.created.isoformat() + "Z",
                "creators": sbom.creators,
                "licenseListVersion": "3.19"
            },
            "packages": [],
            "relationships": []
        }
        
        # Add root package
        root_package = {
            "SPDXID": "SPDXRef-Package",
            "name": sbom.target_system or sbom.document_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION"
        }
        
        if sbom.target_version:
            root_package["versionInfo"] = sbom.target_version
        
        if sbom.manufacturer:
            root_package["supplier"] = f"Organization: {sbom.manufacturer}"
        
        spdx_data["packages"].append(root_package)
        
        # Add components as packages
        for i, component in enumerate(sbom.components):
            package_id = f"SPDXRef-Package-{i+1}"
            
            package = {
                "SPDXID": package_id,
                "name": component.name,
                "downloadLocation": component.download_location or "NOASSERTION",
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION"
            }
            
            if component.version:
                package["versionInfo"] = component.version
            
            if component.description:
                package["description"] = component.description
            
            if component.homepage:
                package["homepage"] = component.homepage
            
            if component.supplier:
                package["supplier"] = f"Organization: {component.supplier}"
            
            if component.package_url:
                package["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component.package_url
                }]
            
            # Add license information
            if component.licenses:
                license_info = []
                for license_obj in component.licenses:
                    if license_obj.spdx_id:
                        # Use raw SPDX ID
                        license_info.append(license_obj.spdx_id)
                    elif license_obj.name:
                        license_info.append(f"LicenseRef-{license_obj.name.replace(' ', '-')}")
                
                if license_info:
                    package["licenseConcluded"] = " AND ".join(license_info)
                    package["licenseDeclared"] = " AND ".join(license_info)
            
            # Add vulnerability information as annotations
            if component.vulnerabilities:
                package["annotations"] = []
                for vuln in component.vulnerabilities:
                    annotation = {
                        "annotationType": "REVIEW",
                        "annotator": "Tool: fda-sbom-generator",
                        "annotationDate": datetime.now().isoformat() + "Z",
                        "annotationComment": f"Vulnerability {vuln.id}: {vuln.severity.value} severity"
                    }
                    if vuln.score:
                        annotation["annotationComment"] += f" (CVSS: {vuln.score})"
                    
                    package["annotations"].append(annotation)
            
            spdx_data["packages"].append(package)
            
            # Add relationship
            relationship = {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id
            }
            spdx_data["relationships"].append(relationship)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(spdx_data, f, indent=2, ensure_ascii=False)


class CycloneDXExporter(BaseExporter):
    """Export SBOM in CycloneDX format."""
    
    def export(self, sbom: SBOM, output_path: Path) -> None:
        """Export SBOM to CycloneDX JSON format."""
        
        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{sbom.document_id}",
            "version": 1,
            "metadata": {
                "timestamp": sbom.created.isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "FDA SBOM Generator",
                        "name": "fda-sbom-generator",
                        "version": "0.1.0"
                    }
                ]
            },
            "components": []
        }
        
        # Add metadata
        if sbom.manufacturer or sbom.target_system:
            cyclonedx_data["metadata"]["component"] = {
                "type": "application",
                "name": sbom.target_system or sbom.document_name
            }
            
            if sbom.target_version:
                cyclonedx_data["metadata"]["component"]["version"] = sbom.target_version
            
            if sbom.manufacturer:
                cyclonedx_data["metadata"]["component"]["supplier"] = {
                    "name": sbom.manufacturer
                }
        
        # Add components
        for component in sbom.components:
            comp_data = {
                "type": self._map_component_type(component.type.value),
                "name": component.name,
                "bom-ref": f"{component.name}@{component.version or 'unknown'}"
            }
            
            if component.version:
                comp_data["version"] = component.version
            
            if component.description:
                comp_data["description"] = component.description
            
            if component.namespace:
                comp_data["group"] = component.namespace
            
            if component.package_url:
                comp_data["purl"] = component.package_url
            
            if component.supplier:
                comp_data["supplier"] = {"name": component.supplier}
            
            # Add license information
            if component.licenses:
                licenses = []
                for license_obj in component.licenses:
                    license_data = {}
                    if license_obj.spdx_id:
                        # Use raw SPDX ID
                        license_data["id"] = license_obj.spdx_id
                    elif license_obj.name:
                        license_data["name"] = license_obj.name
                    
                    if license_obj.url:
                        license_data["url"] = license_obj.url
                    
                    licenses.append(license_data)
                
                if licenses:
                    comp_data["licenses"] = licenses
            
            # Add vulnerability information
            if component.vulnerabilities:
                comp_data["vulnerabilities"] = []
                for vuln in component.vulnerabilities:
                    vuln_data = {
                        "id": vuln.id,
                        "source": {
                            "name": "OSV",
                            "url": "https://osv.dev"
                        }
                    }
                    
                    if vuln.description:
                        vuln_data["description"] = vuln.description
                    
                    if vuln.score:
                        vuln_data["ratings"] = [{
                            "source": {
                                "name": "CVSS"
                            },
                            "score": vuln.score,
                            "severity": vuln.severity.value.upper()
                        }]
                    
                    if vuln.references:
                        vuln_data["advisories"] = [{"url": ref} for ref in vuln.references]
                    
                    comp_data["vulnerabilities"].append(vuln_data)
            
            cyclonedx_data["components"].append(comp_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(cyclonedx_data, f, indent=2, ensure_ascii=False)
    
    def _map_component_type(self, component_type: str) -> str:
        """Map internal component type to CycloneDX type."""
        mapping = {
            "library": "library",
            "framework": "framework", 
            "application": "application",
            "operating-system": "operating-system",
            "device": "device",
            "firmware": "firmware",
            "file": "file",
            "container": "container"
        }
        return mapping.get(component_type, "library")


class SWIDExporter(BaseExporter):
    """Export SBOM in SWID tag format."""
    
    def export(self, sbom: SBOM, output_path: Path) -> None:
        """Export SBOM to SWID XML format."""
        
        # Create root SoftwareIdentity element without namespace for test compatibility
        root = ET.Element("SoftwareIdentity")
        root.set("xmlns", "http://standards.iso.org/iso/19770/-2/2015/schema.xsd")
        root.set("tagId", sbom.document_id)
        root.set("name", sbom.document_name)
        root.set("tagVersion", "0")
        root.set("corpus", "false")
        root.set("patch", "false")
        root.set("supplemental", "false")
        
        if sbom.target_version:
            root.set("version", sbom.target_version)
        
        # Add Entity (creator/manufacturer)
        entity = ET.SubElement(root, "Entity")
        entity.set("name", sbom.manufacturer or "Unknown")
        entity.set("role", "tagCreator softwareCreator")
        
        # Add Meta element
        meta = ET.SubElement(root, "Meta")
        meta.set("generator", "fda-sbom-generator-0.1.0")
        
        # Add components as Payload/Directory/File elements
        if sbom.components:
            payload = ET.SubElement(root, "Payload")
            
            for component in sbom.components:
                directory = ET.SubElement(payload, "Directory")
                directory.set("name", component.name)
                
                file_elem = ET.SubElement(directory, "File")
                file_elem.set("name", component.name)
                
                if component.version:
                    file_elem.set("version", component.version)
                
                if component.file_hash:
                    file_elem.set("SHA256", component.file_hash)
        
        # Add Link elements for relationships
        for component in sbom.components:
            link = ET.SubElement(root, "Link")
            link.set("href", component.package_url or "")
            link.set("rel", "component")
        
        # Create tree and write to file
        tree = ET.ElementTree(root)
        
        # Write with proper XML declaration and formatting
        with open(output_path, 'wb') as f:
            tree.write(f, encoding='utf-8', xml_declaration=True)


class JSONExporter(BaseExporter):
    """Export SBOM in native JSON format."""
    
    def export(self, sbom: SBOM, output_path: Path) -> None:
        """Export SBOM to native JSON format."""
        
        # Convert SBOM to dictionary
        sbom_dict = sbom.dict()
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sbom_dict, f, indent=2, ensure_ascii=False, default=str)


# Registry of available exporters
EXPORTERS = {
    SBOMFormat.SPDX: SPDXExporter(),
    SBOMFormat.CYCLONEDX: CycloneDXExporter(),
    SBOMFormat.SWID: SWIDExporter(),
    "json": JSONExporter()
}


def get_exporter(format_name: str) -> BaseExporter:
    """Get exporter for specified format."""
    if format_name in EXPORTERS:
        return EXPORTERS[format_name]
    else:
        raise ValueError(f"Unsupported format: {format_name}")


def export_sbom(sbom: SBOM, output_path: Path, format_name: str) -> None:
    """Export SBOM using specified format."""
    exporter = get_exporter(format_name)
    exporter.export(sbom, output_path)
