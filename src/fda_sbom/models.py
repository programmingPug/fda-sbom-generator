"""
Data models for FDA SBOM Generator.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator


class SBOMFormat(str, Enum):
    """Supported SBOM formats."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SWID = "swid"


class ComponentType(str, Enum):
    """Types of software components."""
    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"
    CONTAINER = "container"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class License(BaseModel):
    """Software license information."""
    spdx_id: Optional[str] = None
    name: Optional[str] = None
    text: Optional[str] = None
    url: Optional[str] = None

    @validator('spdx_id')
    def validate_spdx_id(cls, v):
        if v and not v.startswith('SPDX-License-Identifier:'):
            return f'SPDX-License-Identifier: {v}'
        return v


class Vulnerability(BaseModel):
    """Security vulnerability information."""
    id: str = Field(..., description="CVE ID or other vulnerability identifier")
    severity: VulnerabilitySeverity = Field(..., description="Severity level")
    score: Optional[float] = Field(None, description="CVSS score", ge=0.0, le=10.0)
    description: Optional[str] = None
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    references: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        protected_namespaces = ()


class Component(BaseModel):
    """Software component information."""
    name: str = Field(..., description="Component name")
    version: Optional[str] = Field(None, description="Component version")
    type: ComponentType = Field(ComponentType.LIBRARY, description="Component type")
    namespace: Optional[str] = Field(None, description="Component namespace/group")
    description: Optional[str] = None
    
    # Package manager specific
    package_manager: Optional[str] = Field(None, description="Package manager (pip, npm, etc.)")
    package_url: Optional[str] = Field(None, description="Package URL (PURL)")
    
    # File information
    file_path: Optional[str] = Field(None, description="File path in project")
    file_hash: Optional[str] = Field(None, description="File hash (SHA-256)")
    
    # License information
    licenses: List[License] = Field(default_factory=list)
    
    # Dependency information
    dependencies: List[str] = Field(default_factory=list, description="Direct dependencies")
    
    # Security information
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    
    # Metadata
    supplier: Optional[str] = Field(None, description="Component supplier/vendor")
    originator: Optional[str] = Field(None, description="Original author/creator")
    download_location: Optional[str] = Field(None, description="Download location")
    homepage: Optional[str] = Field(None, description="Homepage URL")
    
    # FDA specific fields
    medical_device_class: Optional[str] = Field(None, description="FDA medical device class")
    regulatory_status: Optional[str] = Field(None, description="Regulatory approval status")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        protected_namespaces = ()


class SBOM(BaseModel):
    """Software Bill of Materials."""
    # Document metadata
    document_id: str = Field(..., description="Unique document identifier")
    document_name: str = Field(..., description="Document name")
    document_namespace: str = Field(..., description="Document namespace")
    created: datetime = Field(default_factory=datetime.now)
    
    # Creator information
    creators: List[str] = Field(default_factory=list, description="Document creators")
    
    # Target system information
    target_system: Optional[str] = Field(None, description="Target system name")
    target_version: Optional[str] = Field(None, description="Target system version")
    
    # Components
    components: List[Component] = Field(default_factory=list)
    
    # Relationships (component dependencies)
    relationships: Dict[str, List[str]] = Field(default_factory=dict)
    
    # FDA specific metadata
    fda_submission_id: Optional[str] = Field(None, description="FDA submission identifier")
    device_identification: Optional[str] = Field(None, description="Device identification")
    manufacturer: Optional[str] = Field(None, description="Device manufacturer")
    model_number: Optional[str] = Field(None, description="Device model number")
    
    # Validation metadata
    validation_date: Optional[datetime] = None
    validation_status: Optional[str] = None
    compliance_notes: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        protected_namespaces = ()  # Allow model_number field
    
    def add_component(self, component: Component) -> None:
        """Add a component to the SBOM."""
        self.components.append(component)
    
    def get_component_by_name(self, name: str) -> Optional[Component]:
        """Get a component by name."""
        for component in self.components:
            if component.name == name:
                return component
        return None
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all components."""
        vulnerabilities = []
        for component in self.components:
            vulnerabilities.extend(component.vulnerabilities)
        return vulnerabilities
    
    def get_vulnerability_count_by_severity(self) -> Dict[VulnerabilitySeverity, int]:
        """Get count of vulnerabilities by severity."""
        counts = {severity: 0 for severity in VulnerabilitySeverity}
        for vuln in self.get_vulnerabilities():
            counts[vuln.severity] += 1
        return counts
    
    def validate_fda_compliance(self) -> List[str]:
        """Validate FDA compliance and return list of issues."""
        issues = []
        
        # Check required fields
        if not self.document_id:
            issues.append("Document ID is required")
        if not self.document_name:
            issues.append("Document name is required")
        if not self.manufacturer:
            issues.append("Manufacturer is required for FDA compliance")
        
        # Check components
        if not self.components:
            issues.append("SBOM must contain at least one component")
        
        for component in self.components:
            if not component.name:
                issues.append(f"Component name is required")
            if not component.version:
                issues.append(f"Component version is required for {component.name}")
            if not component.licenses:
                issues.append(f"License information is required for {component.name}")
        
        return issues


class SBOMReport(BaseModel):
    """SBOM analysis report."""
    sbom_id: str
    generated_at: datetime = Field(default_factory=datetime.now)
    
    # Summary statistics
    total_components: int = 0
    total_vulnerabilities: int = 0
    vulnerability_counts: Dict[VulnerabilitySeverity, int] = Field(default_factory=dict)
    
    # Compliance status
    fda_compliant: bool = False
    compliance_issues: List[str] = Field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        protected_namespaces = ()
