"""
Test fixtures and utilities for FDA SBOM Generator tests.
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, List
import pytest

from fda_sbom.models import SBOM, Component, ComponentType, License, Vulnerability, VulnerabilitySeverity


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_python_project(temp_project_dir):
    """Create a sample Python project."""
    project_path = temp_project_dir / "python_project"
    project_path.mkdir()
    
    # Create requirements.txt
    requirements = """
requests==2.28.0
click>=8.0.0
pytest==7.2.0
numpy==1.21.0
# This is a comment
flask>=2.0.0
"""
    (project_path / "requirements.txt").write_text(requirements.strip())
    
    # Create pyproject.toml
    pyproject = """
[project]
name = "test-medical-device"
version = "1.0.0"
dependencies = [
    "fastapi>=0.95.0",
    "uvicorn>=0.20.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "black>=22.0",
]
"""
    (project_path / "pyproject.toml").write_text(pyproject.strip())
    
    # Create Python files
    (project_path / "main.py").write_text("import requests\nprint('Hello Medical Device')")
    (project_path / "device_api.py").write_text("from flask import Flask\napp = Flask(__name__)")
    
    return project_path


@pytest.fixture
def sample_nodejs_project(temp_project_dir):
    """Create a sample Node.js project."""
    project_path = temp_project_dir / "nodejs_project"
    project_path.mkdir()
    
    # Create package.json
    package_json = {
        "name": "medical-device-ui",
        "version": "2.1.0",
        "dependencies": {
            "react": "^18.2.0",
            "axios": "^1.3.0",
            "lodash": "4.17.21"
        },
        "devDependencies": {
            "webpack": "^5.75.0",
            "eslint": "^8.30.0"
        }
    }
    (project_path / "package.json").write_text(json.dumps(package_json, indent=2))
    
    # Create JavaScript files
    (project_path / "index.js").write_text("const React = require('react');")
    (project_path / "device-controller.js").write_text("const axios = require('axios');")
    
    return project_path


@pytest.fixture
def sample_dotnet_project(temp_project_dir):
    """Create a sample .NET project."""
    project_path = temp_project_dir / "dotnet_project"
    project_path.mkdir()
    
    # Create .csproj file
    csproj_content = """
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="8.0.0" />
    <PackageReference Include="Swashbuckle.AspNetCore" Version="6.4.0" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog.AspNetCore" Version="7.0.0" />
  </ItemGroup>
</Project>
"""
    (project_path / "MedicalDevice.Api.csproj").write_text(csproj_content.strip())
    
    # Create legacy packages.config
    packages_config = """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="EntityFramework" version="6.4.4" targetFramework="net48" />
  <package id="log4net" version="2.0.15" targetFramework="net48" />
</packages>
"""
    (project_path / "packages.config").write_text(packages_config.strip())
    
    # Create C# files
    (project_path / "Program.cs").write_text("using Microsoft.AspNetCore;\nvar app = WebApplication.Create();")
    
    return project_path


@pytest.fixture
def sample_java_project(temp_project_dir):
    """Create a sample Java Maven project."""
    project_path = temp_project_dir / "java_project"
    project_path.mkdir()
    
    # Create pom.xml
    pom_xml = """
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.medical.device</groupId>
    <artifactId>medical-device-core</artifactId>
    <version>1.2.0</version>
    
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.0.0</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.14.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
    (project_path / "pom.xml").write_text(pom_xml.strip())
    
    # Create Java files
    src_dir = project_path / "src" / "main" / "java" / "com" / "medical" / "device"
    src_dir.mkdir(parents=True)
    (src_dir / "DeviceController.java").write_text("package com.medical.device;\npublic class DeviceController {}")
    
    return project_path


@pytest.fixture
def sample_multi_project_solution(temp_project_dir):
    """Create a multi-project solution."""
    solution_path = temp_project_dir / "medical_device_solution"
    solution_path.mkdir()
    
    # Create .NET solution file
    sln_content = """
Microsoft Visual Studio Solution File, Format Version 12.00
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "DeviceApi", "DeviceApi\\DeviceApi.csproj", "{12345678-1234-1234-1234-123456789ABC}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "DeviceUI", "DeviceUI\\DeviceUI.csproj", "{87654321-4321-4321-4321-CBA987654321}"
EndProject
"""
    (solution_path / "MedicalDevice.sln").write_text(sln_content.strip())
    
    # Create DeviceApi project
    api_dir = solution_path / "DeviceApi"
    api_dir.mkdir()
    api_csproj = """
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="8.0.0" />
  </ItemGroup>
</Project>
"""
    (api_dir / "DeviceApi.csproj").write_text(api_csproj.strip())
    
    # Create DeviceUI project with both .csproj and package.json
    ui_dir = solution_path / "DeviceUI"
    ui_dir.mkdir()
    
    # Add package.json for JavaScript detection
    ui_package_json = {
        "name": "device-ui",
        "version": "1.0.0",
        "dependencies": {
            "react": "^18.2.0",
            "axios": "^1.3.0"
        },
        "devDependencies": {
            "webpack": "^5.75.0"
        }
    }
    (ui_dir / "package.json").write_text(json.dumps(ui_package_json, indent=2))
    
    # Add JavaScript file
    (ui_dir / "index.js").write_text("const React = require('react');")
    
    # Create shared Python utilities
    python_dir = solution_path / "shared-utils"
    python_dir.mkdir()
    (python_dir / "requirements.txt").write_text("pydantic>=2.0.0\nrequests>=2.28.0")
    
    # Add a package.json at root level to help with JavaScript detection
    root_package_json = {
        "name": "medical-device-workspace",
        "private": True,
        "workspaces": ["DeviceUI"],
        "devDependencies": {
            "eslint": "^8.0.0"
        }
    }
    (solution_path / "package.json").write_text(json.dumps(root_package_json, indent=2))
    
    return solution_path


@pytest.fixture
def sample_component():
    """Create a sample component."""
    return Component(
        name="requests",
        version="2.28.0",
        type=ComponentType.LIBRARY,
        package_manager="pip",
        description="Python HTTP library",
        package_url="pkg:pypi/requests@2.28.0",
        licenses=[License(name="Apache-2.0", spdx_id="Apache-2.0")]
    )


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability."""
    return Vulnerability(
        id="CVE-2023-12345",
        severity=VulnerabilitySeverity.HIGH,
        score=7.5,
        description="Example vulnerability for testing",
        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345"]
    )


@pytest.fixture
def sample_sbom(sample_component, sample_vulnerability):
    """Create a sample SBOM."""
    sbom = SBOM(
        document_id="test-sbom-123",
        document_name="Test Medical Device SBOM",
        document_namespace="https://test.medical.device/sbom/123",
        target_system="Test Medical Device",
        target_version="1.0.0",
        manufacturer="Test Medical Devices Inc",
        model_number="TMD-001",
        fda_submission_id="K230001",
        creators=["fda-sbom-generator-0.1.0"]
    )
    
    # Add component with vulnerability
    component = sample_component
    component.vulnerabilities = [sample_vulnerability]
    sbom.add_component(component)
    
    return sbom


@pytest.fixture
def sample_fda_compliant_sbom():
    """Create an FDA compliant SBOM for testing."""
    sbom = SBOM(
        document_id="fda-compliant-test-123",
        document_name="FDA Compliant Test Device",
        document_namespace="https://medical.device/sbom/fda-test",
        target_system="Cardiac Monitor Pro",
        target_version="2.1.0",
        manufacturer="Acme Medical Devices Inc",
        model_number="CMD-2024",
        fda_submission_id="K240015",
        device_identification="UDI-DI-12345678901234",
        creators=["fda-sbom-generator-0.1.0"]
    )
    
    # Add required components with all FDA metadata
    components = [
        Component(
            name="medical-core-lib",
            version="3.2.1",
            type=ComponentType.LIBRARY,
            package_manager="pip",
            description="Core medical device library",
            package_url="pkg:pypi/medical-core-lib@3.2.1",
            licenses=[License(name="MIT", spdx_id="MIT")],
            supplier="Medical Software Corp"
        ),
        Component(
            name="device-firmware",
            version="1.5.2", 
            type=ComponentType.FIRMWARE,
            description="Device firmware component",
            supplier="Hardware Solutions Inc",
            licenses=[License(name="Proprietary", text="Proprietary license")],
            package_url="pkg:generic/device-firmware@1.5.2"
        ),
        Component(
            name=".NET",
            version="8.0",
            type=ComponentType.FRAMEWORK,
            package_manager="dotnet",
            description=".NET Runtime",
            supplier="Microsoft Corporation",
            licenses=[License(name="MIT", spdx_id="MIT")],
            package_url="pkg:generic/dotnet@8.0"
        )
    ]
    
    for component in components:
        sbom.add_component(component)
    
    return sbom


class TestDataGenerator:
    """Helper class to generate test data."""
    
    @staticmethod
    def create_large_project(base_path: Path, num_dependencies: int = 100):
        """Create a large project for performance testing."""
        project_path = base_path / "large_project"
        project_path.mkdir()
        
        # Generate large requirements.txt
        requirements = []
        for i in range(num_dependencies):
            pkg_name = f"test-package-{i:03d}"
            version = f"1.{i % 10}.{i % 5}"
            requirements.append(f"{pkg_name}=={version}")
        
        (project_path / "requirements.txt").write_text("\\n".join(requirements))
        
        # Create many Python files
        for i in range(20):
            (project_path / f"module_{i:03d}.py").write_text(f"# Module {i}")
        
        return project_path
    
    @staticmethod
    def create_vulnerable_project(base_path: Path):
        """Create a project with known vulnerable dependencies."""
        project_path = base_path / "vulnerable_project"
        project_path.mkdir()
        
        # Use known vulnerable versions for testing
        vulnerable_requirements = """
# Known vulnerable versions for testing
requests==2.6.0
django==1.11.0
flask==0.10.1
pillow==5.0.0
"""
        (project_path / "requirements.txt").write_text(vulnerable_requirements.strip())
        return project_path


@pytest.fixture
def test_data_generator():
    """Provide test data generator."""
    return TestDataGenerator()


@pytest.fixture(scope="session")
def test_config():
    """Test configuration."""
    return {
        "timeout": 30,
        "max_components": 1000,
        "vulnerability_check": True,
        "test_manufacturer": "Test Medical Devices Inc",
        "test_submission_id": "K999999"
    }
