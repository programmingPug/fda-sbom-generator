# Multi-Project Solution Scanning Examples

## **Now Fully Supports Multi-Project Solutions!**

The FDA SBOM Generator can now handle complex solutions with multiple projects:

### **Quick Start - Solution Scanning**

```bash
# Scan entire solution with individual SBOMs for each project
fda-sbom solution ./my-solution --manufacturer "MedDevice Corp"

# Generate both individual and consolidated SBOMs
fda-sbom solution ./my-solution \
  --manufacturer "MedDevice Corp" \
  --solution-name "MyDeviceSoftware" \
  --individual-sboms \
  --solution-sbom \
  --format spdx

# Just generate consolidated solution SBOM
fda-sbom solution ./my-solution \
  --manufacturer "MedDevice Corp" \
  --solution-sbom
```

### **Supported Solution Types**

#### **.NET Solutions**
```
MyMedicalDevice/
├── MyDevice.sln
├── DeviceAPI/
│   ├── DeviceAPI.csproj
│   └── packages.config
├── DeviceUI/
│   ├── DeviceUI.csproj
│   └── package.json
└── DeviceCore/
    └── DeviceCore.csproj
```

#### **npm Workspaces**
```
medical-device-software/
├── package.json (with workspaces)
├── packages/
│   ├── device-api/
│   │   └── package.json
│   ├── device-ui/
│   │   └── package.json
│   └── shared-utils/
│       └── package.json
```

#### **Maven Multi-Module**
```
medical-device/
├── pom.xml (parent)
├── device-core/
│   └── pom.xml
├── device-api/
│   └── pom.xml
└── device-ui/
    └── pom.xml
```

#### **Mixed Technology Solutions**
```
medical-device-platform/
├── backend/          # Python API
│   ├── requirements.txt
│   └── pyproject.toml
├── frontend/         # React UI
│   └── package.json
├── embedded/         # C++ firmware
│   └── CMakeLists.txt
└── mobile/          # Android app
    └── build.gradle
```

### **What You Get**

#### **Individual Project SBOMs**
- `backend.spdx.json` - Python API dependencies
- `frontend.spdx.json` - React UI dependencies  
- `embedded.spdx.json` - C++ firmware components
- `mobile.spdx.json` - Android app dependencies

#### **Consolidated Solution SBOM**
- `MyDeviceSoftware-solution.spdx.json` - All components merged
- Cross-project dependency relationships
- Solution-level FDA compliance metadata

#### **Solution Analysis Report**
```json
{
  "solution_name": "MyDeviceSoftware",
  "total_projects": 4,
  "total_components": 247,
  "projects": {
    "backend": {
      "component_count": 45,
      "vulnerability_count": 2,
      "vulnerability_breakdown": {"high": 1, "medium": 1},
      "package_managers": ["pip"]
    },
    "frontend": {
      "component_count": 180,
      "vulnerability_count": 5,
      "vulnerability_breakdown": {"medium": 3, "low": 2},
      "package_managers": ["npm"]
    }
  },
  "solution_summary": {
    "total_vulnerabilities": 7,
    "risk_assessment": "MEDIUM"
  }
}
```

### **FDA Compliance Benefits**

#### **Complete Visibility**
- Every component across all projects
- Cross-project dependency tracking
- Consolidated vulnerability assessment

#### **Regulatory Documentation**
- Solution-level SBOM for FDA submission
- Project-specific SBOMs for detailed analysis
- Comprehensive security risk assessment

#### **Workflow Integration**
```bash
# In your CI/CD pipeline
fda-sbom solution . \
  --manufacturer "$COMPANY_NAME" \
  --solution-name "$DEVICE_NAME" \
  --solution-sbom \
  --output-dir ./regulatory-docs/sboms/
```

### **Advanced Usage**

#### **Python API Integration**
```python
from fda_sbom import SolutionScanner

scanner = SolutionScanner()

# Scan entire solution
project_sboms = scanner.scan_solution(
    solution_path="./my-solution",
    manufacturer="MedDevice Corp",
    include_vulnerabilities=True
)

# Create consolidated SBOM
solution_sbom = scanner.create_solution_sbom(
    project_sboms, 
    "MyDeviceSoftware",
    "MedDevice Corp"
)

# Export solution report
scanner.export_solution_report(
    project_sboms, 
    solution_sbom, 
    "./solution-report.json"
)
```

#### **Custom Project Detection**
The solution scanner automatically detects:
- **File-based indicators**: package.json, requirements.txt, pom.xml, *.csproj
- **Solution files**: *.sln, workspace configurations
- **Multi-level project structures** (up to 3 levels deep)
- **Mixed technology stacks**

### **Real-World Example Output**

```bash
$ fda-sbom solution ./medical-device-platform --manufacturer "Acme Medical" --solution-sbom -v

[INFO] Found 4 projects in solution
[INFO] Scanning project 1/4: backend
[INFO] Scanning project 2/4: frontend  
[INFO] Scanning project 3/4: embedded
[INFO] Scanning project 4/4: mobile
[INFO] Scanning vulnerabilities...

Found 4 projects
Generated solution SBOM: ./medical-device-platform/sboms/medical-device-platform-solution.spdx.json
Generated solution report: ./medical-device-platform/sboms/medical-device-platform-report.json

Solution Summary:
  Projects: 4
  Total Components: 247
  Total Vulnerabilities: 7
  backend: 45 components
  frontend: 180 components
  embedded: 12 components
  mobile: 10 components
```

### **Ready for FDA Submission**

The generated solution SBOM includes all FDA-required metadata:
- **Document identification** with unique IDs
- **Manufacturer information** 
- **Complete component inventory** across all projects
- **Vulnerability assessments** with risk scoring
- **Cross-project relationships** and dependencies
- **Compliance validation** reports

This comprehensive multi-project support makes the tool suitable for complex medical device software platforms that span multiple technologies and teams.
