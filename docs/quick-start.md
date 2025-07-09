# Quick Start Guide

Get up and running with the FDA SBOM Generator in minutes.

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator

# 2. Install with dependencies
pip install -e ".[ui]"

# 3. Verify installation
fda-sbom --help
```

## Fix Common Setup Issues

### Command Not Found (Windows)
```powershell
# Add to PATH temporarily
$env:PATH += ";C:\Users\{USERNAME}\AppData\Roaming\Python\Python313\Scripts"

# Or run directly
python -m fda_sbom.cli ui
```

### Missing Dependencies
```bash
# Install missing packages
pip install flask lxml requests click pydantic
```

## Start the Web Interface

```bash
# Launch web UI
fda-sbom ui

# Open browser to: http://localhost:5000
```

The web interface provides:
- Interactive dashboard
- FDA-compliant forms
- Project scanning
- SBOM generation
- Compliance validation

## Generate Your First Medical Device SBOM

### Option 1: Web Interface
1. Go to `http://localhost:5000`
2. Click "Generate SBOM"
3. Fill in FDA-required fields:
   - Manufacturer: "Your Medical Device Company"
   - Target System: "Your Device Name"
   - Device Model: "MODEL-2024"
   - FDA Submission ID: "K240001"
4. Select project directory
5. Choose format (SPDX recommended)
6. Click "Generate SBOM"

### Option 2: Command Line
```bash
# Navigate to your project
cd /path/to/your/medical-device-software

# Generate FDA-compliant SBOM
fda-sbom generate . \
  --manufacturer "CardioTech Medical Inc" \
  --target-system "Cardiac Monitor Pro" \
  --device-model "CM-PRO-2024" \
  --fda-submission-id "K240156" \
  --format spdx \
  --output cardiac-monitor.spdx.json
```

## Supported Project Types

The tool automatically detects:

| Technology | Files Detected |
|------------|----------------|
| **Python** | `requirements.txt`, `pyproject.toml` |
| **Node.js** | `package.json`, `yarn.lock` |
| **Java** | `pom.xml`, `build.gradle` |
| **.NET** | `*.csproj`, `*.sln` |
| **Generic** | `*.dll`, `*.so`, `*.jar` |

## Quick Project Analysis

```bash
# See what the tool detects in your project
fda-sbom scan .

# Example output:
# Project Analysis
# ================
# Project: ./my-medical-device
# Scanners detected: 2
#   - PythonScanner
#   - FileScanner
# 
# Components found: 15
#   pip: 12 components
#   unknown: 3 components
```

## Common Commands

```bash
# Quick scan without generating SBOM
fda-sbom scan .

# Generate basic SBOM
fda-sbom generate .

# Generate with vulnerability checking
fda-sbom generate . --format spdx

# Skip vulnerabilities for speed
fda-sbom generate . --no-vulnerabilities

# Multi-project solution
fda-sbom solution . --manufacturer "Your Company"

# Validate existing SBOM
fda-sbom validate my-sbom.spdx.json

# System health check
fda-sbom doctor

# Start web interface
fda-sbom ui
```

## Understanding Output

### SBOM Components
Each detected component includes:
- Name and version
- Package manager (pip, npm, maven, nuget)
- License information
- Package URL (PURL)
- Vulnerability data (if enabled)

### FDA Compliance Fields
Required for medical devices:
- Manufacturer information
- Device model and version
- FDA submission ID
- Target system identification
- Creation timestamp
- Creator information

## Multi-Project Solutions

For complex solutions with multiple projects:

```bash
# Scan entire solution
fda-sbom solution ./MedicalDeviceSolution \
  --manufacturer "Healthcare Systems Inc" \
  --solution-name "Patient Management Platform" \
  --individual-sboms \
  --solution-sbom

# Generates:
# - Individual SBOMs for each project
# - Consolidated solution SBOM
# - Comprehensive report
```

## Security Features

```bash
# Include vulnerability scanning
fda-sbom generate . --format spdx

# Generate security report
fda-sbom security my-sbom.spdx.json

# The tool automatically:
# - Scans OSV database for vulnerabilities
# - Provides CVSS scores
# - Generates risk assessments
# - Offers remediation recommendations
```

## Output Formats

### SPDX (FDA Recommended)
```bash
fda-sbom generate . --format spdx --output device.spdx.json
```
- Industry standard
- FDA preferred format
- Complete metadata support

### CycloneDX
```bash
fda-sbom generate . --format cyclonedx --output device.cyclonedx.json
```
- Rich vulnerability data
- Modern JSON schema
- Excellent tool support

### SWID Tags
```bash
fda-sbom generate . --format swid --output device.swid.xml
```
- XML-based format
- Device identification focused
- ISO/IEC 19770-2 compliant

## Best Practices

### 1. Project Structure
```
medical-device-project/
├── requirements.txt     # Keep updated
├── src/                # Source code
├── docs/              # Documentation
└── tests/             # Test files
```

### 2. Regular Generation
```bash
# Add to your CI/CD pipeline
- name: Generate SBOM
  run: |
    fda-sbom generate . \
      --manufacturer "${{ env.MANUFACTURER }}" \
      --format spdx \
      --output sbom.spdx.json
```

### 3. Validation
```bash
# Always validate generated SBOMs
fda-sbom validate sbom.spdx.json

# Check FDA compliance
fda-sbom generate . | grep "FDA Compliant: True"
```

## Troubleshooting

### Quick Fixes

```bash
# Command not found
python -m fda_sbom.cli ui

# Check system status
fda-sbom doctor --check-dependencies

# Permission issues
fda-sbom ui --port 8080

# No components found
fda-sbom scan . --verbose
```

### Common Issues

1. **PATH not set**: Add scripts directory to PATH
2. **Missing Flask**: `pip install flask`
3. **Port in use**: Use `--port 8080`
4. **No dependencies found**: Check file formats and permissions

## Next Steps

- Read the [User Guide](user-guide.md)
- Review [FDA Compliance Guide](fda-compliance.md)
- Explore [CLI Reference](cli-reference.md)
- Learn [Web Interface](web-ui-guide.md)
- Check [Troubleshooting](troubleshooting.md)

## Pro Tips

```bash
# Use aliases for common commands
echo 'alias fda-scan="fda-sbom scan"' >> ~/.bashrc
echo 'alias fda-gen="fda-sbom generate"' >> ~/.bashrc

# Create project templates
mkdir medical-device-template
cd medical-device-template
echo "requests>=2.28.0" > requirements.txt
echo "# Medical Device Software" > README.md

# Batch processing
for dir in project1 project2 project3; do
  fda-sbom generate $dir --format spdx --output ${dir}.spdx.json
done
```

## You're Ready!

You now have everything needed to generate FDA-compliant SBOMs for your medical device software. Start with the web interface for ease of use, then move to CLI for automation.

Happy SBOM generating!
