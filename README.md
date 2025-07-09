# FDA SBOM Generator

A comprehensive Python tool for generating Software Bill of Materials (SBOM) compliant with FDA guidelines for medical device cybersecurity.

## Overview

This tool automatically scans software projects and generates comprehensive SBOMs in FDA-compliant formats. It's specifically designed to meet the FDA's cybersecurity guidelines for medical devices, helping manufacturers create the documentation required for regulatory submissions.

## Features

- **FDA Compliant**: Generates SBOMs following FDA cybersecurity guidelines
- **Multiple Formats**: Supports SPDX, CycloneDX, and SWID tag formats
- **Multi-Language Support**: Python, JavaScript/Node.js, Java/Maven, .NET/C#
- **Vulnerability Detection**: Integrates with OSV database for security analysis
- **Web Interface**: User-friendly web UI for interactive SBOM generation
- **Solution Scanning**: Multi-project solution support (.NET solutions, npm workspaces)
- **Compliance Reporting**: Detailed FDA compliance and security reports
- **CI/CD Ready**: Easy integration with existing development pipelines

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Package

```bash
# Clone or download the project
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator

# Install in development mode
pip install -e .

# Or install with UI dependencies
pip install -e ".[ui]"
```

### Common Installation Issues

#### PATH Issues (Windows)
If you see `'fda-sbom' is not recognized`, the scripts weren't added to PATH:

```powershell
# Add to PATH temporarily
$env:PATH += ";C:\Users\{USERNAME}\AppData\Roaming\Python\Python313\Scripts"

# Or run directly
python -m fda_sbom.cli ui
```

#### Missing Dependencies
```bash
# Install core dependencies first
pip install click pydantic requests lxml flask

# Then install the package
pip install -e .
```

## Quick Start

### Web Interface (Recommended)
```bash
# Start the web UI
fda-sbom ui

# Then open: http://localhost:5000
```

### Command Line Interface

```bash
# Generate SBOM for current directory
fda-sbom generate .

# Medical device example
fda-sbom generate ./cardiac-monitor \
  --manufacturer "CardioTech Medical Inc" \
  --target-system "Cardiac Monitor Pro" \
  --device-model "CM-PRO-2024" \
  --fda-submission-id "K240156" \
  --format spdx

# Multi-project solution
fda-sbom solution ./MedicalDeviceSolution \
  --manufacturer "Medical Systems Corp" \
  --solution-name "Patient Management Platform"
```

## Web Interface

The web UI provides an intuitive interface for:

### Dashboard Features
- **Project Scanner**: Upload/browse projects for analysis
- **SBOM Generator**: Interactive forms for FDA metadata
- **Security Analysis**: Vulnerability scanning and risk assessment
- **Validation Tools**: FDA compliance checking
- **Solution Scanner**: Multi-project analysis
- **Reports & Export**: Download SBOMs and compliance reports

### Starting the Web UI

```bash
# Basic startup
fda-sbom ui

# Custom configuration
fda-sbom ui --host 0.0.0.0 --port 8080 --debug

# Alternative if CLI not installed
python -m fda_sbom.cli ui
```

Access at: `http://localhost:5000`

## Supported Project Types

| Technology | Files Detected | Package Manager |
|------------|----------------|------------------|
| **Python** | `requirements.txt`, `pyproject.toml`, `*.py` | pip |
| **Node.js** | `package.json`, `package-lock.json` | npm |
| **Java** | `pom.xml`, `build.gradle` | Maven/Gradle |
| **.NET** | `*.csproj`, `*.sln`, `packages.config` | NuGet |
| **Generic** | `*.dll`, `*.so`, `*.jar`, `*.exe` | File Scanner |

## FDA Compliance Features

### Required Metadata Support
- Manufacturer information
- Device model and version
- FDA submission ID (510(k), PMA, etc.)
- Device classification (Class I, II, III)
- UDI-DI (Unique Device Identification)
- Target framework identification

### Security Compliance
- Vulnerability assessment via OSV database
- Risk scoring for FDA cybersecurity requirements
- Component license tracking
- Dependency relationship mapping

### Export Formats
- **SPDX 2.3** (FDA recommended): `--format spdx`
- **CycloneDX 1.4**: `--format cyclonedx`
- **SWID Tags**: `--format swid`
- **Native JSON**: `--format json`

## Usage Examples

### Medical Device Software
```bash
# For a .NET medical device application
fda-sbom generate ./MedicalDevice.sln \
  --manufacturer "CardioTech Medical Devices Inc" \
  --target-system "Cardiac Monitor Pro" \
  --target-version "3.2.1" \
  --device-model "CM-PRO-2024" \
  --fda-submission-id "K240156" \
  --format spdx \
  --output cardiac-monitor.spdx.json
```

### Python Medical Research Tool
```bash
# For a Python-based medical research application
fda-sbom generate ./research-tool \
  --manufacturer "Medical Research Corp" \
  --target-system "Clinical Data Analyzer" \
  --format spdx \
  --no-vulnerabilities  # Skip for faster generation
```

### Multi-Language Healthcare Platform
```bash
# For a complex solution with multiple technologies
fda-sbom solution ./HealthcarePlatform \
  --manufacturer "Healthcare Systems Inc" \
  --solution-name "Patient Management Platform" \
  --format cyclonedx \
  --output-dir ./compliance-docs \
  --individual-sboms \
  --solution-sbom
```

## CLI Reference

### Core Commands

```bash
# Generate single project SBOM
fda-sbom generate <path> [options]

# Scan multi-project solution
fda-sbom solution <path> [options]

# Quick project analysis
fda-sbom scan <path>

# Validate existing SBOM
fda-sbom validate <sbom-file>

# Security analysis
fda-sbom security <sbom-file>

# System health check
fda-sbom doctor

# Launch web UI
fda-sbom ui [--host HOST] [--port PORT]
```

### Common Options

```bash
--manufacturer          # Device manufacturer (required for FDA)
--target-system         # Target system name
--device-model          # Device model number
--fda-submission-id     # FDA submission identifier
--format               # Output format (spdx, cyclonedx, swid, json)
--output               # Output file path
--no-vulnerabilities   # Skip vulnerability scanning
--verbose              # Enable detailed logging
```

## Python API

```python
from fda_sbom.generator import SBOMGenerator
from fda_sbom.exporters import export_sbom

# Create generator
generator = SBOMGenerator()

# Generate SBOM
sbom = generator.generate_sbom(
    project_path="./medical-device-software",
    target_system="Insulin Pump Controller",
    manufacturer="DiabeTech Medical Inc",
    device_model="DT-PUMP-2024",
    fda_submission_id="K240789",
    include_vulnerabilities=True
)

# Validate FDA compliance
report = generator.validate_sbom(sbom)
print(f"FDA Compliant: {report.fda_compliant}")

# Export in multiple formats
export_sbom(sbom, "device.spdx.json", "spdx")
export_sbom(sbom, "device.cyclonedx.json", "cyclonedx")
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator

# Install in development mode with all dependencies
pip install -e ".[dev,test,ui]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/           # Unit tests
pytest tests/integration/    # Integration tests
pytest tests/compliance/     # FDA compliance tests
pytest -m "not slow"        # Skip slow tests

# With coverage
pytest --cov=fda_sbom --cov-report=html
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Run all quality checks
pre-commit run --all-files
```

## Troubleshooting

### Common Issues

#### 1. Command Not Found
```bash
# Error: 'fda-sbom' is not recognized
# Solution: Add to PATH or run directly
python -m fda_sbom.cli ui
```

#### 2. Pydantic Warnings
```bash
# Warning about model_number field
# Solution: Already fixed in latest version
```

#### 3. Missing Dependencies
```bash
# Error: No module named 'flask'
pip install flask

# Error: No module named 'lxml'  
pip install lxml
```

#### 4. Permission Errors
```bash
# Error: Permission denied
# Solution: Use higher port number
fda-sbom ui --port 8080
```

#### 5. Large Project Scanning
```bash
# Slow scanning for large projects
fda-sbom generate . --no-vulnerabilities
```

### Getting Help

```bash
# System diagnostic
fda-sbom doctor --check-dependencies

# Verbose output for debugging
fda-sbom generate . --verbose

# Help for any command
fda-sbom --help
fda-sbom generate --help
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is to assist with FDA compliance documentation. Users are responsible for ensuring their SBOMs meet all applicable FDA requirements. Please consult with regulatory experts and legal counsel for compliance validation.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/fda-sbom-generator/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/fda-sbom-generator/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/fda-sbom-generator/discussions)

## Roadmap

- Additional package manager support (Rust, Go, Ruby)
- Enhanced vulnerability database integration
- Docker container scanning
- API-based SBOM management
- Advanced compliance templates
- Cloud deployment options

---

**Made with care for medical device cybersecurity compliance**
