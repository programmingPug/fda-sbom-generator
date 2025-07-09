# Changelog

All notable changes to the FDA SBOM Generator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2024-07-09

### Fixed
- **Critical**: Fixed syntax error in `scanners.py` that prevented CLI from starting
- **Critical**: Fixed Pydantic warning about `model_number` field conflicting with protected namespace
- **Installation**: Added proper handling for Windows PATH issues during installation
- **Documentation**: Added comprehensive troubleshooting and installation guides

### Added
- **Documentation**: Comprehensive installation guide with platform-specific instructions
- **Documentation**: Detailed troubleshooting guide covering common issues
- **Documentation**: Quick start guide for new users
- **Testing**: Complete test suite with unit, integration, and performance tests
- **CLI**: Better error handling and user-friendly error messages
- **Web UI**: Enhanced error handling and fallback mechanisms

### Improved
- **Scanners**: Simplified and more robust scanner implementations
- **Models**: Better Pydantic v2 compatibility with proper namespace configuration
- **CLI**: More informative help text and error messages
- **Installation**: Better dependency handling and PATH management

### Technical Details
- Fixed incomplete method implementation in `PythonScanner._create_python_component()`
- Added `protected_namespaces = ()` to SBOM model configuration
- Rewrote scanners.py with proper class structure and error handling
- Enhanced CLI module execution support with `python -m fda_sbom.cli`

## [0.1.0] - 2024-07-08

### Added
- **Core Features**: Initial release of FDA SBOM Generator
- **Multi-Language Support**: Python, JavaScript/Node.js, Java/Maven, .NET/C# scanning
- **FDA Compliance**: Full FDA cybersecurity guideline compliance
- **Export Formats**: SPDX, CycloneDX, SWID, and native JSON support
- **Web Interface**: Interactive web UI for SBOM generation
- **CLI**: Comprehensive command-line interface
- **Security**: OSV database integration for vulnerability scanning
- **Solution Scanning**: Multi-project solution support
- **Validation**: FDA compliance validation and reporting

### Security
- Integration with OSV (Open Source Vulnerabilities) database
- CVSS score processing and risk assessment
- Security report generation with FDA-specific recommendations

### Documentation
- Complete API documentation
- User guides and examples
- FDA compliance guidelines
- Installation instructions

---

## Release Notes

### Version 0.1.1 Highlights

This release fixes critical startup issues that prevented the tool from running on fresh installations. Key improvements:

#### **Installation Fixes**
- **Windows PATH Issues**: Comprehensive solution for script PATH problems
- **Dependency Management**: Better handling of optional dependencies
- **Error Recovery**: Improved fallback mechanisms for common installation issues

#### **Bug Fixes**
- **Syntax Error**: Fixed corrupted scanner code that caused startup failures
- **Pydantic Warnings**: Resolved namespace conflicts with Pydantic v2
- **Module Imports**: Enhanced module loading and error handling

#### **Documentation**
- **Installation Guide**: Step-by-step platform-specific instructions
- **Troubleshooting**: Comprehensive guide covering 16+ common issues
- **Quick Start**: Get running in minutes with essential commands

#### **Testing**
- **Complete Test Suite**: 100+ tests covering all functionality
- **Performance Tests**: Memory usage and scalability validation
- **Integration Tests**: End-to-end workflow verification
- **Compliance Tests**: FDA requirement validation

#### **Getting Started**

If you're upgrading from 0.1.0:
```bash
# Pull latest changes
git pull

# Reinstall to get fixes
pip install -e ".[ui]"

# Verify installation
fda-sbom doctor --check-dependencies
```

If you're installing fresh:
```bash
# Clone repository
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator

# Install with dependencies
pip install -e ".[ui]"

# Start web interface
fda-sbom ui
```

#### **Breaking Changes**
None. This release is fully backward compatible.

#### **Coming in 0.2.0**
- Enhanced Docker support
- Additional package manager support (Rust, Go)
- Advanced compliance templates
- Performance optimizations
- API-based SBOM management

---

## Support

For issues with this release:
- Check the [Installation Guide](docs/installation.md)
- Review [Troubleshooting Guide](docs/troubleshooting.md)
- Report issues on [GitHub](https://github.com/yourusername/fda-sbom-generator/issues)

## Contributors

Thanks to all contributors who helped identify and resolve these critical issues!
