# Installation Guide

This guide covers detailed installation instructions for the FDA SBOM Generator, including troubleshooting common issues.

## System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, or Linux
- **Memory**: 512MB RAM minimum (2GB recommended for large projects)
- **Disk Space**: 100MB for installation, additional space for generated SBOMs

## Installation Methods

### Method 1: Development Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator

# 2. Install in editable mode with all dependencies
pip install -e ".[ui,dev,test]"

# 3. Verify installation
fda-sbom --help
```

### Method 2: Quick Installation

```bash
# Install with minimal dependencies
pip install -e .

# Add UI support later
pip install flask
```

### Method 3: Manual Dependency Installation

```bash
# Install core dependencies first
pip install click pydantic requests lxml

# Install UI dependencies
pip install flask

# Install development dependencies (optional)
pip install pytest black flake8 mypy

# Then install the package
pip install -e .
```

## Platform-Specific Instructions

### Windows

#### PowerShell (Recommended)
```powershell
# 1. Check Python version
python --version  # Should be 3.8+

# 2. Clone and install
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator
pip install -e ".[ui]"

# 3. Fix PATH if needed (common issue)
$env:PATH += ";$env:APPDATA\Python\Python313\Scripts"
```

#### Command Prompt
```cmd
REM Check Python
python --version

REM Install
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator
pip install -e .[ui]
```

### macOS

```bash
# Install with Homebrew Python (recommended)
brew install python@3.11

# Clone and install
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator
pip3 install -e ".[ui]"

# Verify
fda-sbom --help
```

### Linux (Ubuntu/Debian)

```bash
# Install Python and pip
sudo apt update
sudo apt install python3 python3-pip git

# Clone and install
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator
pip3 install -e ".[ui]"

# Add to PATH if needed
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## Troubleshooting Common Issues

### Issue 1: Command Not Found

**Problem**: `'fda-sbom' is not recognized as a command`

**Cause**: Script directory not in PATH

**Solutions**:

#### Windows
```powershell
# Temporary fix (current session only)
$env:PATH += ";C:\Users\{YOUR_USERNAME}\AppData\Roaming\Python\Python313\Scripts"

# Permanent fix via System Properties
# 1. Win + R → sysdm.cpl → Environment Variables
# 2. Add: C:\Users\{USERNAME}\AppData\Roaming\Python\Python313\Scripts

# Alternative: Run directly
python -m fda_sbom.cli ui
```

#### macOS/Linux
```bash
# Add to shell profile
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Or run directly
python3 -m fda_sbom.cli ui
```

### Issue 2: Pydantic Warnings

**Problem**: `Field "model_number" in SBOM has conflict with protected namespace`

**Cause**: Pydantic v2 namespace protection

**Solution**: Already fixed in the current version. Update your code if using an older version.

### Issue 3: Import Errors

**Problem**: `ModuleNotFoundError: No module named 'flask'`

**Solutions**:
```bash
# Install missing dependencies
pip install flask lxml requests click pydantic

# Or reinstall with all dependencies
pip install -e ".[ui,dev]"
```

### Issue 4: Syntax Errors

**Problem**: `SyntaxError: expected 'except' or 'finally' block`

**Cause**: Corrupted or incomplete installation

**Solution**:
```bash
# Reinstall from scratch
pip uninstall fda-sbom-generator
cd fda-sbom-generator
pip install -e .
```

### Issue 5: Permission Errors

**Problem**: `Permission denied` or `Access is denied`

**Solutions**:

#### Windows
```powershell
# Run as Administrator or use user install
pip install --user -e .

# Use different port for UI
fda-sbom ui --port 8080
```

#### macOS/Linux
```bash
# Use user install
pip3 install --user -e .

# Or use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Issue 6: Slow Performance

**Problem**: Long scanning times for large projects

**Solutions**:
```bash
# Skip vulnerability scanning for speed
fda-sbom generate . --no-vulnerabilities

# Use verbose mode to see progress
fda-sbom generate . --verbose

# Scan specific directories only
fda-sbom generate ./src --no-vulnerabilities
```

## Verification Steps

After installation, verify everything works:

```bash
# 1. Check CLI installation
fda-sbom --help

# 2. Check system setup
fda-sbom doctor --check-dependencies

# 3. Test basic scanning
fda-sbom scan .

# 4. Test web UI
fda-sbom ui
# Should show: "Running at: http://127.0.0.1:5000"

# 5. Test SBOM generation
fda-sbom generate . --no-vulnerabilities --format json
```

## Virtual Environment Setup (Recommended)

For isolated installations:

```bash
# Create virtual environment
python -m venv fda-sbom-env

# Activate (Windows)
fda-sbom-env\Scripts\activate

# Activate (macOS/Linux)  
source fda-sbom-env/bin/activate

# Install in virtual environment
pip install -e ".[ui]"

# Deactivate when done
deactivate
```

## Docker Installation (Alternative)

If you prefer containerized deployment:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install -e ".[ui]"

EXPOSE 5000
CMD ["fda-sbom", "ui", "--host", "0.0.0.0", "--port", "5000"]
```

```bash
# Build and run
docker build -t fda-sbom-generator .
docker run -p 5000:5000 fda-sbom-generator
```

## Development Setup

For contributors and developers:

```bash
# 1. Clone with development branch
git clone -b develop https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator

# 2. Install with all development dependencies
pip install -e ".[dev,test,ui]"

# 3. Install pre-commit hooks
pre-commit install

# 4. Run tests to verify setup
pytest tests/

# 5. Run quality checks
black src/ tests/
flake8 src/ tests/
mypy src/
```

## Uninstallation

To completely remove the FDA SBOM Generator:

```bash
# Uninstall package
pip uninstall fda-sbom-generator

# Remove from PATH (if manually added)
# Windows: Remove from Environment Variables
# macOS/Linux: Remove from ~/.bashrc or ~/.zshrc

# Remove cloned directory
rm -rf fda-sbom-generator
```

## Getting Help

If you encounter issues not covered here:

1. **Check system status**: `fda-sbom doctor --check-dependencies`
2. **Run with verbose output**: `fda-sbom generate . --verbose`
3. **Check GitHub Issues**: [Report new issues](https://github.com/yourusername/fda-sbom-generator/issues)
4. **Review logs**: Enable debug mode for detailed error messages

## Next Steps

After successful installation:

1. Read the [User Guide](docs/user-guide.md)
2. Review [FDA Compliance Guide](docs/fda-compliance.md)
3. Try the [Web Interface Tutorial](docs/web-ui-guide.md)
4. Explore [CLI Reference](docs/cli-reference.md)
