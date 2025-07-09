# Troubleshooting Guide

This guide covers common issues and their solutions when using the FDA SBOM Generator.

## Quick Diagnosis

Before diving into specific issues, run the system diagnostic:

```bash
fda-sbom doctor --check-dependencies
```

This will check:
- Python version compatibility
- Required dependencies installation
- Available scanners
- System configuration

## Installation Issues

### 1. Command Not Found

**Symptoms**:
```
'fda-sbom' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

**Root Cause**: The scripts directory is not in your system PATH.

**Solutions**:

#### Quick Fix (Temporary)
```powershell
# Windows PowerShell
$env:PATH += ";C:\Users\{USERNAME}\AppData\Roaming\Python\Python313\Scripts"

# Run command
fda-sbom ui
```

#### Permanent Fix (Windows)
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Click "Environment Variables..."
3. Under "User variables", find "Path", click "Edit..."
4. Click "New" and add: `C:\Users\{USERNAME}\AppData\Roaming\Python\Python313\Scripts`
5. Click "OK" on all dialogs
6. Restart PowerShell

#### Alternative: Run Directly
```bash
# Use Python module execution
python -m fda_sbom.cli ui
python -m fda_sbom.cli generate .
```

### 2. Pydantic Warnings

**Symptoms**:
```
UserWarning: Field "model_number" in SBOM has conflict with protected namespace "model_".
```

**Root Cause**: Pydantic v2 protects the "model_" namespace by default.

**Solution**: Already fixed in the current version. The warning can be safely ignored, or update to the latest code which includes the fix.

### 3. Syntax Errors in Scanners

**Symptoms**:
```
SyntaxError: expected 'except' or 'finally' block
```

**Root Cause**: Incomplete or corrupted code in scanners.py file.

**Solution**: The scanners.py file has been rewritten. Update your copy or reinstall:
```bash
pip uninstall fda-sbom-generator
git pull  # Get latest code
pip install -e .
```

### 4. Missing Dependencies

**Symptoms**:
```
ModuleNotFoundError: No module named 'flask'
ImportError: No module named 'lxml'
```

**Solutions**:
```bash
# Install missing core dependencies
pip install click pydantic requests lxml

# Install UI dependencies
pip install flask

# Install all dependencies at once
pip install -e ".[ui,dev]"
```

## Runtime Issues

### 5. Web UI Won't Start

**Symptoms**:
```
Error starting web UI: [Errno 10048] Only one usage of each socket address
```

**Cause**: Port 5000 is already in use.

**Solutions**:
```bash
# Use different port
fda-sbom ui --port 8080

# Check what's using port 5000 (Windows)
netstat -ano | findstr :5000

# Kill process using port (Windows)
taskkill /PID {PID_NUMBER} /F
```

### 6. Permission Denied Errors

**Symptoms**:
```
PermissionError: [Errno 13] Permission denied
```

**Causes & Solutions**:

#### File Access
```bash
# Ensure read permissions on project directory
chmod -R 755 /path/to/project  # Linux/macOS
```

#### Port Binding (Linux/macOS)
```bash
# Use port > 1024 or run with sudo
fda-sbom ui --port 8080

# Or with elevated privileges
sudo fda-sbom ui  # Not recommended
```

#### Windows UAC
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
```

### 7. Slow Performance

**Symptoms**: SBOM generation takes a very long time.

**Causes & Solutions**:

#### Large Project with Many Dependencies
```bash
# Skip vulnerability scanning for speed
fda-sbom generate . --no-vulnerabilities

# Use verbose mode to see progress
fda-sbom generate . --verbose

# Scan specific subdirectories
fda-sbom generate ./src
```

#### Network Issues (Vulnerability Scanning)
```bash
# Skip network-dependent operations
fda-sbom generate . --no-vulnerabilities

# Check network connectivity
ping api.osv.dev
```

### 8. Memory Issues

**Symptoms**: Process killed or out of memory errors.

**Solutions**:
```bash
# Scan smaller directories
fda-sbom generate ./src --no-vulnerabilities

# Use file-based scanning only
fda-sbom scan . 

# Increase system virtual memory (Windows)
# Control Panel → System → Advanced → Performance Settings → Virtual Memory
```

## Scanning Issues

### 9. No Components Found

**Symptoms**: "Components found: 0" for projects that should have dependencies.

**Diagnosis**:
```bash
# Check what scanners are detected
fda-sbom scan .

# Use verbose mode
fda-sbom generate . --verbose
```

**Solutions**:

#### Missing Project Files
```bash
# Ensure these files exist in your project:
# Python: requirements.txt, pyproject.toml
# Node.js: package.json
# Java: pom.xml, build.gradle
# .NET: *.csproj, *.sln
```

#### Wrong Directory
```bash
# Make sure you're in the right directory
cd /path/to/your/project
fda-sbom scan .
```

#### File Permissions
```bash
# Ensure files are readable
ls -la requirements.txt  # Should show read permissions
```

### 10. Incomplete Dependency Detection

**Symptoms**: Some known dependencies not appearing in SBOM.

**Causes & Solutions**:

#### Requirements Format Issues
```bash
# Check requirements.txt format
cat requirements.txt

# Ensure proper format:
# package-name==1.0.0
# another-package>=2.0.0
```

#### Parsing Errors
```bash
# Check for parsing warnings
fda-sbom generate . --verbose

# Look for lines like:
# Warning: Could not parse requirements.txt: ...
```

### 11. Vulnerability Scanning Failures

**Symptoms**: Vulnerabilities not detected or scanning errors.

**Diagnosis**:
```bash
# Test network connectivity
curl -s https://api.osv.dev/v1/query

# Check with verbose mode
fda-sbom generate . --verbose
```

**Solutions**:

#### Network Connectivity
```bash
# Skip vulnerability scanning if network issues
fda-sbom generate . --no-vulnerabilities

# Configure proxy if needed (set environment variables)
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

#### API Rate Limiting
```bash
# Reduce concurrent requests by scanning smaller projects
fda-sbom generate ./single-project --vulnerabilities
```

## Output Issues

### 12. Export Format Errors

**Symptoms**: "Error exporting SBOM" or malformed output files.

**Solutions**:
```bash
# Try different output format
fda-sbom generate . --format json  # Simpler format

# Check output directory permissions
ls -la /output/directory/

# Use absolute paths
fda-sbom generate . --output /full/path/to/output.spdx.json
```

### 13. Large SBOM Files

**Symptoms**: Generated SBOMs are unexpectedly large.

**Analysis**:
```bash
# Check component count
fda-sbom scan .

# Remove unnecessary components
fda-sbom generate ./src --no-vulnerabilities
```

**Solutions**:
```bash
# Exclude certain directories
fda-sbom generate . --exclude node_modules --exclude .git

# Use minimal scanning
fda-sbom generate . --format json --no-vulnerabilities
```

## Environment-Specific Issues

### 14. Corporate Network/Proxy

**Symptoms**: Network timeouts or connection errors.

**Solutions**:
```bash
# Configure proxy settings
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Skip external network calls
fda-sbom generate . --no-vulnerabilities --no-update-licenses
```

### 15. Docker/Container Issues

**Symptoms**: Permission or filesystem issues in containers.

**Solutions**:
```dockerfile
# Dockerfile additions
USER root
RUN chmod -R 755 /app
USER nonroot

# Or run container with proper permissions
docker run -u $(id -u):$(id -g) -v $(pwd):/app fda-sbom-generator
```

### 16. CI/CD Pipeline Issues

**Symptoms**: Failures in automated environments.

**Solutions**:
```yaml
# GitHub Actions example
- name: Install FDA SBOM Generator
  run: |
    pip install -e .
    fda-sbom doctor --check-dependencies

- name: Generate SBOM
  run: |
    fda-sbom generate . \
      --no-vulnerabilities \
      --format spdx \
      --output sbom.spdx.json
```

## Getting Help

### Diagnostic Information

When reporting issues, include:

```bash
# System information
fda-sbom doctor --check-dependencies

# Python environment
python --version
pip list | grep -E "(fda-sbom|click|pydantic|flask)"

# Project structure (if relevant)
find . -name "*.py" -o -name "requirements.txt" -o -name "package.json" | head -20

# Error output with verbose mode
fda-sbom generate . --verbose 2>&1 | tee debug.log
```

### Debug Mode

For detailed debugging:

```bash
# Enable maximum verbosity
fda-sbom generate . --verbose

# Use Python debugging
python -m pdb -m fda_sbom.cli generate .

# Check system setup thoroughly
fda-sbom doctor --check-dependencies
```

### Reporting Issues

When creating GitHub issues, please include:

1. **System Information**: OS, Python version, installation method
2. **Error Messages**: Complete error output with stack traces
3. **Reproduction Steps**: Exact commands that cause the issue
4. **Project Type**: What kind of project you're scanning
5. **Environment**: Corporate network, proxy, Docker, etc.

### Community Support

- **GitHub Issues**: [Report bugs](https://github.com/yourusername/fda-sbom-generator/issues)
- **Discussions**: [Ask questions](https://github.com/yourusername/fda-sbom-generator/discussions)
- **Wiki**: [Browse documentation](https://github.com/yourusername/fda-sbom-generator/wiki)

## Prevention Tips

To avoid common issues:

### 1. Environment Setup
```bash
# Use virtual environments for isolation
python -m venv fda-sbom-env
source fda-sbom-env/bin/activate  # Linux/macOS
fda-sbom-env\Scripts\activate     # Windows

# Install with all dependencies
pip install -e ".[ui,dev]"
```

### 2. Regular Updates
```bash
# Keep dependencies updated
pip install --upgrade pip setuptools wheel

# Update the tool
git pull
pip install -e ".[ui]"
```

### 3. Project Organization
```bash
# Ensure proper project structure
project/
├── requirements.txt    # Python dependencies
├── package.json       # Node.js dependencies  
├── pom.xml           # Maven dependencies
├── *.csproj          # .NET dependencies
└── src/              # Source code
```

### 4. Dependency Management
```bash
# Keep dependency files updated
pip freeze > requirements.txt

# Use specific versions when possible
# Good: requests==2.28.0
# Avoid: requests
```

### 5. Testing Before Production
```bash
# Test with small projects first
fda-sbom generate ./test-project --no-vulnerabilities

# Validate output
fda-sbom validate output.spdx.json
```

### 6. Documentation
```bash
# Keep notes on your specific configuration
echo "# FDA SBOM Generator Notes" > SBOM_NOTES.md
echo "Last successful run: $(date)" >> SBOM_NOTES.md
echo "Command used: fda-sbom generate . --format spdx" >> SBOM_NOTES.md
```

## Emergency Recovery

If everything breaks:

### Complete Reset
```bash
# 1. Uninstall completely
pip uninstall fda-sbom-generator

# 2. Clean Python cache
python -c "import site; print(site.getsitepackages())" 
# Remove any fda_sbom directories found

# 3. Fresh install
git clone https://github.com/yourusername/fda-sbom-generator.git
cd fda-sbom-generator
pip install -e ".[ui]"

# 4. Verify
fda-sbom doctor --check-dependencies
```

### Fallback Methods
```bash
# If CLI doesn't work, use Python directly
python -c "
from fda_sbom.generator import SBOMGenerator
gen = SBOMGenerator()
sbom = gen.generate_sbom('.', manufacturer='Test Inc')
print(f'Found {len(sbom.components)} components')
"

# Manual component scanning
python -c "
from fda_sbom.scanners import ScannerRegistry
from pathlib import Path
registry = ScannerRegistry()
scanners = registry.get_applicable_scanners(Path('.'))
print(f'Available scanners: {[s.__class__.__name__ for s in scanners]}')
"
```

This troubleshooting guide should help resolve most issues you'll encounter with the FDA SBOM Generator. Remember to always start with the diagnostic command and work through the most common issues first.
