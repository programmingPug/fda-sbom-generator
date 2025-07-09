# Optional Web UI for FDA SBOM Generator

## **Simple, Optional Web Interface Added!**

The FDA SBOM Generator now includes an **optional web UI** that acts as a user-friendly passthrough to the command-line interface.

### **Two Ways to Use the Tool**

#### **Option 1: Command Line (Existing)**
```bash
# Traditional CLI usage
fda-sbom generate ./my-project --manufacturer "MedDevice Corp"
fda-sbom solution ./my-solution --solution-sbom
fda-sbom validate my-sbom.spdx.json
```

#### **Option 2: Web UI (New)**
```bash
# Start the web interface
fda-sbom ui

# Or directly:
fda-sbom-ui

# Then open: http://localhost:5000
```

### **Getting Started with the UI**

#### **Installation**
```bash
# Install with UI dependencies
pip install -e .[ui]

# Or install Flask separately
pip install flask

# Start the web UI
fda-sbom ui
```

#### **What You Get**
- **Clean, Bootstrap-based interface**
- **All CLI functionality** available through forms
- **Real-time command output** display
- **No data storage** - pure passthrough to CLI
- **Easy project scanning** and SBOM generation
- **Multi-project solution support**

### **UI Features**

#### **Home Page**
- Feature overview and quick start options
- Technology support showcase
- Direct links to main functions

#### **Generate SBOM**
- Form-based SBOM generation
- All CLI options available:
  - Project path selection
  - Manufacturer information (FDA required)
  - Target system and version
  - Output format selection (SPDX, CycloneDX, SWID, JSON)
  - Vulnerability scanning toggle
  - License update options

#### **Solution SBOM**
- Multi-project solution scanning
- Individual vs consolidated SBOM options
- Output directory configuration
- Solution-level metadata

#### **Quick Scan**
- Preview components without generating SBOM
- Fast project analysis
- Scanner detection display

#### **Validate SBOM**
- Upload existing SBOM files
- FDA compliance checking
- Format validation

#### **System Check**
- Dependency verification
- Installation health check
- Scanner availability status

### **Technical Architecture**

#### **Pure Passthrough Design**
```python
# UI simply calls CLI commands
def generate_sbom(form_data):
    cmd = ['fda-sbom', 'generate', form_data['project_path']]
    if form_data.get('manufacturer'):
        cmd.extend(['--manufacturer', form_data['manufacturer']])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result
```

#### **No Data Storage**
- **No database** required
- **No user accounts** or sessions
- **No file uploads** - works with local paths
- **Stateless** - each request is independent

#### **Simple Flask App**
- Lightweight Flask web server
- Bootstrap 5 for responsive design
- Font Awesome icons
- No JavaScript frameworks needed

### **Perfect for Different Users**

#### **Developers**
- Prefer CLI for automation and CI/CD
- Can script and integrate easily
- Fast command-line workflow

#### **QA/Regulatory Teams**
- Prefer visual interface for occasional use
- Form-based input prevents syntax errors
- Clear output display and results

#### **Management/Demos**
- Visual interface for demonstrations
- Easy to show FDA compliance features
- Professional presentation

### **Example UI Workflow**

1. **Start the UI**
   ```bash
   fda-sbom ui --port 8080
   ```

2. **Open Browser**
   - Navigate to `http://localhost:8080`
   - See welcome page with feature overview

3. **Generate SBOM**
   - Click "Generate SBOM"
   - Fill in form:
     - Project Path: `./my-medical-device`
     - Manufacturer: `Acme Medical Devices Inc`
     - Target System: `Cardiac Monitor`
     - Format: `SPDX`
   - Click "Generate SBOM"

4. **View Results**
   - See command executed: `fda-sbom generate ./my-medical-device --manufacturer "Acme Medical Devices Inc" --target-system "Cardiac Monitor" --format spdx`
   - View real-time output
   - See success/error status

### **Security Considerations**

#### **Local Use Only**
- Default binding to `127.0.0.1` (localhost only)
- No external network access by default
- No authentication needed for local use

#### **Production Deployment**
```bash
# For team use (with caution)
fda-sbom ui --host 0.0.0.0 --port 5000

# Consider reverse proxy with authentication for team access
```

### **Screenshots Overview**

#### **Home Page**
- Clean, professional design
- FDA branding and medical device focus
- Quick start options
- Feature highlights

#### **Generate Form**
- Organized sections: Basic Info, FDA Info, Output Options
- Smart defaults and validation
- Real-time command preview
- Clear success/error feedback

#### **Results Display**
- Command executed shown
- Output in terminal-style display
- Color-coded success/error states
- Next steps recommendations

### **Deployment Options**

#### **Local Development**
```bash
fda-sbom ui --debug
```

#### **Team Server**
```bash
# With Docker
docker run -p 5000:5000 fda-sbom-ui

# With systemd service
sudo systemctl start fda-sbom-ui
```

#### **Cloud Deployment**
- Can deploy to any Flask-compatible platform
- Heroku, AWS, Azure, GCP support
- Add authentication layer if needed

### **Benefits of This Approach**

#### **For Users**
- **Choice**: Use CLI or UI based on preference
- **Consistency**: Same functionality, different interface
- **No Learning Curve**: UI is intuitive, CLI is powerful
- **FDA Focus**: Specialized for medical device compliance

#### **For Developers**
- **Simple Implementation**: Flask passthrough to existing CLI
- **No Duplication**: All logic remains in CLI/core
- **Easy Maintenance**: UI changes don't affect core functionality
- **Optional Dependency**: Flask only needed if using UI

### **Ready to Use**

The web UI is now fully integrated and ready to use:

```bash
# Install with UI support
pip install -e .[ui]

# Start the web interface  
fda-sbom ui

# Open http://localhost:5000 in your browser
```

**Perfect for teams that want both the power of CLI automation and the ease of a visual interface!**
