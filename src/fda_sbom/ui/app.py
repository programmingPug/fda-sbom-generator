"""
Web UI for FDA SBOM Generator - Simple passthrough to CLI commands.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
import threading
import time


class SBOMWebUI:
    """Simple web UI that passes through to CLI commands."""
    
    def __init__(self):
        self.app = Flask(__name__, 
                        template_folder=str(Path(__file__).parent / "templates"),
                        static_folder=str(Path(__file__).parent / "static"))
        self.app.secret_key = "fda-sbom-generator-ui"
        self.setup_routes()
        self.running_jobs = {}  # Track background jobs
    
    def setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index():
            """Main page."""
            return render_template('index.html')
        
        @self.app.route('/generate', methods=['GET', 'POST'])
        def generate():
            """Generate SBOM page."""
            if request.method == 'GET':
                return render_template('generate.html')
            
            # Handle form submission
            try:
                form_data = request.form
                project_path = form_data.get('project_path', '.')
                
                # Build CLI command
                cmd = ['fda-sbom', 'generate', project_path]
                
                # Add optional parameters
                if form_data.get('manufacturer'):
                    cmd.extend(['--manufacturer', form_data['manufacturer']])
                if form_data.get('target_system'):
                    cmd.extend(['--target-system', form_data['target_system']])
                if form_data.get('target_version'):
                    cmd.extend(['--target-version', form_data['target_version']])
                if form_data.get('device_model'):
                    cmd.extend(['--device-model', form_data['device_model']])
                if form_data.get('fda_submission_id'):
                    cmd.extend(['--fda-submission-id', form_data['fda_submission_id']])
                if form_data.get('format'):
                    cmd.extend(['--format', form_data['format']])
                if form_data.get('no_vulnerabilities'):
                    cmd.append('--no-vulnerabilities')
                if form_data.get('update_licenses'):
                    cmd.append('--update-licenses')
                
                # Add verbose flag
                cmd.append('--verbose')
                
                # Run command
                result = self._run_command(cmd)
                
                # Debug: Add command and result to the result for troubleshooting
                result['debug_command'] = cmd
                result['debug_python_path'] = sys.executable
                
                if result['success']:
                    flash('SBOM generated successfully!', 'success')
                    return render_template('generate.html', 
                                         result=result, 
                                         form_data=form_data)
                else:
                    error_msg = result.get('error', 'Unknown error occurred')
                    if result.get('stderr'):
                        error_msg = result['stderr']
                    flash(f'Error: {error_msg}', 'error')
                    return render_template('generate.html', 
                                         result=result,
                                         form_data=form_data)
            
            except Exception as e:
                flash(f'Unexpected error: {str(e)}', 'error')
                return render_template('generate.html')
        
        @self.app.route('/solution', methods=['GET', 'POST'])
        def solution():
            """Generate solution SBOM page."""
            if request.method == 'GET':
                return render_template('solution.html')
            
            try:
                form_data = request.form
                solution_path = form_data.get('solution_path', '.')
                
                # Build CLI command
                cmd = ['fda-sbom', 'solution', solution_path]
                
                # Add optional parameters
                if form_data.get('manufacturer'):
                    cmd.extend(['--manufacturer', form_data['manufacturer']])
                if form_data.get('solution_name'):
                    cmd.extend(['--solution-name', form_data['solution_name']])
                if form_data.get('format'):
                    cmd.extend(['--format', form_data['format']])
                if form_data.get('output_dir'):
                    cmd.extend(['--output-dir', form_data['output_dir']])
                
                # Solution options
                if form_data.get('individual_sboms'):
                    cmd.append('--individual-sboms')
                if form_data.get('solution_sbom'):
                    cmd.append('--solution-sbom')
                if form_data.get('no_vulnerabilities'):
                    cmd.append('--no-vulnerabilities')
                
                cmd.append('--verbose')
                
                # Run command
                result = self._run_command(cmd)
                
                if result['success']:
                    flash('Solution SBOM generated successfully!', 'success')
                    return render_template('solution.html', 
                                         result=result, 
                                         form_data=form_data)
                else:
                    error_msg = result.get('error', 'Unknown error occurred')
                    if result.get('stderr'):
                        error_msg = result['stderr']
                    flash(f'Error: {error_msg}', 'error')
                    return render_template('solution.html',
                                         result=result,
                                         form_data=form_data)
            
            except Exception as e:
                flash(f'Unexpected error: {str(e)}', 'error')
                return render_template('solution.html')
        
        @self.app.route('/validate', methods=['GET', 'POST'])
        def validate():
            """Validate SBOM page."""
            if request.method == 'GET':
                return render_template('validate.html')
            
            try:
                form_data = request.form
                sbom_file = form_data.get('sbom_file')
                
                if not sbom_file or not Path(sbom_file).exists():
                    flash('Please provide a valid SBOM file path', 'error')
                    return render_template('validate.html')
                
                # Build CLI command
                cmd = ['fda-sbom', 'validate', sbom_file]
                
                if form_data.get('format'):
                    cmd.extend(['--format', form_data['format']])
                
                cmd.append('--verbose')
                
                # Run command
                result = self._run_command(cmd)
                
                return render_template('validate.html', 
                                     result=result, 
                                     form_data=form_data)
            
            except Exception as e:
                flash(f'Unexpected error: {str(e)}', 'error')
                return render_template('validate.html')
        
        @self.app.route('/scan', methods=['GET', 'POST'])
        def scan():
            """Scan project page."""
            if request.method == 'GET':
                return render_template('scan.html')
            
            try:
                form_data = request.form
                project_path = form_data.get('project_path', '.')
                
                # Build CLI command
                cmd = ['fda-sbom', 'scan', project_path, '--verbose']
                
                # Run command
                result = self._run_command(cmd)
                
                return render_template('scan.html', 
                                     result=result, 
                                     form_data=form_data)
            
            except Exception as e:
                flash(f'Unexpected error: {str(e)}', 'error')
                return render_template('scan.html')
        
        @self.app.route('/doctor')
        def doctor():
            """System check page."""
            try:
                # Run doctor command
                cmd = ['fda-sbom', 'doctor', '--check-dependencies']
                result = self._run_command(cmd)
                
                return render_template('doctor.html', result=result)
            
            except Exception as e:
                flash(f'Error running system check: {str(e)}', 'error')
                return render_template('doctor.html')
        
        @self.app.route('/api/job/<job_id>')
        def job_status(job_id):
            """Get job status (for future async operations)."""
            if job_id in self.running_jobs:
                return jsonify(self.running_jobs[job_id])
            else:
                return jsonify({'status': 'not_found'})
    
    def _run_command(self, cmd: List[str]) -> Dict:
        """Run CLI command and return result."""
        try:
            # Add the project source directory to Python path
            project_src = Path(__file__).parent.parent.parent
            if str(project_src) not in sys.path:
                env = os.environ.copy()
                pythonpath = env.get('PYTHONPATH', '')
                if str(project_src) not in pythonpath:
                    env['PYTHONPATH'] = f"{project_src}{os.pathsep}{pythonpath}" if pythonpath else str(project_src)
            else:
                env = None
            
            python_cmd = [sys.executable, '-m', 'fda_sbom.cli'] + cmd[1:]  # Skip 'fda-sbom'
            
            result = subprocess.run(
                python_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                env=env
            )
            
            # Determine error message
            error_msg = None
            if result.returncode != 0:
                if result.stderr:
                    error_msg = result.stderr
                elif result.stdout:
                    error_msg = result.stdout
                else:
                    error_msg = f"Command failed with return code {result.returncode}"
            
            response = {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'command': ' '.join(cmd)
            }
            
            if error_msg:
                response['error'] = error_msg
            
            return response
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timed out after 5 minutes',
                'command': ' '.join(cmd)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': ' '.join(cmd)
            }
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Run the web UI."""
        print(f"\\nFDA SBOM Generator Web UI")
        print(f"Running at: http://{host}:{port}")
        print(f"Debug mode: {debug}")
        print(f"Press Ctrl+C to stop\\n")
        
        self.app.run(host=host, port=port, debug=debug)


def create_app():
    """Factory function to create Flask app."""
    ui = SBOMWebUI()
    return ui.app


def main():
    """Main entry point for UI."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FDA SBOM Generator Web UI')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    ui = SBOMWebUI()
    ui.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
