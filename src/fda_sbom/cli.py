"""
Command-line interface for FDA SBOM Generator.
"""

import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .generator import SBOMGenerator
from .models import SBOMFormat
from .exporters import export_sbom


@click.group()
@click.version_option(version=__version__, prog_name="fda-sbom")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """FDA-compliant Software Bill of Materials (SBOM) generator."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', type=int, default=5000, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def ui(host, port, debug):
    """Launch the web UI interface."""
    try:
        from .ui.app import SBOMWebUI
        
        click.echo(f"Starting FDA SBOM Generator Web UI...")
        click.echo(f"Open your browser to: http://{host}:{port}")
        
        ui_app = SBOMWebUI()
        ui_app.run(host=host, port=port, debug=debug)
        
    except ImportError:
        click.echo("Error: Flask is required for the web UI. Install with:")
        click.echo("  pip install flask")
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error starting web UI: {e}", err=True)
        sys.exit(1)



@cli.command()
@click.argument('solution_path', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path),
              help='Output directory for SBOMs')
@click.option('--format', '-f', type=click.Choice(['spdx', 'cyclonedx', 'swid', 'json']),
              default='spdx', help='Output format')
@click.option('--solution-name', help='Solution/workspace name')
@click.option('--manufacturer', help='Device manufacturer')
@click.option('--no-vulnerabilities', is_flag=True,
              help='Skip vulnerability scanning')
@click.option('--individual-sboms', is_flag=True,
              help='Generate individual SBOMs for each project')
@click.option('--solution-sbom', is_flag=True,
              help='Generate consolidated solution SBOM')
@click.pass_context
def solution(ctx, solution_path, output_dir, format, solution_name, manufacturer,
             no_vulnerabilities, individual_sboms, solution_sbom):
    """Generate SBOMs for a multi-project solution."""
    
    verbose = ctx.obj.get('verbose', False)
    
    # Set defaults
    if not output_dir:
        output_dir = solution_path / "sboms"
    if not solution_name:
        solution_name = solution_path.name
    if not individual_sboms and not solution_sbom:
        individual_sboms = True  # Default to individual SBOMs
    
    # Create output directory
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    try:
        from .solution import SolutionScanner
        scanner = SolutionScanner()
        
        def progress_callback(message):
            if verbose:
                click.echo(f"[INFO] {message}")
        
        click.echo(f"Scanning solution: {solution_path}")
        
        # Scan all projects
        project_sboms = scanner.scan_solution(
            solution_path=solution_path,
            manufacturer=manufacturer,
            solution_name=solution_name,
            include_vulnerabilities=not no_vulnerabilities,
            progress_callback=progress_callback if verbose else None
        )
        
        click.echo(f"Found {len(project_sboms)} projects")
        
        # Export individual project SBOMs
        if individual_sboms:
            for project_name, sbom in project_sboms.items():
                extensions = {
                    'spdx': 'spdx.json',
                    'cyclonedx': 'cyclonedx.json',
                    'swid': 'swid.xml',
                    'json': 'sbom.json'
                }
                output_file = output_dir / f"{project_name}.{extensions[format]}"
                export_sbom(sbom, output_file, format)
                
                if verbose:
                    click.echo(f"Generated SBOM for {project_name}: {output_file}")
        
        # Export solution SBOM
        if solution_sbom:
            merged_sbom = scanner.create_solution_sbom(
                project_sboms, solution_name, manufacturer
            )
            
            extensions = {
                'spdx': 'spdx.json',
                'cyclonedx': 'cyclonedx.json',
                'swid': 'swid.xml',
                'json': 'sbom.json'
            }
            solution_output = output_dir / f"{solution_name}-solution.{extensions[format]}"
            export_sbom(merged_sbom, solution_output, format)
            
            click.echo(f"Generated solution SBOM: {solution_output}")
            
            # Generate solution report
            report_output = output_dir / f"{solution_name}-report.json"
            scanner.export_solution_report(project_sboms, merged_sbom, report_output)
            click.echo(f"Generated solution report: {report_output}")
        
        # Summary
        total_components = sum(len(sbom.components) for sbom in project_sboms.values())
        total_vulns = sum(len(sbom.get_vulnerabilities()) for sbom in project_sboms.values())
        
        click.echo(f"\nSolution Summary:")
        click.echo(f"  Projects: {len(project_sboms)}")
        click.echo(f"  Total Components: {total_components}")
        if not no_vulnerabilities:
            click.echo(f"  Total Vulnerabilities: {total_vulns}")
        
        for project_name, sbom in project_sboms.items():
            click.echo(f"  {project_name}: {len(sbom.components)} components")
    
    except Exception as e:
        click.echo(f"Error scanning solution: {e}", err=True)
        sys.exit(1)



@cli.command()
@click.argument('project_path', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), 
              help='Output file path')
@click.option('--format', '-f', type=click.Choice(['spdx', 'cyclonedx', 'swid', 'json']),
              default='spdx', help='Output format')
@click.option('--target-system', help='Target system name')
@click.option('--target-version', help='Target system version')
@click.option('--manufacturer', help='Device manufacturer')
@click.option('--device-model', help='Device model number')
@click.option('--fda-submission-id', help='FDA submission identifier')
@click.option('--no-vulnerabilities', is_flag=True, 
              help='Skip vulnerability scanning')
@click.option('--update-licenses', is_flag=True,
              help='Fetch latest license information')
@click.pass_context
def generate(ctx, project_path, output, format, target_system, target_version,
             manufacturer, device_model, fda_submission_id, no_vulnerabilities,
             update_licenses):
    """Generate SBOM for a project."""
    
    verbose = ctx.obj.get('verbose', False)
    
    # Set default output path
    if not output:
        project_name = target_system or project_path.name
        extensions = {
            'spdx': 'spdx.json',
            'cyclonedx': 'cyclonedx.json', 
            'swid': 'swid.xml',
            'json': 'sbom.json'
        }
        output = project_path / f"{project_name}.{extensions[format]}"
    
    generator = SBOMGenerator()
    
    def progress_callback(message):
        if verbose:
            click.echo(f"[INFO] {message}")
    
    try:
        click.echo(f"Generating SBOM for: {project_path}")
        
        # Generate SBOM
        sbom = generator.generate_sbom(
            project_path=project_path,
            target_system=target_system,
            target_version=target_version,
            include_vulnerabilities=not no_vulnerabilities,
            manufacturer=manufacturer,
            device_model=device_model,
            fda_submission_id=fda_submission_id,
            progress_callback=progress_callback if verbose else None
        )
        
        # Update licenses if requested
        if update_licenses:
            if verbose:
                click.echo("[INFO] Updating license information...")
            sbom = generator.update_component_licenses(sbom)
        
        # Export SBOM
        export_sbom(sbom, output, format)
        
        click.echo(f"SBOM generated successfully: {output}")
        click.echo(f"Components found: {len(sbom.components)}")
        
        if not no_vulnerabilities:
            vuln_count = len(sbom.get_vulnerabilities())
            if vuln_count > 0:
                click.echo(f"Vulnerabilities detected: {vuln_count}")
                vuln_counts = sbom.get_vulnerability_count_by_severity()
                for severity, count in vuln_counts.items():
                    if count > 0:
                        click.echo(f"  {severity.value}: {count}")
            else:
                click.echo("No vulnerabilities detected")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('sbom_file', type=click.Path(exists=True, path_type=Path))
@click.option('--format', '-f', type=click.Choice(['spdx', 'cyclonedx', 'swid', 'json']),
              help='SBOM format (auto-detected if not specified)')
@click.pass_context
def validate(ctx, sbom_file, format):
    """Validate an SBOM for FDA compliance."""
    
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Load SBOM
        if verbose:
            click.echo(f"Loading SBOM: {sbom_file}")
        
        # For now, assume JSON format - in a full implementation,
        # we'd need format detection and parsing
        import json
        with open(sbom_file, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
        
        # For demonstration, create a simple validation
        click.echo("SBOM Validation Report")
        click.echo("=" * 50)
        
        required_fields = ['document_id', 'document_name', 'components']
        missing_fields = []
        
        for field in required_fields:
            if field not in sbom_data:
                missing_fields.append(field)
        
        if missing_fields:
            click.echo(f"Missing required fields: {', '.join(missing_fields)}")
        else:
            click.echo("All required fields present")
        
        # Check components
        components = sbom_data.get('components', [])
        click.echo(f"Components found: {len(components)}")
        
        if components:
            components_with_versions = sum(1 for c in components if c.get('version'))
            components_with_licenses = sum(1 for c in components if c.get('licenses'))
            
            click.echo(f"   - With versions: {components_with_versions}/{len(components)}")
            click.echo(f"   - With licenses: {components_with_licenses}/{len(components)}")
        
        # FDA compliance check
        fda_fields = ['manufacturer', 'fda_submission_id']
        fda_present = sum(1 for field in fda_fields if sbom_data.get(field))
        
        if fda_present == len(fda_fields):
            click.echo("FDA-specific fields present")
        else:
            click.echo(f"FDA fields: {fda_present}/{len(fda_fields)} present")
        
        click.echo("\nValidation complete")
        
    except Exception as e:
        click.echo(f"Error validating SBOM: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('project_path', type=click.Path(exists=True, path_type=Path))
@click.pass_context
def scan(ctx, project_path):
    """Scan project and show component summary without generating SBOM."""
    
    verbose = ctx.obj.get('verbose', False)
    
    try:
        generator = SBOMGenerator()
        
        if verbose:
            click.echo(f"Scanning project: {project_path}")
        
        # Get applicable scanners
        scanners = generator.scanner_registry.get_applicable_scanners(Path(project_path))
        
        click.echo("Project Analysis")
        click.echo("=" * 50)
        click.echo(f"Project: {project_path}")
        click.echo(f"Scanners detected: {len(scanners)}")
        
        for scanner in scanners:
            click.echo(f"  - {scanner.__class__.__name__}")
        
        # Scan for components
        components = generator._scan_project(Path(project_path))
        
        click.echo(f"\nComponents found: {len(components)}")
        
        # Group by package manager
        by_package_manager = {}
        for component in components:
            pm = component.package_manager or "unknown"
            if pm not in by_package_manager:
                by_package_manager[pm] = []
            by_package_manager[pm].append(component)
        
        for pm, comps in by_package_manager.items():
            click.echo(f"  {pm}: {len(comps)} components")
            if verbose:
                for comp in comps[:5]:  # Show first 5
                    click.echo(f"    - {comp.name} {comp.version or '(no version)'}")
                if len(comps) > 5:
                    click.echo(f"    ... and {len(comps) - 5} more")
        
    except Exception as e:
        click.echo(f"Error scanning project: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('sbom_file', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output file for security report')
@click.pass_context
def security(ctx, sbom_file, output):
    """Generate security analysis report for an SBOM."""
    
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # This is a simplified version - in full implementation,
        # we'd load and parse the actual SBOM
        click.echo("Security Analysis")
        click.echo("=" * 50)
        click.echo("Security analysis requires a fully parsed SBOM")
        click.echo("    This is a demonstration of the command structure")
        
        if output:
            # Write a sample report
            with open(output, 'w') as f:
                f.write("# Security Analysis Report\n")
                f.write(f"Generated: {click.DateTime().now()}\n")
                f.write("\nThis is a sample security report.\n")
            click.echo(f"Sample report written to: {output}")
        
    except Exception as e:
        click.echo(f"Error generating security report: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--check-dependencies', is_flag=True, help='Check if dependencies are installed')
def doctor(check_dependencies):
    """Check system setup and configuration."""
    
    click.echo("FDA SBOM Generator - System Check")
    click.echo("=" * 50)
    
    # Check Python version
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    click.echo(f"Python version: {python_version}")
    
    if sys.version_info >= (3, 8):
        click.echo("Python version OK")
    else:
        click.echo("Python 3.8+ required")
    
    # Check key dependencies
    dependencies = [
        ('click', 'CLI framework'),
        ('pydantic', 'Data validation'),
        ('requests', 'HTTP requests'),
        ('lxml', 'XML processing'),
    ]
    
    if check_dependencies:
        click.echo("\nChecking dependencies:")
        for dep, description in dependencies:
            try:
                __import__(dep)
                click.echo(f"{dep}: {description}")
            except ImportError:
                click.echo(f"{dep}: {description} - NOT INSTALLED")
    
    # Check scanners
    click.echo("\nAvailable scanners:")
    try:
        from .scanners import ScannerRegistry
        registry = ScannerRegistry()
        for scanner_class in registry.scanners:
            click.echo(f"{scanner_class.__name__}")
    except Exception as e:
        click.echo(f"Error loading scanners: {e}")
    
    click.echo("\nSystem check complete")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
