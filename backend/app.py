"""
Flask backend for ATLAS SBOM Management System
"""

import os
import json
from pathlib import Path
from flask import Flask, send_from_directory, jsonify, request, send_file
from flask_cors import CORS
from datetime import datetime
import sys

app = Flask(__name__)
CORS(app)

# Base directory for backend
BACKEND_DIR = Path(__file__).parent
FRONTEND_DIR = BACKEND_DIR.parent / 'frontend'

# SBOM directories to scan
SBOM_DIRS = {
    'AnalysisBase': BACKEND_DIR / 'AnalysisBase',
    'StatAnalysis': BACKEND_DIR / 'StatAnalysis',
    'Athena': BACKEND_DIR / 'Athena'
}


def get_sbom_signature(sbom_data, build_info=None):
    """Generate a signature for an SBOM to compare if it's identical
    Includes all data except generation timestamp"""
    signature_parts = []
    
    # 1. Components (dependencies) - sorted by name and version
    components = sbom_data.get('components', [])
    normalized_components = sorted([
        (comp.get('name', ''), comp.get('version', ''))
        for comp in components
    ])
    signature_parts.append(('components', tuple(normalized_components)))
    
    # 2. Metadata properties (excluding timestamp)
    metadata = sbom_data.get('metadata', {})
    properties = metadata.get('properties', [])
    # Convert properties list to sorted dict for consistent comparison
    props_dict = {}
    for prop in properties:
        props_dict[prop.get('name', '')] = prop.get('value', '')
    normalized_props = tuple(sorted(props_dict.items()))
    signature_parts.append(('properties', normalized_props))
    
    # 3. Build information (if provided)
    if build_info:
        normalized_build = tuple(sorted(build_info.items()))
        signature_parts.append(('build_info', normalized_build))
    
    return tuple(signature_parts)


def get_next_version_number(base_dir, sboms_dir='SBOMs'):
    """Get the next version number by checking existing version directories"""
    sboms_path = base_dir / sboms_dir
    
    if not sboms_path.exists():
        return 1
    
    # Find all version directories (v1, v2, v3, etc.)
    version_dirs = []
    for item in sboms_path.iterdir():
        if item.is_dir() and item.name.startswith('v'):
            try:
                version_num = int(item.name[1:])  # Extract number after 'v'
                version_dirs.append(version_num)
            except ValueError:
                continue
    
    if not version_dirs:
        return 1
    
    return max(version_dirs) + 1


def find_sbom_files():
    """Scan directories for SBOM JSON files, grouped by project"""
    projects = {}
    
    for sbom_type, base_dir in SBOM_DIRS.items():
        if not base_dir.exists():
            continue
        
        project_sboms = []
            
        # Look for SBOM directories (skip ExampleSBOM)
        for sbom_dir in base_dir.rglob('*'):
            if not sbom_dir.is_dir():
                continue
            
            # Skip ExampleSBOM directories
            if sbom_dir.name == 'ExampleSBOM':
                continue
                
            json_files = list(sbom_dir.glob('*-sbom.json'))
            if json_files:
                for json_file in json_files:
                    md_file = json_file.with_suffix('.md')
                    
                    # Extract metadata
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            
                        metadata = {
                            'timestamp': data.get('metadata', {}).get('timestamp', 'Unknown'),
                            'dependencyCount': len(data.get('components', [])),
                            'sources': [],
                            'properties': {}
                        }
                        
                        # Extract properties
                        if 'metadata' in data and 'properties' in data['metadata']:
                            for prop in data['metadata']['properties']:
                                metadata['properties'][prop['name']] = prop['value']
                        
                        # Extract sources from components
                        if 'components' in data:
                            sources = set()
                            for comp in data['components']:
                                if 'properties' in comp:
                                    for prop in comp['properties']:
                                        if prop.get('name') == 'source':
                                            sources.add(prop.get('value', ''))
                            metadata['sources'] = list(sources)
                        
                        # Generate ID from path (use version directory name)
                        rel_path = json_file.relative_to(BACKEND_DIR)
                        # Extract version from path (e.g., AnalysisBase/SBOMs/v1/... -> v1)
                        path_parts = rel_path.parts
                        version_part = None
                        for i, part in enumerate(path_parts):
                            if part == 'SBOMs' and i + 1 < len(path_parts):
                                version_part = path_parts[i + 1]
                                break
                        sbom_id = f"{sbom_type}-{version_part}" if version_part else f"{sbom_type}-{rel_path.parent.name}"
                        
                        # Create display name with version
                        display_name = f"{sbom_type} {version_part}" if version_part else f"{sbom_type} {rel_path.parent.name}"
                        
                        # Get file modification time for sorting
                        mtime = json_file.stat().st_mtime
                        
                        project_sboms.append({
                            'id': sbom_id,
                            'name': sbom_type,
                            'displayName': display_name,
                            'path': str(rel_path),
                            'jsonPath': str(json_file),
                            'mdPath': str(md_file) if md_file.exists() else None,
                            'metadata': metadata,
                            'mtime': mtime,
                            'signature': get_sbom_signature(data)
                        })
                    except Exception as e:
                        print(f"Error reading {json_file}: {e}", file=sys.stderr)
                        continue
        
        # Sort SBOMs by modification time (newest first)
        project_sboms.sort(key=lambda x: x['mtime'], reverse=True)
        
        if project_sboms:
            projects[sbom_type] = {
                'name': sbom_type,
                'displayName': sbom_type,
                'sboms': project_sboms
            }
    
    return projects


@app.route('/api/sboms', methods=['GET'])
def list_sboms():
    """API endpoint to list all available SBOMs grouped by project"""
    try:
        print("API /api/sboms called", file=sys.stderr)
        projects = find_sbom_files()
        total_sboms = sum(len(p['sboms']) for p in projects.values())
        print(f"Found {len(projects)} projects with {total_sboms} total SBOMs", file=sys.stderr)
        return jsonify({
            'success': True,
            'projects': list(projects.values()),
            'count': total_sboms
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sboms/<sbom_id>', methods=['GET'])
def get_sbom(sbom_id):
    """API endpoint to get a specific SBOM by ID"""
    try:
        projects = find_sbom_files()
        sbom = None
        for project in projects.values():
            sbom = next((s for s in project['sboms'] if s['id'] == sbom_id), None)
            if sbom:
                break
        
        if not sbom:
            return jsonify({
                'success': False,
                'error': 'SBOM not found'
            }), 404
        
        # Load JSON data
        json_path = BACKEND_DIR / sbom['jsonPath']
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Load markdown if available
        md_data = None
        if sbom['mdPath']:
            md_path = BACKEND_DIR / sbom['mdPath']
            if md_path.exists():
                with open(md_path, 'r', encoding='utf-8') as f:
                    md_data = f.read()
        
        return jsonify({
            'success': True,
            'sbom': sbom,
            'data': data,
            'markdown': md_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sboms/<sbom_id>/json', methods=['GET'])
def get_sbom_json(sbom_id):
    """API endpoint to get SBOM JSON file directly"""
    try:
        projects = find_sbom_files()
        sbom = None
        for project in projects.values():
            sbom = next((s for s in project['sboms'] if s['id'] == sbom_id), None)
            if sbom:
                break
        
        if not sbom:
            return jsonify({'error': 'SBOM not found'}), 404
        
        json_path = BACKEND_DIR / sbom['jsonPath']
        return send_file(json_path, mimetype='application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sboms/<sbom_id>/markdown', methods=['GET'])
def get_sbom_markdown(sbom_id):
    """API endpoint to get SBOM markdown file directly"""
    try:
        projects = find_sbom_files()
        sbom = None
        for project in projects.values():
            sbom = next((s for s in project['sboms'] if s['id'] == sbom_id), None)
            if sbom:
                break
        
        if not sbom or not sbom['mdPath']:
            return jsonify({'error': 'SBOM or markdown not found'}), 404
        
        md_path = BACKEND_DIR / sbom['mdPath']
        if not md_path.exists():
            return jsonify({'error': 'Markdown file not found'}), 404
        
        return send_file(md_path, mimetype='text/markdown')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sboms/create', methods=['POST'])
def create_sbom():
    """API endpoint to create a new SBOM"""
    try:
        data = request.get_json()
        sbom_type = data.get('type')  # 'AnalysisBase' or 'StatAnalysis'
        output_dir = data.get('outputDir', 'SBOMs')
        
        if sbom_type not in ['AnalysisBase', 'StatAnalysis']:
            return jsonify({
                'success': False,
                'error': f'Invalid SBOM type: {sbom_type}. Must be AnalysisBase or StatAnalysis'
            }), 400
        
        base_dir = SBOM_DIRS.get(sbom_type)
        if not base_dir or not base_dir.exists():
            return jsonify({
                'success': False,
                'error': f'SBOM directory not found: {sbom_type}'
            }), 404
        
        # Change to the SBOM directory
        original_cwd = os.getcwd()
        os.chdir(base_dir)
        
        is_duplicate = False
        existing_sbom = None
        new_sbom = None
        json_file = None
        md_file = None
        
        try:
            # Import and run the appropriate generator
            if sbom_type == 'AnalysisBase':
                # Add parent directory to path to import the module
                parent_dir = str(base_dir.parent)
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                
                # Import using the directory name as module
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "sbomGenerator", 
                    str(base_dir / "sbomGenerator.py")
                )
                sbom_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(sbom_module)
                SBOMGenerator = sbom_module.SBOMGenerator
                
                generator = SBOMGenerator()
                
                # Parse dependencies
                generator.parse_py_deps()
                generator.parse_cpp_deps()
                
                # Get build info if available
                build_info = generator.parse_build_info()
                
                # Generate and check SBOM first
                analysisbase_version = data.get('analysisbase_version', '24.0')
                externals_version = data.get('externals_version', '24.2.42')
                
                sbom_json = generator.generate_cyclonedx_sbom(analysisbase_version, externals_version)
                new_sbom_data = json.loads(sbom_json)
                
                # Check for duplicates before saving
                projects = find_sbom_files()
                project_sboms = projects.get(sbom_type, {}).get('sboms', [])
                new_signature = get_sbom_signature(new_sbom_data, build_info)
                
                if project_sboms:
                    # Get the most recent SBOM and parse its build info from markdown
                    most_recent = project_sboms[0]
                    recent_md_path = BACKEND_DIR / most_recent.get('mdPath') if most_recent.get('mdPath') else None
                    recent_build_info = None
                    
                    if recent_md_path and recent_md_path.exists():
                        # Parse build info from markdown
                        import re
                        try:
                            with open(recent_md_path, 'r', encoding='utf-8') as f:
                                md_content = f.read()
                            
                            recent_build_info = {}
                            c_match = re.search(r'\|\s*C Compiler\s*\|\s*(.+?)\s*\|', md_content)
                            if c_match:
                                recent_build_info['C Compiler'] = c_match.group(1).strip()
                            
                            cxx_match = re.search(r'\|\s*CXX Compiler\s*\|\s*(.+?)\s*\|', md_content)
                            if cxx_match:
                                recent_build_info['CXX Compiler'] = cxx_match.group(1).strip()
                            
                            platform_match = re.search(r'\|\s*Platform\s*\|\s*(.+?)\s*\|', md_content)
                            if platform_match:
                                recent_build_info['Platform'] = platform_match.group(1).strip()
                        except Exception as e:
                            print(f"Warning: Could not parse build info from markdown: {e}", file=sys.stderr)
                    
                    # Load the existing SBOM JSON to get full data
                    recent_json_path = BACKEND_DIR / most_recent.get('jsonPath')
                    if recent_json_path.exists():
                        with open(recent_json_path, 'r', encoding='utf-8') as f:
                            recent_sbom_data = json.load(f)
                        
                        recent_signature = get_sbom_signature(recent_sbom_data, recent_build_info)
                        
                        if recent_signature == new_signature:
                            is_duplicate = True
                            existing_sbom = most_recent
                
                if not is_duplicate:
                    # Get next version number and create versioned directory
                    version_num = get_next_version_number(base_dir, output_dir)
                    version_dir = base_dir / output_dir / f'v{version_num}'
                    version_dir.mkdir(parents=True, exist_ok=True)
                    
                    json_file = version_dir / f'{sbom_type.lower()}-sbom.json'
                    md_file = version_dir / f'{sbom_type.lower()}-sbom.md'
                    
                    # Save SBOM files
                    with open(json_file, 'w', encoding='utf-8') as f:
                        f.write(sbom_json)
                    
                    md_content = generator.generate_markdown_report(analysisbase_version, externals_version, build_info)
                    with open(md_file, 'w', encoding='utf-8') as f:
                        f.write(md_content)
                
            elif sbom_type == 'StatAnalysis':
                # Import using importlib
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "sbomGenerator", 
                    str(base_dir / "sbomGenerator.py")
                )
                sbom_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(sbom_module)
                SBOMGenerator = sbom_module.SBOMGenerator
                
                generator = SBOMGenerator()
                
                # Generate SBOM to get the data first
                generator.parse_py_deps()
                generator.parse_cpp_deps()
                
                # Create temporary files to get the SBOM data
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_json:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as tmp_md:
                        generator.generate(tmp_json.name, tmp_md.name)
                        
                        # Load the generated SBOM data
                        with open(tmp_json.name, 'r', encoding='utf-8') as f:
                            new_sbom_data = json.load(f)
                        
                        # Check for duplicates before saving
                        projects = find_sbom_files()
                        project_sboms = projects.get(sbom_type, {}).get('sboms', [])
                        # StatAnalysis doesn't have build info, so pass None
                        new_signature = get_sbom_signature(new_sbom_data, None)
                        
                        if project_sboms:
                            # Get the most recent SBOM
                            most_recent = project_sboms[0]
                            # Load the existing SBOM JSON to get full data
                            recent_json_path = BACKEND_DIR / most_recent.get('jsonPath')
                            if recent_json_path.exists():
                                with open(recent_json_path, 'r', encoding='utf-8') as f:
                                    recent_sbom_data = json.load(f)
                                
                                recent_signature = get_sbom_signature(recent_sbom_data, None)
                                
                                if recent_signature == new_signature:
                                    is_duplicate = True
                                    existing_sbom = most_recent
                        
                        if not is_duplicate:
                            # Get next version number and create versioned directory
                            version_num = get_next_version_number(base_dir, output_dir)
                            version_dir = base_dir / output_dir / f'v{version_num}'
                            version_dir.mkdir(parents=True, exist_ok=True)
                            
                            json_file = version_dir / f'{sbom_type.lower()}-sbom.json'
                            md_file = version_dir / f'{sbom_type.lower()}-sbom.md'
                            
                            # Copy temp files to final location
                            import shutil
                            shutil.copy(tmp_json.name, json_file)
                            shutil.copy(tmp_md.name, md_file)
                        
                        # Clean up temp files
                        os.unlink(tmp_json.name)
                        os.unlink(tmp_md.name)
            
            # Return response
            if is_duplicate:
                return jsonify({
                    'success': True,
                    'message': 'SBOM is identical to the most recent one',
                    'isDuplicate': True,
                    'sbom': existing_sbom
                })
            else:
                # Reload to get the new SBOM
                projects = find_sbom_files()
                project_sboms = projects.get(sbom_type, {}).get('sboms', [])
                new_sbom = None
                json_file_abs = json_file.resolve()
                for s in project_sboms:
                    sbom_path_abs = (BACKEND_DIR / s['jsonPath']).resolve()
                    if sbom_path_abs == json_file_abs:
                        new_sbom = s
                        break
                
                return jsonify({
                    'success': True,
                    'message': 'SBOM created successfully',
                    'isDuplicate': False,
                    'sbom': new_sbom,
                    'jsonPath': str(json_file.relative_to(BACKEND_DIR)),
                    'mdPath': str(md_file.relative_to(BACKEND_DIR)) if md_file.exists() else None
                })
            
        finally:
            os.chdir(original_cwd)
                
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500


@app.route('/api/test', methods=['GET'])
def test_api():
    """Test endpoint to verify API routing works"""
    return jsonify({'success': True, 'message': 'API is working!', 'routes': [str(rule) for rule in app.url_map.iter_rules()]})


@app.route('/api/sbom-types', methods=['GET'])
def get_sbom_types():
    """API endpoint to get available SBOM types"""
    available_types = []
    
    for sbom_type, base_dir in SBOM_DIRS.items():
        if base_dir.exists():
            has_generator = (base_dir / 'sbomGenerator.py').exists()
            available_types.append({
                'type': sbom_type,
                'available': has_generator,
                'path': str(base_dir)
            })
    
    return jsonify({
        'success': True,
        'types': available_types
    })


@app.route('/')
def index():
    """Serve the main frontend page"""
    return send_from_directory(str(FRONTEND_DIR), 'index.html')


# Serve frontend static files - use a regex to exclude api routes
@app.route('/<path:path>')
def serve_frontend(path):
    """Serve frontend static files - must be last to not catch API routes"""
    # This should never be called for /api/* routes since they're defined above
    # But add a safety check anyway
    if path.startswith('api/'):
        print(f"ERROR: API route /{path} was caught by catch-all route! This should not happen.", file=sys.stderr)
        return jsonify({'error': 'API endpoint not found'}), 404
    
    # Check if file exists before trying to serve it
    file_path = FRONTEND_DIR / path
    if file_path.exists() and file_path.is_file():
        return send_from_directory(str(FRONTEND_DIR), path)
    else:
        # For SPA routing, serve index.html for non-API routes
        return send_from_directory(str(FRONTEND_DIR), 'index.html')


# Schedule daily SBOM generation
def schedule_daily_runs():
    """Schedule daily SBOM generation runs"""
    import threading
    import schedule
    import time
    import subprocess
    
    def run_daily_sbom_generation():
        """Run the daily SBOM generation script"""
        try:
            script_path = BACKEND_DIR / 'DailyRun.sh'
            if script_path.exists():
                result = subprocess.run(
                    ['bash', str(script_path)],
                    cwd=str(BACKEND_DIR),
                    capture_output=True,
                    text=True
                )
                print(f"Daily SBOM generation completed. Exit code: {result.returncode}", file=sys.stderr)
                if result.stdout:
                    print(f"Output: {result.stdout}", file=sys.stderr)
                if result.stderr:
                    print(f"Errors: {result.stderr}", file=sys.stderr)
            else:
                print(f"DailyRun.sh not found at {script_path}", file=sys.stderr)
        except Exception as e:
            print(f"Error running daily SBOM generation: {e}", file=sys.stderr)
    
    # Schedule to run daily at 2 AM
    schedule.every().day.at("02:00").do(run_daily_sbom_generation)
    
    def run_scheduler():
        """Run the scheduler in a background thread"""
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    print("Daily SBOM generation scheduler started (runs daily at 2:00 AM)", file=sys.stderr)


@app.route('/api/run-daily-sbom', methods=['POST'])
def trigger_daily_sbom():
    """API endpoint to manually trigger daily SBOM generation"""
    try:
        import subprocess
        script_path = BACKEND_DIR / 'DailyRun.sh'
        
        if not script_path.exists():
            return jsonify({
                'success': False,
                'error': 'DailyRun.sh not found'
            }), 404
        
        # Run in background
        subprocess.Popen(
            ['bash', str(script_path)],
            cwd=str(BACKEND_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        return jsonify({
            'success': True,
            'message': 'Daily SBOM generation started in background'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/daily-run-status', methods=['GET'])
def get_daily_run_status():
    """API endpoint to get status of the last daily run"""
    try:
        log_dir = BACKEND_DIR / 'logs'
        if not log_dir.exists():
            return jsonify({
                'success': True,
                'hasRun': False,
                'message': 'No daily runs have been executed yet'
            })
        
        # Find the most recent log file
        log_files = sorted(log_dir.glob('daily_run_*.log'), key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not log_files:
            return jsonify({
                'success': True,
                'hasRun': False,
                'message': 'No log files found'
            })
        
        latest_log = log_files[0]
        
        # Read the last few lines of the log
        with open(latest_log, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            last_lines = lines[-20:] if len(lines) > 20 else lines
        
        return jsonify({
            'success': True,
            'hasRun': True,
            'logFile': latest_log.name,
            'lastModified': datetime.fromtimestamp(latest_log.stat().st_mtime).isoformat(),
            'lastLines': ''.join(last_lines)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Start daily scheduler
    try:
        import schedule
        schedule_daily_runs()
    except ImportError:
        print("Warning: 'schedule' package not installed. Daily runs will not be scheduled.", file=sys.stderr)
        print("Install with: pip install schedule", file=sys.stderr)
    
    # Get port from environment variable, default to 8080
    port = int(os.environ.get('PORT', 8080))
    # Only enable debug mode if explicitly set in environment
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(debug=debug, host='0.0.0.0', port=port)

