#!/usr/bin/env python3
"""
AutoRedTeam Web API Server
Flask backend for the web-based vulnerability scanner
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sys
import json
import uuid
from datetime import datetime
import threading
import time

# Add parent directory to path to import autoredteam modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from autoredteam.main import AutoRedTeam
from autoredteam.model import ScanResult, Vulnerability, VulnerabilityType, RiskLevel

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Store active scans
active_scans = {}

class ScanManager:
    def __init__(self):
        self.scanner = AutoRedTeam()
    
    def start_scan(self, scan_data):
        """Start a new scan in a separate thread"""
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'data': None,
            'error': None,
            'start_time': datetime.now().isoformat()
        }
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, scan_data)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_scan(self, scan_id, scan_data):
        """Run the actual scan"""
        try:
            # Update status
            active_scans[scan_id]['status'] = 'running'
            active_scans[scan_id]['progress'] = 10
            
            # Run the scan using AutoRedTeam
            result = self.scanner.run_scan(
                target_url=scan_data['target_url'],
                max_urls=scan_data.get('max_urls', 20)
            )
            
            # Update status with results
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['progress'] = 100
            active_scans[scan_id]['data'] = result.to_dict() if result else {
                'target_url': scan_data['target_url'],
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_urls_discovered': 0,
                'total_urls_tested': 0,
                'vulnerabilities': []
            }
            
        except Exception as e:
            # Update status with error
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['error'] = str(e)
            print(f"Scan {scan_id} failed: {e}")
    
    def get_scan_status(self, scan_id):
        """Get the status of a scan"""
        if scan_id not in active_scans:
            return None
        return active_scans[scan_id]
    
    def cleanup_old_scans(self):
        """Clean up scans older than 1 hour"""
        current_time = datetime.now()
        to_remove = []
        
        for scan_id, scan_data in active_scans.items():
            if scan_data['status'] in ['completed', 'failed']:
                start_time = datetime.fromisoformat(scan_data['start_time'])
                if (current_time - start_time).total_seconds() > 3600:  # 1 hour
                    to_remove.append(scan_id)
        
        for scan_id in to_remove:
            del active_scans[scan_id]

# Initialize scan manager
scan_manager = ScanManager()

@app.route('/')
def index():
    """API root endpoint"""
    return jsonify({
        'message': 'AutoRedTeam Web API',
        'version': '1.0.0',
        'endpoints': {
            'POST /api/scan': 'Start a new vulnerability scan',
            'GET /api/scan/<scan_id>': 'Get scan status and results',
            'GET /api/download/<scan_id>/<type>': 'Download scan report'
        }
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'target_url' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: target_url'
            }), 400
        
        # Validate URL format
        target_url = data['target_url']
        if not target_url.startswith(('http://', 'https://')):
            return jsonify({
                'success': False,
                'error': 'Invalid URL format. Must start with http:// or https://'
            }), 400
        
        # Start the scan
        scan_id = scan_manager.start_scan(data)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to start scan: {str(e)}'
        }), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status and results of a scan"""
    try:
        scan_data = scan_manager.get_scan_status(scan_id)
        
        if not scan_data:
            return jsonify({
                'success': False,
                'error': 'Scan not found'
            }), 404
        
        response = {
            'success': True,
            'scan_id': scan_id,
            'status': scan_data['status'],
            'progress': scan_data['progress']
        }
        
        if scan_data['status'] == 'completed':
            response['data'] = scan_data['data']
        elif scan_data['status'] == 'failed':
            response['error'] = scan_data['error']
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get scan status: {str(e)}'
        }), 500

@app.route('/api/download/<scan_id>/<report_type>', methods=['GET'])
def download_report(scan_id, report_type):
    """Download scan report in specified format"""
    try:
        scan_data = scan_manager.get_scan_status(scan_id)
        
        if not scan_data:
            return jsonify({
                'success': False,
                'error': 'Scan not found'
            }), 404
        
        if scan_data['status'] != 'completed':
            return jsonify({
                'success': False,
                'error': 'Scan not completed'
            }), 400
        
        if report_type not in ['pdf', 'json']:
            return jsonify({
                'success': False,
                'error': 'Invalid report type. Use "pdf" or "json"'
            }), 400
        
        # Generate report file
        if report_type == 'json':
            # Return JSON data directly
            return jsonify(scan_data['data'])
        else:
            # Generate PDF report
            from autoredteam.report import generate_report
            
            vulnerabilities = scan_data['data']['vulnerabilities']
            report_filename = f"vulnerability_report_{scan_id}.pdf"
            
            # Convert to format expected by report generator
            report_data = []
            for vuln in vulnerabilities:
                report_data.append({
                    'url': vuln['url'],
                    'vuln': vuln['vulnerability_type']
                })
            
            generate_report(report_data, report_filename)
            
            # Send file
            return send_file(
                report_filename,
                as_attachment=True,
                download_name=report_filename,
                mimetype='application/pdf'
            )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to download report: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_scans': len([s for s in active_scans.values() if s['status'] == 'running'])
    })

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans (for debugging)"""
    # Clean up old scans first
    scan_manager.cleanup_old_scans()
    
    scans = []
    for scan_id, scan_data in active_scans.items():
        scans.append({
            'scan_id': scan_id,
            'status': scan_data['status'],
            'start_time': scan_data['start_time'],
            'target_url': scan_data['data']['target_url'] if scan_data['data'] else None
        })
    
    return jsonify({
        'success': True,
        'scans': scans
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500

if __name__ == '__main__':
    print("AutoRedTeam Web API Server")
    print("=" * 40)
    print("Starting server on http://localhost:5000")
    print("Frontend should be served from the frontend/ directory")
    print("=" * 40)
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    ) 