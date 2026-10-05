"""
ArgusOne — Flask API Server + WebSocket

REST API for alerts, stats, and hash-chain verification.
WebSocket for live alert streaming to the dashboard.
"""

import os
import sys
import json
import time
import logging
import threading
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO
from argusone.pipeline import ArgusOnePipeline
from argusone.traffic_generator import TrafficGenerator
from argusone.config import API_HOST, API_PORT, DATA_DIR, BASE_DIR

logger = logging.getLogger("argusone.api")

# Flask app
app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = 'argusone-sih2026-zerodayhunters'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global pipeline reference
pipeline = None
pipeline_thread = None


def alert_callback(alert_data):
    """Push alert to all connected WebSocket clients."""
    socketio.emit('new_alert', alert_data, namespace='/ws')


def create_pipeline():
    """Create and return the pipeline instance."""
    global pipeline
    pipeline = ArgusOnePipeline(alert_callback=alert_callback)
    return pipeline


# Initialize default pipeline on module import so store and stats are available
pipeline = create_pipeline()


# ─── Dashboard serving ───

DASHBOARD_DIR = os.path.join(BASE_DIR, 'dashboard')


@app.route('/')
def serve_dashboard():
    return send_from_directory(DASHBOARD_DIR, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(DASHBOARD_DIR, filename)


# ─── REST API ───

@app.route('/api/alerts')
def get_alerts():
    """Get alerts with optional filters."""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    threat_class = request.args.get('threat_class')
    severity = request.args.get('severity')

    if pipeline:
        alerts = pipeline.alert_store.get_alerts(
            limit=limit, offset=offset,
            threat_class=threat_class, severity=severity
        )
        return jsonify({'alerts': alerts, 'count': len(alerts)})
    return jsonify({'alerts': [], 'count': 0})


@app.route('/api/stats')
def get_stats():
    """Get pipeline and alert statistics."""
    if pipeline:
        return jsonify(pipeline.get_stats())
    return jsonify({'message': 'Pipeline not running'})


@app.route('/api/chain/verify')
def verify_chain():
    """Verify hash-chain integrity."""
    if pipeline:
        is_valid, details = pipeline.alert_store.verify_chain()
        return jsonify({
            'valid': is_valid,
            'details': details,
        })
    return jsonify({'valid': None, 'message': 'Pipeline not initialized'})


@app.route('/api/correlations')
def get_correlations():
    """Get active kill-chain correlations."""
    if pipeline:
        return jsonify({
            'correlations': pipeline.correlation.get_active_correlations()
        })
    return jsonify({'correlations': []})


@app.route('/api/dns')
def get_dns():
    """Get DNS deep inspection records."""
    return jsonify({'records': pipeline.get_dns_intel() if pipeline else []})


@app.route('/api/tls')
def get_tls():
    """Get TLS session inspection records."""
    return jsonify({'records': pipeline.get_tls_intel() if pipeline else []})


@app.route('/api/sources')
def get_sources():
    """Get host threat intelligence profiles."""
    return jsonify({'sources': pipeline.get_source_intel() if pipeline else []})


@app.route('/api/timeline')
def get_timeline():
    """Get MITRE ATT&CK chronological event timeline."""
    return jsonify({'timeline': pipeline.get_timeline() if pipeline else []})


@app.route('/api/telemetry')
def get_telemetry():
    """Get system telemetry and pipeline health."""
    return jsonify(pipeline.get_system_telemetry() if pipeline else {})


@app.route('/api/database')
def get_database():
    """Get active enterprise database engine status."""
    return jsonify(pipeline.alert_store.get_db_status() if pipeline else {})


@app.route('/api/generate', methods=['POST'])
def generate_traffic():
    """Generate synthetic demo traffic."""
    duration = request.json.get('duration', 120) if request.json else 120
    logger.info(f"Generating {duration}s of synthetic traffic...")
    gen = TrafficGenerator()
    gen.generate_all(duration_sec=duration)
    filepath = gen.save_pcap("demo_traffic.pcap")
    return jsonify({
        'status': 'ok',
        'pcap_path': filepath,
        'packet_count': len(gen.packets),
    })


@app.route('/api/run', methods=['POST'])
def run_pipeline():
    """Start the pipeline on a PCAP file."""
    global pipeline, pipeline_thread

    pcap_path = None
    if request.json:
        pcap_path = request.json.get('pcap_path')

    if not pcap_path:
        pcap_path = os.path.join(DATA_DIR, "demo_traffic.pcap")

    if not os.path.exists(pcap_path):
        return jsonify({'error': f'PCAP not found: {pcap_path}'}), 404

    if pipeline and pipeline.stats.get('is_running'):
        return jsonify({'error': 'Pipeline already running'}), 409

    pipeline = create_pipeline()

    def run_in_thread():
        try:
            pipeline.run(pcap_path, speed=0.0)
            socketio.emit('pipeline_complete', pipeline.get_stats(), namespace='/ws')
        except Exception as e:
            logger.error(f"Pipeline thread error: {e}")
            socketio.emit('pipeline_error', {'error': str(e)}, namespace='/ws')

    pipeline_thread = threading.Thread(target=run_in_thread, daemon=True)
    pipeline_thread.start()

    return jsonify({'status': 'started', 'pcap': pcap_path})


@app.route('/api/stop', methods=['POST'])
def stop_pipeline():
    """Stop the running pipeline."""
    if pipeline:
        pipeline.stop()
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})


# ─── WebSocket Events ───

@socketio.on('connect', namespace='/ws')
def ws_connect():
    logger.info("Dashboard client connected")
    if pipeline:
        socketio.emit('stats_update', pipeline.get_stats(), namespace='/ws')


@socketio.on('request_stats', namespace='/ws')
def ws_request_stats():
    if pipeline:
        socketio.emit('stats_update', pipeline.get_stats(), namespace='/ws')


# ─── Entry Point ───

def start_server(host=None, port=None, debug=False):
    """Start the ArgusOne API server."""
    host = host or API_HOST
    port = port or API_PORT

    logger.info(f"ArgusOne API server starting on http://{host}:{port}")
    print(f"\n{'='*60}")
    print(f"  ArgusOne — Passive AI Threat-Intelligence Pipeline")
    print(f"  Team: ZeroDay Hunters | SIH 2026 | SIH26145")
    print(f"{'='*60}")
    print(f"  Dashboard: http://localhost:{port}")
    print(f"  API:       http://localhost:{port}/api/stats")
    print(f"{'='*60}\n")

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
