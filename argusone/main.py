"""
ArgusOne — Main Entry Point

Usage:
    python -m argusone.main                    # Start server + dashboard
    python -m argusone.main --generate         # Generate demo traffic first
    python -m argusone.main --run-demo         # Generate traffic + run pipeline + start server
"""

import os
import sys
import logging
import argparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)-20s | %(levelname)-7s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("argusone")


def main():
    parser = argparse.ArgumentParser(description="ArgusOne — AI Threat Detection Pipeline")
    parser.add_argument('--generate', action='store_true', help='Generate synthetic demo traffic')
    parser.add_argument('--run-demo', action='store_true', help='Generate + run pipeline + start server')
    parser.add_argument('--pcap', type=str, help='Path to PCAP file to analyze')
    parser.add_argument('--port', type=int, default=5000, help='API server port')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='API server host')
    args = parser.parse_args()

    if args.generate or args.run_demo:
        logger.info("Generating synthetic demo traffic...")
        from argusone.traffic_generator import TrafficGenerator
        gen = TrafficGenerator()
        gen.generate_all(duration_sec=120)
        pcap_path = gen.save_pcap("demo_traffic.pcap")
        logger.info(f"Demo traffic saved: {pcap_path}")

        if not args.run_demo:
            return

    if args.run_demo:
        logger.info("Starting ArgusOne in demo mode...")
        from argusone.api import create_pipeline, start_server, socketio, app
        from argusone.config import DATA_DIR
        import threading
        import time

        pipeline = create_pipeline()

        def run_pipeline_after_delay():
            time.sleep(2)  # Wait for server to start
            pcap_path = os.path.join(DATA_DIR, "demo_traffic.pcap")
            logger.info(f"Running pipeline on: {pcap_path}")
            try:
                pipeline.run(pcap_path, speed=0.0)
                socketio.emit('pipeline_complete', pipeline.get_stats(), namespace='/ws')
            except Exception as e:
                logger.error(f"Pipeline error: {e}")

        # Import and set the global pipeline
        import argusone.api as api_module
        api_module.pipeline = pipeline

        pipeline_thread = threading.Thread(target=run_pipeline_after_delay, daemon=True)
        pipeline_thread.start()

        start_server(host=args.host, port=args.port)

    else:
        # Just start the server (manual control via API)
        from argusone.api import start_server
        start_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
