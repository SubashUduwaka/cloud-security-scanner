#!/usr/bin/env python3
"""
Production Server Launcher for Aegis Cloud Scanner
==================================================

Uses Waitress WSGI server for production deployments on Windows and cross-platform.
This is a production-ready alternative to Flask's development server.

Features:
- Cross-platform (Windows, Linux, macOS)
- Production-ready performance
- Multi-threaded request handling
- Proper error handling
- Graceful shutdown

Usage:
    python run_production.py

Configuration:
    - Host: 0.0.0.0 (accessible from network)
    - Port: 5000
    - Threads: 4 (adjustable based on CPU cores)
"""

import os
import sys
import logging
from waitress import serve

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def main():
    """Launch Aegis Cloud Scanner with Waitress production server."""

    # Import the Flask application
    try:
        from wsgi import application
        logger.info("[OK] Successfully imported Flask application")
    except ImportError as e:
        logger.error(f"[ERROR] Failed to import application: {e}")
        logger.error("Make sure wsgi.py exists in the current directory")
        sys.exit(1)

    # Configuration
    host = os.environ.get('AEGIS_HOST', '0.0.0.0')
    port = int(os.environ.get('AEGIS_PORT', 5000))
    threads = int(os.environ.get('AEGIS_THREADS', 4))

    # Display startup banner
    print("\n" + "=" * 60)
    print("  AEGIS CLOUD SECURITY SCANNER - PRODUCTION SERVER")
    print("=" * 60)
    print(f"  Server:    Waitress WSGI Server")
    print(f"  Version:   0.9.2")
    print(f"  Host:      {host}")
    print(f"  Port:      {port}")
    print(f"  Threads:   {threads}")
    print(f"  URL:       http://localhost:{port}")
    print("=" * 60)
    print("\n[OK] Server is starting...\n")
    print("Access the application at: http://localhost:5000")
    print("Network access at: http://<your-ip>:5000")
    print("\n[WARNING] Press Ctrl+C to stop the server\n")
    print("=" * 60 + "\n")

    # Start Waitress server
    try:
        logger.info(f"Starting Waitress server on {host}:{port}")
        serve(
            application,
            host=host,
            port=port,
            threads=threads,
            url_scheme='http',
            ident='Aegis Cloud Scanner/0.9.2',
            # Performance tuning
            channel_timeout=120,
            cleanup_interval=30,
            # Security
            expose_tracebacks=False,
            # Connection settings
            connection_limit=1000,
            backlog=2048
        )
    except KeyboardInterrupt:
        logger.info("\n\n[SHUTDOWN] Server shutdown requested by user")
        print("\n" + "=" * 60)
        print("  Server stopped gracefully")
        print("=" * 60 + "\n")
    except Exception as e:
        logger.error(f"\n\n[ERROR] Server error: {e}")
        print("\n" + "=" * 60)
        print(f"  ERROR: {e}")
        print("  Please check the logs above for details")
        print("=" * 60 + "\n")
        sys.exit(1)

if __name__ == '__main__':
    main()
