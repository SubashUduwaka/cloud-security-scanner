#!/usr/bin/env python3
"""
WSGI Entry Point for Aegis Cloud Scanner
Production-ready WSGI application configuration
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

# Add application directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app import app as application
    from config import get_config
except ImportError:
    # Fallback if config doesn't exist yet
    from app import app as application

# Set production environment
os.environ.setdefault('FLASK_ENV', 'production')

# Configure production logging
if not application.debug and not application.testing:
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Setup file logging
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'aegis_production.log'),
        maxBytes=10240000,  # 10MB
        backupCount=10
    )

    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))

    file_handler.setLevel(logging.INFO)
    application.logger.addHandler(file_handler)
    application.logger.setLevel(logging.INFO)
    application.logger.info('Aegis Cloud Scanner production startup')

# Ensure database is properly initialized
with application.app_context():
    try:
        from app import db
        db.create_all()
        application.logger.info('Database tables created/verified successfully')
    except Exception as e:
        application.logger.error(f'Database initialization error: {str(e)}')

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5000)