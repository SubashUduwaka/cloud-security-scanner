#!/usr/bin/env python3
"""
AEGIS CLOUD SCANNER - LIVE DEMO LOGGER
=====================================

This script provides an enhanced live terminal display for demonstrating
the Aegis Cloud Scanner application to interview panels.

Features:
- Real-time color-coded activity monitoring
- Simulated security scanning activities
- Live statistics and metrics
- Professional demo presentation

Usage: python demo_logger.py
"""

import time
import threading
from aegis_logger import init_demo_logging, live_logger, log_scan_start, log_scan_complete, log_vulnerability, log_critical_finding, log_user_action, log_api_call, log_database_operation, log_authentication, log_security_event

def demo_startup_sequence():
    """Demonstrate the full startup sequence"""
    print("\n🚀 Starting Aegis Cloud Scanner Demo Logger...")
    time.sleep(1)

    # Initialize the enhanced logging system
    demo_logger = init_demo_logging()

    return demo_logger

def simulate_user_interactions():
    """Simulate realistic user interactions with the application"""
    time.sleep(3)  # Wait for startup to complete

    # Simulate user login
    log_authentication("User authentication initiated", "demo_user", True)
    time.sleep(1)

    # Simulate dashboard access
    log_user_action("Dashboard accessed", "Viewing security overview")
    time.sleep(2)

    # Simulate API calls
    log_api_call("/api/v1/dashboard/notifications", "GET")
    time.sleep(1)
    log_api_call("/api/v1/scan/aws", "POST")
    time.sleep(2)

    # Simulate scanning activities
    log_scan_start("AWS", "S3 Buckets")
    time.sleep(3)
    log_vulnerability("S3", "HIGH", "Public bucket with sensitive data detected")
    time.sleep(1)
    log_scan_complete("AWS", 3)
    time.sleep(2)

    # Simulate critical finding
    log_critical_finding("Unencrypted RDS instance exposed to internet", "Database: prod-db-001")
    time.sleep(2)

    # Simulate more user actions
    log_user_action("Report generated", "Security assessment PDF")
    log_database_operation("INSERT", "scan_results")
    time.sleep(1)

    # Simulate GCP scanning
    log_scan_start("GCP", "Compute Engine")
    time.sleep(2)
    log_vulnerability("GCE", "MEDIUM", "VM instance without OS patch management")
    log_scan_complete("GCP", 1)
    time.sleep(2)

    # Simulate Azure scanning
    log_scan_start("Azure", "Storage Accounts")
    time.sleep(2)
    log_scan_complete("Azure", 0)
    time.sleep(1)

    # Simulate security events
    log_security_event("Failed login attempt detected", "WARNING")
    time.sleep(1)
    log_security_event("Multiple failed 2FA attempts", "CRITICAL")
    time.sleep(2)

    # Simulate admin actions
    log_user_action("User settings updated", "2FA enabled")
    log_database_operation("UPDATE", "users")

    print(f"\n🎯 Demo sequence completed! The application is now running with live activity monitoring.")
    print(f"📊 Current stats: {live_logger.get_demo_stats()}")

def main():
    """Main demo function"""
    try:
        # Start the demo logger
        demo_logger = demo_startup_sequence()

        # Start simulated user interactions in a separate thread
        interaction_thread = threading.Thread(target=simulate_user_interactions, daemon=True)
        interaction_thread.start()

        # Keep the demo running
        print(f"\n💡 Press Ctrl+C to stop the demo logger")
        print(f"🔍 This terminal will show all live activities from the Aegis application\n")

        while True:
            time.sleep(10)
            # Periodically show updated stats
            if hasattr(demo_logger, 'print_stats_header'):
                demo_logger.print_stats_header()

    except KeyboardInterrupt:
        print(f"\n\n🛑 Demo logger stopped by user")
        print(f"👋 Thank you for viewing the Aegis Cloud Scanner demonstration!")
    except Exception as e:
        print(f"\n❌ Error in demo logger: {e}")

if __name__ == "__main__":
    main()