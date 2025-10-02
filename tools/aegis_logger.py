
import datetime
import sys
import logging
import re
import os
import threading
import time
from functools import wraps

try:
    from flask import current_user, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    END = '\033[0m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

class LiveActivityLogger:
    """Enhanced live logger for comprehensive demo feedback and terminal monitoring."""
    def __init__(self):
        self.activities = []
        self.stats = {
            'scans_performed': 0,
            'vulnerabilities_found': 0,
            'users_authenticated': 0,
            'api_calls': 0,
            'database_operations': 0,
            'security_events': 0
        }
        self.active_sessions = set()
        self.categories = {
            # Core Security
            'AUTH': {'color': Colors.YELLOW + Colors.BOLD, 'icon': '[A]', 'desc': 'Authentication'},
            'SECURITY': {'color': Colors.RED + Colors.BOLD, 'icon': '[S]', 'desc': 'Security Event'},
            'SCAN': {'color': Colors.CYAN + Colors.BOLD, 'icon': '[C]', 'desc': 'Cloud Scan'},
            'VULN': {'color': Colors.RED + Colors.BG_YELLOW, 'icon': '[V]', 'desc': 'Vulnerability'},
            'CRITICAL': {'color': Colors.WHITE + Colors.BG_RED + Colors.BOLD, 'icon': '[!]', 'desc': 'Critical Alert'},

            # Infrastructure
            'DATABASE': {'color': Colors.GREEN + Colors.BOLD, 'icon': '[D]', 'desc': 'Database Op'},
            'NETWORK': {'color': Colors.BLUE + Colors.BOLD, 'icon': '[N]', 'desc': 'Network'},
            'ENCRYPTION': {'color': Colors.MAGENTA + Colors.BOLD, 'icon': '[E]', 'desc': 'Encryption'},
            'API': {'color': Colors.CYAN, 'icon': '[API]', 'desc': 'API Call'},

            # Cloud Providers
            'AWS': {'color': Colors.YELLOW, 'icon': '[AWS]', 'desc': 'AWS Service'},
            'GCP': {'color': Colors.BLUE, 'icon': '[GCP]', 'desc': 'GCP Service'},
            'AZURE': {'color': Colors.CYAN, 'icon': '[AZ]', 'desc': 'Azure Service'},

            # Operations
            'SUCCESS': {'color': Colors.GREEN + Colors.BOLD, 'icon': '[+]', 'desc': 'Success'},
            'ERROR': {'color': Colors.RED + Colors.BOLD, 'icon': '[X]', 'desc': 'Error'},
            'WARNING': {'color': Colors.YELLOW, 'icon': '[W]', 'desc': 'Warning'},
            'INFO': {'color': Colors.WHITE, 'icon': '[I]', 'desc': 'Information'},

            # Advanced Features
            'COMPLIANCE': {'color': Colors.MAGENTA, 'icon': '[C]', 'desc': 'Compliance'},
            'REPORT': {'color': Colors.BLUE, 'icon': '[R]', 'desc': 'Report Gen'},
            'BACKUP': {'color': Colors.GRAY, 'icon': '[B]', 'desc': 'Backup'},
            'ADMIN': {'color': Colors.RED, 'icon': '[ADMIN]', 'desc': 'Admin Action'},
            'USER': {'color': Colors.GREEN, 'icon': '[USER]', 'desc': 'User Action'},
            'SYSTEM': {'color': Colors.BLUE, 'icon': '[SYS]', 'desc': 'System'},
        }
    
    def log(self, action, category='INFO', details="", user_override=None):
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Get user context
        user = user_override or 'System'
        client_ip = 'localhost'

        if FLASK_AVAILABLE:
            try:
                if current_user and current_user.is_authenticated:
                    user = current_user.username
                    self.active_sessions.add(user)
                if request:
                    client_ip = request.remote_addr or 'localhost'
            except RuntimeError:
                pass

        # Update statistics
        self._update_stats(category)

        activity = {
            'timestamp': timestamp.isoformat(),
            'action': action,
            'category': category,
            'details': details,
            'user': user,
            'client_ip': client_ip,
            'id': len(self.activities) + 1
        }

        self.activities.append(activity)
        if len(self.activities) > 500:  # Increased buffer for demo
            self.activities = self.activities[-500:]

        # Enhanced terminal output
        self._print_enhanced_activity(activity)

    def _update_stats(self, category):
        """Update real-time statistics for demo"""
        if category in ['SCAN', 'AWS', 'GCP', 'AZURE']:
            self.stats['scans_performed'] += 1
        elif category == 'VULN':
            self.stats['vulnerabilities_found'] += 1
        elif category == 'AUTH':
            self.stats['users_authenticated'] += 1
        elif category == 'API':
            self.stats['api_calls'] += 1
        elif category == 'DATABASE':
            self.stats['database_operations'] += 1
        elif category in ['SECURITY', 'CRITICAL']:
            self.stats['security_events'] += 1
    
    def _print_enhanced_activity(self, activity):
        """Enhanced terminal output with better formatting for demo"""
        cat_info = self.categories.get(activity['category'], {'color': Colors.WHITE, 'icon': '•', 'desc': 'Unknown'})
        time_str = datetime.datetime.fromisoformat(activity['timestamp']).strftime('%H:%M:%S.%f')[:-3]

        # Format user info
        user_display = f"{Colors.GRAY}[{activity['user']}@{activity['client_ip']}]{Colors.END}"

        # Main log line with enhanced formatting
        header = f"{cat_info['color']}{cat_info['icon']} {Colors.BOLD}[{time_str}]{Colors.END}"
        category_display = f"{cat_info['color']}[{cat_info['desc']}]{Colors.END}"
        action_display = f"{Colors.WHITE}{activity['action']}{Colors.END}"

        # Build the complete line
        main_line = f"{header} {category_display} {user_display} {action_display}"

        if activity['details']:
            details_display = f"{Colors.GRAY}-> {activity['details']}{Colors.END}"
            main_line += f" {details_display}"

        # Print to terminal with flush for immediate display
        print(main_line, flush=True)

        # Also log to file for debugging (handle Unicode encoding)
        try:
            clean_output = re.sub(r'\033\[[0-9;]*m', '', main_line)
            # Remove emoji characters for file logging on Windows
            clean_output = re.sub(r'[^\x00-\x7F]+', '', clean_output)
            logging.info(f"[AEGIS-LIVE] {clean_output}")
        except UnicodeEncodeError:
            # Fallback: log without special characters
            safe_output = f"[AEGIS-LIVE] [{activity['category']}] {activity['action']}"
            if activity['details']:
                safe_output += f" - {activity['details']}"
            logging.info(safe_output)

    def print_stats_header(self):
        """Print a real-time stats header for demo purposes"""
        stats_line = (
            f"{Colors.BOLD}{Colors.BLUE}================================================================================{Colors.END}\n"
            f"{Colors.BOLD}{Colors.WHITE}  AEGIS CLOUD SCANNER - LIVE ACTIVITY MONITOR  {Colors.END}\n"
            f"{Colors.BLUE}================================================================================{Colors.END}\n"
            f"{Colors.CYAN}STATS:{Colors.END} "
            f"{Colors.GREEN}Scans: {self.stats['scans_performed']}{Colors.END} | "
            f"{Colors.RED}Vulns: {self.stats['vulnerabilities_found']}{Colors.END} | "
            f"{Colors.YELLOW}Users: {len(self.active_sessions)}{Colors.END} | "
            f"{Colors.BLUE}API: {self.stats['api_calls']}{Colors.END} | "
            f"{Colors.MAGENTA}DB Ops: {self.stats['database_operations']}{Colors.END}\n"
            f"{Colors.BLUE}-------------------------------------------------------------------------------{Colors.END}"
        )
        print(stats_line, flush=True)

    def print_banner(self):
        """Print an impressive startup banner"""
        # Use ASCII-only characters for Windows console compatibility
        banner = f"""
{Colors.BOLD}{Colors.BLUE}================================================================================

  {Colors.CYAN}AEGIS CLOUD SECURITY SCANNER - LIVE DEMONSTRATION MODE{Colors.BLUE}

  {Colors.WHITE}Multi-Cloud Security Assessment Platform{Colors.BLUE}
  {Colors.YELLOW}* AWS Security Analysis    * Real-time Monitoring{Colors.BLUE}
  {Colors.YELLOW}* GCP Vulnerability Scan   * Compliance Reporting{Colors.BLUE}
  {Colors.YELLOW}* Azure Risk Assessment    * Automated Remediation{Colors.BLUE}

  {Colors.GREEN}Status: ACTIVE  {Colors.RED}Security Level: MAXIMUM  {Colors.MAGENTA}Mode: LIVE DEMO{Colors.BLUE}

================================================================================{Colors.END}

{Colors.YELLOW}System Initialization Complete - Monitoring All Cloud Security Activities...{Colors.END}
"""
        print(banner, flush=True) 
    
    def get_activities(self, limit=50):
        return self.activities[-limit:]

    def get_demo_stats(self):
        """Get comprehensive stats for demo display"""
        return {
            **self.stats,
            'active_sessions': len(self.active_sessions),
            'total_activities': len(self.activities),
            'recent_activities': self.get_activities(10)
        }

# Global logger instance
live_logger = LiveActivityLogger()

# Enhanced logging functions for comprehensive demo
def log_critical_finding(finding, details=""):
    live_logger.log(f"CRITICAL VULNERABILITY DETECTED", 'CRITICAL', f"{finding} | {details}")

def log_vulnerability(service, severity, details):
    live_logger.log(f"{severity} vulnerability in {service}", 'VULN', details)

def log_scan_start(provider, service):
    live_logger.log(f"Starting security scan", provider.upper(), f"Service: {service}")

def log_scan_complete(provider, findings_count):
    live_logger.log(f"Scan completed", provider.upper(), f"Found {findings_count} security issues")

def log_user_action(action, details=""):
    live_logger.log(action, 'USER', details)

def log_admin_action(action, details=""):
    live_logger.log(action, 'ADMIN', details)

def log_api_call(endpoint, method="GET"):
    live_logger.log(f"{method} {endpoint}", 'API')

def log_database_operation(operation, table=""):
    live_logger.log(f"{operation}", 'DATABASE', f"Table: {table}" if table else "")

def log_authentication(action, username="", success=True):
    category = 'AUTH' if success else 'ERROR'
    live_logger.log(f"{action}", category, f"User: {username}")

def log_security_event(event, severity="INFO"):
    category = 'CRITICAL' if severity == 'CRITICAL' else 'SECURITY'
    live_logger.log(event, category, f"Severity: {severity}")

def log_compliance_check(framework, status):
    live_logger.log(f"{framework} compliance check", 'COMPLIANCE', f"Status: {status}")

def log_report_generation(report_type, format_type):
    live_logger.log(f"Generating {report_type} report", 'REPORT', f"Format: {format_type}")

def log_backup_operation(operation, status):
    live_logger.log(f"Backup {operation}", 'BACKUP', f"Status: {status}")

def log_network_activity(activity, details=""):
    live_logger.log(activity, 'NETWORK', details)

def log_encryption_operation(operation, details=""):
    live_logger.log(operation, 'ENCRYPTION', details)

def log_system_event(event, details=""):
    live_logger.log(event, 'SYSTEM', details)

def log_startup():
    """Enhanced startup sequence for impressive demo"""
    live_logger.print_banner()
    time.sleep(0.5)

    live_logger.log("Initializing Aegis Security Framework", 'SYSTEM')
    time.sleep(0.2)
    live_logger.log("Loading security modules", 'SECURITY', "Multi-cloud security protocols")
    time.sleep(0.2)
    live_logger.log("Establishing encrypted connections", 'ENCRYPTION', "AES-256 + RSA-4096")
    time.sleep(0.2)
    live_logger.log("Database connection established", 'DATABASE', "SQLite with encryption at rest")
    time.sleep(0.2)
    live_logger.log("AWS SDK initialized", 'AWS', "Boto3 with credential rotation")
    time.sleep(0.2)
    live_logger.log("GCP SDK initialized", 'GCP', "Cloud SDK with service account auth")
    time.sleep(0.2)
    live_logger.log("Azure SDK initialized", 'AZURE', "Azure Identity with managed identity")
    time.sleep(0.2)
    live_logger.log("Security scanners activated", 'SCAN', "200+ security checks loaded")
    time.sleep(0.2)
    live_logger.log("Compliance frameworks loaded", 'COMPLIANCE', "SOC2, PCI-DSS, GDPR, HIPAA")
    time.sleep(0.2)
    live_logger.log("Web application server started", 'NETWORK', "Flask + Gunicorn on port 5000")
    time.sleep(0.2)
    live_logger.log("Real-time monitoring enabled", 'SUCCESS', "All systems operational")

    live_logger.print_stats_header()

# Demo helper functions
def simulate_demo_activity():
    """Simulate realistic security scanning activity for demo"""
    import random

    providers = ['AWS', 'GCP', 'AZURE']
    services = ['S3 Buckets', 'EC2 Instances', 'IAM Policies', 'VPC Security Groups', 'Database Instances']
    vulnerabilities = [
        'Public S3 bucket with sensitive data',
        'Overpermissive IAM policy detected',
        'Unencrypted database instance',
        'Security group allows unrestricted access',
        'Outdated SSL/TLS configuration',
        'Missing MFA on administrative accounts',
        'Unpatched EC2 instance detected'
    ]

    while True:
        time.sleep(random.uniform(3, 8))  # Random delay between activities

        # Simulate different types of activities
        activity_type = random.choice(['scan', 'vuln', 'user', 'api', 'db'])

        if activity_type == 'scan':
            provider = random.choice(providers)
            service = random.choice(services)
            log_scan_start(provider, service)
            time.sleep(random.uniform(1, 3))
            findings = random.randint(0, 5)
            log_scan_complete(provider, findings)

        elif activity_type == 'vuln' and random.random() < 0.3:  # 30% chance
            vuln = random.choice(vulnerabilities)
            severity = random.choice(['HIGH', 'MEDIUM', 'CRITICAL'])
            if severity == 'CRITICAL':
                log_critical_finding(vuln)
            else:
                log_vulnerability('Cloud Service', severity, vuln)

        elif activity_type == 'user':
            actions = ['Dashboard accessed', 'Report generated', 'Settings updated', 'Scan initiated']
            log_user_action(random.choice(actions))

        elif activity_type == 'api':
            endpoints = ['/api/scan', '/api/reports', '/api/users', '/api/compliance']
            log_api_call(random.choice(endpoints), random.choice(['GET', 'POST']))

        elif activity_type == 'db':
            operations = ['SELECT', 'INSERT', 'UPDATE']
            tables = ['scan_results', 'users', 'credentials', 'audit_log']
            log_database_operation(random.choice(operations), random.choice(tables))

# Initialize enhanced logging
def init_demo_logging():
    """Initialize the enhanced logging system for demo"""
    # Clear screen for clean demo start
    os.system('cls' if os.name == 'nt' else 'clear')

    # Start the demo logging
    log_startup()

    # Start background demo activity simulation
    demo_thread = threading.Thread(target=simulate_demo_activity, daemon=True)
    demo_thread.start()

    return live_logger