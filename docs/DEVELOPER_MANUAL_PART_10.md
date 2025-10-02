# Aegis Cloud Scanner Developer Manual - Part 10
## Troubleshooting and Maintenance

### Table of Contents
1. [Debugging and Troubleshooting](#debugging-and-troubleshooting)
2. [Performance Optimization](#performance-optimization)
3. [System Monitoring](#system-monitoring)
4. [Operational Procedures](#operational-procedures)
5. [Maintenance Workflows](#maintenance-workflows)
6. [Error Handling and Recovery](#error-handling-and-recovery)
7. [Backup and Disaster Recovery](#backup-and-disaster-recovery)
8. [Health Checks and Diagnostics](#health-checks-and-diagnostics)

---

## 1. Debugging and Troubleshooting

### 1.1 Application Debugging

#### Local Development Debugging
```python
# app.py - Debug configuration
import logging
from flask import Flask
from werkzeug.debug import DebuggedApplication

app = Flask(__name__)

if app.config.get('DEBUG'):
    app.wsgi_app = DebuggedApplication(app.wsgi_app, True)
    app.logger.setLevel(logging.DEBUG)

    # Enable SQLAlchemy query logging
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Custom debug middleware
class DebugMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        if app.config.get('DEBUG'):
            print(f"Request: {environ['REQUEST_METHOD']} {environ['PATH_INFO']}")
            print(f"Headers: {dict(environ)}")
        return self.app(environ, start_response)

if __name__ == '__main__':
    app.wsgi_app = DebugMiddleware(app.wsgi_app)
    app.run(debug=True, host='0.0.0.0', port=5000)
```

#### Production Debugging Tools
```python
# utils/debug_tools.py
import traceback
import sys
from datetime import datetime
from functools import wraps

class ProductionDebugger:
    @staticmethod
    def debug_endpoint(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                start_time = datetime.now()
                result = func(*args, **kwargs)
                end_time = datetime.now()

                app.logger.info(f"Endpoint {func.__name__} executed in {end_time - start_time}")
                return result
            except Exception as e:
                app.logger.error(f"Error in {func.__name__}: {str(e)}")
                app.logger.error(traceback.format_exc())
                raise
        return wrapper

    @staticmethod
    def debug_database_queries():
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        @event.listens_for(Engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            app.logger.debug(f"SQL Query: {statement}")
            app.logger.debug(f"Parameters: {parameters}")
```

### 1.2 Common Issues and Solutions

#### Database Connection Issues
```python
# utils/db_troubleshooting.py
import psycopg2
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

class DatabaseTroubleshooter:
    def __init__(self, database_url):
        self.database_url = database_url

    def test_connection(self):
        try:
            engine = create_engine(self.database_url)
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                return True, "Database connection successful"
        except OperationalError as e:
            return False, f"Database connection failed: {str(e)}"

    def check_database_health(self):
        issues = []
        try:
            engine = create_engine(self.database_url)
            with engine.connect() as conn:
                # Check active connections
                result = conn.execute(text("""
                    SELECT count(*) as active_connections
                    FROM pg_stat_activity
                    WHERE state = 'active'
                """))
                active_conn = result.fetchone()[0]

                if active_conn > 50:
                    issues.append(f"High number of active connections: {active_conn}")

                # Check table sizes
                result = conn.execute(text("""
                    SELECT schemaname,tablename,pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
                    FROM pg_tables
                    WHERE schemaname = 'public'
                    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                """))

                for row in result:
                    if 'GB' in row[2] and float(row[2].split()[0]) > 1:
                        issues.append(f"Large table detected: {row[1]} - {row[2]}")

        except Exception as e:
            issues.append(f"Health check failed: {str(e)}")

        return issues
```

#### Cloud Provider Authentication Issues
```python
# utils/cloud_troubleshooting.py
import boto3
from google.cloud import storage
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

class CloudProviderTroubleshooter:
    @staticmethod
    def test_aws_credentials():
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            return True, f"AWS credentials valid. Account: {identity['Account']}"
        except Exception as e:
            return False, f"AWS credentials invalid: {str(e)}"

    @staticmethod
    def test_gcp_credentials():
        try:
            client = storage.Client()
            buckets = list(client.list_buckets(max_results=1))
            return True, "GCP credentials valid"
        except Exception as e:
            return False, f"GCP credentials invalid: {str(e)}"

    @staticmethod
    def test_azure_credentials():
        try:
            credential = DefaultAzureCredential()
            blob_service = BlobServiceClient(
                account_url="https://test.blob.core.windows.net",
                credential=credential
            )
            return True, "Azure credentials valid"
        except Exception as e:
            return False, f"Azure credentials invalid: {str(e)}"

    @staticmethod
    def diagnose_all_providers():
        results = {}
        results['aws'] = CloudProviderTroubleshooter.test_aws_credentials()
        results['gcp'] = CloudProviderTroubleshooter.test_gcp_credentials()
        results['azure'] = CloudProviderTroubleshooter.test_azure_credentials()
        return results
```

### 1.3 Logging and Monitoring

#### Advanced Logging Configuration
```python
# config/logging_config.py
import logging
import logging.handlers
import os
from datetime import datetime

class CustomFormatter(logging.Formatter):
    def format(self, record):
        record.timestamp = datetime.utcnow().isoformat()
        record.service = 'aegis-cloud-scanner'
        return super().format(record)

def setup_logging(app):
    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        'logs/app.log',
        maxBytes=10000000,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)

    # Custom formatter
    formatter = CustomFormatter(
        '[%(timestamp)s] %(levelname)s in %(module)s: %(message)s'
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)

    # Separate scanner logs
    scanner_logger = logging.getLogger('scanner')
    scanner_handler = logging.handlers.RotatingFileHandler(
        'logs/scanner.log',
        maxBytes=10000000,
        backupCount=10
    )
    scanner_handler.setFormatter(formatter)
    scanner_logger.addHandler(scanner_handler)
    scanner_logger.setLevel(logging.INFO)
```

---

## 2. Performance Optimization

### 2.1 Application Performance

#### Database Query Optimization
```python
# utils/performance_optimizer.py
from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

class QueryProfiler:
    def __init__(self):
        self.slow_queries = []

    def setup_profiling(self):
        @event.listens_for(Engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.time()

        @event.listens_for(Engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            total = time.time() - context._query_start_time
            if total > 1.0:  # Log queries taking more than 1 second
                self.slow_queries.append({
                    'query': statement,
                    'time': total,
                    'parameters': parameters
                })
                app.logger.warning(f"Slow query detected: {total:.2f}s - {statement[:100]}...")

# Database optimization utilities
class DatabaseOptimizer:
    @staticmethod
    def analyze_query_performance():
        """Analyze and suggest query optimizations"""
        suggestions = []

        # Check for missing indexes
        missing_indexes_query = """
        SELECT schemaname, tablename, attname, n_distinct, correlation
        FROM pg_stats
        WHERE schemaname = 'public'
        AND n_distinct > 100
        AND correlation < 0.1
        """

        # Check for unused indexes
        unused_indexes_query = """
        SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
        FROM pg_stat_user_indexes
        WHERE idx_tup_read = 0
        """

        return suggestions

    @staticmethod
    def optimize_scan_queries():
        """Optimize cloud scanning queries"""
        # Add composite indexes for common query patterns
        optimizations = [
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_user_timestamp ON scan_results(user_id, created_at DESC)",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_severity_status ON findings(severity, status)",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cloud_resources_provider_type ON cloud_resources(provider, resource_type)",
        ]
        return optimizations
```

#### Caching Strategy
```python
# utils/cache_optimizer.py
import redis
from functools import wraps
import json
import hashlib

class CacheManager:
    def __init__(self, redis_client):
        self.redis = redis_client

    def cache_result(self, expiration=3600):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Create cache key
                cache_key = f"{func.__name__}:{hashlib.md5(str(args + tuple(kwargs.items())).encode()).hexdigest()}"

                # Try to get from cache
                cached_result = self.redis.get(cache_key)
                if cached_result:
                    return json.loads(cached_result)

                # Execute function and cache result
                result = func(*args, **kwargs)
                self.redis.setex(cache_key, expiration, json.dumps(result, default=str))
                return result
            return wrapper
        return decorator

    def invalidate_pattern(self, pattern):
        """Invalidate cache entries matching pattern"""
        keys = self.redis.keys(pattern)
        if keys:
            self.redis.delete(*keys)

    def get_cache_stats(self):
        """Get cache hit/miss statistics"""
        info = self.redis.info()
        return {
            'hit_rate': info.get('keyspace_hits', 0) / (info.get('keyspace_hits', 0) + info.get('keyspace_misses', 1)),
            'memory_usage': info.get('used_memory_human'),
            'keys_count': self.redis.dbsize()
        }

# Application-specific caching
class ScanCacheManager(CacheManager):
    def cache_scan_results(self, scan_id, results):
        """Cache scan results with appropriate TTL"""
        cache_key = f"scan_results:{scan_id}"
        self.redis.setex(cache_key, 7200, json.dumps(results, default=str))  # 2 hours

    def get_cached_scan_results(self, scan_id):
        """Retrieve cached scan results"""
        cache_key = f"scan_results:{scan_id}"
        cached = self.redis.get(cache_key)
        return json.loads(cached) if cached else None

    def cache_cloud_resources(self, provider, region, resources):
        """Cache cloud resources discovery"""
        cache_key = f"resources:{provider}:{region}"
        self.redis.setex(cache_key, 1800, json.dumps(resources, default=str))  # 30 minutes
```

### 2.2 Scaling Strategies

#### Horizontal Scaling Configuration
```yaml
# k8s/horizontal-pod-autoscaler.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: aegis-scanner-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: aegis-scanner
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

#### Load Balancing Configuration
```nginx
# nginx/load_balancer.conf
upstream aegis_scanner {
    least_conn;
    server aegis-scanner-1:5000 weight=1 max_fails=3 fail_timeout=30s;
    server aegis-scanner-2:5000 weight=1 max_fails=3 fail_timeout=30s;
    server aegis-scanner-3:5000 weight=1 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name aegis-scanner.example.com;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=scan:10m rate=10r/m;

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://aegis_scanner;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 30s;
        proxy_read_timeout 60s;
    }

    location /scan {
        limit_req zone=scan burst=5 nodelay;
        proxy_pass http://aegis_scanner;
        proxy_read_timeout 300s;  # Extended timeout for scans
    }

    # Health check endpoint
    location /health {
        proxy_pass http://aegis_scanner;
        access_log off;
    }
}
```

---

## 3. System Monitoring

### 3.1 Application Metrics

#### Custom Metrics Collection
```python
# utils/metrics.py
import time
from functools import wraps
from collections import defaultdict, deque
import threading

class MetricsCollector:
    def __init__(self):
        self.metrics = defaultdict(list)
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.histograms = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.Lock()

    def timing(self, metric_name):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    self.record_timing(metric_name, time.time() - start_time)
                    return result
                except Exception as e:
                    self.increment_counter(f"{metric_name}.error")
                    raise
            return wrapper
        return decorator

    def record_timing(self, metric_name, duration):
        with self.lock:
            self.histograms[metric_name].append(duration)

    def increment_counter(self, metric_name, value=1):
        with self.lock:
            self.counters[metric_name] += value

    def set_gauge(self, metric_name, value):
        with self.lock:
            self.gauges[metric_name] = value

    def get_metrics(self):
        with self.lock:
            return {
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'histograms': {
                    name: {
                        'count': len(values),
                        'avg': sum(values) / len(values) if values else 0,
                        'min': min(values) if values else 0,
                        'max': max(values) if values else 0,
                        'p95': sorted(values)[int(len(values) * 0.95)] if values else 0
                    }
                    for name, values in self.histograms.items()
                }
            }

# Application-specific metrics
metrics = MetricsCollector()

@metrics.timing('scan.execution_time')
def execute_scan(provider, scan_type):
    # Scan implementation
    pass

def track_scan_metrics():
    metrics.increment_counter('scans.total')
    metrics.set_gauge('scans.active', get_active_scan_count())
    metrics.set_gauge('database.connections', get_db_connection_count())
```

#### Prometheus Integration
```python
# utils/prometheus_metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from flask import Response

# Define metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
SCAN_DURATION = Histogram('scan_duration_seconds', 'Cloud scan duration', ['provider', 'scan_type'])
ACTIVE_SCANS = Gauge('active_scans_total', 'Number of active scans')
DATABASE_CONNECTIONS = Gauge('database_connections_active', 'Active database connections')

class PrometheusMetrics:
    @staticmethod
    def track_request():
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    response = f(*args, **kwargs)
                    REQUEST_COUNT.labels(
                        method=request.method,
                        endpoint=request.endpoint,
                        status=response.status_code
                    ).inc()
                    REQUEST_DURATION.observe(time.time() - start_time)
                    return response
                except Exception as e:
                    REQUEST_COUNT.labels(
                        method=request.method,
                        endpoint=request.endpoint,
                        status=500
                    ).inc()
                    raise
            return wrapper
        return decorator

    @staticmethod
    def metrics_endpoint():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
```

### 3.2 Health Checks

#### Comprehensive Health Check System
```python
# utils/health_checks.py
import psutil
import redis
from sqlalchemy import text
from datetime import datetime, timedelta

class HealthChecker:
    def __init__(self, app, db, redis_client):
        self.app = app
        self.db = db
        self.redis = redis_client

    def check_database(self):
        try:
            with self.db.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {'status': 'healthy', 'message': 'Database connection OK'}
        except Exception as e:
            return {'status': 'unhealthy', 'message': f'Database error: {str(e)}'}

    def check_redis(self):
        try:
            self.redis.ping()
            return {'status': 'healthy', 'message': 'Redis connection OK'}
        except Exception as e:
            return {'status': 'unhealthy', 'message': f'Redis error: {str(e)}'}

    def check_disk_space(self):
        disk_usage = psutil.disk_usage('/')
        free_percent = (disk_usage.free / disk_usage.total) * 100

        if free_percent < 10:
            return {'status': 'unhealthy', 'message': f'Low disk space: {free_percent:.1f}% free'}
        elif free_percent < 20:
            return {'status': 'warning', 'message': f'Disk space warning: {free_percent:.1f}% free'}
        else:
            return {'status': 'healthy', 'message': f'Disk space OK: {free_percent:.1f}% free'}

    def check_memory(self):
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            return {'status': 'unhealthy', 'message': f'High memory usage: {memory.percent}%'}
        elif memory.percent > 80:
            return {'status': 'warning', 'message': f'Memory usage warning: {memory.percent}%'}
        else:
            return {'status': 'healthy', 'message': f'Memory usage OK: {memory.percent}%'}

    def check_cloud_providers(self):
        from utils.cloud_troubleshooting import CloudProviderTroubleshooter
        results = CloudProviderTroubleshooter.diagnose_all_providers()

        healthy_providers = sum(1 for status, _ in results.values() if status)
        total_providers = len(results)

        if healthy_providers == 0:
            return {'status': 'unhealthy', 'message': 'No cloud providers accessible'}
        elif healthy_providers < total_providers:
            return {'status': 'warning', 'message': f'{healthy_providers}/{total_providers} providers accessible'}
        else:
            return {'status': 'healthy', 'message': 'All cloud providers accessible'}

    def get_overall_health(self):
        checks = {
            'database': self.check_database(),
            'redis': self.check_redis(),
            'disk_space': self.check_disk_space(),
            'memory': self.check_memory(),
            'cloud_providers': self.check_cloud_providers()
        }

        overall_status = 'healthy'
        if any(check['status'] == 'unhealthy' for check in checks.values()):
            overall_status = 'unhealthy'
        elif any(check['status'] == 'warning' for check in checks.values()):
            overall_status = 'warning'

        return {
            'status': overall_status,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': checks
        }

# Health check endpoints
@app.route('/health')
def health_check():
    health_checker = HealthChecker(app, db, redis_client)
    health_status = health_checker.get_overall_health()

    status_code = 200
    if health_status['status'] == 'unhealthy':
        status_code = 503
    elif health_status['status'] == 'warning':
        status_code = 200  # Still serving but with warnings

    return jsonify(health_status), status_code

@app.route('/health/ready')
def readiness_check():
    # Kubernetes readiness probe
    health_checker = HealthChecker(app, db, redis_client)
    db_status = health_checker.check_database()
    redis_status = health_checker.check_redis()

    if db_status['status'] == 'healthy' and redis_status['status'] == 'healthy':
        return jsonify({'status': 'ready'}), 200
    else:
        return jsonify({'status': 'not ready'}), 503

@app.route('/health/live')
def liveness_check():
    # Kubernetes liveness probe
    return jsonify({'status': 'alive'}), 200
```

---

## 4. Operational Procedures

### 4.1 Deployment Procedures

#### Blue-Green Deployment Script
```bash
#!/bin/bash
# scripts/blue_green_deploy.sh

set -e

NAMESPACE="aegis-scanner"
APP_NAME="aegis-scanner"
NEW_VERSION=$1
CURRENT_VERSION=$(kubectl get deployment $APP_NAME -n $NAMESPACE -o jsonpath='{.spec.template.spec.containers[0].image}' | cut -d':' -f2)

if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new_version>"
    exit 1
fi

echo "Starting blue-green deployment from $CURRENT_VERSION to $NEW_VERSION"

# Step 1: Deploy green environment
echo "Deploying green environment..."
kubectl set image deployment/$APP_NAME-green $APP_NAME=$APP_NAME:$NEW_VERSION -n $NAMESPACE

# Step 2: Wait for green deployment to be ready
echo "Waiting for green deployment to be ready..."
kubectl rollout status deployment/$APP_NAME-green -n $NAMESPACE --timeout=300s

# Step 3: Run health checks on green environment
echo "Running health checks on green environment..."
GREEN_POD=$(kubectl get pods -n $NAMESPACE -l app=$APP_NAME-green -o jsonpath='{.items[0].metadata.name}')
kubectl exec $GREEN_POD -n $NAMESPACE -- curl -f http://localhost:5000/health/ready

# Step 4: Switch traffic to green
echo "Switching traffic to green environment..."
kubectl patch service $APP_NAME -n $NAMESPACE -p '{"spec":{"selector":{"version":"green"}}}'

# Step 5: Monitor for 5 minutes
echo "Monitoring green environment for 5 minutes..."
sleep 300

# Step 6: Check if rollback is needed
if kubectl exec $GREEN_POD -n $NAMESPACE -- curl -f http://localhost:5000/health; then
    echo "Green environment is healthy. Deployment successful!"

    # Update blue environment to new version for next deployment
    kubectl set image deployment/$APP_NAME-blue $APP_NAME=$APP_NAME:$NEW_VERSION -n $NAMESPACE
    echo "Updated blue environment to $NEW_VERSION"
else
    echo "Green environment unhealthy. Rolling back..."
    kubectl patch service $APP_NAME -n $NAMESPACE -p '{"spec":{"selector":{"version":"blue"}}}'
    echo "Rollback completed"
    exit 1
fi
```

#### Database Migration Procedures
```python
# scripts/migrate_database.py
import os
import sys
from flask import Flask
from flask_migrate import upgrade, downgrade, current
from sqlalchemy import create_engine, text
import subprocess
import time

class DatabaseMigrator:
    def __init__(self, app):
        self.app = app
        self.engine = create_engine(app.config['DATABASE_URL'])

    def backup_database(self):
        """Create database backup before migration"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        backup_file = f"db_backup_{timestamp}.sql"

        cmd = [
            'pg_dump',
            '--no-password',
            '--format=custom',
            '--file', backup_file,
            app.config['DATABASE_URL']
        ]

        try:
            subprocess.run(cmd, check=True)
            print(f"Database backup created: {backup_file}")
            return backup_file
        except subprocess.CalledProcessError as e:
            print(f"Backup failed: {e}")
            return None

    def check_migration_safety(self):
        """Check if migration is safe to run"""
        checks = []

        # Check for long-running transactions
        with self.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT count(*)
                FROM pg_stat_activity
                WHERE state = 'active'
                AND query_start < now() - interval '5 minutes'
            """))
            long_running = result.fetchone()[0]

            if long_running > 0:
                checks.append(f"Warning: {long_running} long-running transactions detected")

        # Check database size
        with self.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT pg_size_pretty(pg_database_size(current_database()))
            """))
            db_size = result.fetchone()[0]
            checks.append(f"Database size: {db_size}")

        return checks

    def migrate_with_monitoring(self):
        """Run migration with monitoring"""
        print("Starting database migration...")

        # Pre-migration checks
        safety_checks = self.check_migration_safety()
        for check in safety_checks:
            print(f"Pre-migration check: {check}")

        # Create backup
        backup_file = self.backup_database()
        if not backup_file:
            print("Migration aborted: backup failed")
            return False

        try:
            # Run migration
            with self.app.app_context():
                upgrade()
            print("Migration completed successfully")
            return True

        except Exception as e:
            print(f"Migration failed: {e}")

            # Offer rollback option
            rollback = input("Would you like to rollback? (y/N): ")
            if rollback.lower() == 'y':
                self.rollback_from_backup(backup_file)

            return False

    def rollback_from_backup(self, backup_file):
        """Rollback database from backup"""
        cmd = [
            'pg_restore',
            '--clean',
            '--if-exists',
            '--no-password',
            '--dbname', app.config['DATABASE_URL'],
            backup_file
        ]

        try:
            subprocess.run(cmd, check=True)
            print("Database rollback completed")
        except subprocess.CalledProcessError as e:
            print(f"Rollback failed: {e}")

if __name__ == '__main__':
    app = Flask(__name__)
    app.config.from_object('config.Config')

    migrator = DatabaseMigrator(app)
    migrator.migrate_with_monitoring()
```

### 4.2 Incident Response

#### Incident Response Playbook
```python
# utils/incident_response.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from datetime import datetime

class IncidentManager:
    def __init__(self, config):
        self.config = config
        self.severity_levels = {
            'critical': {'escalation_time': 15, 'notification_channels': ['email', 'sms', 'slack']},
            'high': {'escalation_time': 30, 'notification_channels': ['email', 'slack']},
            'medium': {'escalation_time': 60, 'notification_channels': ['email']},
            'low': {'escalation_time': 240, 'notification_channels': ['email']}
        }

    def create_incident(self, title, description, severity='medium', affected_services=None):
        incident = {
            'id': self.generate_incident_id(),
            'title': title,
            'description': description,
            'severity': severity,
            'status': 'open',
            'created_at': datetime.utcnow().isoformat(),
            'affected_services': affected_services or [],
            'timeline': []
        }

        self.save_incident(incident)
        self.notify_stakeholders(incident)
        return incident

    def update_incident(self, incident_id, update_text, status=None):
        incident = self.load_incident(incident_id)

        timeline_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'update': update_text
        }

        if status:
            timeline_entry['status_change'] = f"Status changed to: {status}"
            incident['status'] = status

        incident['timeline'].append(timeline_entry)
        self.save_incident(incident)

        if status == 'resolved':
            self.notify_resolution(incident)

    def escalate_incident(self, incident_id):
        incident = self.load_incident(incident_id)
        current_severity = incident['severity']

        severity_order = ['low', 'medium', 'high', 'critical']
        current_index = severity_order.index(current_severity)

        if current_index < len(severity_order) - 1:
            new_severity = severity_order[current_index + 1]
            incident['severity'] = new_severity

            self.update_incident(
                incident_id,
                f"Incident escalated from {current_severity} to {new_severity}",
                status='escalated'
            )

    def generate_incident_report(self, incident_id):
        incident = self.load_incident(incident_id)

        report = f"""
        Incident Report: {incident['title']}

        Incident ID: {incident['id']}
        Severity: {incident['severity']}
        Status: {incident['status']}
        Created: {incident['created_at']}

        Description:
        {incident['description']}

        Affected Services:
        {', '.join(incident['affected_services'])}

        Timeline:
        """

        for entry in incident['timeline']:
            report += f"\n{entry['timestamp']}: {entry['update']}"
            if 'status_change' in entry:
                report += f" ({entry['status_change']})"

        return report

# Automated incident detection
class IncidentDetector:
    def __init__(self, incident_manager):
        self.incident_manager = incident_manager

    def check_system_health(self):
        health_checker = HealthChecker(app, db, redis_client)
        health_status = health_checker.get_overall_health()

        if health_status['status'] == 'unhealthy':
            # Create critical incident
            affected_services = [
                service for service, check in health_status['checks'].items()
                if check['status'] == 'unhealthy'
            ]

            self.incident_manager.create_incident(
                title="System Health Critical",
                description=f"Multiple system components unhealthy: {', '.join(affected_services)}",
                severity='critical',
                affected_services=affected_services
            )

    def check_scan_failures(self):
        # Check for high scan failure rate
        from models import ScanResult

        recent_scans = ScanResult.query.filter(
            ScanResult.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).all()

        if recent_scans:
            failure_rate = sum(1 for scan in recent_scans if scan.status == 'failed') / len(recent_scans)

            if failure_rate > 0.5:  # More than 50% failure rate
                self.incident_manager.create_incident(
                    title="High Scan Failure Rate",
                    description=f"Scan failure rate: {failure_rate:.1%} in the last hour",
                    severity='high',
                    affected_services=['cloud_scanner']
                )
```

---

## 5. Maintenance Workflows

### 5.1 Regular Maintenance Tasks

#### Automated Maintenance Scripts
```python
# scripts/maintenance.py
import os
import sys
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
import subprocess
import shutil

class MaintenanceManager:
    def __init__(self, app):
        self.app = app
        self.engine = create_engine(app.config['DATABASE_URL'])

    def cleanup_old_scan_results(self, days_to_keep=30):
        """Remove scan results older than specified days"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        with self.engine.connect() as conn:
            # Get count of records to be deleted
            result = conn.execute(text("""
                SELECT COUNT(*) FROM scan_results
                WHERE created_at < :cutoff_date
            """), {'cutoff_date': cutoff_date})

            count_to_delete = result.fetchone()[0]
            print(f"Deleting {count_to_delete} old scan results...")

            # Delete old scan results
            conn.execute(text("""
                DELETE FROM scan_results
                WHERE created_at < :cutoff_date
            """), {'cutoff_date': cutoff_date})

            conn.commit()
            print(f"Deleted {count_to_delete} old scan results")

    def cleanup_old_logs(self, days_to_keep=7):
        """Remove log files older than specified days"""
        log_dir = 'logs'
        cutoff_time = datetime.now() - timedelta(days=days_to_keep)

        for filename in os.listdir(log_dir):
            file_path = os.path.join(log_dir, filename)
            if os.path.isfile(file_path):
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                if file_time < cutoff_time:
                    os.remove(file_path)
                    print(f"Deleted old log file: {filename}")

    def optimize_database(self):
        """Run database optimization tasks"""
        with self.engine.connect() as conn:
            print("Running VACUUM ANALYZE...")
            conn.execute(text("VACUUM ANALYZE"))

            print("Updating table statistics...")
            conn.execute(text("ANALYZE"))

            # Check for table bloat
            bloat_query = text("""
                SELECT schemaname, tablename,
                       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                       pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size
                FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            """)

            result = conn.execute(bloat_query)
            print("Table sizes:")
            for row in result:
                print(f"  {row[1]}: {row[2]} (table: {row[3]})")

    def backup_database(self):
        """Create database backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)

        backup_file = os.path.join(backup_dir, f'db_backup_{timestamp}.sql')

        cmd = [
            'pg_dump',
            '--no-password',
            '--format=custom',
            '--file', backup_file,
            self.app.config['DATABASE_URL']
        ]

        try:
            subprocess.run(cmd, check=True)
            print(f"Database backup created: {backup_file}")

            # Compress backup
            subprocess.run(['gzip', backup_file], check=True)
            print(f"Backup compressed: {backup_file}.gz")

            return f"{backup_file}.gz"
        except subprocess.CalledProcessError as e:
            print(f"Backup failed: {e}")
            return None

    def cleanup_old_backups(self, days_to_keep=30):
        """Remove old backup files"""
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            return

        cutoff_time = datetime.now() - timedelta(days=days_to_keep)

        for filename in os.listdir(backup_dir):
            file_path = os.path.join(backup_dir, filename)
            if os.path.isfile(file_path):
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                if file_time < cutoff_time:
                    os.remove(file_path)
                    print(f"Deleted old backup: {filename}")

    def update_ssl_certificates(self):
        """Check and update SSL certificates"""
        cert_file = '/etc/ssl/certs/aegis-scanner.crt'

        if os.path.exists(cert_file):
            # Check certificate expiration
            cmd = ['openssl', 'x509', '-in', cert_file, '-noout', '-dates']
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                output = result.stdout
                print(f"Certificate info:\n{output}")

                # Parse expiration date and warn if expiring soon
                for line in output.split('\n'):
                    if 'notAfter' in line:
                        # Extract and parse date
                        date_str = line.split('=')[1]
                        # Implementation would parse date and check if expiring within 30 days
            else:
                print("Failed to check certificate")

    def run_full_maintenance(self):
        """Run all maintenance tasks"""
        print(f"Starting maintenance at {datetime.now()}")

        try:
            print("1. Creating database backup...")
            self.backup_database()

            print("2. Cleaning up old scan results...")
            self.cleanup_old_scan_results()

            print("3. Cleaning up old logs...")
            self.cleanup_old_logs()

            print("4. Optimizing database...")
            self.optimize_database()

            print("5. Cleaning up old backups...")
            self.cleanup_old_backups()

            print("6. Checking SSL certificates...")
            self.update_ssl_certificates()

            print(f"Maintenance completed at {datetime.now()}")

        except Exception as e:
            print(f"Maintenance failed: {e}")
            raise

# Cron job configuration
# crontab -e
# 0 2 * * 0 /usr/local/bin/python /app/scripts/maintenance.py
```

### 5.2 Security Maintenance

#### Security Audit Script
```python
# scripts/security_audit.py
import os
import subprocess
import json
from datetime import datetime
import requests

class SecurityAuditor:
    def __init__(self):
        self.audit_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'findings': []
        }

    def audit_dependencies(self):
        """Audit Python dependencies for vulnerabilities"""
        try:
            # Run safety check
            result = subprocess.run(['safety', 'check', '--json'], capture_output=True, text=True)

            if result.returncode == 0:
                vulnerabilities = json.loads(result.stdout) if result.stdout else []

                for vuln in vulnerabilities:
                    self.audit_results['findings'].append({
                        'type': 'dependency_vulnerability',
                        'severity': 'high',
                        'package': vuln.get('package'),
                        'vulnerability': vuln.get('vulnerability'),
                        'recommendation': vuln.get('more_info_url')
                    })

            # Check for outdated packages
            result = subprocess.run(['pip', 'list', '--outdated', '--format=json'], capture_output=True, text=True)
            outdated = json.loads(result.stdout) if result.stdout else []

            for package in outdated:
                self.audit_results['findings'].append({
                    'type': 'outdated_dependency',
                    'severity': 'medium',
                    'package': package['name'],
                    'current_version': package['version'],
                    'latest_version': package['latest_version']
                })

        except Exception as e:
            self.audit_results['findings'].append({
                'type': 'audit_error',
                'severity': 'low',
                'error': str(e)
            })

    def audit_file_permissions(self):
        """Check critical file permissions"""
        critical_files = [
            ('.env', '600'),
            ('config.py', '644'),
            ('app.py', '644'),
            ('requirements.txt', '644')
        ]

        for file_path, expected_perm in critical_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                actual_perm = oct(stat.st_mode)[-3:]

                if actual_perm != expected_perm:
                    self.audit_results['findings'].append({
                        'type': 'file_permission',
                        'severity': 'medium',
                        'file': file_path,
                        'expected_permission': expected_perm,
                        'actual_permission': actual_perm
                    })

    def audit_ssl_configuration(self):
        """Check SSL/TLS configuration"""
        try:
            # Check certificate validity
            result = subprocess.run([
                'openssl', 's_client', '-connect', 'localhost:443', '-servername', 'localhost'
            ], input='', capture_output=True, text=True, timeout=10)

            if 'Verify return code: 0 (ok)' not in result.stdout:
                self.audit_results['findings'].append({
                    'type': 'ssl_configuration',
                    'severity': 'high',
                    'issue': 'SSL certificate verification failed'
                })

        except Exception as e:
            self.audit_results['findings'].append({
                'type': 'ssl_audit_error',
                'severity': 'low',
                'error': str(e)
            })

    def audit_docker_security(self):
        """Audit Docker container security"""
        try:
            # Check for running containers
            result = subprocess.run(['docker', 'ps', '--format', 'json'], capture_output=True, text=True)

            if result.returncode == 0:
                containers = [json.loads(line) for line in result.stdout.strip().split('\n') if line]

                for container in containers:
                    # Check if container is running as root
                    inspect_result = subprocess.run([
                        'docker', 'inspect', container['ID'], '--format', '{{.Config.User}}'
                    ], capture_output=True, text=True)

                    if inspect_result.stdout.strip() == '' or inspect_result.stdout.strip() == '0':
                        self.audit_results['findings'].append({
                            'type': 'docker_security',
                            'severity': 'medium',
                            'container': container['Names'],
                            'issue': 'Container running as root user'
                        })

        except Exception as e:
            self.audit_results['findings'].append({
                'type': 'docker_audit_error',
                'severity': 'low',
                'error': str(e)
            })

    def generate_report(self):
        """Generate security audit report"""
        report = f"""
Security Audit Report
Generated: {self.audit_results['timestamp']}

Summary:
- Total findings: {len(self.audit_results['findings'])}
- Critical: {len([f for f in self.audit_results['findings'] if f['severity'] == 'critical'])}
- High: {len([f for f in self.audit_results['findings'] if f['severity'] == 'high'])}
- Medium: {len([f for f in self.audit_results['findings'] if f['severity'] == 'medium'])}
- Low: {len([f for f in self.audit_results['findings'] if f['severity'] == 'low'])}

Detailed Findings:
"""

        for finding in self.audit_results['findings']:
            report += f"\n[{finding['severity'].upper()}] {finding['type']}"
            for key, value in finding.items():
                if key not in ['type', 'severity']:
                    report += f"\n  {key}: {value}"
            report += "\n"

        return report

    def run_audit(self):
        """Run complete security audit"""
        print("Running security audit...")

        self.audit_dependencies()
        self.audit_file_permissions()
        self.audit_ssl_configuration()
        self.audit_docker_security()

        report = self.generate_report()

        # Save report
        with open(f'security_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', 'w') as f:
            f.write(report)

        print(report)
        return self.audit_results

if __name__ == '__main__':
    auditor = SecurityAuditor()
    auditor.run_audit()
```

---

## 6. Error Handling and Recovery

### 6.1 Error Recovery Strategies

#### Automatic Recovery System
```python
# utils/recovery.py
import time
import logging
from functools import wraps
from typing import Callable, Any
import redis

class RecoveryManager:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.logger = logging.getLogger(__name__)

    def retry_with_backoff(self, max_retries=3, base_delay=1, max_delay=60):
        """Decorator for retrying functions with exponential backoff"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                last_exception = None

                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e

                        if attempt == max_retries:
                            self.logger.error(f"Function {func.__name__} failed after {max_retries} retries: {str(e)}")
                            raise e

                        delay = min(base_delay * (2 ** attempt), max_delay)
                        self.logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}. Retrying in {delay}s...")
                        time.sleep(delay)

                raise last_exception
            return wrapper
        return decorator

    def circuit_breaker(self, failure_threshold=5, recovery_timeout=60, expected_exception=Exception):
        """Circuit breaker pattern implementation"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                circuit_key = f"circuit_breaker:{func.__name__}"
                failure_key = f"circuit_breaker_failures:{func.__name__}"

                # Check circuit state
                circuit_state = self.redis.get(circuit_key)

                if circuit_state == b'open':
                    raise Exception(f"Circuit breaker is OPEN for {func.__name__}")

                try:
                    result = func(*args, **kwargs)

                    # Reset failure count on success
                    self.redis.delete(failure_key)
                    self.redis.delete(circuit_key)

                    return result

                except expected_exception as e:
                    # Increment failure count
                    failures = self.redis.incr(failure_key)
                    self.redis.expire(failure_key, recovery_timeout)

                    if failures >= failure_threshold:
                        # Open circuit
                        self.redis.setex(circuit_key, recovery_timeout, 'open')
                        self.logger.error(f"Circuit breaker OPENED for {func.__name__} after {failures} failures")

                    raise e
            return wrapper
        return decorator

    def fallback(self, fallback_func: Callable):
        """Fallback mechanism decorator"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    self.logger.warning(f"Primary function {func.__name__} failed: {str(e)}. Using fallback.")
                    return fallback_func(*args, **kwargs)
            return wrapper
        return decorator

# Application-specific recovery strategies
class ScanRecoveryManager(RecoveryManager):
    def __init__(self, redis_client, db):
        super().__init__(redis_client)
        self.db = db

    @RecoveryManager.retry_with_backoff(max_retries=3)
    def recover_failed_scan(self, scan_id):
        """Attempt to recover a failed scan"""
        from models import ScanResult

        scan = ScanResult.query.get(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        if scan.status != 'failed':
            return scan

        # Reset scan status and retry
        scan.status = 'pending'
        scan.error_message = None
        self.db.session.commit()

        # Trigger scan retry
        self.trigger_scan_retry(scan)
        return scan

    def trigger_scan_retry(self, scan):
        """Trigger scan retry through message queue"""
        retry_payload = {
            'scan_id': scan.id,
            'provider': scan.provider,
            'scan_type': scan.scan_type,
            'retry_attempt': getattr(scan, 'retry_count', 0) + 1
        }

        # Add to retry queue
        self.redis.lpush('scan_retry_queue', json.dumps(retry_payload))
        self.logger.info(f"Queued scan {scan.id} for retry")

    def cleanup_stuck_scans(self):
        """Clean up scans that have been running too long"""
        from models import ScanResult
        from datetime import datetime, timedelta

        stuck_threshold = datetime.utcnow() - timedelta(hours=2)

        stuck_scans = ScanResult.query.filter(
            ScanResult.status == 'running',
            ScanResult.started_at < stuck_threshold
        ).all()

        for scan in stuck_scans:
            self.logger.warning(f"Marking stuck scan {scan.id} as failed")
            scan.status = 'failed'
            scan.error_message = 'Scan timed out - marked as stuck'
            scan.completed_at = datetime.utcnow()

        self.db.session.commit()
        return len(stuck_scans)
```

### 6.2 Data Recovery Procedures

#### Database Recovery Scripts
```python
# scripts/database_recovery.py
import subprocess
import os
from datetime import datetime
import shutil

class DatabaseRecovery:
    def __init__(self, database_url, backup_dir='backups'):
        self.database_url = database_url
        self.backup_dir = backup_dir

    def list_backups(self):
        """List available database backups"""
        if not os.path.exists(self.backup_dir):
            return []

        backups = []
        for filename in os.listdir(self.backup_dir):
            if filename.startswith('db_backup_') and (filename.endswith('.sql') or filename.endswith('.sql.gz')):
                file_path = os.path.join(self.backup_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                backups.append({
                    'filename': filename,
                    'created': file_time,
                    'size': os.path.getsize(file_path)
                })

        return sorted(backups, key=lambda x: x['created'], reverse=True)

    def restore_from_backup(self, backup_filename, confirm=False):
        """Restore database from backup"""
        if not confirm:
            response = input(f"This will restore the database from {backup_filename}. This operation is destructive. Continue? (yes/no): ")
            if response.lower() != 'yes':
                print("Restore cancelled")
                return False

        backup_path = os.path.join(self.backup_dir, backup_filename)

        if not os.path.exists(backup_path):
            print(f"Backup file not found: {backup_path}")
            return False

        try:
            # Create current backup before restore
            current_backup = f"pre_restore_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
            self.create_backup(current_backup)

            # Decompress if needed
            if backup_filename.endswith('.gz'):
                subprocess.run(['gunzip', '-k', backup_path], check=True)
                restore_file = backup_path[:-3]  # Remove .gz extension
            else:
                restore_file = backup_path

            # Restore database
            cmd = [
                'pg_restore',
                '--clean',
                '--if-exists',
                '--no-password',
                '--dbname', self.database_url,
                restore_file
            ]

            subprocess.run(cmd, check=True)
            print(f"Database restored successfully from {backup_filename}")

            # Clean up decompressed file if created
            if backup_filename.endswith('.gz') and os.path.exists(restore_file):
                os.remove(restore_file)

            return True

        except subprocess.CalledProcessError as e:
            print(f"Restore failed: {e}")
            return False

    def create_backup(self, filename):
        """Create a database backup"""
        backup_path = os.path.join(self.backup_dir, filename)

        cmd = [
            'pg_dump',
            '--no-password',
            '--format=custom',
            '--file', backup_path,
            self.database_url
        ]

        try:
            subprocess.run(cmd, check=True)
            print(f"Backup created: {backup_path}")
            return backup_path
        except subprocess.CalledProcessError as e:
            print(f"Backup failed: {e}")
            return None

    def point_in_time_recovery(self, target_time):
        """Perform point-in-time recovery (requires WAL archives)"""
        # This is a simplified example - real PITR requires WAL archiving setup
        print(f"Point-in-time recovery to {target_time} would require WAL archive configuration")
        print("Please ensure you have WAL archiving enabled and archives available")

if __name__ == '__main__':
    import sys

    recovery = DatabaseRecovery(os.environ.get('DATABASE_URL'))

    if len(sys.argv) < 2:
        print("Usage: python database_recovery.py <command> [args]")
        print("Commands:")
        print("  list - List available backups")
        print("  restore <backup_filename> - Restore from backup")
        print("  backup <filename> - Create new backup")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'list':
        backups = recovery.list_backups()
        print("Available backups:")
        for backup in backups:
            print(f"  {backup['filename']} - {backup['created']} ({backup['size']} bytes)")

    elif command == 'restore' and len(sys.argv) > 2:
        recovery.restore_from_backup(sys.argv[2])

    elif command == 'backup' and len(sys.argv) > 2:
        recovery.create_backup(sys.argv[2])

    else:
        print("Invalid command or missing arguments")
```

---

## 7. Backup and Disaster Recovery

### 7.1 Backup Strategy

#### Comprehensive Backup System
```python
# scripts/backup_system.py
import os
import boto3
import tarfile
import gzip
import shutil
from datetime import datetime, timedelta
import subprocess
import json

class BackupManager:
    def __init__(self, config):
        self.config = config
        self.s3_client = boto3.client('s3') if config.get('AWS_BACKUP_ENABLED') else None
        self.backup_dir = config.get('BACKUP_DIR', 'backups')

    def create_full_backup(self):
        """Create a complete system backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"full_backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, backup_name)

        os.makedirs(backup_path, exist_ok=True)

        try:
            # Database backup
            db_backup = self.backup_database(backup_path)

            # Application files backup
            app_backup = self.backup_application_files(backup_path)

            # Configuration backup
            config_backup = self.backup_configuration(backup_path)

            # Logs backup
            logs_backup = self.backup_logs(backup_path)

            # Create manifest
            manifest = {
                'backup_name': backup_name,
                'timestamp': timestamp,
                'components': {
                    'database': db_backup,
                    'application': app_backup,
                    'configuration': config_backup,
                    'logs': logs_backup
                },
                'version': self.get_application_version()
            }

            with open(os.path.join(backup_path, 'manifest.json'), 'w') as f:
                json.dump(manifest, f, indent=2)

            # Compress backup
            compressed_backup = self.compress_backup(backup_path)

            # Upload to cloud storage if configured
            if self.s3_client:
                self.upload_to_s3(compressed_backup)

            # Clean up uncompressed backup
            shutil.rmtree(backup_path)

            print(f"Full backup completed: {compressed_backup}")
            return compressed_backup

        except Exception as e:
            print(f"Backup failed: {e}")
            # Clean up partial backup
            if os.path.exists(backup_path):
                shutil.rmtree(backup_path)
            raise

    def backup_database(self, backup_path):
        """Backup database"""
        db_backup_file = os.path.join(backup_path, 'database.sql')

        cmd = [
            'pg_dump',
            '--no-password',
            '--format=custom',
            '--file', db_backup_file,
            self.config['DATABASE_URL']
        ]

        subprocess.run(cmd, check=True)

        # Compress database backup
        with open(db_backup_file, 'rb') as f_in:
            with gzip.open(f"{db_backup_file}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        os.remove(db_backup_file)
        return f"database.sql.gz"

    def backup_application_files(self, backup_path):
        """Backup application source code and assets"""
        app_backup_file = os.path.join(backup_path, 'application.tar.gz')

        with tarfile.open(app_backup_file, 'w:gz') as tar:
            # Add essential application files
            for item in ['app.py', 'models.py', 'routes/', 'utils/', 'templates/', 'static/']:
                if os.path.exists(item):
                    tar.add(item, arcname=item)

        return 'application.tar.gz'

    def backup_configuration(self, backup_path):
        """Backup configuration files"""
        config_backup_file = os.path.join(backup_path, 'configuration.tar.gz')

        with tarfile.open(config_backup_file, 'w:gz') as tar:
            # Add configuration files
            config_files = ['config.py', '.env.example', 'requirements.txt', 'docker-compose.yml']
            for config_file in config_files:
                if os.path.exists(config_file):
                    tar.add(config_file, arcname=config_file)

        return 'configuration.tar.gz'

    def backup_logs(self, backup_path):
        """Backup log files"""
        if not os.path.exists('logs'):
            return None

        logs_backup_file = os.path.join(backup_path, 'logs.tar.gz')

        with tarfile.open(logs_backup_file, 'w:gz') as tar:
            tar.add('logs', arcname='logs')

        return 'logs.tar.gz'

    def compress_backup(self, backup_path):
        """Compress the entire backup directory"""
        compressed_file = f"{backup_path}.tar.gz"

        with tarfile.open(compressed_file, 'w:gz') as tar:
            tar.add(backup_path, arcname=os.path.basename(backup_path))

        return compressed_file

    def upload_to_s3(self, backup_file):
        """Upload backup to S3"""
        bucket = self.config.get('AWS_BACKUP_BUCKET')
        if not bucket or not self.s3_client:
            return

        key = f"aegis-scanner-backups/{os.path.basename(backup_file)}"

        try:
            self.s3_client.upload_file(backup_file, bucket, key)
            print(f"Backup uploaded to S3: s3://{bucket}/{key}")

            # Set lifecycle policy for automated cleanup
            self.s3_client.put_object_tagging(
                Bucket=bucket,
                Key=key,
                Tagging={
                    'TagSet': [
                        {'Key': 'backup-type', 'Value': 'full'},
                        {'Key': 'retention-days', 'Value': '90'}
                    ]
                }
            )
        except Exception as e:
            print(f"S3 upload failed: {e}")

    def get_application_version(self):
        """Get current application version"""
        try:
            result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True)
            return result.stdout.strip() if result.returncode == 0 else 'unknown'
        except:
            return 'unknown'

    def cleanup_old_backups(self, days_to_keep=30):
        """Remove old local backups"""
        cutoff_time = datetime.now() - timedelta(days=days_to_keep)

        for filename in os.listdir(self.backup_dir):
            if filename.startswith('full_backup_') and filename.endswith('.tar.gz'):
                file_path = os.path.join(self.backup_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))

                if file_time < cutoff_time:
                    os.remove(file_path)
                    print(f"Removed old backup: {filename}")

class DisasterRecoveryManager:
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager

    def create_disaster_recovery_plan(self):
        """Generate disaster recovery documentation"""
        plan = """
        Aegis Cloud Scanner - Disaster Recovery Plan

        1. ASSESSMENT PHASE
           - Identify scope of disaster (hardware failure, data corruption, security breach)
           - Assess data integrity and availability
           - Determine recovery objectives (RTO/RPO)

        2. RECOVERY PROCEDURES

           Database Recovery:
           - Restore from latest backup: python scripts/database_recovery.py restore <backup_file>
           - Verify data integrity: python scripts/verify_data_integrity.py
           - Update connection strings if needed

           Application Recovery:
           - Deploy from version control: git checkout <commit_hash>
           - Restore configuration files from backup
           - Update environment variables
           - Restart services: docker-compose up -d

           Infrastructure Recovery:
           - Provision new infrastructure using Terraform
           - Configure load balancers and networking
           - Update DNS records
           - Deploy application containers

        3. VERIFICATION STEPS
           - Run health checks: curl http://localhost:5000/health
           - Verify database connectivity
           - Test critical user flows
           - Validate security configurations

        4. COMMUNICATION
           - Notify stakeholders of recovery status
           - Update status page
           - Document lessons learned

        Recovery Time Objectives:
        - Database: 2 hours
        - Application: 1 hour
        - Full system: 4 hours

        Recovery Point Objectives:
        - Database: 1 hour (hourly backups)
        - Configuration: 24 hours (daily backups)
        """

        with open('disaster_recovery_plan.md', 'w') as f:
            f.write(plan)

        return plan

    def test_recovery_procedures(self):
        """Test disaster recovery procedures"""
        test_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'tests': []
        }

        # Test database backup/restore
        try:
            backup_file = self.backup_manager.backup_database('test_backups')
            # In a real test, you'd restore to a test database
            test_results['tests'].append({
                'test': 'database_backup',
                'status': 'pass',
                'details': f'Backup created: {backup_file}'
            })
        except Exception as e:
            test_results['tests'].append({
                'test': 'database_backup',
                'status': 'fail',
                'details': str(e)
            })

        # Test configuration backup
        try:
            config_backup = self.backup_manager.backup_configuration('test_backups')
            test_results['tests'].append({
                'test': 'configuration_backup',
                'status': 'pass',
                'details': f'Config backup created: {config_backup}'
            })
        except Exception as e:
            test_results['tests'].append({
                'test': 'configuration_backup',
                'status': 'fail',
                'details': str(e)
            })

        return test_results
```

---

## 8. Health Checks and Diagnostics

### 8.1 Advanced Diagnostics

#### System Diagnostics Tool
```python
# scripts/system_diagnostics.py
import psutil
import subprocess
import json
import time
from datetime import datetime, timedelta
import requests

class SystemDiagnostics:
    def __init__(self):
        self.diagnostics = {
            'timestamp': datetime.utcnow().isoformat(),
            'system': {},
            'application': {},
            'network': {},
            'performance': {}
        }

    def collect_system_info(self):
        """Collect system-level diagnostics"""
        # CPU information
        self.diagnostics['system']['cpu'] = {
            'count': psutil.cpu_count(),
            'usage_percent': psutil.cpu_percent(interval=1),
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
        }

        # Memory information
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()

        self.diagnostics['system']['memory'] = {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'usage_percent': memory.percent,
            'swap_total_gb': round(swap.total / (1024**3), 2),
            'swap_usage_percent': swap.percent
        }

        # Disk information
        disk = psutil.disk_usage('/')
        self.diagnostics['system']['disk'] = {
            'total_gb': round(disk.total / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'usage_percent': round((disk.used / disk.total) * 100, 2)
        }

        # Process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                if proc.info['cpu_percent'] > 1.0 or proc.info['memory_percent'] > 1.0:
                    processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self.diagnostics['system']['top_processes'] = sorted(
            processes, key=lambda x: x['cpu_percent'], reverse=True
        )[:10]

    def collect_application_info(self):
        """Collect application-specific diagnostics"""
        try:
            # Check if application is running
            response = requests.get('http://localhost:5000/health', timeout=5)
            self.diagnostics['application']['health_status'] = response.status_code
            self.diagnostics['application']['health_response'] = response.json()
        except Exception as e:
            self.diagnostics['application']['health_status'] = 'error'
            self.diagnostics['application']['health_error'] = str(e)

        # Check database connections
        try:
            result = subprocess.run([
                'psql', os.environ.get('DATABASE_URL'),
                '-c', 'SELECT count(*) FROM pg_stat_activity WHERE state = \'active\';'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                active_connections = int(result.stdout.split('\n')[2].strip())
                self.diagnostics['application']['database_connections'] = active_connections
        except Exception as e:
            self.diagnostics['application']['database_error'] = str(e)

        # Check Redis connectivity
        try:
            import redis
            r = redis.Redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379'))
            r.ping()
            info = r.info()
            self.diagnostics['application']['redis'] = {
                'connected_clients': info.get('connected_clients'),
                'used_memory_human': info.get('used_memory_human'),
                'total_commands_processed': info.get('total_commands_processed')
            }
        except Exception as e:
            self.diagnostics['application']['redis_error'] = str(e)

    def collect_network_info(self):
        """Collect network diagnostics"""
        # Network interfaces
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = [addr._asdict() for addr in addrs]

        self.diagnostics['network']['interfaces'] = interfaces

        # Network I/O statistics
        net_io = psutil.net_io_counters()
        self.diagnostics['network']['io_stats'] = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }

        # Test external connectivity
        test_hosts = ['8.8.8.8', 'google.com', 'github.com']
        connectivity = {}

        for host in test_hosts:
            try:
                result = subprocess.run(['ping', '-c', '1', host],
                                      capture_output=True, text=True, timeout=5)
                connectivity[host] = result.returncode == 0
            except:
                connectivity[host] = False

        self.diagnostics['network']['connectivity'] = connectivity

    def collect_performance_metrics(self):
        """Collect performance metrics"""
        # Response time test
        try:
            start_time = time.time()
            response = requests.get('http://localhost:5000/health', timeout=10)
            response_time = time.time() - start_time

            self.diagnostics['performance']['health_response_time'] = response_time
        except Exception as e:
            self.diagnostics['performance']['health_response_error'] = str(e)

        # Database query performance
        try:
            start_time = time.time()
            result = subprocess.run([
                'psql', os.environ.get('DATABASE_URL'),
                '-c', 'SELECT count(*) FROM users;'
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                query_time = time.time() - start_time
                self.diagnostics['performance']['database_query_time'] = query_time
        except Exception as e:
            self.diagnostics['performance']['database_query_error'] = str(e)

    def run_full_diagnostics(self):
        """Run complete system diagnostics"""
        print("Running system diagnostics...")

        self.collect_system_info()
        self.collect_application_info()
        self.collect_network_info()
        self.collect_performance_metrics()

        return self.diagnostics

    def generate_report(self):
        """Generate diagnostic report"""
        diagnostics = self.run_full_diagnostics()

        report = f"""
System Diagnostics Report
Generated: {diagnostics['timestamp']}

SYSTEM INFORMATION:
- CPU: {diagnostics['system']['cpu']['count']} cores, {diagnostics['system']['cpu']['usage_percent']}% usage
- Memory: {diagnostics['system']['memory']['usage_percent']}% used ({diagnostics['system']['memory']['available_gb']}GB available)
- Disk: {diagnostics['system']['disk']['usage_percent']}% used ({diagnostics['system']['disk']['free_gb']}GB free)

APPLICATION STATUS:
- Health Check: {diagnostics['application'].get('health_status', 'Unknown')}
- Database Connections: {diagnostics['application'].get('database_connections', 'Unknown')}
- Redis Status: {'Connected' if 'redis' in diagnostics['application'] else 'Error'}

PERFORMANCE METRICS:
- Health Endpoint Response Time: {diagnostics['performance'].get('health_response_time', 'Unknown')}s
- Database Query Time: {diagnostics['performance'].get('database_query_time', 'Unknown')}s

NETWORK STATUS:
"""

        for host, status in diagnostics['network'].get('connectivity', {}).items():
            report += f"- {host}: {'✓' if status else '✗'}\n"

        # Save detailed diagnostics to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        with open(f'diagnostics_{timestamp}.json', 'w') as f:
            json.dump(diagnostics, f, indent=2)

        print(report)
        return report, diagnostics

if __name__ == '__main__':
    diagnostics = SystemDiagnostics()
    report, data = diagnostics.generate_report()
```

---

## Conclusion

This comprehensive troubleshooting and maintenance guide provides:

1. **Debugging Tools**: Advanced debugging utilities for both development and production environments
2. **Performance Optimization**: Database optimization, caching strategies, and scaling solutions
3. **System Monitoring**: Custom metrics collection, Prometheus integration, and health checks
4. **Operational Procedures**: Deployment scripts, incident response, and database migration procedures
5. **Maintenance Workflows**: Automated maintenance tasks and security auditing
6. **Error Handling**: Recovery strategies, circuit breakers, and fallback mechanisms
7. **Backup & Recovery**: Comprehensive backup systems and disaster recovery procedures
8. **Health Checks**: Advanced diagnostics and system monitoring tools

These tools and procedures ensure the Aegis Cloud Scanner application maintains high availability, performance, and reliability in production environments. Regular execution of these maintenance tasks and monitoring procedures will help prevent issues and ensure smooth operation of the system.

Remember to:
- Schedule regular maintenance windows
- Monitor system metrics continuously
- Test backup and recovery procedures regularly
- Keep documentation updated
- Train team members on incident response procedures
- Review and update security measures regularly

This concludes the complete Developer Manual for the Aegis Cloud Scanner application.