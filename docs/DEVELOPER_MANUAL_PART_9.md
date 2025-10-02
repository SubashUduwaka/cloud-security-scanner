# Aegis Cloud Scanner - Developer Manual
## Part 9: Deployment and DevOps

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** DevOps Engineers, Infrastructure Engineers, Release Managers
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Deployment Architecture Overview](#deployment-architecture-overview)
2. [Containerization with Docker](#containerization-with-docker)
3. [Infrastructure as Code](#infrastructure-as-code)
4. [CI/CD Pipeline](#cicd-pipeline)
5. [Environment Management](#environment-management)
6. [Production Deployment](#production-deployment)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Backup and Disaster Recovery](#backup-and-disaster-recovery)
9. [Security Hardening](#security-hardening)
10. [Scaling and Performance](#scaling-and-performance)

---

## Deployment Architecture Overview

### Target Deployment Platforms

The Aegis Cloud Scanner supports multiple deployment architectures:

```
┌─────────────────────────────────────────────────────────────┐
│                    Production Architecture                   │
├─────────────────────────────────────────────────────────────┤
│  Load Balancer (Nginx/AWS ALB) → Web Application Servers    │
│  ├── Web Server 1 (Docker Container)                       │
│  ├── Web Server 2 (Docker Container)                       │
│  └── Web Server N (Auto-scaling)                           │
├─────────────────────────────────────────────────────────────┤
│  Background Processing                                       │
│  ├── Celery Workers (Docker Containers)                    │
│  └── Scheduler (APScheduler/Celery Beat)                   │
├─────────────────────────────────────────────────────────────┤
│  Data Layer                                                 │
│  ├── PostgreSQL (Primary + Read Replicas)                  │
│  ├── Redis (Session Store + Cache)                         │
│  └── File Storage (S3/NFS)                                 │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Services                                    │
│  ├── Monitoring (Prometheus + Grafana)                     │
│  ├── Logging (ELK Stack)                                   │
│  └── Secret Management (HashiCorp Vault)                   │
└─────────────────────────────────────────────────────────────┘
```

### Deployment Strategies

1. **Blue-Green Deployment**: Zero-downtime deployments with instant rollback capability
2. **Rolling Deployment**: Gradual replacement of instances for minimal service disruption
3. **Canary Deployment**: Risk-minimized releases to subset of users
4. **A/B Testing**: Feature flag-controlled deployments for testing

### Environment Hierarchy

```yaml
environments:
  development:
    purpose: "Local development and testing"
    infrastructure: "Docker Compose"
    database: "SQLite/PostgreSQL"
    scaling: "Single instance"

  staging:
    purpose: "Integration testing and QA"
    infrastructure: "Kubernetes/Docker Swarm"
    database: "PostgreSQL with test data"
    scaling: "Multi-instance"

  production:
    purpose: "Live user-facing environment"
    infrastructure: "Kubernetes/AWS ECS"
    database: "PostgreSQL with clustering"
    scaling: "Auto-scaling enabled"

  disaster-recovery:
    purpose: "Backup production environment"
    infrastructure: "Cross-region deployment"
    database: "PostgreSQL replica"
    scaling: "Reduced capacity"
```

---

## Containerization with Docker

### Multi-Stage Dockerfile

```dockerfile
# Multi-stage build for optimized production image
FROM python:3.13-slim as builder

# Set build arguments
ARG BUILD_ENV=production
ARG APP_VERSION=latest

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt

# Production stage
FROM python:3.13-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r aegis \
    && useradd -r -g aegis aegis

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=aegis:aegis . .

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads /app/reports \
    && chown -R aegis:aegis /app

# Switch to non-root user
USER aegis

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:application"]

# Development stage
FROM builder as development

# Install development dependencies
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY . .

# Expose port for development
EXPOSE 5000

# Development command
CMD ["python", "app.py"]
```

### Docker Compose Configuration

```yaml
# docker-compose.yml - Development environment
version: '3.8'

services:
  web:
    build:
      context: .
      target: development
      dockerfile: Dockerfile
    ports:
      - "5000:5000"
    volumes:
      - .:/app
      - /app/venv  # Exclude virtual environment from bind mount
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=1
      - DATABASE_URL=postgresql://aegis:scanner123@postgres:5432/aegis_dev
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    networks:
      - aegis-network

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: aegis_dev
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD: scanner123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aegis -d aegis_dev"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - aegis-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - aegis-network

  celery-worker:
    build:
      context: .
      target: development
    command: celery -A app.celery worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://aegis:scanner123@postgres:5432/aegis_dev
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    volumes:
      - .:/app
    networks:
      - aegis-network

  celery-beat:
    build:
      context: .
      target: development
    command: celery -A app.celery beat --loglevel=info
    environment:
      - DATABASE_URL=postgresql://aegis:scanner123@postgres:5432/aegis_dev
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    volumes:
      - .:/app
    networks:
      - aegis-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - web
    networks:
      - aegis-network

volumes:
  postgres_data:
  redis_data:

networks:
  aegis-network:
    driver: bridge
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml - Production environment
version: '3.8'

services:
  web:
    build:
      context: .
      target: production
      args:
        BUILD_ENV: production
        APP_VERSION: ${APP_VERSION:-latest}
    restart: unless-stopped
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - SECRET_KEY=${SECRET_KEY}
      - LICENSE_PUBLIC_KEY=${LICENSE_PUBLIC_KEY}
    secrets:
      - db_password
      - secret_key
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - aegis-network
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
    networks:
      - aegis-network

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis_data:/data
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
    networks:
      - aegis-network

secrets:
  db_password:
    external: true
  secret_key:
    external: true

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  aegis-network:
    driver: overlay
    attachable: true
```

### Container Optimization

```dockerfile
# .dockerignore - Optimize build context
.git
.gitignore
README.md
Dockerfile
docker-compose*.yml
.dockerignore
.env
.env.*
venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.pytest_cache/
.coverage
htmlcov/
.tox/
.cache/
nosetests.xml
coverage.xml
*.log
logs/
.DS_Store
Thumbs.db
```

### Multi-Architecture Build

```bash
#!/bin/bash
# scripts/build-multiarch.sh

# Setup buildx for multi-architecture builds
docker buildx create --name aegis-builder --use
docker buildx inspect --bootstrap

# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --target production \
  --tag aegis-scanner:latest \
  --tag aegis-scanner:${VERSION} \
  --push \
  .

# Build development image
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --target development \
  --tag aegis-scanner:dev \
  --push \
  .
```

---

## Infrastructure as Code

### Terraform Configuration

```hcl
# terraform/main.tf - AWS Infrastructure
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "aegis-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"

    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aegis-cloud-scanner"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# VPC Configuration
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "${var.project_name}-${var.environment}"
  cidr = var.vpc_cidr

  azs             = data.aws_availability_zones.available.names
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "${var.project_name}-${var.environment}-vpc"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "aegis" {
  name = "${var.project_name}-${var.environment}"

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs.name
      }
    }
  }

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Application Load Balancer
resource "aws_lb" "aegis" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = var.environment == "prod"

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb-logs"
    enabled = true
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "aegis" {
  identifier = "${var.project_name}-${var.environment}"

  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = var.db_instance_class
  allocated_storage   = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.aegis.name

  backup_retention_period = var.environment == "prod" ? 30 : 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  storage_encrypted = true
  kms_key_id       = aws_kms_key.aegis.arn

  deletion_protection = var.environment == "prod"
  skip_final_snapshot = var.environment != "prod"

  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn        = aws_iam_role.rds_monitoring.arn

  tags = {
    Name = "${var.project_name}-${var.environment}-db"
  }
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "aegis" {
  name       = "${var.project_name}-${var.environment}-cache-subnet"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "aegis" {
  replication_group_id         = "${var.project_name}-${var.environment}"
  description                  = "Redis cluster for Aegis Cloud Scanner"

  node_type                   = var.redis_node_type
  port                        = 6379
  parameter_group_name        = "default.redis7"

  num_cache_clusters          = var.redis_num_cache_nodes
  subnet_group_name           = aws_elasticache_subnet_group.aegis.name
  security_group_ids          = [aws_security_group.redis.id]

  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = var.redis_auth_token

  automatic_failover_enabled  = var.redis_num_cache_nodes > 1
  multi_az_enabled           = var.redis_num_cache_nodes > 1

  snapshot_retention_limit    = var.environment == "prod" ? 5 : 1
  snapshot_window            = "03:00-05:00"

  tags = {
    Name = "${var.project_name}-${var.environment}-redis"
  }
}

# S3 Bucket for file storage
resource "aws_s3_bucket" "aegis_storage" {
  bucket = "${var.project_name}-${var.environment}-storage-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_versioning" "aegis_storage" {
  bucket = aws_s3_bucket.aegis_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aegis_storage" {
  bucket = aws_s3_bucket.aegis_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.aegis.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.project_name}-${var.environment}"
  retention_in_days = var.environment == "prod" ? 30 : 7
  kms_key_id       = aws_kms_key.aegis.arn
}

# KMS Key for encryption
resource "aws_kms_key" "aegis" {
  description             = "KMS key for Aegis Cloud Scanner ${var.environment}"
  deletion_window_in_days = 7

  tags = {
    Name = "${var.project_name}-${var.environment}-kms"
  }
}

resource "aws_kms_alias" "aegis" {
  name          = "alias/${var.project_name}-${var.environment}"
  target_key_id = aws_kms_key.aegis.key_id
}

# Random ID for unique resource naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}
```

### Terraform Variables

```hcl
# terraform/variables.tf
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "aegis-cloud-scanner"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 100
}

variable "db_max_allocated_storage" {
  description = "RDS maximum allocated storage in GB"
  type        = number
  default     = 1000
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.medium"
}

variable "redis_num_cache_nodes" {
  description = "Number of cache nodes"
  type        = number
  default     = 2
}
```

### Kubernetes Configuration

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aegis-scanner
  labels:
    name: aegis-scanner
    environment: production

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aegis-config
  namespace: aegis-scanner
data:
  FLASK_ENV: "production"
  LOG_LEVEL: "INFO"
  REDIS_URL: "redis://redis-service:6379/0"
  DATABASE_URL: "postgresql://aegis:$(DB_PASSWORD)@postgres-service:5432/aegis_prod"

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aegis-secrets
  namespace: aegis-scanner
type: Opaque
data:
  DB_PASSWORD: <base64-encoded-password>
  SECRET_KEY: <base64-encoded-secret-key>
  REDIS_PASSWORD: <base64-encoded-redis-password>

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegis-web
  namespace: aegis-scanner
  labels:
    app: aegis-web
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: aegis-web
  template:
    metadata:
      labels:
        app: aegis-web
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: aegis-web
        image: aegis-scanner:latest
        ports:
        - containerPort: 8000
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: aegis-secrets
              key: DB_PASSWORD
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: aegis-secrets
              key: SECRET_KEY
        envFrom:
        - configMapRef:
            name: aegis-config
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        volumeMounts:
        - name: aegis-storage
          mountPath: /app/uploads
      volumes:
      - name: aegis-storage
        persistentVolumeClaim:
          claimName: aegis-storage-pvc

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: aegis-web-service
  namespace: aegis-scanner
spec:
  selector:
    app: aegis-web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8000
  type: ClusterIP

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aegis-ingress
  namespace: aegis-scanner
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - scanner.aegis.com
    secretName: aegis-tls
  rules:
  - host: scanner.aegis.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: aegis-web-service
            port:
              number: 80

---
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: aegis-web-hpa
  namespace: aegis-scanner
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: aegis-web
  minReplicas: 3
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
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  release:
    types: [ published ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
  PYTHON_VERSION: '3.13'

jobs:
  test:
    name: Run Tests
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_USER: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ env.PYTHON_VERSION }}
        cache: 'pip'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt

    - name: Run linting
      run: |
        flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
        flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

    - name: Run type checking
      run: mypy . --ignore-missing-imports

    - name: Run security scan
      run: |
        bandit -r . -f json -o bandit-report.json
        safety check --json --output safety-report.json
      continue-on-error: true

    - name: Run unit tests
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
        REDIS_URL: redis://localhost:6379/0
        SECRET_KEY: test-secret-key
      run: |
        pytest tests/ --cov=. --cov-report=xml --cov-report=html --junitxml=junit.xml

    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella

    - name: Upload test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results
        path: |
          junit.xml
          htmlcov/
          bandit-report.json
          safety-report.json

  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'

    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  build:
    name: Build and Push Image
    runs-on: ubuntu-latest
    needs: test
    if: github.ref == 'refs/heads/main' || github.event_name == 'release'

    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
      image-tag: ${{ steps.meta.outputs.tags }}

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}

    - name: Build and push Docker image
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        target: production
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        platforms: linux/amd64,linux/arm64
        build-args: |
          BUILD_ENV=production
          APP_VERSION=${{ steps.meta.outputs.version }}

    - name: Generate SBOM
      uses: anchore/sbom-action@v0
      with:
        image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
        format: spdx-json
        output-file: sbom.spdx.json

    - name: Upload SBOM
      uses: actions/upload-artifact@v3
      with:
        name: sbom
        path: sbom.spdx.json

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment: staging

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBECONFIG }}

    - name: Deploy to staging
      run: |
        # Update image tag in Kubernetes manifests
        sed -i "s|aegis-scanner:latest|${{ needs.build.outputs.image-tag }}|g" k8s/staging/deployment.yaml

        # Apply Kubernetes manifests
        kubectl apply -f k8s/staging/ -n aegis-staging

        # Wait for rollout
        kubectl rollout status deployment/aegis-web -n aegis-staging --timeout=300s

    - name: Run smoke tests
      run: |
        # Wait for service to be ready
        kubectl wait --for=condition=ready pod -l app=aegis-web -n aegis-staging --timeout=120s

        # Run smoke tests
        STAGING_URL=$(kubectl get service aegis-web-service -n aegis-staging -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
        python scripts/smoke-tests.py --url "http://${STAGING_URL}"

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: [build, deploy-staging]
    if: github.event_name == 'release'
    environment: production

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.PROD_KUBECONFIG }}

    - name: Blue-Green Deployment
      run: |
        # Update image tag
        sed -i "s|aegis-scanner:latest|${{ needs.build.outputs.image-tag }}|g" k8s/production/deployment.yaml

        # Create blue deployment
        kubectl apply -f k8s/production/ -n aegis-production

        # Wait for new pods to be ready
        kubectl rollout status deployment/aegis-web -n aegis-production --timeout=600s

        # Run health checks
        python scripts/health-check.py --namespace aegis-production

        # Switch traffic (this would be more complex in real blue-green)
        kubectl patch service aegis-web-service -n aegis-production -p '{"spec":{"selector":{"version":"new"}}}'

    - name: Post-deployment tests
      run: |
        # Run comprehensive post-deployment tests
        python scripts/post-deployment-tests.py --environment production

    - name: Rollback on failure
      if: failure()
      run: |
        echo "Deployment failed, rolling back..."
        kubectl rollout undo deployment/aegis-web -n aegis-production
        kubectl rollout status deployment/aegis-web -n aegis-production --timeout=300s

  notify:
    name: Notify Teams
    runs-on: ubuntu-latest
    needs: [deploy-staging, deploy-production]
    if: always()

    steps:
    - name: Notify Slack
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
        fields: repo,message,commit,author,action,eventName,ref,workflow
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        REGISTRY = 'ghcr.io'
        IMAGE_NAME = 'aegis-cloud-scanner'
        DOCKER_BUILDKIT = '1'
        KUBECONFIG = credentials('k8s-kubeconfig')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 1, unit: 'HOURS')
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT_SHORT = env.GIT_COMMIT.take(8)
                    env.BUILD_TAG = "${env.BRANCH_NAME}-${env.BUILD_NUMBER}-${env.GIT_COMMIT_SHORT}"
                }
            }
        }

        stage('Setup') {
            parallel {
                stage('Python Setup') {
                    steps {
                        sh '''
                            python3 -m venv venv
                            . venv/bin/activate
                            pip install --upgrade pip
                            pip install -r requirements.txt
                            pip install -r requirements-dev.txt
                        '''
                    }
                }

                stage('Docker Setup') {
                    steps {
                        sh 'docker --version'
                        sh 'docker buildx create --use --name aegis-builder'
                    }
                }
            }
        }

        stage('Code Quality') {
            parallel {
                stage('Lint') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            flake8 . --format=junit-xml --output-file=flake8-results.xml
                            pylint app/ --output-format=parseable --reports=no > pylint-report.txt || true
                        '''
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'flake8-results.xml'
                            recordIssues enabledForFailure: true, tools: [pyLint(pattern: 'pylint-report.txt')]
                        }
                    }
                }

                stage('Security Scan') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            bandit -r . -f json -o bandit-report.json
                            safety check --json --output safety-report.json
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: '*-report.json', fingerprint: true
                        }
                    }
                }

                stage('Type Checking') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            mypy . --junit-xml mypy-results.xml
                        '''
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'mypy-results.xml'
                        }
                    }
                }
            }
        }

        stage('Test') {
            steps {
                sh '''
                    . venv/bin/activate
                    export DATABASE_URL="sqlite:///test.db"
                    export REDIS_URL="redis://localhost:6379/1"
                    export SECRET_KEY="test-secret-key"

                    # Start test services
                    docker-compose -f docker-compose.test.yml up -d postgres redis
                    sleep 10

                    # Run tests
                    pytest tests/ \
                        --cov=. \
                        --cov-report=xml \
                        --cov-report=html \
                        --junitxml=junit.xml \
                        --cov-fail-under=80
                '''
            }
            post {
                always {
                    publishTestResults testResultsPattern: 'junit.xml'
                    publishCoverage adapters: [coberturaAdapter('coverage.xml')], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
                cleanup {
                    sh 'docker-compose -f docker-compose.test.yml down -v'
                }
            }
        }

        stage('Build') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    tag pattern: 'v\\d+\\.\\d+\\.\\d+', comparator: 'REGEXP'
                }
            }
            steps {
                script {
                    def image = docker.build("${REGISTRY}/${IMAGE_NAME}:${BUILD_TAG}",
                        "--target production .")

                    docker.withRegistry("https://${REGISTRY}", 'github-token') {
                        image.push()
                        image.push('latest')
                    }

                    env.IMAGE_TAG = "${REGISTRY}/${IMAGE_NAME}:${BUILD_TAG}"
                }
            }
        }

        stage('Deploy to Staging') {
            when {
                branch 'main'
            }
            steps {
                script {
                    deployToEnvironment('staging', env.IMAGE_TAG)
                }
            }
        }

        stage('Integration Tests') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    . venv/bin/activate
                    python scripts/integration-tests.py --environment staging
                '''
            }
        }

        stage('Deploy to Production') {
            when {
                tag pattern: 'v\\d+\\.\\d+\\.\\d+', comparator: 'REGEXP'
            }
            steps {
                script {
                    input message: 'Deploy to production?', ok: 'Deploy',
                          submitterParameter: 'DEPLOYER'

                    deployToEnvironment('production', env.IMAGE_TAG)
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            slackSend channel: '#deployments',
                     color: 'good',
                     message: ":white_check_mark: Pipeline succeeded for ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
        }
        failure {
            slackSend channel: '#deployments',
                     color: 'danger',
                     message: ":x: Pipeline failed for ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
        }
    }
}

def deployToEnvironment(environment, imageTag) {
    sh """
        # Update Kubernetes manifests with new image tag
        sed -i 's|aegis-scanner:latest|${imageTag}|g' k8s/${environment}/deployment.yaml

        # Apply Kubernetes manifests
        kubectl apply -f k8s/${environment}/ -n aegis-${environment}

        # Wait for rollout
        kubectl rollout status deployment/aegis-web -n aegis-${environment} --timeout=600s

        # Run health check
        python scripts/health-check.py --namespace aegis-${environment}
    """
}
```

---

## Environment Management

### Environment Configuration

```bash
#!/bin/bash
# scripts/setup-environment.sh

set -euo pipefail

ENVIRONMENT=${1:-development}
CONFIG_DIR="config/environments"

echo "Setting up environment: $ENVIRONMENT"

# Create environment-specific configuration
case $ENVIRONMENT in
    development)
        export FLASK_ENV=development
        export FLASK_DEBUG=1
        export DATABASE_URL="sqlite:///aegis_dev.db"
        export REDIS_URL="redis://localhost:6379/0"
        export LOG_LEVEL=DEBUG
        ;;

    staging)
        export FLASK_ENV=production
        export FLASK_DEBUG=0
        export DATABASE_URL=${STAGING_DATABASE_URL}
        export REDIS_URL=${STAGING_REDIS_URL}
        export LOG_LEVEL=INFO
        ;;

    production)
        export FLASK_ENV=production
        export FLASK_DEBUG=0
        export DATABASE_URL=${PROD_DATABASE_URL}
        export REDIS_URL=${PROD_REDIS_URL}
        export LOG_LEVEL=WARNING
        ;;

    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

# Load environment-specific secrets
if [[ -f "$CONFIG_DIR/$ENVIRONMENT.env" ]]; then
    set -a
    source "$CONFIG_DIR/$ENVIRONMENT.env"
    set +a
fi

# Validate required environment variables
required_vars=(
    "DATABASE_URL"
    "REDIS_URL"
    "SECRET_KEY"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "Error: Required environment variable $var is not set"
        exit 1
    fi
done

echo "Environment $ENVIRONMENT configured successfully"
```

### Configuration Management

```python
# config/environments.py
import os
from pathlib import Path
from typing import Dict, Any

class EnvironmentConfig:
    """Environment-specific configuration management"""

    def __init__(self, environment: str = None):
        self.environment = environment or os.getenv('FLASK_ENV', 'development')
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load environment-specific configuration"""
        config_file = Path(f"config/environments/{self.environment}.yaml")

        if config_file.exists():
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)

        return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for environment"""
        configs = {
            'development': {
                'database': {
                    'url': 'sqlite:///aegis_dev.db',
                    'pool_size': 5,
                    'echo': True
                },
                'redis': {
                    'url': 'redis://localhost:6379/0',
                    'timeout': 5
                },
                'logging': {
                    'level': 'DEBUG',
                    'format': 'detailed'
                },
                'security': {
                    'csrf_enabled': True,
                    'session_timeout': 3600,
                    'rate_limit': {
                        'enabled': False
                    }
                },
                'features': {
                    'async_scanning': False,
                    'background_jobs': True,
                    'caching': False
                }
            },
            'staging': {
                'database': {
                    'url': os.getenv('STAGING_DATABASE_URL'),
                    'pool_size': 20,
                    'echo': False
                },
                'redis': {
                    'url': os.getenv('STAGING_REDIS_URL'),
                    'timeout': 10
                },
                'logging': {
                    'level': 'INFO',
                    'format': 'json'
                },
                'security': {
                    'csrf_enabled': True,
                    'session_timeout': 1800,
                    'rate_limit': {
                        'enabled': True,
                        'requests_per_minute': 60
                    }
                },
                'features': {
                    'async_scanning': True,
                    'background_jobs': True,
                    'caching': True
                }
            },
            'production': {
                'database': {
                    'url': os.getenv('PROD_DATABASE_URL'),
                    'pool_size': 50,
                    'echo': False
                },
                'redis': {
                    'url': os.getenv('PROD_REDIS_URL'),
                    'timeout': 15
                },
                'logging': {
                    'level': 'WARNING',
                    'format': 'json'
                },
                'security': {
                    'csrf_enabled': True,
                    'session_timeout': 900,
                    'rate_limit': {
                        'enabled': True,
                        'requests_per_minute': 100
                    }
                },
                'features': {
                    'async_scanning': True,
                    'background_jobs': True,
                    'caching': True
                }
            }
        }

        return configs.get(self.environment, configs['development'])

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def update(self, key: str, value: Any):
        """Update configuration value"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

# Environment configuration singleton
env_config = EnvironmentConfig()
```

### Secret Management

```python
# config/secrets.py
import os
import base64
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet

class SecretManager:
    """Manage application secrets securely"""

    def __init__(self):
        self.encryption_key = self._get_encryption_key()
        self.fernet = Fernet(self.encryption_key) if self.encryption_key else None
        self.secrets_cache = {}

    def _get_encryption_key(self) -> Optional[bytes]:
        """Get encryption key for secrets"""
        key = os.getenv('SECRETS_ENCRYPTION_KEY')
        if key:
            return base64.urlsafe_b64decode(key)
        return None

    def get_secret(self, secret_name: str, default: str = None) -> Optional[str]:
        """Get secret value"""
        # Try environment variable first
        env_var = f"SECRET_{secret_name.upper()}"
        value = os.getenv(env_var)

        if value:
            return value

        # Try encrypted secrets file
        if self.fernet:
            encrypted_value = self._read_encrypted_secret(secret_name)
            if encrypted_value:
                try:
                    decrypted = self.fernet.decrypt(encrypted_value.encode())
                    return decrypted.decode()
                except Exception:
                    pass

        # Try external secret management (AWS Secrets Manager, etc.)
        external_value = self._get_external_secret(secret_name)
        if external_value:
            return external_value

        return default

    def _read_encrypted_secret(self, secret_name: str) -> Optional[str]:
        """Read encrypted secret from file"""
        secrets_file = f"secrets/{secret_name}.enc"
        if os.path.exists(secrets_file):
            with open(secrets_file, 'r') as f:
                return f.read().strip()
        return None

    def _get_external_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from external secret management system"""
        # AWS Secrets Manager implementation
        if os.getenv('AWS_SECRETS_MANAGER_REGION'):
            try:
                import boto3
                secrets_client = boto3.client(
                    'secretsmanager',
                    region_name=os.getenv('AWS_SECRETS_MANAGER_REGION')
                )

                response = secrets_client.get_secret_value(
                    SecretId=f"aegis-scanner/{secret_name}"
                )
                return response['SecretString']
            except Exception:
                pass

        # HashiCorp Vault implementation
        vault_url = os.getenv('VAULT_URL')
        vault_token = os.getenv('VAULT_TOKEN')

        if vault_url and vault_token:
            try:
                import requests

                headers = {'X-Vault-Token': vault_token}
                response = requests.get(
                    f"{vault_url}/v1/secret/data/aegis-scanner/{secret_name}",
                    headers=headers,
                    timeout=10
                )

                if response.status_code == 200:
                    data = response.json()
                    return data['data']['data'].get(secret_name)
            except Exception:
                pass

        return None

    def set_secret(self, secret_name: str, secret_value: str):
        """Set secret value (for development/testing)"""
        if self.fernet:
            encrypted = self.fernet.encrypt(secret_value.encode())

            os.makedirs('secrets', exist_ok=True)
            with open(f'secrets/{secret_name}.enc', 'w') as f:
                f.write(encrypted.decode())

    def get_database_url(self) -> str:
        """Get database connection URL"""
        return self.get_secret('database_url') or os.getenv('DATABASE_URL')

    def get_secret_key(self) -> str:
        """Get Flask secret key"""
        return self.get_secret('secret_key') or os.getenv('SECRET_KEY')

    def get_redis_url(self) -> str:
        """Get Redis connection URL"""
        return self.get_secret('redis_url') or os.getenv('REDIS_URL')

# Global secret manager instance
secret_manager = SecretManager()
```

---

**End of Part 9**

**Next:** Part 10 will cover Troubleshooting and Maintenance, including debugging techniques, performance optimization, system monitoring, and operational procedures.