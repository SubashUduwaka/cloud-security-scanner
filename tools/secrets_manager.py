# secrets_manager.py - Production-ready secrets management
import os
import logging
from typing import Optional, Dict, Any
import json

logger = logging.getLogger(__name__)

class SecretsManager:
    """
    Production-ready secrets management with support for multiple backends:
    - Environment variables (development)
    - AWS Secrets Manager (production)
    - Azure Key Vault (production)
    - Google Secret Manager (production)
    - File-based secrets (container orchestration)
    """
    
    def __init__(self):
        self.backend = self._detect_backend()
        logger.info(f"Initialized secrets manager with backend: {self.backend}")
    
    def _detect_backend(self) -> str:
        """Detect which secrets backend to use based on environment"""
        if os.getenv('AWS_SECRETS_MANAGER_SECRET_NAME'):
            return 'aws'
        elif os.getenv('AZURE_KEY_VAULT_URL'):
            return 'azure'
        elif os.getenv('GCP_SECRET_MANAGER_PROJECT_ID'):
            return 'gcp'
        elif os.path.exists('/run/secrets'):  # Docker secrets
            return 'docker'
        elif os.path.exists('/var/secrets/kubernetes.io'):  # Kubernetes secrets
            return 'kubernetes'
        else:
            return 'env'  # Environment variables (development)
    
    def get_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret value from the configured backend"""
        try:
            if self.backend == 'aws':
                return self._get_aws_secret(secret_name, default)
            elif self.backend == 'azure':
                return self._get_azure_secret(secret_name, default)
            elif self.backend == 'gcp':
                return self._get_gcp_secret(secret_name, default)
            elif self.backend == 'docker':
                return self._get_docker_secret(secret_name, default)
            elif self.backend == 'kubernetes':
                return self._get_kubernetes_secret(secret_name, default)
            else:
                return self._get_env_secret(secret_name, default)
        except Exception as e:
            logger.error(f"Failed to retrieve secret '{secret_name}': {e}")
            return default
    
    def _get_env_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from environment variables"""
        return os.getenv(secret_name, default)
    
    def _get_aws_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from AWS Secrets Manager"""
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            secret_manager_name = os.getenv('AWS_SECRETS_MANAGER_SECRET_NAME')
            region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            
            client = boto3.client('secretsmanager', region_name=region)
            response = client.get_secret_value(SecretId=secret_manager_name)
            
            secrets = json.loads(response['SecretString'])
            return secrets.get(secret_name, default)
            
        except ImportError:
            logger.warning("boto3 not installed, falling back to environment variables")
            return self._get_env_secret(secret_name, default)
        except ClientError as e:
            logger.error(f"AWS Secrets Manager error: {e}")
            return default
    
    def _get_azure_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from Azure Key Vault"""
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential
            
            vault_url = os.getenv('AZURE_KEY_VAULT_URL')
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=vault_url, credential=credential)
            
            secret = client.get_secret(secret_name)
            return secret.value
            
        except ImportError:
            logger.warning("Azure SDK not installed, falling back to environment variables")
            return self._get_env_secret(secret_name, default)
        except Exception as e:
            logger.error(f"Azure Key Vault error: {e}")
            return default
    
    def _get_gcp_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from Google Secret Manager"""
        try:
            from google.cloud import secretmanager
            
            project_id = os.getenv('GCP_SECRET_MANAGER_PROJECT_ID')
            client = secretmanager.SecretManagerServiceClient()
            
            name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
            response = client.access_secret_version(request={"name": name})
            
            return response.payload.data.decode("UTF-8")
            
        except ImportError:
            logger.warning("Google Cloud SDK not installed, falling back to environment variables")
            return self._get_env_secret(secret_name, default)
        except Exception as e:
            logger.error(f"Google Secret Manager error: {e}")
            return default
    
    def _get_docker_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from Docker secrets"""
        try:
            secret_path = f"/run/secrets/{secret_name}"
            if os.path.exists(secret_path):
                with open(secret_path, 'r') as f:
                    return f.read().strip()
            return default
        except Exception as e:
            logger.error(f"Docker secrets error: {e}")
            return default
    
    def _get_kubernetes_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from Kubernetes secrets"""
        try:
            secret_path = f"/var/secrets/kubernetes.io/{secret_name}"
            if os.path.exists(secret_path):
                with open(secret_path, 'r') as f:
                    return f.read().strip()
            return default
        except Exception as e:
            logger.error(f"Kubernetes secrets error: {e}")
            return default
    
    def get_database_url(self) -> Optional[str]:
        """Get database URL with proper fallback"""
        return self.get_secret('DATABASE_URL')
    
    def get_secret_key(self) -> str:
        """Get Flask secret key with secure fallback"""
        secret_key = self.get_secret('SECRET_KEY')
        if not secret_key:
            logger.warning("SECRET_KEY not found in secrets, generating random key")
            import secrets
            return secrets.token_hex(32)
        return secret_key
    
    def get_master_password(self) -> Optional[str]:
        """Get Aegis master password"""
        return self.get_secret('AEGIS_MASTER_PASSWORD')
    
    def get_mail_config(self) -> Dict[str, Any]:
        """Get email configuration"""
        return {
            'MAIL_SERVER': self.get_secret('MAIL_SERVER'),
            'MAIL_PORT': int(self.get_secret('MAIL_PORT', '587')),
            'MAIL_USE_TLS': self.get_secret('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't'),
            'MAIL_USERNAME': self.get_secret('MAIL_USERNAME'),
            'MAIL_PASSWORD': self.get_secret('MAIL_PASSWORD'),
        }
    
    def validate_production_secrets(self) -> Dict[str, bool]:
        """Validate that all required production secrets are available"""
        required_secrets = [
            'SECRET_KEY',
            'AEGIS_MASTER_PASSWORD',
            'MAIL_SERVER',
            'MAIL_USERNAME',
            'MAIL_PASSWORD'
        ]
        
        validation_results = {}
        for secret in required_secrets:
            value = self.get_secret(secret)
            validation_results[secret] = value is not None and len(value.strip()) > 0
        
        return validation_results

# Global instance
secrets_manager = SecretsManager()