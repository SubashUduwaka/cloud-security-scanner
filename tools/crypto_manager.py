import os
import base64
import logging
from datetime import datetime
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets


def generate_secure_password() -> str:
    """Generate a cryptographically secure password (32 bytes)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

class SecureCryptoManager:
    """
    Secure credential encryption manager with proper key derivation
    and separation of concerns.
    """
    
    def __init__(self, master_password: Optional[str] = None, salt_path: Optional[str] = None):
        """
        Initialize the crypto manager.
        
        Args:
            master_password: Master password for key derivation (if None, generates one)
            salt_path: Path to store/load salt file
        """
        self.salt_path = salt_path or os.path.join(os.getcwd(), '.salt')
        self._fernet = None
        self._initialize_crypto(master_password)
    
    def _initialize_crypto(self, master_password: Optional[str]) -> None:
        """Initialize cryptographic components with proper key derivation."""
        try:
            
            salt = self._load_or_generate_salt()
            
            
            if not master_password:
                master_password = generate_secure_password() # Use the new standalone function
                logging.warning("Generated new master password. Store it securely!")
                logging.warning(f"Master Password: {master_password}")
            
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,  
                backend=default_backend()
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            self._fernet = Fernet(key)
            
            logging.info("Crypto manager initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize crypto manager: {e}")
            raise
    
    def _load_or_generate_salt(self) -> bytes:
        """Load existing salt or generate a new one."""
        try:
            if os.path.exists(self.salt_path):
                with open(self.salt_path, 'rb') as f:
                    salt = f.read()
                logging.debug("Loaded existing salt")
            else:
                salt = os.urandom(16)  # 128-bit salt
                with open(self.salt_path, 'wb') as f:
                    f.write(salt)
                
                if hasattr(os, 'chmod'):
                    os.chmod(self.salt_path, 0o600)
                logging.info("Generated new salt file")
            
            return salt
            
        except Exception as e:
            logging.error(f"Salt management failed: {e}")
            raise
    
    
    

    ...
    def encrypt_credential(self, credential: str, context: str = "credential") -> str:
        """
        Encrypt a credential string.
        
        Args:
            credential: The credential to encrypt
            context: Description for logging purposes
            
        Returns:
            Base64 encoded encrypted credential
            
        Raises:
            ValueError: If crypto manager is not initialized
        """
        if not self._fernet:
            raise ValueError("Crypto manager not properly initialized")
        
        try:
            encrypted_data = self._fernet.encrypt(credential.encode('utf-8'))
            encoded_data = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
            logging.info(f"Successfully encrypted {context}")
            logging.debug(f"Encrypted data length: {len(encoded_data)} characters")
            
            return encoded_data
            
        except Exception as e:
            logging.error(f"Failed to encrypt {context}: {e}")
            raise
    
    def decrypt_credential(self, encrypted_credential: str, context: str = "credential") -> str:
        """
        Decrypt a credential string.
        
        Args:
            encrypted_credential: Base64 encoded encrypted credential
            context: Description for logging purposes
            
        Returns:
            Decrypted credential string
            
        Raises:
            ValueError: If crypto manager is not initialized or decryption fails
        """
        if not self._fernet:
            raise ValueError("Crypto manager not properly initialized")
        
        try:
            
            encrypted_data = base64.urlsafe_b64decode(encrypted_credential.encode('utf-8'))
            
            
            decrypted_data = self._fernet.decrypt(encrypted_data)
            credential = decrypted_data.decode('utf-8')
            
            logging.info(f"Successfully decrypted {context}")
            
            return credential
            
        except Exception as e:
            logging.error(f"Failed to decrypt {context}: {e}")
            raise ValueError(f"Decryption failed for {context}")
    
    def rotate_encryption_key(self, new_master_password: str) -> 'SecureCryptoManager':
        """
        Create a new crypto manager with a different master password.
        Used for key rotation.
        
        Args:
            new_master_password: New master password
            
        Returns:
            New SecureCryptoManager instance
        """
        logging.info("Rotating encryption key")
        return SecureCryptoManager(new_master_password, self.salt_path)
    
    def is_initialized(self) -> bool:
        """Check if crypto manager is properly initialized."""
        return self._fernet is not None
    
    def health_check(self) -> dict:
        """
        Perform a health check on the crypto manager.
        
        Returns:
            Dictionary with health status information
        """
        try:
            
            test_data = "health_check_test_string"
            encrypted = self.encrypt_credential(test_data, "health_check")
            decrypted = self.decrypt_credential(encrypted, "health_check")
            
            success = decrypted == test_data
            
            return {
                "status": "healthy" if success else "unhealthy",
                "initialized": self.is_initialized(),
                "salt_file_exists": os.path.exists(self.salt_path),
                "test_encryption_cycle": success,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Crypto manager health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "initialized": self.is_initialized(),
                "salt_file_exists": os.path.exists(self.salt_path),
                "timestamp": datetime.now().isoformat()
            }



class CredentialMigrator:
    """Helper class to migrate from old encryption to new secure encryption."""
    
    def __init__(self, old_fernet_key: str, new_crypto_manager: SecureCryptoManager):
        """
        Initialize migrator.
        
        Args:
            old_fernet_key: The old Fernet key from .env
            new_crypto_manager: New secure crypto manager
        """
        self.old_fernet = Fernet(old_fernet_key.encode()) if old_fernet_key else None
        self.new_crypto = new_crypto_manager
    
    def migrate_credential(self, old_encrypted_credential: str, context: str = "credential") -> str:
        """
        Migrate a credential from old encryption to new encryption.
        
        Args:
            old_encrypted_credential: Credential encrypted with old method
            context: Description for logging
            
        Returns:
            Credential encrypted with new method
        """
        if not self.old_fernet:
            raise ValueError("Old encryption key not provided")
        
        try:
            
            decrypted = self.old_fernet.decrypt(old_encrypted_credential.encode()).decode()
            
            
            new_encrypted = self.new_crypto.encrypt_credential(decrypted, context)
            
            logging.info(f"Successfully migrated {context}")
            return new_encrypted
            
        except Exception as e:
            logging.error(f"Failed to migrate {context}: {e}")
            raise



def setup_secure_crypto_manager() -> SecureCryptoManager:
    """
    Setup secure crypto manager with proper configuration.
    
    Returns:
        Configured SecureCryptoManager instance
    """
    
    try:
        from secrets_manager import secrets_manager
        master_password = secrets_manager.get_master_password()
    except ImportError:
        
        master_password = os.getenv('AEGIS_MASTER_PASSWORD')
    
    if not master_password:
        logging.warning("No master password found in environment. Generating new one.")
        logging.warning("Set AEGIS_MASTER_PASSWORD environment variable for production use.")
        logging.warning("Current environment variables containing 'AEGIS':")
        for key, value in os.environ.items():
            if 'AEGIS' in key.upper():
                logging.warning(f"  {key} = {value[:20]}..." if len(value) > 20 else f"  {key} = {value}")
    else:
        logging.info(f"Master password found in environment (length: {len(master_password)})")
    
    return SecureCryptoManager(master_password)