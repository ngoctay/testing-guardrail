import hashlib
import hmac
import secrets
from typing import Optional
from cryptography.fernet import Fernet
import base64

from app.config import get_settings

settings = get_settings()


class TokenManager:
    """Secure token handling for encryption and verification."""

    def __init__(self, encryption_key: Optional[str] = None):
        key = encryption_key or settings.secret_key
        # Derive a valid Fernet key from the secret
        derived_key = hashlib.sha256(key.encode()).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(derived_key))

    def encrypt_token(self, token: str) -> str:
        """Encrypt a token for secure storage."""
        return self.fernet.encrypt(token.encode()).decode()

    def decrypt_token(self, encrypted: str) -> str:
        """Decrypt a stored token."""
        return self.fernet.decrypt(encrypted.encode()).decode()

    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    @staticmethod
    def verify_api_key(api_key: str, hashed: str) -> bool:
        """Verify an API key against its hash."""
        return hmac.compare_digest(
            hashlib.sha256(api_key.encode()).hexdigest(),
            hashed
        )


def verify_github_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str,
) -> bool:
    """Verify GitHub webhook signature."""
    if not signature.startswith("sha256="):
        return False

    expected_signature = "sha256=" + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)
