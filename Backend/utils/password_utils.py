"""Hash passwords and verify login attempts with bcrypt."""

import bcrypt


MAX_BCRYPT_PASSWORD_BYTES = 72


def _password_bytes(password: str) -> bytes:
    """Implement the internal password bytes step used by this module's public workflow.

    It remains private so callers depend on the supported public interface.
    """
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_BCRYPT_PASSWORD_BYTES:
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    return encoded


def hash_password(password: str) -> str:
    """Convert a plaintext password into a bcrypt hash suitable for storage.

    The original password is never returned or written to logs.
    """
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """Check a plaintext login password against its stored bcrypt hash.

    Only a boolean match result is returned so credentials do not escape this helper.
    """
    try:
        return bcrypt.checkpw(
            _password_bytes(password),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False
