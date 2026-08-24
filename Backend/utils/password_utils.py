"""Hash passwords and verify login attempts with bcrypt."""

import bcrypt


MAX_BCRYPT_PASSWORD_BYTES = 72


# Encode and truncate a password to bcrypt’s supported 72-byte input limit.
def _password_bytes(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_BCRYPT_PASSWORD_BYTES:
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    return encoded


# Convert a plaintext password into a bcrypt hash suitable for storage.
def hash_password(password: str) -> str:
    """Convert a plaintext password into a bcrypt hash suitable for storage.

    The original password is never returned or written to logs.
    """
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("utf-8")


# Check a plaintext login password against its stored bcrypt hash.
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
