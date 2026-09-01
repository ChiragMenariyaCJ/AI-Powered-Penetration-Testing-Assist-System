
# This file handles password utils.
import bcrypt


MAX_BCRYPT_PASSWORD_BYTES = 72


# Work with password bytes.
def _password_bytes(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_BCRYPT_PASSWORD_BYTES:
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    return encoded


# Hash password.
def hash_password(password: str) -> str:
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("utf-8")


# Verify password.
def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            _password_bytes(password),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False
