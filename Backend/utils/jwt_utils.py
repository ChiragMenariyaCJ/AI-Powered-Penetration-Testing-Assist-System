"""Create and verify signed authentication tokens."""

from datetime import UTC, datetime, timedelta
from jose import JWTError, jwt

from Backend.config import settings


def create_access_token(data: dict) -> str:
    """Perform the token operation needed to create access token.

    Signing configuration comes from application settings rather than from the request.
    """
    payload = data.copy()

    payload["exp"] = datetime.now(UTC) + timedelta(
        hours=settings.access_token_expire_hours
    )

    return jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def decode_access_token(token: str) -> dict | None:
    """Perform the token operation needed to decode access token.

    Signing configuration comes from application settings rather than from the request.
    """
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )
    except JWTError:
        return None
