"""Create and verify signed authentication tokens."""

from datetime import UTC, datetime, timedelta
from jose import JWTError, jwt

from Backend.config import settings


def create_access_token(data: dict) -> str:
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
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )
    except JWTError:
        return None
