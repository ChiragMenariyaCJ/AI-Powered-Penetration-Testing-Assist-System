from datetime import datetime, timedelta
from jose import jwt

SECRET_KEY = "change_this_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 2


def create_access_token(data: dict) -> str:
    payload = data.copy()

    payload["exp"] = datetime.utcnow() + timedelta(
        hours=ACCESS_TOKEN_EXPIRE_HOURS
    )

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )