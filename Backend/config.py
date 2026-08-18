import json
import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:  # Environment variables still work without optional .env loading.
    def load_dotenv() -> bool:
        return False


load_dotenv()


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _cors_origins(value: str | None) -> tuple[str, ...]:
    if not value:
        return ("http://localhost:3000", "http://localhost:8000")

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = [item.strip() for item in value.split(",")]

    if not isinstance(parsed, list):
        raise ValueError("CORS_ORIGINS must be a JSON array or comma-separated list")
    return tuple(str(item).strip() for item in parsed if str(item).strip())


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_host: str
    api_port: int
    secret_key: str
    algorithm: str
    access_token_expire_hours: int
    nmap_path: str
    nmap_timeout: int
    cors_origins: tuple[str, ...]
    debug: bool


def get_settings() -> Settings:
    secret_key = os.getenv("SECRET_KEY", "change-this-development-secret")

    return Settings(
        database_url=os.getenv(
            "DATABASE_URL",
            "mysql+pymysql://ptas_user:ptas_password@localhost:3306/ptas_db",
        ),
        api_host=os.getenv("API_HOST", "127.0.0.1"),
        api_port=int(os.getenv("API_PORT", "8000")),
        secret_key=secret_key,
        algorithm=os.getenv("ALGORITHM", "HS256"),
        access_token_expire_hours=int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "2")),
        nmap_path=os.getenv("NMAP_PATH", "nmap"),
        nmap_timeout=int(os.getenv("NMAP_TIMEOUT", "300")),
        cors_origins=_cors_origins(os.getenv("CORS_ORIGINS")),
        debug=_as_bool(os.getenv("DEBUG"), default=False),
    )


settings = get_settings()
