
# This file handles config.
import json
import os
import secrets
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:  # Environment variables still work without optional .env loading.
    # Load dotenv.
    def load_dotenv() -> bool:
        return False


# Load local development values before constructing the immutable settings object.
load_dotenv()


# Convert a setting to a Boolean value.
def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Work with cors origins.
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


# Handle the settings.
@dataclass(frozen=True)
class Settings:

    app_env: str
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

    # Check whether production.
    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


# Get settings.
def get_settings() -> Settings:

    app_env = os.getenv("APP_ENV", "development").strip().lower()
    if app_env not in {"development", "test", "production"}:
        raise ValueError("APP_ENV must be development, test, or production")

    secret_key = os.getenv("SECRET_KEY", "").strip()
    if app_env == "production":
        if len(secret_key) < 32:
            raise ValueError("SECRET_KEY must contain at least 32 characters in production")
    elif not secret_key:
        # An unpredictable per-process key is safer than a shared source-code default.
        secret_key = secrets.token_urlsafe(32)

    return Settings(
        app_env=app_env,
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
        debug=_as_bool(os.getenv("DEBUG"), default=app_env == "development"),
    )


settings = get_settings()
