"""Application configuration loaded from environment variables / .env file.

Never hardcode secrets in source. All runtime configuration is read from the
environment or a local `.env` file (see `.env.example`).
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Location of this file: <repo>/backend/app/config.py
# parents[0] = app, parents[1] = backend, parents[2] = repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
DEFAULT_DB_PATH = (BACKEND_DIR / "cybersentinel.db").as_posix()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = "CyberSentinel"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # --- Security ---
    SECRET_KEY: str = "dev-only-insecure-secret-key-change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    AUTH_ENABLED: bool = True
    # bcrypt cost factor. 12 is the production default; lower it in tests for speed.
    BCRYPT_ROUNDS: int = 12

    # --- Database ---
    DATABASE_URL: str = f"sqlite:///{DEFAULT_DB_PATH}"
    AUTO_CREATE_TABLES: bool = True

    # --- HTTP ---
    CORS_ORIGINS: str = "*"
    REPORTS_DIR: str = "reports"          # relative to repo root
    FRONTEND_DIR: str = "frontend"        # relative to repo root

    # --- Scan engine ---
    SCAN_MAX_CONCURRENT: int = 2
    SCAN_TIMEOUT_SECONDS: int = 300
    NMAP_BIN_PATH: str = "nmap"

    # --- Target safety policy ---
    ALLOW_EXTERNAL_TARGETS: bool = False
    ALLOWED_TARGETS: str = ""

    # --- Web scanner ---
    WEB_CONNECT_TIMEOUT: float = 5.0
    WEB_READ_TIMEOUT: float = 10.0
    WEB_MAX_RESPONSE_BYTES: int = 2_000_000

    # --- Directory discovery ---
    DIRECTORY_WORDLIST: str = (
        "admin,api,backup,.git/config,config,console,debug,dev,docs,jenkins,"
        "login,phpmyadmin,private,robots.txt,server-status,test,uploads,wp-admin"
    )
    DIRECTORY_MAX_PATHS: int = 30
    DIRECTORY_DELAY_SECONDS: float = 0.2

    # --- Rate limiting ---
    RATE_LIMIT_REQUESTS: int = 120
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    AUTH_RATE_LIMIT_REQUESTS: int = 10
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # --- Derived helpers ---
    @property
    def cors_origin_list(self) -> list[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def directory_wordlist(self) -> list[str]:
        return [
            p.strip().lstrip("/")
            for p in self.DIRECTORY_WORDLIST.split(",")
            if p.strip()
        ]

    @property
    def allowed_targets(self) -> list[str]:
        return [
            t.strip()
            for t in self.ALLOWED_TARGETS.split(",")
            if t.strip()
        ]

    @property
    def reports_path(self) -> Path:
        p = Path(self.REPORTS_DIR)
        return p if p.is_absolute() else REPO_ROOT / p

    @property
    def frontend_path(self) -> Path:
        p = Path(self.FRONTEND_DIR)
        return p if p.is_absolute() else REPO_ROOT / p

    def validate_for_production(self) -> None:
        """Refuse to start in a non-development environment with a default secret."""
        if self.APP_ENV != "development" and self.SECRET_KEY.startswith("dev-only"):
            raise RuntimeError(
                "SECRET_KEY must be set to a strong random value outside development."
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_for_production()
    return settings
