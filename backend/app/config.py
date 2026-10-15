# Backend configuration using Pydantic Settings

from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource, EnvSettingsSource, DotEnvSettingsSource


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: EnvSettingsSource,
        dotenv_settings: DotEnvSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Priority: init_settings > env_settings > dotenv_settings > file_secret_settings
        # This ensures environment variables (set by docker-compose) override .env file
        return init_settings, env_settings, dotenv_settings, file_secret_settings

    # Application
    app_name: str = "Zero Phishing AI"
    app_env: str = "development"
    debug: bool = True
    log_level: str = "INFO"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_workers: int = 1

    # Database
    database_url: str = Field(default="postgresql+asyncpg://postgres:postgres@localhost:5432/zerophish")
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Google OAuth
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8080/auth/google/callback"

    # Microsoft OAuth
    microsoft_client_id: str = ""
    microsoft_client_secret: str = ""
    microsoft_tenant_id: str = "common"
    microsoft_redirect_uri: str = "http://localhost:8080/auth/microsoft/callback"

    # JWT
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # Google Safe Browsing
    safe_browsing_api_key: str = ""

    # User hashing
    user_hash_secret: str = ""

    # PhishTank
    phishtank_api_key: str = ""
    phishtank_data_url: str = "https://data.phishtank.com/data/online-valid.csv"

    # Google Gemini
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"

    # Domain reputation
    brand_list_path: str = "./data/brands.json"
    whois_cache_ttl_hours: int = 24

    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 3600

    # CORS
    cors_origins: list[str] = Field(default_factory=lambda: ["chrome-extension://*"])

    # OpenTelemetry
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "zero-phishing-backend"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def brand_list_file(self) -> Path:
        return Path(self.brand_list_path)


@lru_cache
def get_settings() -> Settings:
    return Settings()