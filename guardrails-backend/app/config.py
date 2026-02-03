from functools import lru_cache
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application configuration settings."""

    # Application
    app_name: str = "Guardrails API"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # Database
    database_url: str = "postgresql://localhost:5432/guardrails"

    # Security
    secret_key: str = "change-me-in-production"
    allowed_origins: str = "*"

    # AI Configuration (Vercel AI Gateway)
    anthropic_base_url: str = "https://ai-gateway.vercel.sh"
    vercel_ai_gateway_api_key: Optional[str] = None
    ai_model: str = "anthropic/claude-haiku-4.5"
    ai_max_tokens: int = 4096

    # GitHub
    github_app_id: Optional[str] = None
    github_private_key: Optional[str] = None
    github_webhook_secret: Optional[str] = None

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_period: int = 60  # seconds

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
