from functools import lru_cache

from pydantic import Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    ci_project_id: str | None = None
    ci_commit_sha: str | None = None

    gitlab_api_key: SecretStr = Field(description="GitLab API Key")
    gitlab_base_url: str = Field(default="https://gitlab.com", description="GitLab base url")

    anthropic_api_key: SecretStr = Field(description="Anthropic API Key")
    anthropic_base_url: str | None = Field(default=None, description="Anthropic API base url")

    @field_validator("gitlab_base_url", "anthropic_base_url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        """Validate URL format."""
        if value is not None:
            HttpUrl(value)
        return value


@lru_cache
def get_settings() -> Settings:
    """Factory function to get settings instance."""
    return Settings()
