from functools import lru_cache

from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    ci_server_url: str | None = Field(default=None, description="GitLab CI server url")
    ci_project_id: str | None = None
    ci_merge_request_iid: str | None = None
    ci_project_dir: str | None = None

    gitlab_api_key: SecretStr = Field(description="GitLab API Key")
    gitlab_base_url: str = Field(default="https://gitlab.com", description="GitLab base url")

    anthropic_api_key: SecretStr = Field(description="Anthropic API Key")
    anthropic_base_url: str | None = Field(default=None, description="Anthropic API base url")
    claude_model: str = Field(description="Default claude model to use")

    enable_hard_exclusions: bool = True
    enable_claude_filtering: bool = True

    @model_validator(mode="before")
    @classmethod
    def resolve_gitlab_base_url_from_ci(cls, data: dict) -> dict:
        """Resolve gitlab_base_url from CI_SERVER_URL if not set."""
        if isinstance(data, dict):
            # Only set if not already provided
            if "gitlab_base_url" not in data or data["gitlab_base_url"] is None:
                ci_server_url = data.get("ci_server_url")
                if ci_server_url:
                    data["gitlab_base_url"] = ci_server_url
        return data

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
