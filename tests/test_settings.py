"""Tests for Settings — validation, parsing, and defaults."""

import os

import pytest
from pydantic import ValidationError

from app.config.settings import Settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Prevent locally loaded .env from leaking into tests."""
    for key in list(os.environ.keys()):
        if key.startswith("CI_") or key in (
            "GITLAB_API_KEY",
            "GITLAB_BASE_URL",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_MODEL",
            "CLAUDE_FILTERING_MODEL",
            "ENABLE_HARD_EXCLUSIONS",
            "ENABLE_CLAUDE_FILTERING",
            "EXCLUDE_DIRECTORIES",
            "CUSTOM_FILTER_INSTRUCTIONS",
            "CUSTOM_SECURITY_SCAN_INSTRUCTIONS",
            "SKIP_REVIEWED",
        ):
            monkeypatch.delenv(key, raising=False)


def _settings(**kwargs) -> Settings:
    """Create Settings isolated from .env file on disk."""
    return Settings(_env_file=None, **kwargs)


class TestParseExcludeDirectories:
    def test_comma_separated_string(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            exclude_directories="node_modules,dist,build",
        )
        assert s.exclude_directories == ["node_modules", "dist", "build"]

    def test_empty_string(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            exclude_directories="",
        )
        assert s.exclude_directories == []

    def test_list_passthrough(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            exclude_directories=["a", "b"],
        )
        assert s.exclude_directories == ["a", "b"]

    def test_strips_whitespace(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            exclude_directories=" a , b , c ",
        )
        assert s.exclude_directories == ["a", "b", "c"]


class TestDefaults:
    def test_default_gitlab_base_url(self):
        s = _settings(gitlab_api_key="test", anthropic_api_key="test", claude_model="test")
        assert s.gitlab_base_url == "https://gitlab.com"

    def test_default_enable_hard_exclusions(self):
        s = _settings(gitlab_api_key="test", anthropic_api_key="test", claude_model="test")
        assert s.enable_hard_exclusions is True

    def test_default_enable_claude_filtering(self):
        s = _settings(gitlab_api_key="test", anthropic_api_key="test", claude_model="test")
        assert s.enable_claude_filtering is False

    def test_default_skip_reviewed(self):
        s = _settings(gitlab_api_key="test", anthropic_api_key="test", claude_model="test")
        assert s.skip_reviewed is True


class TestResolveGitLabBaseUrl:
    def test_ci_server_url_used_when_base_not_set(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            ci_server_url="https://git.company.com",
        )
        assert s.gitlab_base_url == "https://git.company.com"

    def test_explicit_base_url_takes_priority(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            ci_server_url="https://git.company.com",
            gitlab_base_url="https://custom.gitlab.io",
        )
        assert s.gitlab_base_url == "https://custom.gitlab.io"


class TestRequiredFields:
    def test_missing_gitlab_api_key(self, monkeypatch):
        monkeypatch.delenv("GITLAB_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            Settings(_env_file=None, anthropic_api_key="test", claude_model="test")

    def test_missing_anthropic_api_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            Settings(_env_file=None, gitlab_api_key="test", claude_model="test")

    def test_missing_claude_model(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_MODEL", raising=False)
        with pytest.raises(ValidationError):
            Settings(_env_file=None, gitlab_api_key="test", anthropic_api_key="test")


class TestUrlValidation:
    def test_invalid_gitlab_base_url(self):
        with pytest.raises(ValidationError):
            _settings(
                gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
                gitlab_base_url="not-a-url",
            )

    def test_valid_gitlab_base_url(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            gitlab_base_url="https://gitlab.example.com",
        )
        assert s.gitlab_base_url == "https://gitlab.example.com"

    def test_none_anthropic_base_url_ok(self):
        s = _settings(
            gitlab_api_key="test", anthropic_api_key="test", claude_model="test",
            anthropic_base_url=None,
        )
        assert s.anthropic_base_url is None
