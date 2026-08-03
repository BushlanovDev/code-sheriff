"""Tests for main.py helper functions."""

import sys
from unittest.mock import patch

from app.claude import Finding, SecurityReviewOutput
from app.config import Settings
from app.constants import REVIEW_HEADER, Severity
from app.gitlab.models import Discussion, MergeRequestData
from app.main import (
    _format_review_to_markdown,
    _get_tool_summary,
    _is_already_reviewed,
    _merge_request_param,
)


def test_is_already_reviewed():
    discussions: list[Discussion] = [
        {"notes": [{"body": "Some comment"}]},
        {"notes": [{"body": f"{REVIEW_HEADER}\nCommit: 12345678"}]},
    ]

    # Matching SHA
    assert _is_already_reviewed(discussions, "1234567890abcdef") is True
    # Different SHA
    assert _is_already_reviewed(discussions, "abcdef12") is False
    # Empty SHA
    assert _is_already_reviewed(discussions, "") is False
    # Empty discussions
    assert _is_already_reviewed([], "12345678") is False


def test_format_review_empty():
    result = SecurityReviewOutput(
        findings=[],
        analysis_summary={
            "files_reviewed": 1,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "review_completed": True,
        },
    )
    markdown = _format_review_to_markdown(result, None)
    assert "No notable security or code quality issues found" in markdown


def test_format_review_with_findings():
    result = SecurityReviewOutput(
        findings=[
            Finding(
                file="app.py",
                line=1,
                severity=Severity.HIGH,
                category="sql_injection",
                description="d1",
                exploit_scenario="e",
                recommendation="r",
                confidence=0.9,
            ),
            Finding(
                file="main.py",
                line=2,
                severity=Severity.LOW,
                category="info",
                description="d2",
                exploit_scenario="e",
                recommendation="r",
                confidence=0.9,
            ),
        ],
        analysis_summary={
            "files_reviewed": 1,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 1,
            "review_completed": True,
        },
    )
    mr_data: MergeRequestData = {
        "author": {"name": "Test User"},
        "source_branch": "feature/test",
        "diff_refs": {"head_sha": "abcdef", "base_sha": "123456", "start_sha": "123456"},
    }
    markdown = _format_review_to_markdown(result, mr_data)

    assert "Issues Found (2)" in markdown
    assert "HIGH" in markdown
    assert "LOW" in markdown
    assert "Test User" in markdown
    assert "feature/test" in markdown


def test_merge_request_param_from_settings():
    settings = Settings(
        _env_file=None,
        gitlab_api_key="key",
        anthropic_api_key="key",
        claude_model="model",
        ci_project_id="123",
        ci_merge_request_iid="456",
    )
    pid, iid = _merge_request_param(settings)
    assert pid == "123"
    assert iid == 456


@patch.dict("os.environ", {}, clear=True)
@patch.object(sys, "argv", ["main.py", "789", "101"])
def test_merge_request_param_from_argv():
    settings = Settings(
        _env_file=None,
        gitlab_api_key="key",
        anthropic_api_key="key",
        claude_model="model",
    )
    pid, iid = _merge_request_param(settings)
    assert pid == "789"
    assert iid == 101


def test_get_tool_summary():
    assert "ls -la" in _get_tool_summary("Bash", {"command": "ls -la"})
    assert "test.py" in _get_tool_summary("Read", {"file_path": "test.py"})

    grep_summary = _get_tool_summary("Grep", {"pattern": "TODO", "path": "app/"})
    assert "TODO" in grep_summary
    assert "app/" in grep_summary

    assert _get_tool_summary("UnknownTool", {}) == "..."
