from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from claude_agent_sdk.types import SystemPromptPreset
from pydantic import BaseModel, Field

from app.config import Settings
from app.constants import Severity


class Finding(BaseModel):
    file: str
    line: int
    severity: Severity
    category: str
    description: str
    exploit_scenario: str
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)


class AnalysisSummary(BaseModel):
    files_reviewed: int
    high_severity: int
    medium_severity: int
    low_severity: int
    review_completed: bool


class SecurityReviewOutput(BaseModel):
    findings: list[Finding]
    analysis_summary: AnalysisSummary


class FilterOutput(BaseModel):
    confidence_score: float = Field(ge=0.0, le=1.0)
    justification: str
    keep_finding: bool
    exclusion_reason: str | None = None


def get_claude_code_agent(settings: Settings, repo_dir: Path) -> ClaudeSDKClient:
    review_schema = SecurityReviewOutput.model_json_schema()
    print(review_schema) # TODO

    options = ClaudeAgentOptions(
        model=settings.claude_model,
        setting_sources=["project"],
        allowed_tools=["Read", "Glob", "Grep", "Bash", "StructuredOutput"],
        disallowed_tools=["Write", "Edit", "WebSearch", "WebFetch", "AskUserQuestion", "TodoWrite"],
        permission_mode="bypassPermissions",
        max_turns=50,
        cwd=repo_dir,
        system_prompt=SystemPromptPreset(type="preset", preset="claude_code"),
        output_format={
            "type": "json_schema",
            "schema": review_schema,
        },
    )

    return ClaudeSDKClient(options=options)


def get_claude_filter_agent(model: str) -> ClaudeSDKClient:
    filter_schema = FilterOutput.model_json_schema()
    print(filter_schema) # TODO

    options = ClaudeAgentOptions(
        model=model,
        setting_sources=["project"],
        allowed_tools=["StructuredOutput"],
        disallowed_tools=["Write", "Edit", "WebSearch", "WebFetch", "AskUserQuestion",
                          "TodoWrite", "Bash", "Read", "Grep", "Glob"],
        permission_mode="bypassPermissions",
        max_turns=10,
        cwd=Path.cwd(),
        output_format={
            "type": "json_schema",
            "schema": filter_schema,
        },
    )

    return ClaudeSDKClient(options=options)
