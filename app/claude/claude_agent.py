from pathlib import Path
from typing import List, Literal

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from claude_agent_sdk.types import SystemPromptPreset
from pydantic import BaseModel

from app.config import Settings


class Finding(BaseModel):
    file: str
    line: int
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    category: str
    description: str
    exploit_scenario: str
    recommendation: str
    confidence: float


class AnalysisSummary(BaseModel):
    files_reviewed: int
    high_severity: int
    medium_severity: int
    low_severity: int
    review_completed: bool


class SecurityReviewOutput(BaseModel):
    findings: List[Finding]
    analysis_summary: AnalysisSummary


def get_claude_code_agent(settings: Settings, repo_dir: Path) -> ClaudeSDKClient:
    review_schema = {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "number"},
                        "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                        "category": {"type": "string"},
                        "description": {"type": "string"},
                        "exploit_scenario": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    },
                    "required": [
                        "file",
                        "line",
                        "severity",
                        "category",
                        "description",
                        "exploit_scenario",
                        "recommendation",
                        "confidence",
                    ],
                },
            },
            "analysis_summary": {
                "type": "object",
                "properties": {
                    "files_reviewed": {"type": "number"},
                    "high_severity": {"type": "number"},
                    "medium_severity": {"type": "number"},
                    "low_severity": {"type": "number"},
                    "review_completed": {"type": "boolean"},
                },
                "required": ["files_reviewed", "high_severity", "medium_severity", "low_severity", "review_completed"],
            },
        },
        "required": ["findings", "analysis_summary"],
    }

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
