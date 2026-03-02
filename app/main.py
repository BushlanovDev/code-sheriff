import asyncio
import sys
from pathlib import Path
from typing import Tuple

from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk.types import SystemPromptPreset
from pydantic import ValidationError

from app import get_mr_review_prompt
from app.config import get_settings, Settings
from app.constants import ExitCode
from app.gitlab import GitLabClient


def _get_settings() -> Settings:
    try:
        # Get environment configuration
        settings = get_settings()
    except ValidationError as e:
        print("Error: Validating settings failed.")
        print("Please check the following environment variables (or .env file):")
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            print(f"  - {field}: {error['msg']}")
        sys.exit(ExitCode.CONFIGURATION_ERROR)

    return settings


def _merge_request_info(settings: Settings) -> Tuple[str, int]:
    """Get project and merge request from GitLab environment or args"""
    project_id = settings.ci_project_id
    mr_iid = settings.ci_merge_request_iid

    if not project_id or not mr_iid:
        if len(sys.argv) > 2:
            project_id = sys.argv[1]
            mr_iid = sys.argv[2]
        else:
            print("Error: CI_PROJECT_ID and CI_MERGE_REQUEST_IID must be set in environment.")
            print("Usage: python main.py <project_id> <merge_request_iid>")
            sys.exit(ExitCode.CONFIGURATION_ERROR)

    return project_id, int(mr_iid)


async def main() -> None:
    """Main execution function for GitHub Action."""
    settings = _get_settings()
    # Get project and merge request from GitLab environment or args
    project_id, mr_iid = _merge_request_info(settings)

    # Get repo directory from environment or use current directory
    repo_dir = Path(settings.ci_project_dir) if settings.ci_project_dir else Path.cwd()
    if not repo_dir.exists():
        print(f"Repository directory does not exist: {repo_dir}")
        sys.exit(ExitCode.CONFIGURATION_ERROR)

    print(f"Starting review for Project: {project_id}, merge request: {mr_iid}")

    gitlab_client = GitLabClient(
        base_url=settings.gitlab_base_url,
        token=settings.gitlab_api_key.get_secret_value(),
    )

    mr_data = gitlab_client.get_merge_request_data(project_id, mr_iid)
    # Check if MR is already merged or closed
    if mr_data.get("state") in ["merged", "closed"]:
        print(f"MR is {mr_data.get('state')}, skipping review")
        sys.exit(ExitCode.SUCCESS)

    mr_changes = gitlab_client.get_merge_request_changes(project_id, mr_iid)
    # Check for empty diff
    if not mr_changes.get("changes"):
        print("No changes detected in MR")
        sys.exit(ExitCode.SUCCESS)

    mr_diff = gitlab_client.format_mr_diff(mr_changes)
    # Generate security audit prompt
    prompt = get_mr_review_prompt(mr_data, mr_diff)

    # Check prompt size
    prompt_size = len(prompt.encode("utf-8"))
    if prompt_size > 1024 * 1024:  # 1MB
        print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB")

    #################################################################################

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
        disallowed_tools=["Write", "Edit", "WebSearch", "WebFetch", "AskUserQuestion"],
        permission_mode="bypassPermissions",
        max_turns=100,
        cwd=repo_dir,
        system_prompt=SystemPromptPreset(type="preset", preset="claude_code"),
        output_format={
            "type": "json_schema",
            "schema": review_schema,
        },
    )

    async for message in query(prompt=prompt, options=options):
        print(message)
        print("#################################################################################")

    #################################################################################

    sys.exit(ExitCode.SUCCESS)


if __name__ == "__main__":
    asyncio.run(main())
