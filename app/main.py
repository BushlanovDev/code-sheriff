import asyncio
import sys
from pathlib import Path
from typing import Tuple, List, Any, Dict

from claude_agent_sdk import AssistantMessage, ResultMessage
from pydantic import BaseModel, ValidationError

from app.claude import get_claude_code_agent

from app import get_mr_review_prompt
from app.config import get_settings, Settings
from app.constants import ExitCode
from app.gitlab import GitLabClient


class AnalysisSummary(BaseModel):
    files_reviewed: int
    high_severity: int
    medium_severity: int
    low_severity: int
    review_completed: bool


class SecurityReviewOutput(BaseModel):
    findings: List[Any]
    analysis_summary: AnalysisSummary


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


def _get_block_input_dict(block: Any) -> Dict[str, Any]:
    input_data = getattr(block, "input", {}) or {}
    if isinstance(input_data, dict):
        return input_data
    return getattr(input_data, "__dict__", {}) or {}


def _get_tool_summary(name: str, block_input: Dict[str, Any]) -> str:
    match name:
        case "Bash":
            return str(block_input.get("command", "command"))
        case "Read":
            return str(block_input.get("file_path", "file"))
        case "Glob":
            return str(block_input.get("pattern", "pattern"))
        case "Grep":
            pattern = block_input.get("pattern", "pattern")
            path = block_input.get("path", ".")
            return f'"{pattern}" in {path}'
        case _:
            return ""


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

    claude_code_agent = get_claude_code_agent(settings, repo_dir)
    final_output: SecurityReviewOutput | None = None

    async with claude_code_agent:
        await claude_code_agent.query(prompt)

        async for message in claude_code_agent.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if hasattr(block, "name"):
                        block_input = _get_block_input_dict(block)

                        if block.name == "Task":
                            print(f"🤖 Delegating to: {block_input.get('subagent_type', 'unknown')}")
                        else:
                            print(f"📂 {block.name}: {_get_tool_summary(block.name, block_input)}")

            elif isinstance(message, ResultMessage):
                print(message)
                if message.subtype == "success" and message.structured_output is not None:
                    try:
                        final_output = SecurityReviewOutput.model_validate(message.structured_output)
                    except ValidationError as e:
                        print(f"Failed to parse structured output: {e}")

                    cost = getattr(message, "total_cost_usd", 0.0)
                    duration = getattr(message, "duration_ms", 0) / 1000
                    usage = getattr(message, "usage", {})
                    input_tokens = usage.get("input_tokens", 0)
                    output_tokens = usage.get("output_tokens", 0)

                    print(f"\n✅ Review complete!")
                    print(f"Cost: ${cost:.4f}")
                    print(f"Duration: {duration:.4f}")
                    print(f"Input tokens: {input_tokens}")
                    print(f"Output tokens: {output_tokens}")
                else:
                    print(f"\n❌ Review failed: {getattr(message, 'subtype', 'unknown error')}")

    if final_output:
        print("\n--- Parsed Security Review Output ---")
        print(final_output.model_dump_json(indent=2))

    #################################################################################

    sys.exit(ExitCode.SUCCESS)


if __name__ == "__main__":
    asyncio.run(main())
