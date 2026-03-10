import asyncio
import sys
from collections import defaultdict
from pathlib import Path
from typing import Tuple, Any, Dict

import requests
from claude_agent_sdk import AssistantMessage, ResultMessage, ClaudeSDKClient
from pydantic import ValidationError

from app.claude import get_claude_code_agent, SecurityReviewOutput

from app import get_security_audit_prompt, FindingsFilter
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


def _merge_request_param(settings: Settings) -> Tuple[str, int]:
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
            return "..."


def _format_review_to_markdown(result: SecurityReviewOutput, mr_data: Dict | None = None) -> str:
    """Format the JSON review result into a nice GitLab Markdown string."""
    # score = result.get('overallScore', 0)
    # summary = result.get('summary', 'No summary provided.')
    findings = result.findings
    analysis_summary = result.analysis_summary

    md = "## 🤖 Code Review"

    # Add MR reference if available
    if mr_data:
        mr_iid = mr_data.get("iid", "?")
        md += f": !{mr_iid}\n\n"
        md += f"**Branch:** `{mr_data.get('source_branch', '?')}` → `{mr_data.get('target_branch', '?')}`\n"
        md += f"**Author:** {mr_data.get('author', {}).get('name', 'Unknown')}\n"
    else:
        md += "\n"

    md += f"**Files reviewed:** {analysis_summary.files_reviewed}\n\n"

    if not findings:
        md += "### ✅ No notable security or code quality issues found.\n"
        return md

    md += f"### 📊 Issues Found ({len(findings)})\n\n"

    categorized_findings: Dict[str, list] = defaultdict(list)
    for finding in findings:
        categorized_findings[str(finding.severity)].append(finding)

    # Print in order of severity
    for severity in ["HIGH", "MEDIUM", "LOW"]:
        cat_findings = categorized_findings[severity]
        if not cat_findings:
            continue

        icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(severity, "⚪")

        md += f"#### {icon}  {severity} ({len(cat_findings)})\n"

        for finding in cat_findings:
            location = f"`{finding.file}:{finding.line}`" if finding.line else f"`{finding.file}`"

            md += f"- **[{finding.category}]** {location}: {finding.description}\n"
            md += f"  - *Exploit scenario:* {finding.exploit_scenario}\n"
            md += f"  - *Recommendation:* {finding.recommendation}\n"
        md += "\n"

    return md


async def _run_security_audit(claude_code_agent: ClaudeSDKClient, prompt: str) -> SecurityReviewOutput | None:
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
                if message.subtype == "success" and message.structured_output is not None:
                    try:
                        final_output = SecurityReviewOutput.model_validate(message.structured_output)
                    except ValidationError as e:
                        print(f"Failed to parse structured output: {e}")

                    cost = getattr(message, "total_cost_usd", 0.0)
                    duration = getattr(message, "duration_api_ms", 0) / 1000
                    usage = getattr(message, "usage", {})
                    input_tokens = usage.get("input_tokens", 0)
                    output_tokens = usage.get("output_tokens", 0)

                    print(f"\n✅ Review complete!")
                    print(f"Cost: ${cost:.4f}")
                    print(f"Duration: {duration:.4f}")
                    print(f"Input tokens: {input_tokens}")
                    print(f"Output tokens: {output_tokens}")
                    print(f"Tokens per second: {output_tokens / duration:.2f}")
                else:
                    print(f"\n❌ Review failed: {getattr(message, 'subtype', 'unknown error')}")
                    sys.exit(ExitCode.GENERAL_ERROR)

    return final_output


async def main() -> None:
    """Main execution function for GitHub Action."""
    settings = _get_settings()
    # Get project and merge request from GitLab environment or args
    project_id, mr_iid = _merge_request_param(settings)

    # Get repo directory from environment or use current directory
    repo_dir = Path(settings.ci_project_dir) if settings.ci_project_dir else Path.cwd()
    if not repo_dir.exists():
        print(f"Repository directory does not exist: {repo_dir}")
        sys.exit(ExitCode.CONFIGURATION_ERROR)

    print(f"Starting review for Project: {project_id}, merge request: {mr_iid}")
    print(
        f"Filtering: Hard exclusions={settings.enable_hard_exclusions}, Claude API={settings.enable_claude_filtering}"
    )

    gitlab_client = GitLabClient(
        base_url=settings.gitlab_base_url,
        token=settings.gitlab_api_key.get_secret_value(),
        excluded_dirs=settings.exclude_directories,
    )

    print("Getting merge request info...")
    try:
        mr_data = gitlab_client.get_merge_request(project_id, mr_iid)
    except Exception as e:
        print(f"Failed to fetch MR data: {str(e)}")
        sys.exit(ExitCode.GENERAL_ERROR)

    # Check if MR is already merged or closed
    if mr_data.get("state") in ["merged", "closed"]:
        print(f"MR is {mr_data.get('state')}, skipping review")
        sys.exit(ExitCode.SUCCESS)

    print("Getting merge request changes...")
    try:
        mr_changes = gitlab_client.get_merge_request_changes(project_id, mr_iid)
    except Exception as e:
        print(f"Failed to fetch MR changes: {str(e)}")
        sys.exit(ExitCode.GENERAL_ERROR)

    # Check for empty diff
    if not mr_changes.get("changes"):
        print("No changes detected in MR")
        sys.exit(ExitCode.SUCCESS)

    mr_diff = gitlab_client.format_merge_request_diff(mr_changes)
    # Generate security audit prompt
    prompt = get_security_audit_prompt(mr_data, mr_diff)

    # Check prompt size
    prompt_size = len(prompt.encode("utf-8"))
    if prompt_size > 1024 * 1024:  # 1MB
        print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB")

    print(f"🤖 Run Claude Code security audit")
    final_output: SecurityReviewOutput | None = None
    try:
        claude_code_agent = get_claude_code_agent(settings, repo_dir)
        final_output = await _run_security_audit(claude_code_agent, prompt)
    except Exception as e:
        print(f"❌ Claude code agent error: {e}")
        sys.exit(ExitCode.GENERAL_ERROR)

    if not final_output:
        print("❌ Failed to get a structured review result from the agent.")
        sys.exit(ExitCode.GENERAL_ERROR)

    # Filter findings to reduce false positives
    original_finding_count = len(final_output.findings)
    if settings.enable_hard_exclusions or settings.enable_claude_filtering:
        print(f"\nFiltering {original_finding_count} findings...")

        try:
            filter = FindingsFilter(
                use_hard_exclusions=settings.enable_hard_exclusions,
                use_claude_filtering=settings.enable_claude_filtering,
                api_key=settings.anthropic_api_key.get_secret_value(),
                # model=settings.claude_filter_model,
                # custom_filtering_instructions=settings.custom_filter_instructions,
            )

            # Apply FindingsFilter
            filter_success, filtered_results, stats = filter.filter_findings(
                findings=final_output.findings,
                pr_context={"mr": mr_data},
            )

            if filter_success:
                final_output.findings = filtered_results["filtered_findings"]
                removed_count = original_finding_count - stats.kept_findings
                print(
                    f"Filtered: {removed_count} findings removed ({stats.hard_excluded} hard rules, "
                    f"{stats.claude_excluded} Claude API)"
                )

                if filtered_results["analysis_summary"].get("average_confidence"):
                    avg_conf = filtered_results["analysis_summary"]["average_confidence"]
                    print(f"Average confidence: {avg_conf:.2f}")
            else:
                print("[Warning] Filtering failed, continuing with unfiltered results")

        except Exception as e:
            print(f"[Warning] Filtering error: {e}. Continuing with unfiltered results.")

    markdown_report = _format_review_to_markdown(final_output, mr_data)
    print("\n\n------ REVIEW REPORT ------\n")
    print(markdown_report)
    print("---------------------------\n")

    print("Posting comments to GitLab MR...")
    gitlab_client.create_merge_request_note(project_id, mr_iid, markdown_report)
    print("Summary posted successfully!")

    # Post inline discussions for each findings
    discussions_created = 0

    for finding in final_output.findings:
        # Format issue as markdown
        severity_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(finding.severity, "⚪")

        issue_body = f"### {severity_icon} {finding.severity}: {finding.category}\n\n"
        issue_body += f"{finding.description}\n\n"
        issue_body += f"{finding.exploit_scenario}\n\n"
        issue_body += f"{finding.recommendation}\n\n"

        position = gitlab_client.build_position_for_issue(mr_changes, finding)
        if position:
            # Create inline discussion
            try:
                gitlab_client.create_merge_request_discussion(project_id, mr_iid, position, issue_body)
                discussions_created += 1
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 400:
                    # Invalid position, fall back to summary
                    print(f"[Warning] Invalid position for {finding.file}:{finding.line}")
                    # orphan_findings.append(finding)
                else:
                    raise
        else:
            # No position found, add to orphans
            print(f"[Warning] Could not find position for {finding.file}:{finding.line}")
            # orphan_findings.append(finding)

    print(f"Created {discussions_created} inline discussions")

    high_sev_count = sum(1 for i in final_output.findings if i.severity in ["HIGH"])
    if high_sev_count > 0:
        print(f"Analysis failed: Found {high_sev_count} HIGH/MEDIUM issues. Rejecting MR.")
        sys.exit(ExitCode.GENERAL_ERROR)

    #################################################################################

    print("Code is clean. Success!")
    sys.exit(ExitCode.SUCCESS)


def cli_main() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
