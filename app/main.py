import asyncio
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests
from claude_agent_sdk import AssistantMessage, ClaudeSDKClient, ResultMessage
from dotenv import load_dotenv
from pydantic import ValidationError

from app import FindingsFilter, get_security_audit_prompt
from app.claude import Finding, SecurityReviewOutput, get_claude_code_agent
from app.config import Settings, get_settings
from app.constants import ExitCode
from app.gitlab import GitLabClient

load_dotenv()


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


def _merge_request_param(settings: Settings) -> tuple[str, int]:
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


def _get_block_input_dict(block: Any) -> dict[str, Any]:
    input_data = getattr(block, "input", {}) or {}
    if isinstance(input_data, dict):
        return input_data
    return getattr(input_data, "__dict__", {}) or {}


def _get_tool_summary(name: str, block_input: dict[str, Any]) -> str:
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


def _is_already_reviewed(discussions: list[dict], head_sha: str) -> bool:
    """Check if a review summary note already exists for this commit SHA."""
    if not head_sha:
        return False
    sha_short = head_sha[:8]
    for disc in discussions:
        for note in disc.get("notes", []):
            body = note.get("body", "")
            if body.startswith("## 🤖 Code Review") and sha_short in body:
                return True
    return False


def _format_review_to_markdown(result: SecurityReviewOutput, mr_data: dict | None = None) -> str:
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
        sha = mr_data.get("sha", "")
        if sha:
            md += f"**Commit:** `{sha[:8]}`\n"
    else:
        md += "\n"

    md += f"**Files reviewed:** {analysis_summary.files_reviewed}\n\n"

    if not findings:
        md += "### ✅ No notable security or code quality issues found.\n"
        return md

    md += f"### 📊 Issues Found ({len(findings)})\n\n"

    categorized_findings: dict[str, list] = defaultdict(list)
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

                    print("\n✅ Review complete!\n")
                    print(f"Cost: ${cost:.2f}")
                    print(f"Duration: {duration:.2f}")
                    print(f"Input tokens: {input_tokens}")
                    print(f"Output tokens: {output_tokens}")
                    print(f"Tokens per second: {output_tokens / duration:.2f}")
                else:
                    print(f"\n❌ Review failed: {getattr(message, 'subtype', 'unknown error')}")
                    print(f"❌ Result: {getattr(message, 'result', 'unknown result')}")
                    sys.exit(ExitCode.GENERAL_ERROR)

    return final_output


async def main() -> None:
    """Main execution function for GitLab Action."""
    settings = _get_settings()
    # Get project and merge request from GitLab environment or args
    project_id, mr_iid = _merge_request_param(settings)

    # Get repo directory from environment or use current directory
    repo_dir = Path(settings.ci_project_dir) if settings.ci_project_dir else Path.cwd()
    if not repo_dir.exists():
        print(f"Repository directory does not exist: {repo_dir}")
        sys.exit(ExitCode.CONFIGURATION_ERROR)

    print(f"Starting review for Project: {project_id}, merge request: {mr_iid}")
    print(f"Filtering: Hard exclusions={settings.enable_hard_exclusions}, LLM={settings.enable_claude_filtering}\n")

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

    # Fetch existing discussions early (used for caching and later for duplicate check)
    existing_discussions: list[dict] = []
    try:
        existing_discussions = gitlab_client.get_merge_request_discussions(project_id, mr_iid)
    except Exception as e:
        print(f"[Warning] Failed to fetch existing discussions: {e}")

    # Check if review already done for current head SHA
    if settings.skip_reviewed:
        head_sha = mr_data.get("sha", "")
        if _is_already_reviewed(existing_discussions, head_sha):
            print(f"Review already exists for SHA {head_sha[:8]}, skipping.")
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

    # Build changed files list without excluded and generated files
    changed_files = []
    for change in mr_changes.get("changes", []):
        old_path = change.get("old_path", "")
        new_path = change.get("new_path", "")
        if (old_path and gitlab_client._is_excluded(old_path)) or (new_path and gitlab_client._is_excluded(new_path)):
            continue
        diff = change.get("diff", "")
        if gitlab_client._is_generated(diff):
            continue
        if new_path:
            changed_files.append(new_path)
        elif old_path:
            changed_files.append(old_path)

    mr_diff = gitlab_client.format_merge_request_diff(mr_changes)

    # Read custom instructions from files if provided
    custom_scan_text = None
    if settings.custom_security_scan_instructions:
        scan_path = Path(settings.custom_security_scan_instructions)
        if scan_path.exists():
            custom_scan_text = scan_path.read_text(encoding="utf-8")
        else:
            print(f"[Warning] Custom security scan instructions file not found: {scan_path}")

    custom_filter_text = None
    if settings.custom_filter_instructions:
        filter_path = Path(settings.custom_filter_instructions)
        if filter_path.exists():
            custom_filter_text = filter_path.read_text(encoding="utf-8")
        else:
            print(f"[Warning] Custom false positive filtering instructions file not found: {filter_path}")

    # Generate security audit prompt
    prompt = get_security_audit_prompt(mr_data, changed_files, mr_diff, custom_scan_text)

    # Check prompt size
    prompt_size = len(prompt.encode("utf-8"))
    if prompt_size > 1024 * 1024:  # 1MB
        print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB")

    print("\n🤖 Run Claude Code security audit")
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
                model=settings.claude_model,
                use_hard_exclusions=settings.enable_hard_exclusions,
                use_claude_filtering=settings.enable_claude_filtering,
                custom_filtering_instructions=custom_filter_text,
                repo_dir=repo_dir,
            )

            # Apply FindingsFilter
            filter_success, filtered_results, stats = await filter.filter_findings(
                findings=final_output.findings,
                mr_context={"mr": mr_data},
            )

            if filter_success:
                final_output.findings = filtered_results["filtered_findings"]
                removed_count = original_finding_count - stats.kept_findings
                print(
                    f"Filtered: {removed_count} findings removed ({stats.hard_excluded} hard rules, "
                    f"{stats.claude_excluded} LLM)"
                )

                if filtered_results["analysis_summary"].get("average_confidence"):
                    avg_conf = filtered_results["analysis_summary"]["average_confidence"]
                    print(f"Average confidence: {avg_conf:.2f}")
            else:
                print("[Warning] Filtering failed, continuing with unfiltered results")

        except Exception as e:
            print(f"[Warning] Filtering error: {e}. Continuing with unfiltered results.")

    # Apply finding-level directory exclusion
    final_kept_findings = []
    for finding in final_output.findings:
        if finding.file and gitlab_client._is_excluded(finding.file):
            print(f"Skipping finding in excluded directory: {finding.file}")
            continue
        final_kept_findings.append(finding)

    final_output.findings = final_kept_findings

    markdown_report = _format_review_to_markdown(final_output, mr_data)
    print(f"\n{markdown_report}")

    # Re-fetch discussions to get any new ones created during the review
    print("Checking for existing discussions...")
    try:
        existing_discussions = gitlab_client.get_merge_request_discussions(project_id, mr_iid)
    except Exception as e:
        print(f"[Warning] Failed to re-fetch discussions: {e}. Using previously fetched data.")
        existing_discussions = []

    existing_notes_info = []
    summary_note_id = None
    for disc in existing_discussions:
        for note in disc.get("notes", []):
            body = note.get("body", "")
            if body.startswith("## 🤖 Code Review"):
                if summary_note_id is None:
                    summary_note_id = note.get("id")
                continue
            existing_notes_info.append({"body": body, "position": note.get("position")})

    print("Posting comments to GitLab MR...")
    if summary_note_id:
        gitlab_client.update_merge_request_note(project_id, mr_iid, summary_note_id, markdown_report)
        print("Summary updated successfully!")
    else:
        gitlab_client.create_merge_request_note(project_id, mr_iid, markdown_report)
        print("Summary posted successfully!")

    def is_duplicate_finding(f: Finding) -> bool:
        severity_marker = {"HIGH": "🔴 HIGH", "MEDIUM": "🟠 MEDIUM", "LOW": "🟡 LOW"}.get(
            f.severity, f"⚪ {f.severity}"
        )

        for note_info in existing_notes_info:
            body = note_info["body"]
            pos = note_info["position"]

            if severity_marker not in body:
                continue

            # 1. Inline note position match
            if pos:
                if (pos.get("new_path") == f.file and pos.get("new_line") == f.line) or (
                    pos.get("old_path") == f.file and pos.get("old_line") == f.line
                ):
                    return True

            # 2. Orphan note match in general MR notes
            location_str = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            if location_str in body:
                return True

        return False

    # Post inline discussions for each findings
    discussions_created = 0
    orphan_findings = []

    for finding in final_output.findings:
        if is_duplicate_finding(finding):
            print(f"Skipping duplicate finding: {finding.file}:{finding.line} ({finding.category})")
            continue

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
                    orphan_findings.append(finding)
                else:
                    raise
        else:
            # No position found, add to orphans
            print(f"[Warning] Could not find position for {finding.file}:{finding.line}")
            orphan_findings.append(finding)

    print(f"Created {discussions_created} inline discussions")

    if orphan_findings:
        print(f"Found {len(orphan_findings)} orphan findings, adding as general MR note...")
        orphan_body = "### ⚠️ Security Issues (Unmatched Diff Positions)\n\n"
        orphan_body += (
            "The following issues were identified but could not be mapped to specific lines in the MR diff:\n\n"
        )
        for finding in orphan_findings:
            severity_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(finding.severity, "⚪")
            location = f"`{finding.file}:{finding.line}`" if finding.line else f"`{finding.file}`"
            orphan_body += f"#### {severity_icon} {finding.severity}: {finding.category} at {location}\n"
            orphan_body += f"{finding.description}\n\n"
            orphan_body += f"**Exploit Scenario:** {finding.exploit_scenario}\n\n"
            orphan_body += f"**Recommendation:** {finding.recommendation}\n\n"
            orphan_body += "---\n\n"

        try:
            gitlab_client.create_merge_request_note(project_id, mr_iid, orphan_body)
        except Exception as e:
            print(f"Failed to post orphan findings note: {e}")

    high_sev_count = sum(1 for i in final_output.findings if i.severity in ["HIGH"])
    if high_sev_count > 0:
        print(f"\nAnalysis failed: Found {high_sev_count} HIGH/MEDIUM issues. Rejecting MR.")
        sys.exit(ExitCode.GENERAL_ERROR)

    print("\nCode is clean. Success!")
    sys.exit(ExitCode.SUCCESS)


def cli_main() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
