import asyncio
import sys

from pydantic import ValidationError

from app.config import get_settings
from app.constants import ExitCode
from app.gitlab import GitLabClient


async def main() -> None:
    """Main execution function for GitHub Action."""
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

    # Get project and commit from GitLab environment or args
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

    print(f"Starting review for Project: {project_id}, merge request: {mr_iid}")

    gitlab_client = GitLabClient(
        base_url=settings.gitlab_base_url,
        token=settings.gitlab_api_key.get_secret_value(),
    )

    mr_data = gitlab_client.get_merge_request(project_id, int(mr_iid))
    # Check if MR is already merged or closed
    if mr_data.get("state") in ["merged", "closed"]:
        print(f"MR is {mr_data.get('state')}, skipping review")
        sys.exit(ExitCode.SUCCESS)

    changes_data = gitlab_client.get_merge_request_changes(project_id, int(mr_iid))
    # Check for empty diff
    if not changes_data.get("changes"):
        print("No changes detected in MR")
        sys.exit(ExitCode.SUCCESS)

    diff_text = gitlab_client.format_mr_diff_to_unified(changes_data)
    print(diff_text)

    sys.exit(ExitCode.SUCCESS)


if __name__ == "__main__":
    asyncio.run(main())
