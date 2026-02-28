import asyncio
import sys

from pydantic import ValidationError

from app.config import get_settings


async def main() -> None:
    try:
        settings = get_settings()
    except ValidationError as e:
        print("Error: Validating settings failed.")
        print("Please check the following environment variables (or .env file):")
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            print(f"  - {field}: {error['msg']}")
        sys.exit(1)

    # Get project and commit from GitLab environment or args
    project_id = settings.ci_project_id
    commit_sha = settings.ci_commit_sha

    if not project_id or not commit_sha:
        if len(sys.argv) > 2:
            project_id = sys.argv[1]
            commit_sha = sys.argv[2]
        else:
            print("Error: CI_PROJECT_ID and CI_COMMIT_SHA must be set in environment.")
            print("Usage: python main.py <project_id> <commit_sha>")
            sys.exit(1)

    print(f"Starting review for Project: {project_id}, Commit: {commit_sha}")

    print(f"Settings for GitLab API: {settings.gitlab_base_url}")
    print(f"Settings for Anthropic API: {settings.anthropic_base_url}")


if __name__ == "__main__":
    asyncio.run(main())
