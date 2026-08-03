import re
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast
from urllib.parse import quote

import requests

from app.claude import Finding
from app.constants import GENERATED_MARKERS
from app.gitlab.models import DiffPosition, Discussion, MergeRequestData, MRChangesData

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_TIMEOUT = 30  # seconds


def _retry_on_rate_limit(max_retries: int = 3, delay: int = 2) -> Callable[[F], F]:
    """Decorator to retry on 429 rate limit responses."""

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 429:
                        wait_time = delay * (2**attempt)
                        print(f"Rate limited, waiting {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        raise
            raise Exception("Max retries exceeded due to rate limiting")

        return cast(F, wrapper)

    return decorator


class GitLabClient:
    def __init__(self, base_url: str, token: str, excluded_dirs: list[str] | None = None) -> None:
        """Initialize the GitLab API client.

        Args:
            param base_url: The base URL of the GitLab instance.
            param token: The GitLab access token.
            excluded_dirs: Excluded directories.
        """
        self.base_url: str = base_url
        self.token: str = token
        self.excluded_dirs: list[str] = excluded_dirs or []

        self.api_url: str = f"{self.base_url}/api/v4"
        self._session: requests.Session = requests.Session()
        self._session.headers.update(
            {
                "PRIVATE-TOKEN": self.token,
                "Accept": "application/json",
            }
        )

    def _get_project_id(self, project_id: str) -> str:
        """URL encode the project ID if it's a project path (e.g. namespace/repo)."""
        return quote(str(project_id), safe="")

    def _parse_diff_position(
        self, diff: str, target_line: int, old_path: str, new_path: str, base_sha: str, head_sha: str, start_sha: str
    ) -> DiffPosition | None:
        """Parse diff to find position dict for a target line number.

        Args:
            diff: Unified diff text
            target_line: Line number in NEW version to find
            old_path: Old file path
            new_path: New file path
            base_sha, head_sha, start_sha: SHAs from diff_refs

        Returns:
            Position dict for GitLab API or None if line not found
        """

        lines = diff.split("\n")
        current_new_line = None

        for line in lines:
            # Match hunk header: @@ -old_start,old_count +new_start,new_count @@
            hunk_match = re.match(r"@@\s+-(\d+),?\d*\s+\+(\d+),?\d*\s+@@", line)
            if hunk_match:
                current_new_line = int(hunk_match.group(2))
                continue

            if current_new_line is not None:
                if line.startswith("+") and not line.startswith("++"):
                    # This is an added line in new version
                    if current_new_line == target_line:
                        # Found our target line!
                        return DiffPosition(
                            base_sha=base_sha,
                            head_sha=head_sha,
                            start_sha=start_sha,
                            old_path=old_path,
                            new_path=new_path,
                            position_type="text",
                            new_line=target_line,
                        )
                    current_new_line += 1
                elif not line.startswith("-"):
                    # Context line - also counts
                    current_new_line += 1

        return None

    def is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory patterns."""
        for excluded_dir in self.excluded_dirs:
            # Normalize excluded directory (remove leading ./ if present)
            normalized_excluded = excluded_dir[2:] if excluded_dir.startswith("./") else excluded_dir

            # Check if file starts with excluded directory
            if filepath.startswith(excluded_dir + "/"):
                return True
            if filepath.startswith(normalized_excluded + "/"):
                return True

            # Check if excluded directory appears anywhere in the path
            if "/" + normalized_excluded + "/" in filepath:
                return True

        return False

    @_retry_on_rate_limit()
    def get_merge_request(self, project_id: str, mr_iid: int) -> MergeRequestData:
        """Fetch metadata for a specific Merge Request.

        GET /api/v4/projects/{id}/merge_requests/{mr_iid}
        """
        url = f"{self.api_url}/projects/{self._get_project_id(project_id)}/merge_requests/{mr_iid}"
        response = self._session.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        return cast(MergeRequestData, response.json())

    @_retry_on_rate_limit()
    def get_merge_request_changes(self, project_id: str, mr_iid: int) -> MRChangesData:
        """Fetch the diff and SHA references for a specific MR.

        Returns dict with 'changes' list and 'diff_refs' dict containing
        base_sha, head_sha, start_sha needed for positioning discussions.

        GET /api/v4/projects/{id}/merge_requests/{mr_iid}/changes
        """
        url = f"{self.api_url}/projects/{self._get_project_id(project_id)}/merge_requests/{mr_iid}/changes"
        response = self._session.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        return cast(MRChangesData, response.json())

    def is_generated(self, diff_content: str) -> bool:
        """Check if a diff section belongs to a generated file."""
        # Check only first ~20 lines of diff for markers (header area)
        header = "\n".join(diff_content.split("\n")[:20])
        return any(marker in header for marker in GENERATED_MARKERS)

    def format_merge_request_diff(self, changes_data: MRChangesData) -> str:
        """Format GitLab MR changes diff into unified diff string.

        Args:
            changes_data: Response from get_merge_request_changes()

        Returns:
            Unified diff format string
        """
        diff_text = ""
        for file in changes_data.get("changes", []):
            old_path = file.get("old_path", "")
            new_path = file.get("new_path", "")

            if (old_path and self.is_excluded(old_path)) or (new_path and self.is_excluded(new_path)):
                continue

            diff = file.get("diff", "")

            # Skip generated files
            if self.is_generated(diff):
                print(f"[Debug] Filtering out generated file: {new_path or old_path}")
                continue

            diff_text += f"diff --git a/{old_path} b/{new_path}\n"
            diff_text += f"--- a/{old_path}\n+++ b/{new_path}\n"
            diff_text += f"{diff}\n\n"

        return diff_text

    @_retry_on_rate_limit()
    def create_merge_request_discussion(
        self, project_id: str, mr_iid: int, position: DiffPosition, body: str
    ) -> dict[str, Any]:
        """Create an inline discussion on a specific line.

        POST /api/v4/projects/{id}/merge_requests/{mr_iid}/discussions

        Args:
            project_id: Project ID or path
            mr_iid: Merge Request IID
            position: Dict with base_sha, head_sha, start_sha, old_path, new_path,
                      position_type, and new_line
            body: Discussion body text (markdown)
        """
        url = f"{self.api_url}/projects/{self._get_project_id(project_id)}/merge_requests/{mr_iid}/discussions"
        payload: dict[str, Any] = {
            "body": body,
            "position": position,
        }
        response = self._session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        return cast(dict[str, Any], response.json())

    @_retry_on_rate_limit()
    def create_merge_request_note(self, project_id: str, mr_iid: int, body: str) -> dict[str, Any]:
        """Create a general note/comment on a Merge Request.

        POST /api/v4/projects/{id}/merge_requests/{mr_iid}/notes
        """
        url = f"{self.api_url}/projects/{self._get_project_id(project_id)}/merge_requests/{mr_iid}/notes"
        payload = {"body": body}
        response = self._session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        return cast(dict[str, Any], response.json())

    @_retry_on_rate_limit()
    def update_merge_request_note(self, project_id: str, mr_iid: int, note_id: int, body: str) -> dict[str, Any]:
        """Update a general note/comment on a Merge Request.

        PUT /api/v4/projects/{id}/merge_requests/{mr_iid}/notes/{note_id}
        """
        url = f"{self.api_url}/projects/{self._get_project_id(project_id)}/merge_requests/{mr_iid}/notes/{note_id}"
        payload = {"body": body}
        response = self._session.put(url, json=payload, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        return cast(dict[str, Any], response.json())

    @_retry_on_rate_limit()
    def get_merge_request_discussions(self, project_id: str, mr_iid: int) -> list[Discussion]:
        """Fetch all discussions for a specific Merge Request.

        GET /api/v4/projects/{id}/merge_requests/{mr_iid}/discussions
        """
        discussions: list[Discussion] = []
        url = f"{self.api_url}/projects/{self._get_project_id(project_id)}/merge_requests/{mr_iid}/discussions"
        page = 1
        while True:
            params = {"page": page, "per_page": 100}
            response = self._session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()

            data = response.json()
            if not data:
                break

            discussions.extend(data)

            if "X-Next-Page" not in response.headers or not response.headers["X-Next-Page"]:
                break
            page += 1

        return discussions

    def build_position_for_issue(self, changes_data: MRChangesData, finding: Finding) -> DiffPosition | None:
        """Build GitLab discussion position for a security issue.

        Args:
            changes_data: Response from get_merge_request_changes()
            finding: Finding dict with 'file' and 'line' keys

        Returns:
            Position dict for GitLab API, or None if position cannot be determined
        """
        diff_refs = changes_data.get("diff_refs", {})
        base_sha = diff_refs.get("base_sha", "")
        head_sha = diff_refs.get("head_sha", "")
        start_sha = diff_refs.get("start_sha", "")

        target_file = finding.file
        target_line = finding.line

        if not target_file or not target_line:
            return None

        # Find the file in changes (match by new_path first, then fall back to old_path)
        for change in changes_data.get("changes", []):
            if change.get("new_path") == target_file or change.get("old_path") == target_file:
                # Parse diff to find position
                position = self._parse_diff_position(
                    change.get("diff", ""),
                    target_line,
                    change.get("old_path", ""),
                    change.get("new_path", ""),
                    base_sha,
                    head_sha,
                    start_sha,
                )
                if position:
                    return position

        return None
