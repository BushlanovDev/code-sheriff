"""Evaluation engine for running security audits on GitLab Merge Requests.

Clones (or reuses) a GitLab repository, checks out MR changes via git
worktrees, and runs the full Code Sheriff pipeline programmatically.
"""

import asyncio
import contextlib
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

# ── Timeout constants (seconds) ─────────────────────────────────

TIMEOUT_SHORT = 10
TIMEOUT_GIT_OPERATION = 60
TIMEOUT_CLONE = 300
TIMEOUT_FETCH = 600
TIMEOUT_WORKTREE = 300
TIMEOUT_WORKTREE_CREATE = 1200


# ── Data classes ────────────────────────────────────────────────


@dataclass
class EvalCase:
    """Single evaluation test case."""

    project_id: str  # e.g. "namespace/project"
    mr_iid: int
    description: str = ""


@dataclass
class EvalResult:
    """Result of a single evaluation."""

    project_id: str
    mr_iid: int
    description: str

    # Evaluation results
    success: bool
    runtime_seconds: float
    findings_count: int
    detected_vulnerabilities: bool

    # Optional
    error_message: str = ""
    findings_summary: list[dict[str, Any]] | None = None
    full_findings: list[dict[str, Any]] | None = None

    # Cost / performance
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Engine ──────────────────────────────────────────────────────


class EvaluationEngine:
    """Engine for running security evaluations on GitLab MRs."""

    def __init__(
        self,
        work_dir: str | None = None,
        gitlab_base_url: str = "https://gitlab.com",
        verbose: bool = False,
    ):
        if work_dir is None:
            work_dir = str(Path("~/code/audit").expanduser())
        self.work_dir = work_dir
        Path(self.work_dir).mkdir(parents=True, exist_ok=True)

        self.gitlab_base_url = gitlab_base_url.rstrip("/")
        self.verbose = verbose

        self.gitlab_token = os.environ.get("GITLAB_API_KEY", "")
        self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable required")

        # Per-repo locks for concurrent access
        self._repo_locks: dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()

    # ── Logging ──────────────────────────────────────────────────

    def log(self, message: str, prefix: str = "[EVAL]") -> None:
        if self.verbose:
            ts = time.strftime("%H:%M:%S")
            print(f"{prefix} [{ts}] {message}", file=sys.stderr)

    # ── Repo lock helpers ────────────────────────────────────────

    def _get_repo_lock(self, project_id: str) -> threading.Lock:
        with self._locks_lock:
            if project_id not in self._repo_locks:
                self._repo_locks[project_id] = threading.Lock()
            return self._repo_locks[project_id]

    # ── Worktree management ──────────────────────────────────────

    def _clean_worktrees(self, repo_path: str, branch_pattern: str | None = None) -> None:
        """Prune stale/locked worktrees and matching branches."""
        if not Path(repo_path).exists():
            return

        try:
            subprocess.run(
                ["git", "-C", repo_path, "worktree", "prune"],
                check=False,
                capture_output=True,
                timeout=TIMEOUT_SHORT,
            )

            result = subprocess.run(
                ["git", "-C", repo_path, "worktree", "list", "--porcelain"],
                capture_output=True,
                text=True,
                check=True,
                timeout=TIMEOUT_SHORT,
            )

            worktrees: list[dict[str, Any]] = []
            current: dict[str, Any] = {}
            for line in result.stdout.strip().split("\n"):
                if not line:
                    if current:
                        worktrees.append(current)
                        current = {}
                elif line.startswith("worktree "):
                    current["path"] = line[9:]
                elif line.startswith("branch "):
                    current["branch"] = line[7:]
                elif line == "locked":
                    current["locked"] = True
            if current:
                worktrees.append(current)

            for wt in worktrees:
                if wt.get("path") == repo_path:
                    continue
                should_remove = bool(wt.get("locked"))
                if not should_remove and branch_pattern and "branch" in wt:
                    branch_name = wt["branch"].replace("refs/heads/", "")
                    if branch_pattern in branch_name:
                        should_remove = True

                if should_remove:
                    self.log(f"Removing worktree: {wt.get('path')}")
                    try:
                        subprocess.run(
                            ["git", "-C", repo_path, "worktree", "remove", "--force", wt["path"]],
                            check=False,
                            capture_output=True,
                            timeout=TIMEOUT_SHORT,
                        )
                        if Path(wt["path"]).exists():
                            shutil.rmtree(wt["path"], ignore_errors=True)
                    except Exception as e:
                        self.log(f"Error removing worktree {wt.get('path')}: {e}")

            # Clean matching branches
            if branch_pattern:
                result = subprocess.run(
                    ["git", "-C", repo_path, "branch", "--list"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=TIMEOUT_SHORT,
                )
                for line in result.stdout.strip().split("\n"):
                    branch = line.strip().lstrip("* ")
                    if branch and branch_pattern in branch:
                        subprocess.run(
                            ["git", "-C", repo_path, "branch", "-D", branch],
                            check=False,
                            capture_output=True,
                            timeout=TIMEOUT_SHORT,
                        )
                        self.log(f"Deleted branch: {branch}")

        except Exception as e:
            self.log(f"Error during worktree cleanup: {e}")

    def _get_eval_branch_name(self, test_case: EvalCase) -> str:
        safe_project = test_case.project_id.replace("/", "-").replace(".", "-")
        ts = time.strftime("%Y%m%d-%H%M%S")
        return f"eval-mr-{safe_project}-{test_case.mr_iid}-{ts}"

    # ── Repository setup ─────────────────────────────────────────

    def _setup_repository(self, test_case: EvalCase) -> tuple[bool, str, str]:
        """Clone/update repo and create worktree for MR.

        Returns:
            (success, worktree_path, error_message)
        """
        project_id = test_case.project_id
        safe_name = project_id.replace("/", "_")
        base_repo_path = str(Path(self.work_dir) / safe_name)

        repo_lock = self._get_repo_lock(project_id)

        with repo_lock:
            # Clone if needed
            if not Path(base_repo_path).exists():
                self.log(f"Cloning {project_id} to {base_repo_path}")
                clone_url = f"{self.gitlab_base_url}/{project_id}.git"
                if self.gitlab_token:
                    # Use oauth2 token for GitLab clone
                    clone_url = f"https://oauth2:{self.gitlab_token}@{self.gitlab_base_url.removeprefix('https://').removeprefix('http://')}/{project_id}.git"

                try:
                    subprocess.run(
                        ["git", "clone", "--filter=blob:none", clone_url, base_repo_path],
                        check=True,
                        capture_output=True,
                        timeout=TIMEOUT_CLONE,
                    )
                except subprocess.CalledProcessError as e:
                    error = f"Failed to clone: {e.stderr.decode()}"
                    self.log(error)
                    return False, "", error

            # Clean stale worktrees
            eval_prefix = f"eval-mr-{safe_name}-{test_case.mr_iid}"
            self._clean_worktrees(base_repo_path, eval_prefix)

            eval_branch = self._get_eval_branch_name(test_case)
            worktree_path = str(Path(self.work_dir) / f"{safe_name}_mr{test_case.mr_iid}_{int(time.time())}")

            try:
                # Fetch MR head (GitLab pattern)
                self.log(f"Fetching MR !{test_case.mr_iid} from {project_id}")
                subprocess.run(
                    [
                        "git",
                        "-C",
                        base_repo_path,
                        "fetch",
                        "origin",
                        f"merge-requests/{test_case.mr_iid}/head:mr-{test_case.mr_iid}",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=TIMEOUT_FETCH,
                )

                # Create worktree
                self.log(f"Creating worktree at {worktree_path}")
                subprocess.run(
                    [
                        "git",
                        "-C",
                        base_repo_path,
                        "worktree",
                        "add",
                        "-b",
                        eval_branch,
                        worktree_path,
                        f"mr-{test_case.mr_iid}",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=TIMEOUT_WORKTREE_CREATE,
                )
                return True, worktree_path, ""

            except subprocess.CalledProcessError as e:
                error = f"Failed to set up worktree: {e.stderr.decode()}"
                self.log(error)
                if Path(worktree_path).exists():
                    shutil.rmtree(worktree_path, ignore_errors=True)
                with contextlib.suppress(Exception):
                    subprocess.run(
                        ["git", "-C", base_repo_path, "worktree", "remove", "--force", worktree_path],
                        check=False,
                        capture_output=True,
                        timeout=TIMEOUT_SHORT,
                    )
                return False, "", error

    def _cleanup_worktree(self, test_case: EvalCase, worktree_path: str) -> None:
        if not Path(worktree_path).exists():
            return

        safe_name = test_case.project_id.replace("/", "_")
        base_repo_path = str(Path(self.work_dir) / safe_name)

        with self._get_repo_lock(test_case.project_id):
            try:
                subprocess.run(
                    ["git", "-C", base_repo_path, "worktree", "remove", "--force", worktree_path],
                    check=False,
                    capture_output=True,
                    timeout=TIMEOUT_WORKTREE,
                )
                if Path(worktree_path).exists():
                    shutil.rmtree(worktree_path, ignore_errors=True)
                self.log(f"Cleaned up worktree: {worktree_path}")
            except Exception as e:
                self.log(f"Error cleaning up worktree: {e}")

    # ── Run evaluation ───────────────────────────────────────────

    def run_evaluation(self, test_case: EvalCase) -> EvalResult:
        """Run security evaluation on a single MR."""
        start_time = time.time()
        self.log(f"Starting evaluation of {test_case.project_id}!{test_case.mr_iid}")

        success, worktree_path, error_msg = self._setup_repository(test_case)
        if not success:
            return EvalResult(
                project_id=test_case.project_id,
                mr_iid=test_case.mr_iid,
                description=test_case.description,
                success=False,
                runtime_seconds=time.time() - start_time,
                findings_count=0,
                detected_vulnerabilities=False,
                error_message=f"Repository setup failed: {error_msg}",
            )

        try:
            result = asyncio.run(self._run_audit(test_case, worktree_path))
            result.runtime_seconds = time.time() - start_time
            return result
        except Exception as e:
            return EvalResult(
                project_id=test_case.project_id,
                mr_iid=test_case.mr_iid,
                description=test_case.description,
                success=False,
                runtime_seconds=time.time() - start_time,
                findings_count=0,
                detected_vulnerabilities=False,
                error_message=f"Audit execution failed: {e}",
            )
        finally:
            self._cleanup_worktree(test_case, worktree_path)

    async def _run_audit(self, test_case: EvalCase, repo_path: str) -> EvalResult:
        """Run the Code Sheriff audit pipeline programmatically."""
        from app.claude import SecurityReviewOutput, get_claude_code_agent
        from app.config import Settings
        from app.gitlab import GitLabClient
        from app.prompts import get_security_audit_prompt

        # Build settings from environment
        settings = Settings(
            gitlab_api_key=self.gitlab_token or "eval-token",
            anthropic_api_key=self.anthropic_api_key,
            claude_model=os.environ.get("CLAUDE_MODEL", "claude-opus-4-6"),
            gitlab_base_url=self.gitlab_base_url,
        )

        gitlab_client = GitLabClient(
            base_url=settings.gitlab_base_url,
            token=self.gitlab_token,
            excluded_dirs=cast(list[str], settings.exclude_directories),
        )

        # Get MR data
        self.log(f"Fetching MR data for !{test_case.mr_iid}")
        mr_data = gitlab_client.get_merge_request(test_case.project_id, test_case.mr_iid)
        mr_changes = gitlab_client.get_merge_request_changes(test_case.project_id, test_case.mr_iid)

        # Build changed files list
        changed_files = []
        for change in mr_changes.get("changes", []):
            new_path = change.get("new_path", "")
            old_path = change.get("old_path", "")
            if (new_path and gitlab_client.is_excluded(new_path)) or (old_path and gitlab_client.is_excluded(old_path)):
                continue
            diff = change.get("diff", "")
            if gitlab_client.is_generated(diff):
                continue
            changed_files.append(new_path or old_path)

        mr_diff = gitlab_client.format_merge_request_diff(mr_changes)

        # Compute stats
        total_add = total_del = 0
        for change in mr_changes.get("changes", []):
            for line in change.get("diff", "").split("\n"):
                if line.startswith("+") and not line.startswith("+++"):
                    total_add += 1
                elif line.startswith("-") and not line.startswith("---"):
                    total_del += 1

        prompt = get_security_audit_prompt(
            mr_data,
            changed_files,
            mr_diff,
            changes_stats={"files_changed": len(changed_files), "additions": total_add, "deletions": total_del},
        )

        # Run Claude agent
        self.log("Running Claude Code security audit")
        from claude_agent_sdk import ResultMessage

        repo_dir = Path(repo_path)
        claude_agent = get_claude_code_agent(settings, repo_dir)

        final_output: SecurityReviewOutput | None = None
        cost = 0.0
        in_tokens = out_tokens = 0

        async with claude_agent:
            await claude_agent.query(prompt)
            async for message in claude_agent.receive_response():
                if (
                    isinstance(message, ResultMessage)
                    and message.subtype == "success"
                    and message.structured_output is not None
                ):
                    from pydantic import ValidationError

                    try:
                        final_output = SecurityReviewOutput.model_validate(message.structured_output)
                    except ValidationError as e:
                        self.log(f"Failed to parse output: {e}")
                    cost = getattr(message, "total_cost_usd", 0.0)
                    usage = getattr(message, "usage", {})
                    in_tokens = usage.get("input_tokens", 0)
                    out_tokens = usage.get("output_tokens", 0)

        if not final_output:
            return EvalResult(
                project_id=test_case.project_id,
                mr_iid=test_case.mr_iid,
                description=test_case.description,
                success=False,
                runtime_seconds=0,
                findings_count=0,
                detected_vulnerabilities=False,
                error_message="No structured output received from agent",
            )

        findings = [f.model_dump() for f in final_output.findings]
        findings_summary = [
            {
                "file": f.get("file", "unknown"),
                "line": f.get("line", 0),
                "severity": f.get("severity", "UNKNOWN"),
                "category": f.get("category", "unknown"),
                "description": f.get("description", ""),
            }
            for f in findings[:10]
        ]

        return EvalResult(
            project_id=test_case.project_id,
            mr_iid=test_case.mr_iid,
            description=test_case.description,
            success=True,
            runtime_seconds=0,
            findings_count=len(findings),
            detected_vulnerabilities=len(findings) > 0,
            findings_summary=findings_summary,
            full_findings=findings,
            cost_usd=cost,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
        )


# ── Convenience function ────────────────────────────────────────


def run_single_evaluation(
    test_case: EvalCase,
    verbose: bool = False,
    work_dir: str | None = None,
    gitlab_base_url: str = "https://gitlab.com",
) -> EvalResult:
    """Run a single evaluation (convenience wrapper)."""
    engine = EvaluationEngine(work_dir=work_dir, gitlab_base_url=gitlab_base_url, verbose=verbose)
    return engine.run_evaluation(test_case)
