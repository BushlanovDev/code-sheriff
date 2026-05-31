"""Tests for eval_engine.py."""

from pathlib import Path

from app.evals.eval_engine import EvalCase, EvalResult, EvaluationEngine


def test_eval_case_defaults():
    case = EvalCase(project_id="test/repo", mr_iid=1)
    assert case.description == ""


def test_eval_result_to_dict():
    result = EvalResult(
        project_id="test/repo",
        mr_iid=1,
        description="test",
        success=True,
        runtime_seconds=10.5,
        findings_count=5,
        detected_vulnerabilities=True,
    )
    d = result.to_dict()
    assert d["success"] is True
    assert d["findings_count"] == 5
    assert d["detected_vulnerabilities"] is True


def test_get_eval_branch_name():
    engine = EvaluationEngine(gitlab_base_url="http://test", work_dir="/tmp/test")
    case = EvalCase(project_id="group/sub/repo", mr_iid=42)
    branch = engine._get_eval_branch_name(case)
    assert "eval-mr-group-sub-repo-42" in branch


def test_clean_worktrees_missing_repo(tmp_path: Path):
    engine = EvaluationEngine(gitlab_base_url="http://test", work_dir=str(tmp_path))
    # Should not crash if the repo path doesn't exist
    engine._clean_worktrees(str(tmp_path / "nonexistent"))
