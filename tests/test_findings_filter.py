"""Tests for FindingsFilter — hard exclusion + stats (LLM filtering not tested here)."""

from pathlib import Path

from app.findings_filter import FindingsFilter
from tests.helpers import make_finding


class TestFilterFindingsEmpty:
    async def test_empty_findings(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        success, results, stats = await f.filter_findings([])
        assert success is True
        assert results.filtered_findings == []
        assert stats.total_findings == 0

    async def test_stats_zero_runtime(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        _, _, stats = await f.filter_findings([])
        assert stats.runtime_seconds >= 0.0


class TestHardExclusionFiltering:
    async def test_dos_finding_excluded(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        findings = [make_finding(description="Denial of service attack")]
        success, results, stats = await f.filter_findings(findings)
        assert success is True
        assert len(results.filtered_findings) == 0
        assert stats.hard_excluded == 1

    async def test_real_finding_kept(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        findings = [make_finding(description="SQL injection in login query")]
        success, results, stats = await f.filter_findings(findings)
        assert success is True
        assert len(results.filtered_findings) == 1
        assert stats.kept_findings == 1

    async def test_mixed_findings(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        findings = [
            make_finding(description="SQL injection"),
            make_finding(description="Denial of service attack"),
            make_finding(description="Hardcoded API key found"),
            make_finding(description="Missing rate limit"),
        ]
        success, results, stats = await f.filter_findings(findings)
        assert success is True
        assert stats.total_findings == 4
        assert stats.hard_excluded == 2  # DOS + rate limit
        assert stats.kept_findings == 2  # SQL + API key


class TestNoHardExclusions:
    async def test_all_kept_when_disabled(self):
        f = FindingsFilter(model="test", use_hard_exclusions=False, use_claude_filtering=False)
        findings = [
            make_finding(description="Denial of service attack"),
            make_finding(description="Missing rate limit"),
        ]
        success, results, stats = await f.filter_findings(findings)
        assert success is True
        assert len(results.filtered_findings) == 2
        assert stats.hard_excluded == 0
        assert stats.kept_findings == 2


class TestFilterStats:
    async def test_exclusion_breakdown(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        findings = [
            make_finding(description="Denial of service via large payload"),
            make_finding(description="Resource exhaustion attack"),
        ]
        _, _, stats = await f.filter_findings(findings)
        assert len(stats.exclusion_breakdown) > 0

    async def test_analysis_summary_structure(self):
        f = FindingsFilter(model="test", use_hard_exclusions=True, use_claude_filtering=False)
        findings = [make_finding()]
        _, results, _ = await f.filter_findings(findings)
        summary = results.analysis_summary
        assert summary.total_findings >= 0
        assert summary.kept_findings >= 0
        assert summary.excluded_findings >= 0
        assert summary.hard_excluded >= 0
        assert summary.runtime_seconds >= 0.0


class TestReadFile:
    def test_read_existing_file(self, tmp_path: Path):
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')", encoding="utf-8")
        f = FindingsFilter(model="test", repo_dir=tmp_path)
        success, content, error = f._read_file("test.py")
        assert success is True
        assert "print('hello')" in content

    def test_read_missing_file(self, tmp_path: Path):
        f = FindingsFilter(model="test", repo_dir=tmp_path)
        success, content, error = f._read_file("nonexistent.py")
        assert success is False
        assert "not found" in error.lower()

    def test_absolute_path(self, tmp_path: Path):
        test_file = tmp_path / "abs.py"
        test_file.write_text("x = 1", encoding="utf-8")
        f = FindingsFilter(model="test")
        success, content, error = f._read_file(str(test_file))
        assert success is True
        assert "x = 1" in content
