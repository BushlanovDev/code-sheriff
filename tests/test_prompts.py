"""Tests for prompt generation functions."""

from app.prompts import get_filtering_prompt, get_security_audit_prompt

# ── get_security_audit_prompt() ─────────────────────────────────


class TestSecurityAuditPrompt:
    MR_DATA = {
        "title": "Fix auth bypass",
        "description": "Fixes a critical auth issue",
        "author": {"name": "dev"},
        "source_branch": "fix/auth",
        "target_branch": "main",
    }
    CHANGED_FILES = ["src/auth.py", "src/utils.py"]
    DIFF_TEXT = "@@ -1 +1 @@\n-old\n+new\n"

    def test_contains_mr_title(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT)
        assert "Fix auth bypass" in prompt

    def test_contains_changed_files(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT)
        assert "src/auth.py" in prompt
        assert "src/utils.py" in prompt

    def test_contains_diff_when_included(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT, include_diff=True)
        assert "MERGE REQUEST DIFF CONTENT" in prompt
        assert self.DIFF_TEXT in prompt

    def test_no_diff_when_excluded(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT, include_diff=False)
        assert self.DIFF_TEXT not in prompt
        assert "NOTE: MR diff was omitted" in prompt

    def test_custom_scan_instructions(self):
        custom = "Check for LDAP injection in all LDAP queries"
        prompt = get_security_audit_prompt(
            self.MR_DATA,
            self.CHANGED_FILES,
            self.DIFF_TEXT,
            custom_scan_instructions=custom,
        )
        assert custom in prompt

    def test_no_custom_instructions(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT)
        assert "LDAP injection" not in prompt

    def test_changes_stats_included(self):
        stats = {"files_changed": 3, "additions": 50, "deletions": 10}
        prompt = get_security_audit_prompt(
            self.MR_DATA,
            self.CHANGED_FILES,
            self.DIFF_TEXT,
            changes_stats=stats,
        )
        assert "Files changed: 3" in prompt
        assert "Lines added: 50" in prompt
        assert "Lines deleted: 10" in prompt

    def test_empty_diff(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, "")
        assert "MERGE REQUEST DIFF CONTENT" not in prompt

    def test_author_and_branches(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT)
        assert "Author: dev" in prompt
        assert "fix/auth" in prompt
        assert "main" in prompt

    def test_json_schema_present(self):
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT)
        assert '"findings"' in prompt
        assert '"analysis_summary"' in prompt

    def test_line_numbering_guidance(self):
        """Ensure the LINE NUMBERING section is present."""
        prompt = get_security_audit_prompt(self.MR_DATA, self.CHANGED_FILES, self.DIFF_TEXT)
        assert "LINE NUMBERING" in prompt


# ── get_filtering_prompt() ──────────────────────────────────────


class TestFilteringPrompt:
    def test_contains_finding_json(self):
        finding_json = '{"file": "x.py", "description": "SQL injection"}'
        prompt = get_filtering_prompt(
            mr_info="MR #1",
            finding_json=finding_json,
            filtering_section=None,
            file_content_section="",
        )
        assert finding_json in prompt

    def test_contains_mr_info(self):
        prompt = get_filtering_prompt(
            mr_info="MR Context:\n- Title: Fix",
            finding_json="{}",
            filtering_section=None,
            file_content_section="",
        )
        assert "MR Context" in prompt

    def test_custom_filtering_instructions(self):
        custom = "Ignore all XSS findings in this project"
        prompt = get_filtering_prompt(
            mr_info="",
            finding_json="{}",
            filtering_section=custom,
            file_content_section="",
        )
        assert custom in prompt

    def test_default_filtering_when_none(self):
        prompt = get_filtering_prompt(
            mr_info="",
            finding_json="{}",
            filtering_section=None,
            file_content_section="",
        )
        assert "HARD EXCLUSIONS" in prompt

    def test_file_content_included(self):
        content = "\n\nFile Content (app.py):\n```\ndef foo(): pass\n```"
        prompt = get_filtering_prompt(
            mr_info="",
            finding_json="{}",
            filtering_section=None,
            file_content_section=content,
        )
        assert "def foo(): pass" in prompt

    def test_confidence_scale_0_to_1(self):
        """Ensure the prompt uses 0.0-1.0 scale, not 1-10."""
        prompt = get_filtering_prompt(
            mr_info="",
            finding_json="{}",
            filtering_section=None,
            file_content_section="",
        )
        assert "0.0" in prompt or "0.0-0.3" in prompt
        assert "1-10" not in prompt
