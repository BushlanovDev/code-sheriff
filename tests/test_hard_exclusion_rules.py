"""Tests for HardExclusionRules — regex-based false positive filtering."""


from app.claude import Finding
from app.constants import Severity
from app.findings_filter import HardExclusionRules


def _make_finding(
    file: str = "app/server.py",
    description: str = "Some issue",
    category: str = "security_issue",
    severity: Severity = Severity.HIGH,
    line: int = 1,
) -> Finding:
    """Helper to create a Finding with sensible defaults."""
    return Finding(
        file=file,
        line=line,
        severity=severity,
        category=category,
        description=description,
        exploit_scenario="n/a",
        recommendation="n/a",
        confidence=0.9,
    )


# ── DOS patterns ────────────────────────────────────────────────


class TestDOSPatterns:
    def test_denial_of_service(self):
        f = _make_finding(description="This is a denial of service attack vector")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_resource_exhaustion(self):
        f = _make_finding(description="Could exhaust server memory resources")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_unbounded_loop(self):
        f = _make_finding(description="Unbounded loop could cause issues")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── Rate limiting ───────────────────────────────────────────────


class TestRateLimitingPatterns:
    def test_missing_rate_limit(self):
        f = _make_finding(description="Missing rate limit on API endpoint")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_implement_rate_limit(self):
        f = _make_finding(description="Should implement rate limiting")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_unlimited_requests(self):
        f = _make_finding(description="Unlimited requests allowed")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── Resource leaks ──────────────────────────────────────────────


class TestResourcePatterns:
    def test_memory_leak(self):
        f = _make_finding(description="Potential memory leak in handler")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_unclosed_connection(self):
        f = _make_finding(description="Unclosed connection after request")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_database_leak(self):
        f = _make_finding(description="Database leak in connection pool")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── Open redirect ───────────────────────────────────────────────


class TestOpenRedirectPatterns:
    def test_open_redirect(self):
        f = _make_finding(description="Open redirect vulnerability found")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_unvalidated_redirect(self):
        f = _make_finding(description="Unvalidated redirect in login flow")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── Regex injection ─────────────────────────────────────────────


class TestRegexInjection:
    def test_regex_injection(self):
        f = _make_finding(description="Regex injection in search endpoint")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_regex_dos(self):
        f = _make_finding(description="Regular expression denial of service")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── Memory safety (language-dependent) ──────────────────────────


class TestMemorySafety:
    def test_buffer_overflow_in_python_excluded(self):
        """Memory safety in non-C files should be excluded."""
        f = _make_finding(file="app.py", description="Buffer overflow vulnerability")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_buffer_overflow_in_c_kept(self):
        """Memory safety in C files should NOT be excluded."""
        f = _make_finding(file="main.c", description="Buffer overflow vulnerability")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_buffer_overflow_in_cpp_kept(self):
        f = _make_finding(file="parser.cpp", description="Buffer overflow in parser")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_use_after_free_in_rust_excluded(self):
        f = _make_finding(file="lib.rs", description="Use-after-free in handler")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_integer_overflow_in_js_excluded(self):
        f = _make_finding(file="calc.js", description="Integer overflow in calculation")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── SSRF (context-dependent) ────────────────────────────────────


class TestSSRFPatterns:
    def test_ssrf_in_html_excluded(self):
        f = _make_finding(file="page.html", description="SSRF vulnerability")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_ssrf_in_python_kept(self):
        """SSRF in server-side code should NOT be excluded."""
        f = _make_finding(file="server.py", description="SSRF vulnerability")
        assert HardExclusionRules.get_exclusion_reason(f) is None


# ── Markdown files ──────────────────────────────────────────────


class TestMarkdownExclusion:
    def test_finding_in_markdown(self):
        f = _make_finding(file="README.md", description="Hardcoded API key")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_finding_in_uppercase_md(self):
        f = _make_finding(file="CHANGELOG.MD", description="SQL injection")
        assert HardExclusionRules.get_exclusion_reason(f) is not None


# ── Should NOT be excluded ──────────────────────────────────────


class TestKeptFindings:
    def test_sql_injection_kept(self):
        f = _make_finding(description="SQL injection in user query")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_hardcoded_api_key_kept(self):
        f = _make_finding(description="Hardcoded API key in source code")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_command_injection_kept(self):
        f = _make_finding(description="Command injection via subprocess call")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_rce_kept(self):
        f = _make_finding(description="Remote code execution via pickle deserialization")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_auth_bypass_kept(self):
        f = _make_finding(description="Authentication bypass in login endpoint")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_xss_kept(self):
        f = _make_finding(file="app.py", description="Cross-site scripting via dangerouslySetInnerHTML")
        assert HardExclusionRules.get_exclusion_reason(f) is None


# ── Edge cases ──────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_description(self):
        f = _make_finding(description="", category="")
        assert HardExclusionRules.get_exclusion_reason(f) is None

    def test_category_matches_pattern(self):
        """Pattern should match against category (title) too."""
        f = _make_finding(description="vulnerability found", category="denial of service")
        assert HardExclusionRules.get_exclusion_reason(f) is not None

    def test_case_insensitive(self):
        f = _make_finding(description="DENIAL OF SERVICE attack")
        assert HardExclusionRules.get_exclusion_reason(f) is not None
