"""Findings filter for reducing false positives in security audit results."""

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from re import Pattern
from typing import Any

from app.claude import Finding
from app.prompts import get_filtering_prompt


@dataclass
class FilterStats:
    """Statistics about the filtering process."""

    total_findings: int = 0
    hard_excluded: int = 0
    claude_excluded: int = 0
    kept_findings: int = 0
    exclusion_breakdown: dict[str, int] = field(default_factory=dict)
    confidence_scores: list[float] = field(default_factory=list)
    runtime_seconds: float = 0.0


class HardExclusionRules:
    """Hard exclusion rules for common false positives."""

    # Pre-compiled regex patterns for better performance
    _DOS_PATTERNS: list[Pattern] = [
        re.compile(r"\b(denial of service|dos attack|resource exhaustion)\b", re.IGNORECASE),
        re.compile(r"\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b", re.IGNORECASE),
        re.compile(r"\b(infinite|unbounded).*?(loop|recursion)\b", re.IGNORECASE),
    ]

    _RATE_LIMITING_PATTERNS: list[Pattern] = [
        re.compile(r"\b(missing|lack of|no)\s+rate\s+limit", re.IGNORECASE),
        re.compile(r"\brate\s+limiting\s+(missing|required|not implemented)", re.IGNORECASE),
        re.compile(r"\b(implement|add)\s+rate\s+limit", re.IGNORECASE),
        re.compile(r"\bunlimited\s+(requests|calls|api)", re.IGNORECASE),
    ]

    _RESOURCE_PATTERNS: list[Pattern] = [
        re.compile(r"\b(resource|memory|file)\s+leak\s+potential", re.IGNORECASE),
        re.compile(r"\bunclosed\s+(resource|file|connection)", re.IGNORECASE),
        re.compile(r"\b(close|cleanup|release)\s+(resource|file|connection)", re.IGNORECASE),
        re.compile(r"\bpotential\s+memory\s+leak", re.IGNORECASE),
        re.compile(r"\b(database|thread|socket|connection)\s+leak", re.IGNORECASE),
    ]

    _OPEN_REDIRECT_PATTERNS: list[Pattern] = [
        re.compile(r"\b(open redirect|unvalidated redirect)\b", re.IGNORECASE),
        re.compile(r"\b(redirect.(attack|exploit|vulnerability))\b", re.IGNORECASE),
        re.compile(r"\b(malicious.redirect)\b", re.IGNORECASE),
    ]

    _MEMORY_SAFETY_PATTERNS: list[Pattern] = [
        re.compile(r"\b(buffer overflow|stack overflow|heap overflow)\b", re.IGNORECASE),
        re.compile(r"\b(oob)\s+(read|write|access)\b", re.IGNORECASE),
        re.compile(r"\b(out.?of.?bounds?)\b", re.IGNORECASE),
        re.compile(r"\b(memory safety|memory corruption)\b", re.IGNORECASE),
        re.compile(r"\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b", re.IGNORECASE),
        re.compile(r"\b(segmentation fault|segfault|memory violation)\b", re.IGNORECASE),
        re.compile(r"\b(bounds check|boundary check|array bounds)\b", re.IGNORECASE),
        re.compile(r"\b(integer overflow|integer underflow|integer conversion)\b", re.IGNORECASE),
        re.compile(r"\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b", re.IGNORECASE),
    ]

    _REGEX_INJECTION: list[Pattern] = [
        re.compile(r"\b(regex|regular expression)\s+injection\b", re.IGNORECASE),
        re.compile(r"\b(regex|regular expression)\s+denial of service\b", re.IGNORECASE),
        re.compile(r"\b(regex|regular expression)\s+flooding\b", re.IGNORECASE),
    ]

    _SSRF_PATTERNS: list[Pattern] = [
        re.compile(r"\b(ssrf|server\s+.?side\s+.?request\s+.?forgery)\b", re.IGNORECASE),
    ]

    @classmethod
    def get_exclusion_reason(cls, finding: Finding) -> str | None:
        """Check if a finding should be excluded based on hard rules.

        Args:
            finding: Security finding to check. Expected keys:

        Returns:
            Exclusion reason if finding should be excluded, None otherwise
        """
        # Check if finding is in a Markdown file
        file_path = finding.file
        if file_path.lower().endswith(".md"):
            return "Finding in Markdown documentation file"

        description = finding.description
        title = finding.category

        # Handle None values
        if description is None:
            description = ""
        if title is None:
            title = ""

        combined_text = f"{title} {description}".lower()

        # Check DOS patterns
        for pattern in cls._DOS_PATTERNS:
            if pattern.search(combined_text):
                return "Generic DOS/resource exhaustion finding (low signal)"

        # Check rate limiting patterns
        for pattern in cls._RATE_LIMITING_PATTERNS:
            if pattern.search(combined_text):
                return "Generic rate limiting recommendation"

        # Check resource patterns - always exclude
        for pattern in cls._RESOURCE_PATTERNS:
            if pattern.search(combined_text):
                return "Resource management finding (not a security vulnerability)"

        # Check open redirect patterns
        for pattern in cls._OPEN_REDIRECT_PATTERNS:
            if pattern.search(combined_text):
                return "Open redirect vulnerability (not high impact)"

        # Check regex injection patterns
        for pattern in cls._REGEX_INJECTION:
            if pattern.search(combined_text):
                return "Regex injection finding (not applicable)"

        # Check memory safety patterns - exclude if NOT in C/C++ files
        c_cpp_extensions = {".c", ".cc", ".cpp", ".h"}
        file_ext = ""
        if "." in file_path:
            file_ext = f".{file_path.lower().split('.')[-1]}"

        # If file doesn't have a C/C++ extension (including no extension), exclude memory safety findings
        if file_ext not in c_cpp_extensions:
            for pattern in cls._MEMORY_SAFETY_PATTERNS:
                if pattern.search(combined_text):
                    return "Memory safety finding in non-C/C++ code (not applicable)"

        # Check SSRF patterns - exclude if in HTML files only
        html_extensions = {".html"}

        # If file has HTML extension, exclude SSRF findings
        if file_ext in html_extensions:
            for pattern in cls._SSRF_PATTERNS:
                if pattern.search(combined_text):
                    return "SSRF finding in HTML file (not applicable to client-side code)"

        return None


class FindingsFilter:
    """Main filter class for security findings.

    Implements two-stage filtering:
    1. Hard exclusion rules (regex-based)
    2. LLM filtering (optional, for single finding validation)
    """

    def __init__(
        self,
        model: str,
        use_hard_exclusions: bool = True,
        use_claude_filtering: bool = True,
        custom_filtering_instructions: str | None = None,
        repo_dir: Path | None = None,
    ):
        """Initialize findings filter.

        Args:
            model: Claude model to use for filtering
            use_hard_exclusions: Whether to apply hard exclusion rules
            use_claude_filtering: Whether to use LLM for filtering
            custom_filtering_instructions: Optional custom filtering instructions
            repo_dir: Optional repository path for resolving files
        """
        self.model = model
        self.use_hard_exclusions = use_hard_exclusions
        self.use_claude_filtering = use_claude_filtering
        self.custom_filtering_instructions = custom_filtering_instructions
        self.repo_dir = repo_dir

    def _read_file(self, file_path: str) -> tuple[bool, str, str]:
        """Read a file to include its context in the prompt."""
        try:
            path = Path(file_path)
            if not path.is_absolute() and self.repo_dir:
                path = self.repo_dir / file_path

            if not path.exists():
                return False, "", f"File not found: {path}"
            if not path.is_file():
                return False, "", f"Path is not a file: {path}"

            try:
                with open(path, encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(path, encoding="latin-1") as f:
                    content = f.read()
            return True, content, ""
        except Exception as e:
            return False, "", f"Error reading file {file_path}: {str(e)}"

    async def filter_findings(
        self, findings: list[Finding], mr_context: dict[str, Any] | None = None
    ) -> tuple[bool, dict[str, Any], FilterStats]:
        """Filter security findings to remove false positives.

        Args:
            findings: List of security findings from Claude audit
            mr_context: Optional context (commit data, etc.)

        Returns:
            Tuple of (success, filtered_results, stats)
        """
        start_time = time.time()

        if not findings:
            stats = FilterStats(total_findings=0, runtime_seconds=0.0)
            return (
                True,
                {
                    "filtered_findings": [],
                    "excluded_findings": [],
                    "analysis_summary": {
                        "total_findings": 0,
                        "kept_findings": 0,
                        "excluded_findings": 0,
                        "exclusion_breakdown": {},
                    },
                },
                stats,
            )

        # Initialize statistics
        stats = FilterStats(total_findings=len(findings))

        # Step 1: Apply hard exclusion rules
        findings_after_hard = []
        excluded_hard = []

        if self.use_hard_exclusions:
            for i, finding in enumerate(findings):
                exclusion_reason = HardExclusionRules.get_exclusion_reason(finding)
                if exclusion_reason:
                    excluded_hard.append(
                        {
                            "finding": finding,
                            "index": i,
                            "exclusion_reason": exclusion_reason,
                            "filter_stage": "hard_rules",
                        }
                    )
                    stats.hard_excluded += 1

                    # Track exclusion breakdown
                    key = exclusion_reason.split("(")[0].strip()
                    stats.exclusion_breakdown[key] = stats.exclusion_breakdown.get(key, 0) + 1
                else:
                    findings_after_hard.append(finding)

            print(f"Hard exclusions removed {stats.hard_excluded} findings\n")
        else:
            findings_after_hard = list(findings)

        # Step 2: Apply LLM filtering if enabled
        findings_after_claude: list[Finding] = []
        excluded_claude: list[dict[str, Any]] = []

        if self.use_claude_filtering and findings_after_hard:
            # Process findings individually
            print(f"Processing {len(findings_after_hard)} findings through LLM...")
            from claude_agent_sdk import ResultMessage

            from app.claude import FilterOutput, get_claude_filter_agent

            filter_agent = get_claude_filter_agent(self.model)

            for finding in findings_after_hard:
                finding_json = finding.model_dump_json(indent=2)

                mr_info = ""
                if mr_context:
                    mr = mr_context.get("mr")
                    if isinstance(mr, dict):
                        mr_info = (
                            f"MR Context:\n- Title: {mr.get('title', 'unknown')}\n"
                            f"- Description: {(mr.get('description') or '')[:500]}..."
                        )

                file_content_section = ""
                if finding.file:
                    success, content, err = self._read_file(finding.file)
                    if success:
                        file_content_section = f"\n\nFile Content ({finding.file}):\n```\n{content}\n```"
                    else:
                        file_content_section = f"\n\nFile Content ({finding.file}): Error reading file - {err}"

                prompt = get_filtering_prompt(
                    mr_info=mr_info,
                    finding_json=finding_json,
                    filtering_section=self.custom_filtering_instructions,
                    file_content_section=file_content_section,
                )

                try:
                    result_output: dict | None = None
                    async with filter_agent:
                        await filter_agent.query(prompt)
                        async for message in filter_agent.receive_response():
                            if (
                                isinstance(message, ResultMessage)
                                and message.subtype == "success"
                                and message.structured_output
                            ):
                                result_output = message.structured_output

                    if result_output:
                        filter_result = FilterOutput.model_validate(result_output)
                        stats.confidence_scores.append(filter_result.confidence_score)

                        if not filter_result.keep_finding:
                            excluded_claude.append(
                                {
                                    "finding": finding,
                                    "confidence_score": filter_result.confidence_score,
                                    "exclusion_reason": filter_result.exclusion_reason or "Excluded by LLM",
                                    "justification": filter_result.justification,
                                    "filter_stage": "claude_api",
                                }
                            )
                            stats.claude_excluded += 1
                        else:
                            findings_after_claude.append(finding.copy())
                            stats.kept_findings += 1
                    else:
                        print(f"LLM returned no result for finding in {finding.file}:{finding.line}")
                        findings_after_claude.append(finding.copy())
                        stats.kept_findings += 1
                except Exception as e:
                    print(f"Error querying filter agent for finding {finding.file}:{finding.line} - {e}")
                    findings_after_claude.append(finding.copy())
                    stats.kept_findings += 1
        else:
            # No Claude filtering - keep all findings from hard filter
            for finding in findings_after_hard:
                enriched_finding = finding.copy()
                findings_after_claude.append(enriched_finding)
                stats.kept_findings += 1

        # Combine all excluded findings
        all_excluded = excluded_hard + excluded_claude

        # Calculate final statistics
        stats.runtime_seconds = time.time() - start_time

        # Build filtered results
        filtered_results = {
            "filtered_findings": findings_after_claude,
            "excluded_findings": all_excluded,
            "analysis_summary": {
                "total_findings": stats.total_findings,
                "kept_findings": stats.kept_findings,
                "excluded_findings": len(all_excluded),
                "hard_excluded": stats.hard_excluded,
                "claude_excluded": stats.claude_excluded,
                "exclusion_breakdown": stats.exclusion_breakdown,
                "average_confidence": sum(stats.confidence_scores) / len(stats.confidence_scores)
                if stats.confidence_scores
                else None,
                "runtime_seconds": stats.runtime_seconds,
            },
        }

        print(
            f"Filtering completed: {stats.kept_findings}/{stats.total_findings} "
            f"findings kept ({stats.runtime_seconds:.1f}s)\n"
        )

        return True, filtered_results, stats
