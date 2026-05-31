"""Shared test fixtures and factories."""

from app.claude import Finding
from app.constants import Severity


def make_finding(
    file: str = "app/server.py",
    line: int = 1,
    severity: Severity = Severity.HIGH,
    category: str = "security_issue",
    description: str = "Some issue",
    exploit_scenario: str = "n/a",
    recommendation: str = "n/a",
    confidence: float = 0.9,
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        file=file,
        line=line,
        severity=severity,
        category=category,
        description=description,
        exploit_scenario=exploit_scenario,
        recommendation=recommendation,
        confidence=confidence,
    )
