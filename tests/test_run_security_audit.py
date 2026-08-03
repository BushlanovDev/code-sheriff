"""Tests for _run_security_audit, in particular the recovery of a submitted result.

The agent sometimes hands a valid result to StructuredOutput, the tool accepts it, and the
session still refuses to finish: a stop hook keeps demanding another call and the loop burns
every remaining turn re-submitting the same payload. The ResultMessage then carries no
structured output at all. These tests pin down that the review survives that.
"""

from collections.abc import AsyncIterator
from typing import Any

import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage
from claude_agent_sdk.types import ToolUseBlock

from app.constants import MAX_STRUCTURED_OUTPUT_SUBMITS, ExitCode
from app.main import _run_security_audit

PAYLOAD: dict[str, Any] = {
    "findings": [
        {
            "file": "views/operators.php",
            "line": 83,
            "severity": "MEDIUM",
            "category": "xss",
            "description": "Gate name reaches HTML without encoding",
            "exploit_scenario": "Stored payload runs for other admins",
            "recommendation": "Wrap in CHtml::encode()",
            "confidence": 0.8,
        }
    ],
    "analysis_summary": {
        "files_reviewed": 6,
        "high_severity": 0,
        "medium_severity": 1,
        "low_severity": 0,
        "review_completed": True,
    },
}


class FakeAgent:
    """Stand-in for ClaudeSDKClient: async context manager plus a canned message stream."""

    def __init__(self, messages: list[Any]) -> None:
        self._messages = messages
        self.prompts: list[str] = []
        self.consumed = 0

    async def __aenter__(self) -> "FakeAgent":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def query(self, prompt: str) -> None:
        self.prompts.append(prompt)

    async def receive_response(self) -> AsyncIterator[Any]:
        for message in self._messages:
            self.consumed += 1
            yield message


def submit(payload: dict[str, Any]) -> AssistantMessage:
    return AssistantMessage(
        content=[ToolUseBlock(id="tool-1", name="StructuredOutput", input=payload)],
        model="test-model",
    )


def read_file(path: str = "a.php") -> AssistantMessage:
    return AssistantMessage(
        content=[ToolUseBlock(id="tool-0", name="Read", input={"file_path": path})],
        model="test-model",
    )


def result(
    subtype: str = "error_max_turns",
    structured_output: Any = None,
    text: str | None = None,
) -> ResultMessage:
    return ResultMessage(
        subtype=subtype,
        duration_ms=1000,
        duration_api_ms=1000,
        is_error=subtype != "success",
        num_turns=51,
        session_id="session",
        total_cost_usd=0.5,
        usage={"input_tokens": 10, "output_tokens": 20},
        result=text,
        structured_output=structured_output,
    )


async def test_recovers_and_stops_when_session_loops() -> None:
    """A session that never finishes still yields the review, and stops re-submitting."""
    agent = FakeAgent([submit(PAYLOAD) for _ in range(8)])

    output = await _run_security_audit(agent, "prompt")  # type: ignore[arg-type]

    assert output is not None
    assert len(output.findings) == 1
    assert output.findings[0].line == 83
    # The loop is abandoned as soon as it is clearly looping, instead of draining the stream.
    assert agent.consumed == MAX_STRUCTURED_OUTPUT_SUBMITS


async def test_recovers_after_failed_result_message() -> None:
    """One submit followed by a failed ResultMessage: the payload is still used."""
    agent = FakeAgent([read_file(), submit(PAYLOAD), result(subtype="error_max_turns")])

    output = await _run_security_audit(agent, "prompt")  # type: ignore[arg-type]

    assert output is not None
    assert output.analysis_summary.files_reviewed == 6


async def test_exits_when_failure_and_nothing_was_submitted() -> None:
    """With no payload to fall back on the run still fails loudly."""
    agent = FakeAgent([read_file(), result(subtype="error_during_execution")])

    with pytest.raises(SystemExit) as excinfo:
        await _run_security_audit(agent, "prompt")  # type: ignore[arg-type]

    assert excinfo.value.code == ExitCode.GENERAL_ERROR


async def test_success_path_still_uses_structured_output() -> None:
    """The normal path is untouched by the recovery logic."""
    agent = FakeAgent([read_file(), submit(PAYLOAD), result(subtype="success", structured_output=PAYLOAD)])

    output = await _run_security_audit(agent, "prompt")  # type: ignore[arg-type]

    assert output is not None
    assert len(output.findings) == 1


async def test_context_overflow_raises_so_caller_can_retry_without_diff() -> None:
    """Context overflow must propagate: main() retries with include_diff=False."""
    agent = FakeAgent([result(subtype="error", text="Prompt is too long for the model")])

    with pytest.raises(RuntimeError, match="too long"):
        await _run_security_audit(agent, "prompt")  # type: ignore[arg-type]


async def test_malformed_payload_is_not_passed_off_as_a_review() -> None:
    """A payload that fails validation must not become a silent empty review."""
    agent = FakeAgent([submit({"findings": "not a list"}), result(subtype="error_max_turns")])

    output = await _run_security_audit(agent, "prompt")  # type: ignore[arg-type]

    assert output is None
