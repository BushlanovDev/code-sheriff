"""Security and code review prompt templates for GitLab agent."""

from typing import Any


def get_security_audit_prompt(
    mr_data: dict[str, Any], changed_files: list[str], diff_text: str, custom_scan_instructions: str | None = None
) -> str:
    """Generate security and code review prompt for Merge Request analysis.

    Args:
        mr_data: MR metadata from GitLab API
        changed_files: List of file paths modified in the MR without excluded
        diff_text: Formatted unified diff of the entire MR
        custom_scan_instructions: Optional custom security categories or instructions to append

    Returns:
        Formatted prompt string
    """
    title = mr_data.get("title", "Unknown MR")
    description = mr_data.get("description", "")
    author = mr_data.get("author", {}).get("name", "Unknown")
    source_branch = mr_data.get("source_branch", "?")
    target_branch = mr_data.get("target_branch", "?")

    custom_categories_section = f"\n{custom_scan_instructions}\n" if custom_scan_instructions else ""
    files_changed_list = "\n".join([f"- {f}" for f in changed_files])

    return f"""
You are a senior security engineer conducting a focused security review of a GitLab Merge Request: "{title}"

CONTEXT:
- Author: {author}
- Source Branch: {source_branch} → Target Branch: {target_branch}
- MR Description: {description}

FILES MODIFIED:
{files_changed_list}

MERGE REQUEST DIFF CONTENT:
```diff
{diff_text}
```
Review the complete diff above. This contains all code changes in the MR.

OBJECTIVE:
Perform a security-focused code review to identify HIGH-CONFIDENCE security vulnerabilities that could have real exploitation potential. This is not a general code review - focus ONLY on security implications newly added by this PR. Do not comment on existing security concerns.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident of actual exploitability
2. AVOID NOISE: Skip theoretical issues, style concerns, or low-impact findings
3. FOCUS ON IMPACT: Prioritize vulnerabilities that could lead to unauthorized access, data breaches, or system compromise
4. DO NOT IMAGINATE PROBLEMS THAT DO NOT EXIST: study only real changes in new code and their impact on the security of the project.
5. EXCLUSIONS: Do NOT report the following issue types:
   - Denial of Service (DOS) vulnerabilities, even if they allow service disruption
   - Secrets or sensitive data stored on disk (these are handled by other processes)
   - Rate limiting or resource exhaustion issues
6. EXPLORE CONTEXT: If the provided diff text is not clear enough, use your available tools (Glob, Read, Grep, Bash) to explore the surrounding codebase to understand how this modified code integrates with the rest of the application.

SECURITY CATEGORIES TO EXAMINE:

**Input Validation Vulnerabilities:**
- SQL injection via unsanitized user input
- Command injection in system calls or subprocesses
- XXE injection in XML parsing
- Template injection in templating engines
- NoSQL injection in database queries
- Path traversal in file operations

**Authentication & Authorization Issues:**
- Authentication bypass logic
- Privilege escalation paths
- Session management flaws
- JWT token vulnerabilities
- Authorization logic bypasses

**Crypto & Secrets Management:**
- Hardcoded API keys, passwords, or tokens
- Weak cryptographic algorithms or implementations
- Improper key storage or management
- Cryptographic randomness issues
- Certificate validation bypasses

**Injection & Code Execution:**
- Remote code execution via deseralization
- Pickle injection in Python
- YAML deserialization vulnerabilities
- Eval injection in dynamic code execution
- XSS vulnerabilities in web applications (reflected, stored, DOM-based)

**Data Exposure:**
- Sensitive data logging or storage
- PII handling violations
- API endpoint data leakage
- Debug information exposure
{custom_categories_section}
Additional notes:
- Even if something is only exploitable from the local network, it can still be a HIGH severity issue

ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

Phase 2 - Comparative Analysis:
- Compare new code changes against existing security patterns
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that introduces new attack surfaces

Phase 3 - Vulnerability Assessment:
- Examine each modified file for security implications
- Trace data flow from user inputs to sensitive operations
- Look for privilege boundaries being crossed unsafely
- Identify injection points and unsafe deserialization

REQUIRED OUTPUT FORMAT:

You MUST output your findings as structured JSON with this exact schema:

{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH",
      "category": "sql_injection",
      "description": "User input passed to SQL query without parameterization",
      "exploit_scenario": "Attacker could extract database contents by manipulating the 'search' parameter with SQL injection payloads like '1; DROP TABLE users--'",
      "recommendation": "Replace string formatting with parameterized queries using SQLAlchemy or equivalent",
      "confidence": 0.9
    }}
  ],
  "analysis_summary": {{
    "files_reviewed": 8,
    "high_severity": 1,
    "medium_severity": 0,
    "low_severity": 0,
    "review_completed": true,
  }}
}}

LINE NUMBERING:
The "line" number MUST accurately refer to the line in the NEW version of the file.
To avoid hallucinating line numbers:
- Count carefully from the `+` line number in the `@@ ... +new_line,count @@` hunk header.
- Remember that deleted lines (starting with `-`) do NOT increase the line counter for the new file. Only context lines (starting with a space) and added lines (starting with `+`) increase the new line counter.
- If you have any doubt, use the `Grep` tool or `Bash` with `cat -n` to find the exact line number of the vulnerable code snippet in the local file. Do not just guess.

SEVERITY GUIDELINES:
- **HIGH**: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- **MEDIUM**: Vulnerabilities requiring specific conditions but with significant impact
- **LOW**: Defense-in-depth issues or lower-impact vulnerabilities

CONFIDENCE SCORING:
- 0.9-1.0: Certain exploit path identified, tested if possible
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Don't report (too speculative)

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a MR review.

IMPORTANT EXCLUSIONS - DO NOT REPORT:
- Denial of Service (DOS) vulnerabilities or resource exhaustion attacks
- Secrets/credentials stored on disk (these are managed separately)
- Rate limiting concerns or service overload scenarios. Services do not need to implement rate limiting.
- Memory consumption or CPU exhaustion issues.
- Lack of input validation on non-security-critical fields. If there isn't a proven problem from a lack of input validation, don't report it.

Begin your analysis now. Use the repository exploration tools to understand the codebase context, then analyze the MR changes for security implications.

Your final reply must contain the JSON and nothing else. You should not reply again after outputting the JSON.
"""


def get_filtering_prompt(
    mr_info: str, finding_json: str, filtering_section: str | None, file_content_section: str
) -> str:
    """Generate filtering prompt for LLM.

    Args:
        mr_info: Formatted MR context string.
        finding_json: JSON representation of the finding.
        filtering_section: Custom filtering instructions or default.
        file_content_section: Content of the file where the finding was found.

    Returns:
        Formatted prompt string.
    """
    _DEFAULT_FILTERING_INSTRUCTIONS = """\
HARD EXCLUSIONS - Automatically exclude findings matching these patterns:
1. Denial of Service (DOS) vulnerabilities or resource exhaustion attacks
2. Secrets/credentials stored on disk (these are managed separately)
3. Rate limiting concerns or service overload scenarios (services don't need to implement rate limiting)
4. Memory consumption or CPU exhaustion issues
5. Lack of input validation on non-security-critical fields without proven security impact
6. Input sanitization concerns for CI/CD pipeline workflows
7. A lack of hardening measures. Code is not expected to implement all security best practices, just avoid obvious vulnerabilities.
8. Race conditions or timing attacks that are theoretical rather than practical issues. Only report a race condition if it is extremely problematic.
9. Vulnerabilities related to outdated third-party libraries. These are managed separately and should not be reported here.
10. Memory safety issues such as buffer overflows or use-after-free-vulnerabilities are impossible in rust. Do not report memory safety issues in rust code.
11. Files that are only unit tests or only used as part of running tests.
12. Log spoofing concerns. Outputing un-sanitized user input to logs is not a vulnerability.
13. SSRF vulnerabilities that only control the path. SSRF is only a concern if it can control the host or protocol.
14. Including user-controlled content in AI system prompts is not a vulnerability. In general, the inclusion of user input in an AI prompt is not a vulnerability.
15. Do not report issues related to adding a dependency to a project that is not available from the relevant package repository. Depending on internal libraries that are not publicly available is not a vulnerability.
16. Do not report issues that cause the code to crash, but are not actually a vulnerability. E.g. a variable that is undefined or null is not a vulnerability.

SIGNAL QUALITY CRITERIA - For remaining findings, assess:
1. Is there a concrete, exploitable vulnerability with a clear attack path?
2. Does this represent a real security risk vs theoretical best practice?
3. Are there specific code locations and reproduction steps?
4. Would this finding be actionable for a security team?

PRECEDENTS -
1. Logging high value secrets in plaintext is a vulnerability. Otherwise, do not report issues around theoretical exposures of secrets. Logging URLs is assumed to be safe. Logging request headers is assumed to be dangerous since they likely contain credentials.
2. UUIDs can be assumed to be unguessable and do not need to be validated. If a vulnerabilities requires guessing a UUID, it is not a valid vulnerability.
3. Audit logs are not a critical security feature and should not be reported as a vulnerability if they are missing or modified.
4. Environment variables and CLI flags are trusted values. Attackers are not able to modify them in a secure environment. Any attack that relies on controlling an environment variable is invalid.
5. Resource management issues such as memory or file descriptor leaks are not valid.
6. Subtle or low impact web vulnerabilities such as tabnabbing, XS-Leaks, prototype pollution, and open redirects are not valid.
7. Vulnerabilities related to outdated third-party libraries. These are managed separately and should not be reported here.
8. React is generally secure against XSS. React does not need to sanitize or escape user input unless it is using dangerouslySetInnerHTML or similar methods. Do not report XSS vulnerabilities in React components or tsx files unless they are using unsafe methods.
9. Most vulnerabilities in CI/CD pipeline configurations are not exploitable in practice. Before validating a CI/CD pipeline vulnerability ensure it is concrete and has a very specific attack path.
10. A lack of permission checking or authentication in client-side TS code is not a vulnerability. Client-side code is not trusted and does not need to implement these checks, they are handled on the server-side. The same applies to all flows that send untrusted data to the backend, the backend is responsible for validating and sanitizing all inputs.
11. Only include MEDIUM findings if they are obvious and concrete issues.
12. Most vulnerabilities in ipython notebooks (*.ipynb files) are not exploitable in practice. Before validating a notebook vulnerability ensure it is concrete and has a very specific attack path.
13. Logging non-PII data is not a vulnerability even if the data may be sensitive. Only report logging vulnerabilities if they expose sensitive information such as secrets, passwords, or personally identifiable information (PII).
14. Command injection vulnerabilities in shell scripts are generally not exploitable in practice since shell scripts generally do not run with untrusted user input. Only report command injection vulnerabilities in shell scripts if they are concrete and have a very specific attack path for untrusted input.
15. SSRF (Server-Side Request Forgery) vulnerabilities in client-side JavaScript/TypeScript files (.js, .ts, .tsx, .jsx) are not valid since client-side code cannot make server-side requests that would bypass firewalls or access internal resources. Only report SSRF in server-side code (e.g. Python or JS that is known to run on the server-side). The same logic applies to path-traversal attacks, they are not a problem in client-side JS.
16. Path traversal attacks using ../ are generally not a problem when triggering HTTP requests. These are generally only relevant when reading files where the ../ may allow accessing unintended files.
17. Injecting into log queries is generally not an issue. Only report this if the injection will definitely lead to exposing sensitive data to external users.
"""

    if not filtering_section:
        filtering_section = _DEFAULT_FILTERING_INSTRUCTIONS

    return f"""
I need you to analyze a security finding from an automated code audit and determine if it's a false positive.

{mr_info}

{filtering_section}

Finding to analyze:
```json
{finding_json}
```
{file_content_section}

Respond using the structured output tool.
"""
