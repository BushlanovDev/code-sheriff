# GitLab Security Review Agent

AI-powered security review agent for GitLab Merge Requests. Uses [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via `claude-agent-sdk` to analyze code changes for security vulnerabilities with deep semantic understanding.

Inspired by [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) GitHub Action, adapted for GitLab CI/CD.

## Features

- **AI-Powered Analysis**: Uses Claude's advanced reasoning to detect security vulnerabilities with deep semantic understanding
- **Diff-Aware Scanning**: For PRs, only analyzes changed files
- **MR Comments**: Automatically comments on MRs with security findings
- **Contextual Understanding**: Goes beyond pattern matching to understand code semantics
- **Language Agnostic**: Works with any programming language
- **False Positive Filtering**: Advanced filtering to reduce noise and focus on real vulnerabilities

## Quick Start

### GitLab CI/CD

Add a job to your `.gitlab-ci.yml`:

```yaml
security-review:
  stage: test
  image: python:3.13-slim
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GITLAB_API_KEY: $GITLAB_API_KEY
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
    CLAUDE_MODEL: "claude-opus-4-6"
    ENABLE_HARD_EXCLUSIONS: "true"
    ENABLE_CLAUDE_FILTERING: "false"
    SKIP_REVIEWED: "true"
  before_script:
    - pip install uv
    - uv sync --frozen
  script:
    - uv run review-agent
  allow_failure: true
```

### Run locally

Copy `.env.example` to `.env` and fill in the required values:

```bash
cp .env.example .env

# Requires Python >= 3.13 and uv
uv sync

# Via entry point
uv run review-agent <project_id> <merge_request_iid>

# Or as module
uv run python -m app <project_id> <merge_request_iid>
```

> **Note:** `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, and `CI_PROJECT_DIR` are provided automatically by GitLab CI in merge request pipelines.

## Configuration

All settings are loaded from environment variables (or `.env` file).

| Variable                            | Description                                                                    | Default               | Required |
|-------------------------------------|--------------------------------------------------------------------------------|-----------------------|----------|
| `GITLAB_API_KEY`                    | GitLab Access Token with `api` scope                                           | None                  | Yes      |
| `ANTHROPIC_API_KEY`                 | Anthropic Claude API key for security analysis                                 | None                  | Yes      |
| `CLAUDE_MODEL`                      | Claude model to use                                                            | `claude-opus-4-6`     | No       |
| `GITLAB_BASE_URL`                   | GitLab instance URL (auto-resolved from `CI_SERVER_URL`)                       | `https://gitlab.com`  | No       |
| `ENABLE_HARD_EXCLUSIONS`            | Enable regex-based false positive filtering                                    | `true`                | No       |
| `ENABLE_CLAUDE_FILTERING`           | Enable LLM-based second-stage filtering                                        | `false`               | No       |
| `EXCLUDE_DIRECTORIES`               | Comma-separated list of directories to exclude                                 | None                  | No       |
| `CUSTOM_SECURITY_SCAN_INSTRUCTIONS` | Path to `.txt` file with custom security categories to append to audit prompt  | None                  | No       |
| `CUSTOM_FILTER_INSTRUCTIONS`        | Path to `.txt` file with custom false positive filtering instructions          | None                  | No       |
| `SKIP_REVIEWED`                     | Skip review if summary for current commit SHA already exists                   | `true`                | No       |

## How It Works

### Architecture

```
app/
├── main.py                # Entry point: orchestrates the review pipeline
├── prompts.py             # Security audit and filtering prompt templates
├── findings_filter.py     # Two-stage false positive filtering (hard rules + LLM)
├── constants.py           # Constants
├── claude/
│   └── claude_agent.py    # Claude SDK client setup, Pydantic models (Finding, FilterOutput)
├── config/
│   └── settings.py        # Pydantic-settings based configuration
└── gitlab/
    └── gitlab_client.py   # GitLab API client (MR data, discussions, inline comments)
```

### Workflow

1. **MR Analysis**: When a merge request is opened, Claude analyzes the diff to understand what changed
2. **Contextual Review**: Claude examines the code changes in context, understanding the purpose and potential security implications
3. **Finding Generation**: Security issues are identified with detailed explanations, severity ratings, and remediation guidance
4. **False Positive Filtering**: Advanced filtering removes low-impact or false positive prone findings to reduce noise
5. **MR Comments**: Findings are posted as review comments on the specific lines of code

## Security Analysis Capabilities

### Types of Vulnerabilities Detected

- **Injection Attacks**: SQL injection, command injection, LDAP injection, XPath injection, NoSQL injection, XXE
- **Authentication & Authorization**: Broken authentication, privilege escalation, insecure direct object references, bypass logic, session flaws
- **Data Exposure**: Hardcoded secrets, sensitive data logging, information disclosure, PII handling violations
- **Cryptographic Issues**: Weak algorithms, improper key management, insecure random number generation
- **Input Validation**: Missing validation, improper sanitization, buffer overflows
- **Business Logic Flaws**: Race conditions, time-of-check-time-of-use (TOCTOU) issues
- **Configuration Security**: Insecure defaults, missing security headers, permissive CORS
- **Supply Chain**: Vulnerable dependencies, typosquatting risks
- **Code Execution**: RCE via deserialization, pickle injection, eval injection
- **Cross-Site Scripting (XSS)**: Reflected, stored, and DOM-based XSS

### False Positive Filtering

The tool automatically excludes a variety of low-impact and false positive prone findings to focus on high-impact vulnerabilities:
- Denial of Service vulnerabilities
- Rate limiting concerns
- Memory/CPU exhaustion issues
- Generic input validation without proven impact
- Open redirect vulnerabilities

The false positive filtering can also be tuned as needed for a given project's security goals.

### Benefits Over Traditional SAST

- **Contextual Understanding**: Understands code semantics and intent, not just patterns
- **Lower False Positives**: AI-powered analysis reduces noise by understanding when code is actually vulnerable
- **Detailed Explanations**: Provides clear explanations of why something is a vulnerability and how to fix it
- **Adaptive Learning**: Can be customized with organization-specific security requirements

## Development

```bash
# Install dev dependencies
uv sync --group dev

# Lint
uv run ruff check .

# Format
uv run ruff format .

# Type check
uv run mypy .
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
