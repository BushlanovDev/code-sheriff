# Security Audit Evaluation Tool

Evaluate the Code Sheriff security review pipeline on any GitLab Merge Request.

## Requirements

- Python 3.13+
- Git 2.20+ (for worktree support)
- Environment variables:
  - `ANTHROPIC_API_KEY`: Required for Claude API access
  - `GITLAB_API_KEY`: Recommended for private repos and API rate limits

## Usage

```bash
# Basic usage
uv run code-sheriff-eval namespace/project#42 --verbose

# Or as module
uv run python -m app.evals.run_eval namespace/project#42 --verbose

# Custom GitLab instance
uv run code-sheriff-eval namespace/project#42 --gitlab-url https://git.company.com

# Custom work directory
uv run code-sheriff-eval namespace/project#42 --work-dir /tmp/eval-repos
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `mr` | MR in format `namespace/project#mr_iid` | Required |
| `--output-dir` | Directory for JSON results | `./eval_results` |
| `--work-dir` | Directory for cloned repos | `~/code/audit` |
| `--gitlab-url` | GitLab instance URL | `https://gitlab.com` |
| `--verbose` | Enable verbose logging | `false` |

## Output

JSON file in the output directory with:
- Success/failure status
- Runtime metrics
- Cost and token usage
- Security findings with file, line, severity, and descriptions

Example: `eval_results/mr_namespace_project_42.json`

## Architecture

1. Clones the repository once as a base (with `--filter=blob:none` for speed)
2. Fetches MR changes via `git fetch origin merge-requests/{iid}/head`
3. Creates a lightweight worktree for the MR
4. Runs the full Code Sheriff pipeline (Claude SDK agent)
5. Collects and saves results
6. Cleans up worktree automatically
