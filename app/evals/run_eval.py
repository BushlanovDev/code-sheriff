#!/usr/bin/env python3
"""CLI for running security evaluation on a single GitLab Merge Request."""

import argparse
import json
import os
import sys
from pathlib import Path

from app.evals.eval_engine import EvalCase, run_single_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run security evaluation on a single GitLab MR",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "mr",
        type=str,
        help="MR to evaluate: 'namespace/project#mr_iid' (e.g. 'mygroup/myapp#42')",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./eval_results",
        help="Directory for evaluation results",
    )
    parser.add_argument(
        "--work-dir",
        type=str,
        default=None,
        help="Directory for temporary repositories (default: ~/code/audit)",
    )
    parser.add_argument(
        "--gitlab-url",
        type=str,
        default=os.environ.get("GITLAB_BASE_URL", "https://gitlab.com"),
        help="GitLab instance URL",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Validate env
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable is not set")
        sys.exit(1)

    # Parse MR specification: "namespace/project#iid"
    try:
        if "#" not in args.mr:
            raise ValueError("Missing '#' separator")
        project_part, iid_str = args.mr.rsplit("#", 1)
        mr_iid = int(iid_str)
        if "/" not in project_part:
            raise ValueError("Project must be in 'namespace/project' format")
        parts = project_part.split("/")
        if len(parts) < 2 or not all(parts):
            raise ValueError("Namespace and project name cannot be empty")
    except ValueError as e:
        print(f"Error: Invalid MR format '{args.mr}': {e}")
        print("Expected: 'namespace/project#mr_iid'")
        print("Example:  'mygroup/myapp#42'")
        sys.exit(1)

    print(f"\nEvaluating MR: {project_part}!{mr_iid}")
    print("-" * 60)

    test_case = EvalCase(
        project_id=project_part,
        mr_iid=mr_iid,
        description=f"Evaluation for {project_part}!{mr_iid}",
    )

    result = run_single_evaluation(
        test_case,
        verbose=args.verbose,
        work_dir=args.work_dir,
        gitlab_base_url=args.gitlab_url,
    )

    # Display results
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS:")
    print(f"  Success:          {result.success}")
    print(f"  Runtime:          {result.runtime_seconds:.1f}s")
    print(f"  Vulnerabilities:  {result.detected_vulnerabilities}")
    print(f"  Findings count:   {result.findings_count}")

    if result.cost_usd > 0:
        print(f"  Cost:             ${result.cost_usd:.4f}")
        print(f"  Input tokens:     {result.input_tokens}")
        print(f"  Output tokens:    {result.output_tokens}")

    if result.error_message:
        print(f"\n  Error: {result.error_message}")

    if result.full_findings:
        print("\nFindings:")
        for f in result.full_findings:
            sev = f.get("severity", "?")
            file = f.get("file", "unknown")
            line = f.get("line", "?")
            print(f"  - [{sev}] {file}:{line}")
            if "category" in f:
                print(f"    Category: {f['category']}")
            if "description" in f:
                print(f"    {f['description']}")
            if "exploit_scenario" in f:
                print(f"    Exploit: {f['exploit_scenario']}")
            if "recommendation" in f:
                print(f"    Fix: {f['recommendation']}")
            if "confidence" in f:
                print(f"    Confidence: {f['confidence']}")
            print()

    # Save result
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    safe_name = project_part.replace("/", "_")
    result_file = output_path / f"mr_{safe_name}_{mr_iid}.json"

    with result_file.open("w") as fp:
        json.dump(result.to_dict(), fp, indent=2)

    print(f"Result saved to: {result_file}")
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
