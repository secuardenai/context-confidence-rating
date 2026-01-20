#!/usr/bin/env python3
"""
CCR CLI - Command-line interface for Context Confidence Rating analysis
"""

import argparse
import json
import sys
from pathlib import Path
from ccr import ContextAnalyzer
from ccr.context_generator import ContextGenerator


def main():
    # Check if first argument is 'context' subcommand
    if len(sys.argv) > 1 and sys.argv[1] == "context":
        return run_context_cli()

    # Otherwise, run the legacy CCR analysis
    return run_ccr_cli()


def run_context_cli():
    """Run the context generation CLI."""
    parser = argparse.ArgumentParser(
        prog="ccr context",
        description="Generate rich codebase context for LLM security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate markdown context (default)
  ccr context /path/to/repo

  # Generate JSON context
  ccr context /path/to/repo --format json

  # Generate XML context (Claude's preferred format)
  ccr context /path/to/repo --format xml

  # Generate context for a specific file
  ccr context /path/to/repo --file src/api/auth.ts

  # Save to file for LLM use
  ccr context /path/to/repo --format markdown > REPO_CONTEXT.md
        """,
    )

    parser.add_argument("repo_path", help="Path to the repository to analyze")
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json", "xml"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--file",
        dest="target_file",
        help="Generate detailed context for a specific file",
    )

    # Skip 'context' in argv
    args = parser.parse_args(sys.argv[2:])

    try:
        generator = ContextGenerator(args.repo_path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        context = generator.generate_context(target_file=args.target_file)
    except Exception as e:
        print(f"Error generating context: {e}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(generator.to_json(context))
    elif args.format == "xml":
        print(generator.to_xml(context))
    else:
        print(generator.to_markdown(context))

    return 0


def run_ccr_cli():
    """Run the legacy CCR analysis CLI."""
    parser = argparse.ArgumentParser(
        prog="ccr",
        description="Context Confidence Rating - Security context analysis for codebases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze repository baseline (CCR score)
  ccr /path/to/repo

  # Generate LLM-ready context (NEW!)
  ccr context /path/to/repo

  # Generate context in different formats
  ccr context /path/to/repo --format markdown
  ccr context /path/to/repo --format json
  ccr context /path/to/repo --format xml

  # Calculate CCR for specific finding
  ccr /path/to/repo --finding finding.json

  # Verbose output with reasoning
  ccr /path/to/repo --verbose

  # Analyze with inline finding
  ccr /path/to/repo --file "app.py" --vuln "SQL Injection" --severity "HIGH"
        """,
    )

    parser.add_argument("repo_path", help="Path to the repository to analyze")

    parser.add_argument("--finding", help="Path to JSON file containing finding details")

    parser.add_argument("--file", help="File path for inline finding")

    parser.add_argument(
        "--vuln",
        "--vulnerability",
        dest="vulnerability",
        help="Vulnerability name for inline finding",
    )

    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Severity level for inline finding",
    )

    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output with reasoning"
    )

    parser.add_argument("--version", action="version", version="%(prog)s 0.2.0")

    args = parser.parse_args()

    # Initialize analyzer
    try:
        analyzer = ContextAnalyzer(args.repo_path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Prepare finding if provided
    finding = None

    if args.finding:
        # Load from JSON file
        try:
            with open(args.finding, "r") as f:
                finding = json.load(f)
        except Exception as e:
            print(f"Error loading finding file: {e}", file=sys.stderr)
            return 1

    elif args.file or args.vulnerability or args.severity:
        # Build from inline arguments
        if not all([args.file, args.vulnerability, args.severity]):
            print(
                "Error: --file, --vuln, and --severity must all be provided together",
                file=sys.stderr,
            )
            return 1

        finding = {
            "file": args.file,
            "vulnerability": args.vulnerability,
            "severity": args.severity,
        }

    # Calculate CCR
    try:
        result = analyzer.calculate_ccr(finding)
    except Exception as e:
        print(f"Error calculating CCR: {e}", file=sys.stderr)
        return 1

    # Output results
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_human_readable(result, analyzer, args.verbose)

    return 0


def print_human_readable(result, analyzer, verbose=False):
    """Print results in human-readable format"""

    print("\n" + "=" * 60)
    print("  Context Confidence Rating (CCR) Analysis")
    print("=" * 60)

    # Score and confidence
    print(f"\n  CCR Score: {result.score}/100")
    print(f"  Confidence Level: {result.confidence.upper()}")

    # Confidence level explanation
    if result.confidence == "high":
        print("   Strong context understanding - findings highly reliable")
    elif result.confidence == "medium":
        print("   Moderate context - some uncertainty in analysis")
    else:
        print("   Limited context - findings may need manual verification")

    # Context signals
    if verbose:
        print("\n  Context Signals Detected:")
        for signal, details in result.factors.items():
            if details["present"]:
                signal_name = signal.replace("has_", "").replace("_", " ").title()
                contribution = details["contribution"]
                print(f"   [+] {signal_name} (+{contribution} points)")

                if details.get("details"):
                    d = details["details"]
                    if "frameworks" in d:
                        print(f"      Frameworks: {', '.join(d['frameworks'])}")
                    if "files" in d:
                        print(f"      Files: {', '.join(d['files'][:3])}")
                    if "controls" in d:
                        print(f"      Controls: {', '.join(d['controls'][:3])}")

        print("\n  Reasoning:")
        for reason in result.reasoning:
            print(f"   {reason}")

    # Repository overview
    context = analyzer.analyze_repository_context()
    print(f"\n  Repository Overview:")
    print(
        f"   Languages: {', '.join(context['languages']) if context['languages'] else 'Not detected'}"
    )
    print(f"   Files: {context['file_count']}")

    if context["has_framework_detection"].get("frameworks"):
        frameworks = context["has_framework_detection"]["frameworks"]
        print(f"   Frameworks: {', '.join(frameworks)}")

    # Recommendations based on what's missing
    print("\n  Recommendations:")

    recommendations = []

    if not result.factors.get("has_dependency_tracking", {}).get("present"):
        recommendations.append("Add dependency management files (requirements.txt, package.json)")

    if not result.factors.get("has_config_awareness", {}).get("present"):
        recommendations.append("Create configuration files to improve context understanding")

    if not result.factors.get("has_security_controls", {}).get("present"):
        recommendations.append("Add security controls (SECURITY.md, CI/CD workflows)")
    elif (
        result.factors.get("has_security_controls", {}).get("details", {}).get("strength", 0) < 0.6
    ):
        # Check what specific controls are missing
        controls = (
            result.factors.get("has_security_controls", {}).get("details", {}).get("controls", [])
        )
        if "code_ownership" not in controls:
            recommendations.append("Add CODEOWNERS file for code review requirements")
        if "pre_commit_hooks" not in controls:
            recommendations.append("Consider adding pre-commit hooks for automated checks")

    if not result.factors.get("has_test_coverage", {}).get("present"):
        recommendations.append("Add test coverage for better code flow analysis")

    if not result.factors.get("has_framework_detection", {}).get("present"):
        recommendations.append(
            "Framework detection failed - ensure dependencies are properly declared"
        )

    # Add general recommendations based on score
    if result.score >= 70:
        recommendations.append("Excellent context signals detected!")
        recommendations.append("Consider integrating CCR into your CI/CD pipeline")
    elif not recommendations:
        recommendations.append(
            "Consider adding security scanning configurations (.semgrep.yml, .snyk)"
        )
        recommendations.append("Consider integrating CCR into your CI/CD pipeline")

    for rec in recommendations:
        print(f"   - {rec}")

    # Suggest context command
    print("\n  Tip: Use 'ccr context <repo>' to generate LLM-ready context")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    sys.exit(main())
