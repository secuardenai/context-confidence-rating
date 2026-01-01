#!/usr/bin/env python3
"""
CCR CLI - Command-line interface for Context Confidence Rating analysis
"""

import argparse
import json
import sys
from pathlib import Path
from ccr import ContextAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="Calculate Context Confidence Ratings for security findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze repository baseline
  ccr analyze /path/to/repo

  # Calculate CCR for specific finding
  ccr analyze /path/to/repo --finding finding.json

  # Output as JSON
  ccr analyze /path/to/repo --json

  # Analyze with inline finding
  ccr analyze /path/to/repo --file "app.py" --vuln "SQL Injection" --severity "HIGH"
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

    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

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
    print("  Context Confidence Rating (CCR™) Analysis")
    print("=" * 60)

    # Score and confidence
    print(f"\n📊 CCR Score: {result.score}/100")
    print(f"🎯 Confidence Level: {result.confidence.upper()}")

    # Confidence level explanation
    if result.confidence == "high":
        print("   ✓ Strong context understanding - findings highly reliable")
    elif result.confidence == "medium":
        print("   ⚠ Moderate context - some uncertainty in analysis")
    else:
        print("   ⚠ Limited context - findings may need manual verification")

    # Context signals
    if verbose:
        print("\n📋 Context Signals Detected:")
        for signal, details in result.factors.items():
            if details["present"]:
                signal_name = signal.replace("has_", "").replace("_", " ").title()
                contribution = details["contribution"]
                print(f"   ✓ {signal_name} (+{contribution} points)")

                if details.get("details"):
                    d = details["details"]
                    if "frameworks" in d:
                        print(f"      Frameworks: {', '.join(d['frameworks'])}")
                    if "files" in d:
                        print(f"      Files: {', '.join(d['files'][:3])}")
                    if "controls" in d:
                        print(f"      Controls: {', '.join(d['controls'][:3])}")

        print("\n💡 Reasoning:")
        for reason in result.reasoning:
            print(f"   {reason}")

    # Repository overview
    context = analyzer.analyze_repository_context()
    print(f"\n📁 Repository Overview:")
    print(
        f"   Languages: {', '.join(context['languages']) if context['languages'] else 'Not detected'}"
    )
    print(f"   Files: {context['file_count']}")

    if context["has_framework_detection"].get("frameworks"):
        frameworks = context["has_framework_detection"]["frameworks"]
        print(f"   Frameworks: {', '.join(frameworks)}")

    # Recommendations
    print("\n💡 Recommendations:")

    if result.score < 40:
        print("   • Add dependency management files (requirements.txt, package.json)")
        print("   • Create configuration files to improve context understanding")
        print("   • Add security controls (SECURITY.md, CI/CD workflows)")
    elif result.score < 70:
        print("   • Consider adding test coverage for better code flow analysis")
        print("   • Document security controls (SECURITY.md, CODEOWNERS)")
        print("   • Add security scanning configurations")
    else:
        print("   • Excellent context signals detected!")
        print("   • Consider integrating CCR into your CI/CD pipeline")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    sys.exit(main())
