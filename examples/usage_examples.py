#!/usr/bin/env python3
"""
Example usage of Context Confidence Rating library
"""

from ccr import ContextAnalyzer


def example_1_baseline_analysis():
    """Example 1: Calculate baseline CCR for a repository"""
    print("\n" + "=" * 60)
    print("Example 1: Repository Baseline Analysis")
    print("=" * 60)

    # Point to your repository
    analyzer = ContextAnalyzer(".")

    # Get baseline CCR
    result = analyzer.calculate_repo_baseline_ccr()

    print(f"\nRepository CCR Score: {result.score}/100")
    print(f"Confidence Level: {result.confidence}")
    print("\nContext Signals Detected:")
    for signal, details in result.factors.items():
        if details["present"]:
            print(f"  ✓ {signal}: +{details['contribution']} points")


def example_2_finding_analysis():
    """Example 2: Calculate CCR for a specific security finding"""
    print("\n" + "=" * 60)
    print("Example 2: Security Finding Analysis")
    print("=" * 60)

    analyzer = ContextAnalyzer(".")

    # Simulate a security finding from a scanner
    finding = {"file": "api/payments.py", "vulnerability": "SQL Injection", "severity": "HIGH"}

    result = analyzer.calculate_ccr(finding)

    print(f"\nFinding: {finding['vulnerability']}")
    print(f"File: {finding['file']}")
    print(f"Severity: {finding['severity']}")
    print(f"\nCCR Score: {result.score}/100")
    print(f"Confidence: {result.confidence}")
    print("\nReasoning:")
    for reason in result.reasoning:
        print(f"  {reason}")


def example_3_multiple_findings():
    """Example 3: Prioritize multiple findings using CCR"""
    print("\n" + "=" * 60)
    print("Example 3: Prioritizing Multiple Findings")
    print("=" * 60)

    analyzer = ContextAnalyzer(".")

    # Simulate findings from a security scanner
    findings = [
        {"file": "api/auth.py", "vulnerability": "Weak Password Hash", "severity": "HIGH"},
        {
            "file": "utils/logger.py",
            "vulnerability": "Information Disclosure",
            "severity": "MEDIUM",
        },
        {"file": "api/payments.py", "vulnerability": "SQL Injection", "severity": "CRITICAL"},
        {"file": "tests/test_api.py", "vulnerability": "Hardcoded Credentials", "severity": "HIGH"},
    ]

    # Calculate CCR for each finding
    results = []
    for finding in findings:
        ccr_result = analyzer.calculate_ccr(finding)
        results.append(
            {"finding": finding, "ccr": ccr_result.score, "confidence": ccr_result.confidence}
        )

    # Sort by severity and CCR
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    results.sort(
        key=lambda x: (severity_order.get(x["finding"]["severity"], 0), x["ccr"]), reverse=True
    )

    print("\nPrioritized Findings (by Severity + CCR):\n")
    for i, result in enumerate(results, 1):
        f = result["finding"]
        print(f"{i}. [{f['severity']}] {f['vulnerability']}")
        print(f"   File: {f['file']}")
        print(f"   CCR: {result['ccr']}/100 ({result['confidence']} confidence)")
        print()


def example_4_json_output():
    """Example 4: Export results as JSON for CI/CD"""
    print("\n" + "=" * 60)
    print("Example 4: JSON Output for CI/CD")
    print("=" * 60)

    import json

    analyzer = ContextAnalyzer(".")
    result = analyzer.calculate_repo_baseline_ccr()

    # Convert to JSON
    json_output = json.dumps(result.to_dict(), indent=2)

    print("\nJSON Output:")
    print(json_output)

    print("\n💡 Use this in CI/CD to fail builds when CCR < threshold")


def example_5_context_insights():
    """Example 5: Get detailed context insights"""
    print("\n" + "=" * 60)
    print("Example 5: Detailed Context Insights")
    print("=" * 60)

    analyzer = ContextAnalyzer(".")
    context = analyzer.analyze_repository_context()

    print("\n📊 Repository Context Analysis:")
    print(f"\nLanguages Detected: {', '.join(context['languages'])}")
    print(f"Total Files: {context['file_count']}")

    if context["has_framework_detection"]["detected"]:
        fw = context["has_framework_detection"]
        print(f"\nFrameworks: {', '.join(fw['frameworks'])}")
        print(f"Framework Detection Strength: {fw['strength']:.2f}")

    if context["has_dependency_tracking"]["detected"]:
        deps = context["has_dependency_tracking"]
        print(f"\nDependency Files: {', '.join(deps['files'])}")

    if context["has_security_controls"]["detected"]:
        sec = context["has_security_controls"]
        print(f"\nSecurity Controls: {', '.join(sec['controls'])}")

    print("\n💡 Higher context signals = more accurate security analysis")


if __name__ == "__main__":
    print("\n" + "🔍 CCR Library Examples".center(60))

    try:
        example_1_baseline_analysis()
        example_2_finding_analysis()
        example_3_multiple_findings()
        example_4_json_output()
        example_5_context_insights()

        print("\n" + "=" * 60)
        print("✅ All examples completed successfully!")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("\nMake sure you're running this from a valid repository directory.")
