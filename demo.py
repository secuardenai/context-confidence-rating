#!/usr/bin/env python3
"""
Quick demo of CCR library - analyzes current directory
"""

from ccr import ContextAnalyzer


def main():
    print("\n" + "="*60)
    print("  Context Confidence Rating (CCR™) Demo")
    print("="*60)
    
    try:
        # Analyze current directory
        print("\n🔍 Analyzing current directory...")
        analyzer = ContextAnalyzer(".")
        
        # Get baseline score
        result = analyzer.calculate_repo_baseline_ccr()
        
        print(f"\n📊 CCR Score: {result.score}/100")
        print(f"🎯 Confidence: {result.confidence.upper()}")
        
        # Show what was detected
        context = analyzer.analyze_repository_context()
        print(f"\n📁 Languages: {', '.join(context['languages']) or 'None detected'}")
        print(f"📄 Files: {context['file_count']}")
        
        if context['has_framework_detection']['detected']:
            frameworks = context['has_framework_detection']['frameworks']
            print(f"🎨 Frameworks: {', '.join(frameworks)}")
        
        # Simple recommendation
        print("\n💡 Recommendation:")
        if result.score >= 70:
            print("   ✅ Excellent! Your repo has strong context signals.")
            print("   → Security findings will be highly reliable.")
        elif result.score >= 40:
            print("   ⚠️  Good, but could be better.")
            print("   → Consider adding more context signals (see README).")
        else:
            print("   ⚠️  Limited context detected.")
            print("   → Add dependency files, tests, and security controls.")
        
        print("\n" + "="*60)
        print("💻 Run 'ccr analyze . --verbose' for detailed analysis")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}\n")
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
