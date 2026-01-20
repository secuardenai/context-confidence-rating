# Context Confidence Rating (CCR™)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![PyPI](https://img.shields.io/pypi/v/context-confidence-rating)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Downloads](https://img.shields.io/pypi/dm/context-confidence-rating)
![Status](https://img.shields.io/badge/status-beta-orange)

**Why CVSS fails modern apps — and how CCR fixes it.**

CCR helps you understand *how much* a security scanner actually understands your codebase's risk context—not just whether vulnerabilities exist, but whether they're actually exploitable given your application's architecture, dependencies, and security controls.

> Finding: SQL Injection
> CVSS: 9.8 (Critical)
> CCR: 0.42 (Low confidence)
> 
>> Why?
>>  - Internal admin-only endpoint
>>  - No external exposure
>>  - No user-controlled input path


🎯 **Built by [Secuarden](https://secuarden.com)** - Product Security Intelligence Platform


## 🚀 Quick Start

```bash
# Install
pip install context-confidence-rating

# Analyze a repository (CCR score)
ccr /path/to/your/repo

# Generate LLM-ready context for security analysis
ccr context /path/to/repo

# Get CCR for a specific finding
ccr /path/to/repo --file "api/auth.py" --vuln "SQL Injection" --severity "HIGH"
```

## 💡 What is CCR?

**Context Confidence Rating (CCR™)** is a 0-100 score that indicates how well security analysis tools understand your codebase's actual risk context. Higher scores mean:

- ✅ Better understanding of data flows
- ✅ More accurate vulnerability prioritization  
- ✅ Fewer false positives to investigate
- ✅ More reliable findings for compliance audits

### ℹ️ CCR does not replace CVSS. It explains when CVSS overreacts.

### The Problem It Solves

Traditional security scanners give you:
> ❌ "Found 500 vulnerabilities" (but 480 are noise)

CCR-enhanced analysis gives you:
> ✅ "Found 20 exploitable vulnerabilities (CCR 85/100 confidence)"

## 📊 Usage

### Python API

```python
from ccr import ContextAnalyzer, ContextGenerator

# Initialize analyzer
analyzer = ContextAnalyzer("/path/to/repo")

# Get baseline repository CCR
baseline = analyzer.calculate_repo_baseline_ccr()
print(f"Repository CCR: {baseline.score}/100")

# Calculate CCR for a specific finding
finding = {
    "file": "api/payments.py",
    "vulnerability": "SQL Injection",
    "severity": "HIGH"
}

result = analyzer.calculate_ccr(finding)
print(f"Finding CCR: {result.score}/100 ({result.confidence})")
print(f"Reasoning: {result.reasoning}")

# Generate LLM-ready context
generator = ContextGenerator("/path/to/repo")
context = generator.generate_context()

# Output as markdown for LLM consumption
print(generator.to_markdown(context))

# Or as JSON/XML
print(generator.to_json(context))
print(generator.to_xml(context))

# Generate context for a specific file
file_context = generator.generate_context(target_file="src/api/auth.ts")
print(generator.to_markdown(file_context))
```

### Command Line

```bash
# Analyze repository baseline
ccr /path/to/repo

# Verbose output with reasoning
ccr /path/to/repo --verbose

# JSON output for CI/CD integration
ccr /path/to/repo --json

# Analyze specific finding
ccr /path/to/repo \
  --file "src/auth.py" \
  --vuln "Hardcoded Credentials" \
  --severity "CRITICAL"
```

### LLM Context Generation

Generate rich codebase context to improve LLM security analysis:

```bash
# Generate markdown context (default)
ccr context /path/to/repo

# Generate JSON context
ccr context /path/to/repo --format json

# Generate XML context (Claude's preferred format)
ccr context /path/to/repo --format xml

# Generate context for a specific file
ccr context /path/to/repo --file src/api/auth.ts

# Save to file for LLM use
ccr context /path/to/repo > REPO_CONTEXT.md
```

Then use the context with your LLM:

```
Here's my codebase context:
<context>
{paste REPO_CONTEXT.md}
</context>

Here's a security finding from my scanner:
<finding>
SQL Injection in api/users.py line 42
</finding>

Is this exploitable given my codebase architecture?
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan with CCR

on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run SAST scanner
        run: semgrep --config=auto --json > findings.json

      - name: Calculate Context Confidence
        run: |
          pip install context-confidence-rating
          ccr . --json > ccr-report.json

      - name: Check CCR threshold
        run: |
          CCR_SCORE=$(jq '.score' ccr-report.json)
          if [ "$CCR_SCORE" -lt 60 ]; then
            echo "::warning::Low context confidence ($CCR_SCORE/100) - findings may need manual review"
          fi
```

### AI-Powered Security Review with Context

```yaml
# .github/workflows/ai-security-review.yml
name: AI Security Review

on: [pull_request]

jobs:
  ai-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Generate Security Context
        run: |
          pip install context-confidence-rating
          ccr context . --format markdown > .github/SECURITY_CONTEXT.md

      - name: AI Security Review
        uses: anthropic/claude-action@v1
        with:
          prompt: |
            Review this PR for security issues.

            <repo_context>
            $(cat .github/SECURITY_CONTEXT.md)
            </repo_context>

            <diff>
            ${{ github.event.pull_request.diff }}
            </diff>
```

## 🔍 What CCR Analyzes

CCR examines your repository for context signals:

| Signal | Weight | What It Means |
|--------|--------|---------------|
| **Framework Detection** | 15% | Understanding of web frameworks (Django, Flask, Express) |
| **Dependency Tracking** | 15% | Presence of `requirements.txt`, `package.json`, etc. |
| **Data Flow Analysis** | 20% | Ability to trace data through your code |
| **Entry Point Mapping** | 15% | Understanding of application entry points |
| **Config Awareness** | 10% | Detection of configuration files |
| **Security Controls** | 15% | Presence of security policies, CI/CD, CODEOWNERS |
| **Test Coverage** | 10% | Existence of test files and frameworks |

### CCR Score Ranges

- **71-100 (High)**: Strong context understanding - findings highly reliable
- **41-70 (Medium)**: Moderate context - some findings may need verification
- **0-40 (Low)**: Limited context - manual review recommended

## 🎯 Use Cases

### 1. **Vulnerability Triage**
Re-rank scanner outputs based on actual exploitability in your codebase.

```python
findings = run_security_scanner()  # Returns 500 findings
for finding in findings:
    ccr_result = analyzer.calculate_ccr(finding)
    if ccr_result.score >= 70 and finding.severity == "HIGH":
        prioritize_for_immediate_fix(finding)
```

### 2. **Audit Preparation**
Show auditors you have strong context understanding.

```python
ccr_result = analyzer.calculate_repo_baseline_ccr()
print(f"Our security analysis has {ccr_result.score}/100 context confidence")
# Demonstrates mature security posture
```

### 3. **Scanner Comparison**
Evaluate which security tools work best for *your* codebase.

```python
# Tool A gives 500 findings with CCR 45 (low confidence)
# Tool B gives 50 findings with CCR 82 (high confidence)
# → Tool B is more effective for your context
```

### 4. **CI/CD Quality Gate**
Fail builds when context drops below threshold.

```bash
ccr . --json | jq '.score' | awk '$1 < 60 {exit 1}'
```

## 🛠️ Installation

### From PyPI (when published)

```bash
pip install context-confidence-rating
```

### From Source

```bash
git clone https://github.com/secuardenai/context-confidence-rating.git
cd context-confidence-rating
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/secuardenai/context-confidence-rating.git
cd context-confidence-rating
pip install -e ".[dev]"
pytest
```

## 📖 Example Output

```
============================================================
  Context Confidence Rating (CCR™) Analysis
============================================================

📊 CCR Score: 78/100
🎯 Confidence Level: HIGH
   ✓ Strong context understanding - findings highly reliable

📋 Context Signals Detected:
   ✓ Framework Detection (+15 points)
      Frameworks: Flask, SQLAlchemy
   ✓ Dependency Tracking (+15 points)
      Files: requirements.txt, Pipfile.lock
   ✓ Data Flow Analysis (+20 points)
   ✓ Entry Point Mapping (+15 points)
   ✓ Security Controls (+13 points)
      Controls: security_policy, ci_cd_pipeline, code_ownership

💡 Reasoning:
   ✓ Framework Detection
   ✓ Dependency Tracking
   ✓ Data Flow Analysis
   ✓ Entry Point Mapping
   ✓ Config Awareness
   ✓ Security Controls
   ↑ High-severity finding prioritization (+5)

📁 Repository Overview:
   Languages: Python, JavaScript
   Files: 247
   Frameworks: Flask, SQLAlchemy

💡 Recommendations:
   • Excellent context signals detected!
   • Consider integrating CCR into your CI/CD pipeline

============================================================
```

## 📋 Case Study: Better-Auth Password Module

Here's a real example showing how CCR context changes security analysis results.

**Target:** [better-auth](https://github.com/better-auth/better-auth) - a popular TypeScript authentication library

**File analyzed:** `packages/better-auth/src/crypto/password.ts`

```typescript
const config = {
  N: 16384,
  r: 16,
  p: 1,
  dkLen: 64,
};

export const hashPassword = async (password: string) => {
  const salt = hex.encode(crypto.getRandomValues(new Uint8Array(16)));
  const key = await generateKey(password, salt);
  return `${salt}:${hex.encode(key)}`;
};
```

### Without Context (Traditional Scanner)

| Severity | Finding | Recommendation |
|----------|---------|----------------|
| **HIGH** | CWE-916: Scrypt N=16384 below OWASP minimum | Increase N to 131072 |
| **MEDIUM** | CWE-330: 16-byte salt may be insufficient | Use 32-byte salt |
| **LOW** | CWE-754: No hash format validation | Add format checks |
| **INFO** | Missing input validation on password | Add length checks |

**Result:** 4 findings requiring remediation

### With CCR Context

```bash
ccr context /path/to/better-auth --file packages/better-auth/src/crypto/password.ts
```

```
## File Context: `packages/better-auth/src/crypto/password.ts`
- **Type:** authentication
- **Functions:** generateKey, hashPassword, verifyPassword
- **User input handling:** No
- **Database operations:** No
- **Auth checks:** No
- **Input validation:** No
```

| Severity | Finding | Context-Aware Assessment |
|----------|---------|--------------------------|
| **LOW** | Scrypt N=16384 | Library defaults are tunable by consumers. Document recommendations. |
| **Not Exploitable** | 16-byte salt | 128-bit is sufficient per NIST SP 800-132. Using audited @noble/hashes. |
| **Not Exploitable** | Hash format validation | Line 38-39 throws BetterAuthError. constantTimeEqual prevents timing attacks. |
| **Not Applicable** | Missing input validation | This is a crypto utility, not an API endpoint. Zod validation exists at API boundary. |

**Result:** 1 documentation item, 3 non-issues dismissed

### Why Context Matters

The CCR context revealed:
- This is a **library**, not application code - consumers configure parameters
- **Zod validation** exists at API boundaries in the codebase
- Uses **@noble/hashes**, a well-audited crypto library
- File **doesn't handle user input directly** - it's an internal utility
- Repository has **SECURITY.md** and **CODEOWNERS** - mature security practices

**Noise reduction: 75%** (4 findings → 1 actionable item)

---

## 🔗 Integration with Security Tools

CCR is designed to enhance—not replace—existing security scanners:

- ✅ **Semgrep**: Enhance SAST findings with context scores
- ✅ **Bandit**: Add confidence to Python security analysis
- ✅ **Snyk**: Contextualize dependency vulnerability impact
- ✅ **GitHub Security**: Prioritize CodeQL/Dependabot alerts
- ✅ **Custom Tools**: Integrate via JSON output

## 🤝 Contributing

We welcome contributions! This is an open-source project maintained by Secuarden.

```bash
# Setup development environment
git clone https://github.com/secuardenai/context-confidence-rating.git
cd context-confidence-rating
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black ccr/
flake8 ccr/
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Credits

Created by the [Secuarden](https://secuarden.com) team.


---

## 🚀 Want More?

CCR is the open-source foundation of [**Secuarden**](https://secuarden.com) - our Product Security Intelligence Platform that:

- 🔍 Transforms generic SAST findings into audit-ready compliance evidence
- 🎯 Prioritizes vulnerabilities using CCR + exploitability analysis
- 📊 Maps findings to SOC 2, ISO 27001, PCI-DSS requirements
- 🤖 Generates AI-powered remediation with context-aware code suggestions
- ✅ Provides PR-level security enforcement with intelligent blocking

[**Try Secuarden Free →**](https://secuarden.com)

---

**Questions?** Open an issue or email [tech@secuarden.com](mailto:tech@secuarden.com)
