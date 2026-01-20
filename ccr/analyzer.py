"""
Context Confidence Rating (CCR™) Analyzer
A lightweight library for calculating context-aware security confidence scores.

Copyright (c) 2025 Secuarden
Licensed under MIT License
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence levels for CCR scores"""

    LOW = "low"  # 0-40: Limited context understanding
    MEDIUM = "medium"  # 41-70: Moderate context understanding
    HIGH = "high"  # 71-100: Strong context understanding


@dataclass
class CCRResult:
    """Result of CCR analysis"""

    score: int  # 0-100
    confidence: str
    factors: Dict[str, any]
    reasoning: List[str]

    def to_dict(self):
        return asdict(self)


class ContextAnalyzer:
    """
    Analyzes code repositories to calculate Context Confidence Ratings
    for security findings.
    """

    # Weight factors for different context signals
    WEIGHTS = {
        "has_framework_detection": 15,
        "has_dependency_tracking": 15,
        "has_dataflow_analysis": 20,
        "has_entrypoint_mapping": 15,
        "has_config_awareness": 10,
        "has_security_controls": 15,
        "has_test_coverage": 10,
    }

    def __init__(self, repo_path: str):
        """
        Initialize analyzer with repository path.

        Args:
            repo_path: Path to the repository to analyze
        """
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        self._context_cache = None

    def analyze_repository_context(self) -> Dict[str, any]:
        """
        Analyze repository to build context understanding.

        Returns:
            Dictionary containing context signals
        """
        if self._context_cache:
            return self._context_cache

        context = {
            "has_framework_detection": self._detect_frameworks(),
            "has_dependency_tracking": self._detect_dependencies(),
            "has_dataflow_analysis": self._analyze_dataflow_potential(),
            "has_entrypoint_mapping": self._find_entrypoints(),
            "has_config_awareness": self._detect_config_files(),
            "has_security_controls": self._detect_security_controls(),
            "has_test_coverage": self._detect_test_files(),
            "languages": self._detect_languages(),
            "file_count": self._count_files(),
        }

        self._context_cache = context
        return context

    def calculate_ccr(self, finding: Dict[str, any]) -> CCRResult:
        """
        Calculate Context Confidence Rating for a security finding.

        Args:
            finding: Dictionary with keys: file, vulnerability, severity

        Returns:
            CCRResult with score and analysis
        """
        context = self.analyze_repository_context()

        # Base score from context signals
        base_score = 0
        factors = {}
        reasoning = []

        for signal, weight in self.WEIGHTS.items():
            signal_value = context.get(signal, False)

            if signal_value:
                contribution = weight
                if isinstance(signal_value, dict):
                    # Adjust weight based on signal strength
                    strength = signal_value.get("strength", 1.0)
                    contribution = int(weight * strength)

                base_score += contribution
                factors[signal] = {
                    "present": True,
                    "contribution": contribution,
                    "details": signal_value if isinstance(signal_value, dict) else None,
                }
                reasoning.append(f"✓ {signal.replace('has_', '').replace('_', ' ').title()}")
            else:
                factors[signal] = {"present": False, "contribution": 0}

        # Adjust score based on finding specifics
        if finding:
            file_path = finding.get("file", "")
            severity = finding.get("severity", "").upper()

            # Boost if we have specific context about this file
            if self._has_file_context(file_path):
                boost = 10
                base_score = min(100, base_score + boost)
                reasoning.append(f"↑ File-specific context available (+{boost})")

            # Slight boost for critical findings (more context needed)
            if severity in ["CRITICAL", "HIGH"]:
                boost = 5
                base_score = min(100, base_score + boost)
                reasoning.append(f"↑ High-severity finding prioritization (+{boost})")

        # Determine confidence level
        if base_score >= 71:
            confidence = ConfidenceLevel.HIGH.value
        elif base_score >= 41:
            confidence = ConfidenceLevel.MEDIUM.value
        else:
            confidence = ConfidenceLevel.LOW.value

        return CCRResult(
            score=base_score, confidence=confidence, factors=factors, reasoning=reasoning
        )

    def calculate_repo_baseline_ccr(self) -> CCRResult:
        """
        Calculate baseline CCR for the repository (without specific finding).

        Returns:
            CCRResult representing overall repository context understanding
        """
        return self.calculate_ccr(None)

    def _detect_frameworks(self) -> Dict[str, any]:
        """Detect web frameworks and their patterns"""
        frameworks = []

        # Python frameworks
        if self._file_exists("manage.py") or self._file_exists("wsgi.py"):
            frameworks.append("Django")
        if self._file_contains_pattern(["requirements.txt", "pyproject.toml"], "flask"):
            frameworks.append("Flask")
        if self._file_contains_pattern(["requirements.txt", "pyproject.toml"], "fastapi"):
            frameworks.append("FastAPI")
        if self._file_contains_pattern(["requirements.txt", "pyproject.toml"], "sqlalchemy"):
            frameworks.append("SQLAlchemy")

        # Node.js/JavaScript frameworks
        if self._file_contains_pattern(["package.json"], '"express"'):
            frameworks.append("Express")
        if (
            self._file_contains_pattern(["package.json"], '"next"')
            or self._file_exists("next.config.js")
            or self._file_exists("next.config.mjs")
        ):
            frameworks.append("Next.js")
        if self._file_contains_pattern(["package.json"], '"react"'):
            frameworks.append("React")
        if self._file_contains_pattern(["package.json"], '"vue"'):
            frameworks.append("Vue")
        if self._file_contains_pattern(["package.json"], '"svelte"') or self._file_exists(
            "svelte.config.js"
        ):
            frameworks.append("Svelte")
        if self._file_contains_pattern(["package.json"], '"nuxt"') or self._file_exists(
            "nuxt.config.ts"
        ):
            frameworks.append("Nuxt")
        if self._file_contains_pattern(["package.json"], '"hono"'):
            frameworks.append("Hono")
        if self._file_contains_pattern(["package.json"], '"fastify"'):
            frameworks.append("Fastify")
        if self._file_contains_pattern(["package.json"], '"koa"'):
            frameworks.append("Koa")
        if self._file_contains_pattern(["package.json"], '"nestjs"') or self._file_contains_pattern(
            ["package.json"], '"@nestjs/core"'
        ):
            frameworks.append("NestJS")
        if self._file_contains_pattern(["package.json"], '"prisma"') or self._file_exists(
            "prisma/schema.prisma"
        ):
            frameworks.append("Prisma")
        if self._file_contains_pattern(["package.json"], '"drizzle-orm"'):
            frameworks.append("Drizzle")
        if self._file_contains_pattern(["package.json"], '"typeorm"'):
            frameworks.append("TypeORM")
        if self._file_contains_pattern(["package.json"], '"trpc"') or self._file_contains_pattern(
            ["package.json"], '"@trpc/server"'
        ):
            frameworks.append("tRPC")
        if self._file_contains_pattern(["package.json"], '"zod"'):
            frameworks.append("Zod")

        # Build tools / Meta-frameworks
        if self._file_contains_pattern(["package.json"], '"turbo"') or self._file_exists(
            "turbo.json"
        ):
            frameworks.append("Turborepo")
        if (
            self._file_contains_pattern(["package.json"], '"vite"')
            or self._file_exists("vite.config.ts")
            or self._file_exists("vite.config.js")
        ):
            frameworks.append("Vite")
        if self._file_contains_pattern(["package.json"], '"vitest"') or self._file_exists(
            "vitest.config.ts"
        ):
            frameworks.append("Vitest")

        # Ruby
        if self._file_exists("Gemfile"):
            if self._file_contains_pattern(["Gemfile"], "rails"):
                frameworks.append("Rails")
            else:
                frameworks.append("Ruby")

        # Go
        if self._file_contains_pattern(["go.mod"], "gin-gonic"):
            frameworks.append("Gin")
        if self._file_contains_pattern(["go.mod"], "echo"):
            frameworks.append("Echo")
        if self._file_contains_pattern(["go.mod"], "fiber"):
            frameworks.append("Fiber")

        # Rust
        if self._file_contains_pattern(["Cargo.toml"], "actix"):
            frameworks.append("Actix")
        if self._file_contains_pattern(["Cargo.toml"], "axum"):
            frameworks.append("Axum")
        if self._file_contains_pattern(["Cargo.toml"], "rocket"):
            frameworks.append("Rocket")

        return {
            "detected": len(frameworks) > 0,
            "frameworks": frameworks,
            "strength": min(1.0, len(frameworks) * 0.15 + 0.1) if frameworks else 0,
        }

    def _detect_dependencies(self) -> Dict[str, any]:
        """Detect dependency management files"""
        dep_files = [
            # Python
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
            # JavaScript/Node
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lockb",
            # Ruby
            "Gemfile",
            "Gemfile.lock",
            # Java
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            # Go
            "go.mod",
            "go.sum",
            # Rust
            "Cargo.toml",
            "Cargo.lock",
            # .NET
            "packages.config",
            "*.csproj",
            # PHP
            "composer.json",
            "composer.lock",
        ]

        found = [f for f in dep_files if self._file_exists(f)]

        return {"detected": len(found) > 0, "files": found, "strength": min(1.0, len(found) * 0.2)}

    def _analyze_dataflow_potential(self) -> Dict[str, any]:
        """Analyze if dataflow analysis is feasible"""
        # Simplified: check for structured code that enables dataflow
        indicators = {
            "has_imports": self._has_import_statements(),
            "has_functions": self._has_function_definitions(),
            "has_classes": self._has_class_definitions(),
        }

        strength = sum(indicators.values()) / len(indicators)

        return {"detected": strength > 0.3, "indicators": indicators, "strength": strength}

    def _find_entrypoints(self) -> Dict[str, any]:
        """Find application entrypoints"""
        entrypoints = []

        # Common entrypoint files at root level
        entry_files = [
            # Python
            "main.py",
            "app.py",
            "server.py",
            "__main__.py",
            "wsgi.py",
            "asgi.py",
            # JavaScript/TypeScript
            "index.js",
            "index.ts",
            "index.mjs",
            "index.mts",
            "server.js",
            "server.ts",
            "app.js",
            "app.ts",
            "main.js",
            "main.ts",
            # Go
            "main.go",
            # Rust
            "main.rs",
            "lib.rs",
        ]

        for entry in entry_files:
            if self._file_exists(entry):
                entrypoints.append(entry)

        # Check for routes/handlers directories
        route_dirs = ["routes", "api", "handlers", "controllers", "endpoints", "pages", "app"]
        has_routes = any(self._directory_exists(d) for d in route_dirs)

        # Check for src directory with entrypoints (common pattern)
        src_entries = [
            "src/index.ts",
            "src/index.js",
            "src/main.ts",
            "src/main.js",
            "src/app.ts",
            "src/app.js",
        ]
        for entry in src_entries:
            if self._file_exists(entry):
                entrypoints.append(entry)

        # Check for monorepo packages with their own entrypoints
        has_packages = self._directory_exists("packages") or self._directory_exists("apps")

        # Check package.json for main/exports fields
        has_pkg_entrypoint = False
        pkg_path = self.repo_path / "package.json"
        if pkg_path.exists():
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg = __import__("json").load(f)
                    if pkg.get("main") or pkg.get("exports") or pkg.get("module"):
                        has_pkg_entrypoint = True
            except:
                pass

        return {
            "detected": len(entrypoints) > 0 or has_routes or has_packages or has_pkg_entrypoint,
            "files": entrypoints,
            "has_route_structure": has_routes,
            "has_monorepo_structure": has_packages,
            "has_package_entrypoint": has_pkg_entrypoint,
            "strength": min(
                1.0,
                (len(entrypoints) * 0.2)
                + (0.3 if has_routes else 0)
                + (0.3 if has_packages else 0)
                + (0.2 if has_pkg_entrypoint else 0),
            ),
        }

    def _detect_config_files(self) -> Dict[str, any]:
        """Detect configuration files"""
        config_files = []

        patterns = [
            # Python
            "config.py",
            "settings.py",
            "pytest.ini",
            "setup.cfg",
            "tox.ini",
            "pyproject.toml",
            # JavaScript/TypeScript
            "tsconfig.json",
            "jsconfig.json",
            "vite.config.ts",
            "vite.config.js",
            "vitest.config.ts",
            "vitest.config.js",
            "jest.config.js",
            "jest.config.ts",
            "webpack.config.js",
            "rollup.config.js",
            "esbuild.config.js",
            "turbo.json",
            "biome.json",
            ".eslintrc",
            ".eslintrc.js",
            ".eslintrc.json",
            ".prettierrc",
            ".prettierrc.js",
            ".prettierrc.json",
            "next.config.js",
            "next.config.mjs",
            "nuxt.config.ts",
            "svelte.config.js",
            # General
            "config.json",
            "config.yaml",
            "config.yml",
            ".env.example",
            ".env.template",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Dockerfile",
            "Makefile",
        ]

        for pattern in patterns:
            if self._file_exists(pattern):
                config_files.append(pattern)

        return {
            "detected": len(config_files) > 0,
            "files": config_files,
            "strength": min(1.0, len(config_files) * 0.15),
        }

    def _detect_security_controls(self) -> Dict[str, any]:
        """Detect security-related files and configurations"""
        controls = []

        # Security policy
        if self._file_exists("SECURITY.md") or self._file_exists(".github/SECURITY.md"):
            controls.append("security_policy")

        # CI/CD pipelines
        if (
            self._directory_exists(".github/workflows")
            or self._directory_exists(".gitlab-ci.yml")
            or self._file_exists(".travis.yml")
            or self._file_exists("Jenkinsfile")
            or self._file_exists(".circleci/config.yml")
        ):
            controls.append("ci_cd_pipeline")

        # Code ownership
        if (
            self._file_exists("CODEOWNERS")
            or self._file_exists(".github/CODEOWNERS")
            or self._file_exists("docs/CODEOWNERS")
        ):
            controls.append("code_ownership")

        # Pre-commit hooks
        if self._file_exists(".pre-commit-config.yaml") or self._file_exists(".husky"):
            controls.append("pre_commit_hooks")

        # Contributing guidelines
        if self._file_exists("CONTRIBUTING.md") or self._file_exists(".github/CONTRIBUTING.md"):
            controls.append("contributing_guidelines")

        # Code of conduct
        if self._file_exists("CODE_OF_CONDUCT.md") or self._file_exists(
            ".github/CODE_OF_CONDUCT.md"
        ):
            controls.append("code_of_conduct")

        # Check for security scanning configs
        security_configs = [
            ".semgrep.yml",
            ".semgrep.yaml",
            "semgrep.yml",
            ".bandit",
            "bandit.yaml",
            ".snyk",
            "sonar-project.properties",
            ".gitleaks.toml",
            "trivy.yaml",
            ".trivyignore",
            "codecov.yml",
            ".codecov.yml",
        ]

        for config in security_configs:
            if self._file_exists(config):
                controls.append(f"scanner_config_{config}")

        return {
            "detected": len(controls) > 0,
            "controls": controls,
            "strength": min(1.0, len(controls) * 0.2),
        }

    def _detect_test_files(self) -> Dict[str, any]:
        """Detect test files and frameworks"""
        test_indicators = []

        # Test directories
        test_dirs = ["tests", "test", "__tests__", "spec"]
        for dir_name in test_dirs:
            if self._directory_exists(dir_name):
                test_indicators.append(f"test_dir_{dir_name}")

        # Test files pattern
        if self._has_test_files():
            test_indicators.append("test_files")

        return {
            "detected": len(test_indicators) > 0,
            "indicators": test_indicators,
            "strength": min(1.0, len(test_indicators) * 0.3),
        }

    def _detect_languages(self) -> List[str]:
        """Detect programming languages in repo"""
        languages = set()

        extensions = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".go": "Go",
            ".rs": "Rust",
            ".java": "Java",
            ".rb": "Ruby",
            ".php": "PHP",
        }

        for file_path in self.repo_path.rglob("*"):
            if file_path.is_file():
                ext = file_path.suffix
                if ext in extensions:
                    languages.add(extensions[ext])

        return list(languages)

    def _count_files(self) -> int:
        """Count source code files"""
        count = 0
        for file_path in self.repo_path.rglob("*"):
            if file_path.is_file() and not any(part.startswith(".") for part in file_path.parts):
                count += 1
        return count

    def _has_file_context(self, file_path: str) -> bool:
        """Check if we have specific context about a file"""
        if not file_path:
            return False

        full_path = self.repo_path / file_path
        return full_path.exists()

    def _file_exists(self, filename: str) -> bool:
        """Check if file exists in repo"""
        return (self.repo_path / filename).exists()

    def _directory_exists(self, dirname: str) -> bool:
        """Check if directory exists in repo"""
        return (self.repo_path / dirname).is_dir()

    def _file_contains_pattern(self, filenames: List[str], pattern: str) -> bool:
        """Check if any file contains a pattern"""
        for filename in filenames:
            file_path = self.repo_path / filename
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        if pattern.lower() in f.read().lower():
                            return True
                except:
                    pass
        return False

    def _has_import_statements(self) -> bool:
        """Check if code has import statements"""
        # Check Python files
        for py_file in self.repo_path.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read(1000)  # Just check first 1000 chars
                    if "import " in content:
                        return True
            except:
                pass
        # Check JS/TS files
        for ext in ["*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.mts"]:
            for js_file in self.repo_path.rglob(ext):
                try:
                    with open(js_file, "r", encoding="utf-8") as f:
                        content = f.read(1000)
                        if "import " in content or "require(" in content:
                            return True
                except:
                    pass
        return False

    def _has_function_definitions(self) -> bool:
        """Check if code has function definitions"""
        # Check Python files
        for py_file in self.repo_path.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read(2000)
                    if "def " in content:
                        return True
            except:
                pass
        # Check JS/TS files
        for ext in ["*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.mts"]:
            for js_file in self.repo_path.rglob(ext):
                try:
                    with open(js_file, "r", encoding="utf-8") as f:
                        content = f.read(2000)
                        if "function " in content or "=> " in content or "async " in content:
                            return True
                except:
                    pass
        return False

    def _has_class_definitions(self) -> bool:
        """Check if code has class definitions"""
        # Check Python files
        for py_file in self.repo_path.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read(2000)
                    if "class " in content:
                        return True
            except:
                pass
        # Check JS/TS files
        for ext in ["*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.mts"]:
            for js_file in self.repo_path.rglob(ext):
                try:
                    with open(js_file, "r", encoding="utf-8") as f:
                        content = f.read(2000)
                        if "class " in content or "interface " in content or "type " in content:
                            return True
                except:
                    pass
        return False

    def _has_test_files(self) -> bool:
        """Check for test files"""
        test_patterns = [
            # Python
            "test_*.py",
            "*_test.py",
            # JavaScript
            "*.test.js",
            "*.spec.js",
            "*.test.mjs",
            "*.spec.mjs",
            # TypeScript
            "*.test.ts",
            "*.spec.ts",
            "*.test.tsx",
            "*.spec.tsx",
            "*.test.mts",
            "*.spec.mts",
        ]

        for pattern in test_patterns:
            if list(self.repo_path.rglob(pattern)):
                return True
        return False
