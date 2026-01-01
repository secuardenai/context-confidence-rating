"""
Context Confidence Rating (CCR™) Analyzer
A lightweight library for calculating context-aware security confidence scores.

Copyright (c) 2025 Secuarden by Appsec360
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

        # Node.js frameworks
        if self._file_contains_pattern(["package.json"], '"express"'):
            frameworks.append("Express")
        if self._file_contains_pattern(["package.json"], '"next"'):
            frameworks.append("Next.js")

        # Other indicators
        if self._file_exists("Gemfile"):
            frameworks.append("Ruby/Rails")

        return {
            "detected": len(frameworks) > 0,
            "frameworks": frameworks,
            "strength": min(1.0, len(frameworks) * 0.3),
        }

    def _detect_dependencies(self) -> Dict[str, any]:
        """Detect dependency management files"""
        dep_files = [
            "requirements.txt",
            "Pipfile",
            "pyproject.toml",
            "poetry.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "Gemfile",
            "Gemfile.lock",
            "pom.xml",
            "build.gradle",
            "go.mod",
            "go.sum",
        ]

        found = [f for f in dep_files if self._file_exists(f)]

        return {"detected": len(found) > 0, "files": found, "strength": min(1.0, len(found) * 0.25)}

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

        # Common entrypoint files
        entry_files = [
            "main.py",
            "app.py",
            "server.py",
            "__main__.py",
            "index.js",
            "server.js",
            "app.js",
            "main.go",
            "main.rs",
        ]

        for entry in entry_files:
            if self._file_exists(entry):
                entrypoints.append(entry)

        # Check for routes/handlers
        has_routes = (
            self._directory_exists("routes")
            or self._directory_exists("api")
            or self._directory_exists("handlers")
        )

        return {
            "detected": len(entrypoints) > 0 or has_routes,
            "files": entrypoints,
            "has_route_structure": has_routes,
            "strength": min(1.0, (len(entrypoints) * 0.3) + (0.4 if has_routes else 0)),
        }

    def _detect_config_files(self) -> Dict[str, any]:
        """Detect configuration files"""
        config_files = []

        patterns = [
            "config.py",
            "settings.py",
            "config.json",
            "config.yaml",
            "config.yml",
            ".env.example",
            "docker-compose.yml",
            "Dockerfile",
            "pytest.ini",
            "setup.cfg",
            "tox.ini",
        ]

        for pattern in patterns:
            if self._file_exists(pattern):
                config_files.append(pattern)

        return {
            "detected": len(config_files) > 0,
            "files": config_files,
            "strength": min(1.0, len(config_files) * 0.2),
        }

    def _detect_security_controls(self) -> Dict[str, any]:
        """Detect security-related files and configurations"""
        controls = []

        if self._file_exists("SECURITY.md"):
            controls.append("security_policy")
        if self._file_exists(".github/workflows"):
            controls.append("ci_cd_pipeline")
        if self._file_exists("CODEOWNERS"):
            controls.append("code_ownership")
        if self._file_exists(".pre-commit-config.yaml"):
            controls.append("pre_commit_hooks")

        # Check for security scanning configs
        security_configs = [
            ".semgrep.yml",
            ".bandit",
            "bandit.yaml",
            ".snyk",
            "sonar-project.properties",
        ]

        for config in security_configs:
            if self._file_exists(config):
                controls.append(f"scanner_config_{config}")

        return {
            "detected": len(controls) > 0,
            "controls": controls,
            "strength": min(1.0, len(controls) * 0.25),
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
        for py_file in self.repo_path.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read(1000)  # Just check first 1000 chars
                    if "import " in content:
                        return True
            except:
                pass
        return False

    def _has_function_definitions(self) -> bool:
        """Check if code has function definitions"""
        for py_file in self.repo_path.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read(2000)
                    if "def " in content or "function " in content:
                        return True
            except:
                pass
        return False

    def _has_class_definitions(self) -> bool:
        """Check if code has class definitions"""
        for py_file in self.repo_path.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read(2000)
                    if "class " in content:
                        return True
            except:
                pass
        return False

    def _has_test_files(self) -> bool:
        """Check for test files"""
        test_patterns = ["test_*.py", "*_test.py", "*.test.js", "*.spec.js"]

        for pattern in test_patterns:
            if list(self.repo_path.rglob(pattern)):
                return True
        return False
