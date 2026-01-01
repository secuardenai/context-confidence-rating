"""
Tests for Context Confidence Rating library
"""

import pytest
import tempfile
import os
from pathlib import Path
from ccr import ContextAnalyzer, CCRResult, ConfidenceLevel


@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)

        # Create some basic structure
        (repo_path / "app.py").write_text("import flask\n\ndef hello():\n    return 'Hello'")
        (repo_path / "requirements.txt").write_text("flask==2.0.0\nrequests==2.26.0")
        (repo_path / "tests").mkdir()
        (repo_path / "tests" / "test_app.py").write_text("def test_hello():\n    assert True")

        yield repo_path


@pytest.fixture
def rich_repo():
    """Create a repository with many context signals"""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)

        # Files
        (repo_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)")
        (repo_path / "requirements.txt").write_text("flask==2.0.0")
        (repo_path / "config.py").write_text("DEBUG = False")
        (repo_path / "SECURITY.md").write_text("# Security Policy")
        (repo_path / "CODEOWNERS").write_text("* @security-team")

        # Directories
        (repo_path / "tests").mkdir()
        (repo_path / "tests" / "test_app.py").write_text("def test():\n    pass")
        (repo_path / "api").mkdir()
        (repo_path / "api" / "routes.py").write_text("# routes")

        # GitHub workflows
        (repo_path / ".github").mkdir()
        (repo_path / ".github" / "workflows").mkdir()
        (repo_path / ".github" / "workflows" / "test.yml").write_text("name: Test")

        yield repo_path


class TestContextAnalyzer:

    def test_initialization(self, temp_repo):
        """Test analyzer initialization"""
        analyzer = ContextAnalyzer(str(temp_repo))
        assert analyzer.repo_path == temp_repo

    def test_invalid_path(self):
        """Test initialization with invalid path"""
        with pytest.raises(ValueError):
            ContextAnalyzer("/nonexistent/path")

    def test_calculate_baseline_ccr(self, temp_repo):
        """Test baseline CCR calculation"""
        analyzer = ContextAnalyzer(str(temp_repo))
        result = analyzer.calculate_repo_baseline_ccr()

        assert isinstance(result, CCRResult)
        assert 0 <= result.score <= 100
        assert result.confidence in ["low", "medium", "high"]

    def test_calculate_ccr_with_finding(self, temp_repo):
        """Test CCR calculation with specific finding"""
        analyzer = ContextAnalyzer(str(temp_repo))

        finding = {"file": "app.py", "vulnerability": "SQL Injection", "severity": "HIGH"}

        result = analyzer.calculate_ccr(finding)

        assert isinstance(result, CCRResult)
        assert 0 <= result.score <= 100
        assert result.confidence in ["low", "medium", "high"]
        assert len(result.reasoning) > 0

    def test_framework_detection(self, temp_repo):
        """Test framework detection"""
        analyzer = ContextAnalyzer(str(temp_repo))
        context = analyzer.analyze_repository_context()

        assert context["has_framework_detection"]["detected"] == True
        assert "Flask" in context["has_framework_detection"]["frameworks"]

    def test_dependency_tracking(self, temp_repo):
        """Test dependency file detection"""
        analyzer = ContextAnalyzer(str(temp_repo))
        context = analyzer.analyze_repository_context()

        assert context["has_dependency_tracking"]["detected"] == True
        assert "requirements.txt" in context["has_dependency_tracking"]["files"]

    def test_test_detection(self, temp_repo):
        """Test test file detection"""
        analyzer = ContextAnalyzer(str(temp_repo))
        context = analyzer.analyze_repository_context()

        assert context["has_test_coverage"]["detected"] == True

    def test_language_detection(self, temp_repo):
        """Test programming language detection"""
        analyzer = ContextAnalyzer(str(temp_repo))
        context = analyzer.analyze_repository_context()

        assert "Python" in context["languages"]

    def test_rich_repo_high_score(self, rich_repo):
        """Test that repository with many signals gets high score"""
        analyzer = ContextAnalyzer(str(rich_repo))
        result = analyzer.calculate_repo_baseline_ccr()

        # Rich repo should have high CCR
        assert result.confidence in ["medium", "high"]
        assert result.score > 30  # Should be well above minimal

    def test_security_controls_detection(self, rich_repo):
        """Test security controls detection"""
        analyzer = ContextAnalyzer(str(rich_repo))
        context = analyzer.analyze_repository_context()

        assert context["has_security_controls"]["detected"] == True
        controls = context["has_security_controls"]["controls"]
        assert "security_policy" in controls
        assert "code_ownership" in controls
        assert "ci_cd_pipeline" in controls

    def test_entrypoint_detection(self, rich_repo):
        """Test application entrypoint detection"""
        analyzer = ContextAnalyzer(str(rich_repo))
        context = analyzer.analyze_repository_context()

        assert context["has_entrypoint_mapping"]["detected"] == True

    def test_config_detection(self, rich_repo):
        """Test configuration file detection"""
        analyzer = ContextAnalyzer(str(rich_repo))
        context = analyzer.analyze_repository_context()

        assert context["has_config_awareness"]["detected"] == True
        assert "config.py" in context["has_config_awareness"]["files"]

    def test_result_to_dict(self, temp_repo):
        """Test CCRResult serialization"""
        analyzer = ContextAnalyzer(str(temp_repo))
        result = analyzer.calculate_repo_baseline_ccr()

        result_dict = result.to_dict()

        assert "score" in result_dict
        assert "confidence" in result_dict
        assert "factors" in result_dict
        assert "reasoning" in result_dict

    def test_confidence_levels(self):
        """Test confidence level mappings"""
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.HIGH.value == "high"

    def test_severity_boost(self, temp_repo):
        """Test that high-severity findings get CCR boost"""
        analyzer = ContextAnalyzer(str(temp_repo))

        finding_high = {"file": "app.py", "vulnerability": "SQL Injection", "severity": "HIGH"}

        finding_low = {"file": "app.py", "vulnerability": "SQL Injection", "severity": "LOW"}

        result_high = analyzer.calculate_ccr(finding_high)
        result_low = analyzer.calculate_ccr(finding_low)

        # High severity should get a boost
        assert result_high.score >= result_low.score

    def test_file_context_boost(self, temp_repo):
        """Test that existing files get context boost"""
        analyzer = ContextAnalyzer(str(temp_repo))

        finding_exists = {
            "file": "app.py",  # exists
            "vulnerability": "SQL Injection",
            "severity": "HIGH",
        }

        finding_missing = {
            "file": "missing.py",  # doesn't exist
            "vulnerability": "SQL Injection",
            "severity": "HIGH",
        }

        result_exists = analyzer.calculate_ccr(finding_exists)
        result_missing = analyzer.calculate_ccr(finding_missing)

        # File that exists should get boost
        assert result_exists.score >= result_missing.score

    def test_caching(self, temp_repo):
        """Test that context is cached"""
        analyzer = ContextAnalyzer(str(temp_repo))

        # First call
        context1 = analyzer.analyze_repository_context()

        # Second call should use cache
        context2 = analyzer.analyze_repository_context()

        assert context1 == context2
        assert analyzer._context_cache is not None


class TestEdgeCases:

    def test_empty_repository(self):
        """Test with empty repository"""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = ContextAnalyzer(tmpdir)
            result = analyzer.calculate_repo_baseline_ccr()

            # Should still work, just low score
            assert result.score >= 0
            assert result.confidence == "low"

    def test_none_finding(self, temp_repo):
        """Test CCR calculation with None finding"""
        analyzer = ContextAnalyzer(str(temp_repo))
        result = analyzer.calculate_ccr(None)

        # Should calculate baseline
        assert isinstance(result, CCRResult)

    def test_minimal_finding(self, temp_repo):
        """Test with minimal finding info"""
        analyzer = ContextAnalyzer(str(temp_repo))

        finding = {"file": "test.py"}  # Minimal info
        result = analyzer.calculate_ccr(finding)

        assert isinstance(result, CCRResult)
        assert result.score >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
