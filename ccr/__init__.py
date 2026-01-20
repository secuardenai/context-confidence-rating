"""
Context Confidence Rating (CCR™) - Lightweight Security Context Analyzer

A library for calculating context-aware confidence scores for security findings.
Helps prioritize vulnerabilities based on actual exploitability in your codebase.

Also provides rich codebase context generation for LLM security analysis.

Copyright (c) 2025 Secuarden 
Licensed under MIT License
"""

from .analyzer import ContextAnalyzer, CCRResult, ConfidenceLevel
from .context_generator import ContextGenerator, RepoContext

__version__ = "0.2.0"
__all__ = ["ContextAnalyzer", "CCRResult", "ConfidenceLevel", "ContextGenerator", "RepoContext"]
