"""
Context Confidence Rating (CCR™) - Lightweight Security Context Analyzer

A library for calculating context-aware confidence scores for security findings.
Helps prioritize vulnerabilities based on actual exploitability in your codebase.

Copyright (c) 2025 Secuarden by Appsec360
Licensed under MIT License
"""

from .analyzer import ContextAnalyzer, CCRResult, ConfidenceLevel

__version__ = "0.1.2"
__all__ = ["ContextAnalyzer", "CCRResult", "ConfidenceLevel"]
