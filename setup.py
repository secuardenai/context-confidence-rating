from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="context-confidence-rating",
    version="0.1.2",
    author="Secuarden Team",
    author_email="hello@secuarden.com",
    description="Calculate context-aware confidence scores for security findings",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/secuardenai/context-confidence-rating",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies for lightweight version
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ccr=ccr.cli:main",
        ],
    },
    keywords="security, vulnerability, context, confidence, sast, analysis",
   project_urls={
    "Bug Reports": "https://github.com/SecuardenAI/context-confidence-rating/issues",
    "Source": "https://github.com/SecuardenAI/context-confidence-rating",
    "Documentation": "https://github.com/SecuardenAI/context-confidence-rating#readme",
},
)
