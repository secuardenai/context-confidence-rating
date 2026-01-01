# Contributing to Context Confidence Rating (CCR)

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)

### Suggesting Features

We welcome feature suggestions! Please open an issue describing:
- The use case for the feature
- How it would work
- Why it would be valuable

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install dev dependencies**: `pip install -e ".[dev]"`
3. **Make your changes**
4. **Add tests** for new functionality
5. **Run the test suite**: `pytest tests/`
6. **Format your code**: `black ccr/ tests/`
7. **Check linting**: `flake8 ccr/ tests/`
8. **Submit a pull request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/context-confidence-rating.git
cd context-confidence-rating

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Format code
black ccr/ tests/ examples/

# Check linting
flake8 ccr/ tests/ examples/
```

### Code Style

- We use [Black](https://black.readthedocs.io/) for code formatting
- Follow PEP 8 guidelines
- Add docstrings to all public methods
- Keep functions focused and testable

### Testing Guidelines

- Write tests for all new functionality
- Aim for high test coverage
- Use descriptive test names
- Include both positive and negative test cases

### Commit Messages

Use clear, descriptive commit messages:
- `feat: Add support for Go language detection`
- `fix: Correct CCR calculation for edge case`
- `docs: Update README with new examples`
- `test: Add tests for config file detection`

### Code Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, your PR will be merged

## Community Guidelines

- Be respectful and inclusive
- Help others learn and grow
- Focus on constructive feedback
- Celebrate contributions of all sizes

## Questions?

- Open an issue for technical questions
- Email [hello@secuarden.com](mailto:hello@secuarden.com) for other inquiries
- Check existing issues before opening new ones

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping improve CCR! 🙏
