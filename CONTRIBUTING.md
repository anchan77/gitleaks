# Contributing to Gitleaks (Python)

Thank you for considering contributing to Gitleaks! This document provides guidelines for contributing to the Python implementation of Gitleaks.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Requests](#pull-requests)
- [Adding New Rules](#adding-new-rules)
- [Issue Guidelines](#issue-guidelines)

## Getting Started

### Prerequisites

- Python 3.10 or newer
- Poetry (recommended) or pip
- Git
- Basic knowledge of regular expressions
- Familiarity with secret detection concepts

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/yourusername/gitleaks.git
cd gitleaks
```

## Development Environment

### Install Poetry

Poetry is the recommended way to manage dependencies for development:

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Verify installation
poetry --version
```

### Install Dependencies

```bash
# Install all dependencies including dev dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### Alternative: Using pip

If you prefer pip over Poetry:

```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

## Code Style

We follow strict code style guidelines to maintain consistency across the codebase.

### Style Guidelines

- **PEP 8**: Follow PEP 8 style guide for Python code
- **Line length**: Maximum 100 characters
- **Type hints**: All functions must have type annotations
- **Docstrings**: Use Google-style docstrings for public APIs
- **Imports**: Use absolute imports, organize with isort

### Formatting Tools

We use the following tools (automatically configured in `pyproject.toml`):

#### Black

Black is our code formatter:

```bash
# Format all code
poetry run black src tests

# Check formatting without making changes
poetry run black --check src tests
```

#### Ruff

Ruff is our linter:

```bash
# Lint all code
poetry run ruff check src tests

# Auto-fix issues where possible
poetry run ruff check --fix src tests
```

#### MyPy

MyPy is our static type checker:

```bash
# Type check all code
poetry run mypy src

# Type check with verbose output
poetry run mypy --show-error-codes src
```

### Pre-commit Hooks

We recommend setting up pre-commit hooks:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## Testing

We maintain high test coverage (target: 80%+) and use pytest for testing.

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage report
poetry run pytest --cov=gitleaks --cov-report=term-missing

# Run specific test file
poetry run pytest tests/test_detector.py

# Run specific test function
poetry run pytest tests/test_detector.py::test_detect_secret

# Run with verbose output
poetry run pytest -v

# Run with debug output
poetry run pytest -s

# Run failed tests only
poetry run pytest --lf
```

### Writing Tests

- **Location**: Tests should mirror the `src/` structure in `tests/`
- **Naming**: Test files should be named `test_*.py`
- **Coverage**: Aim for high coverage of new code
- **Fixtures**: Use pytest fixtures for common setup
- **Async tests**: Use `pytest-asyncio` for async code

Example test structure:

```python
"""Tests for the detection engine."""
import pytest
from gitleaks.detector.engine import Detector

@pytest.fixture
def detector():
    """Create a detector instance for testing."""
    return Detector()

def test_detect_aws_key(detector):
    """Test detection of AWS access keys."""
    content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
    findings = detector.detect(content)
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-token"

@pytest.mark.asyncio
async def test_async_scan(detector):
    """Test async scanning functionality."""
    result = await detector.scan_async("/path/to/dir")
    assert result is not None
```

### Test Coverage

Check coverage report:

```bash
# Generate HTML coverage report
poetry run pytest --cov=gitleaks --cov-report=html

# Open in browser (on macOS)
open htmlcov/index.html

# On Linux
xdg-open htmlcov/index.html
```

## Pull Requests

### Before Submitting

1. **Search existing issues**: Check if your issue/feature is already reported
2. **Create an issue**: Open an issue before starting significant work
3. **Branch naming**: Use descriptive branch names:
   - `feature/add-new-rule`
   - `fix/entropy-calculation`
   - `docs/update-readme`

### PR Guidelines

1. **Link to issue**: Reference the issue number in your PR description
2. **Descriptive title**: Use a clear, descriptive title
3. **Description**: Explain what changes you made and why
4. **Tests**: Include tests for new functionality
5. **Documentation**: Update documentation as needed
6. **Changelog**: Add a note to the changelog if applicable

### PR Template

```markdown
## Description
Brief description of changes

## Related Issue
Fixes #123

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] New tests added
- [ ] Code coverage maintained/improved

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
```

### Code Review Process

1. Automated checks must pass (tests, linting, type checking)
2. At least one maintainer must approve
3. All review comments must be addressed
4. Commits should be clean and well-organized

## Adding New Rules

To add a new detection rule to the default configuration:

### 1. Create a Rule Definition

Add your rule to `src/gitleaks/config/gitleaks.toml`:

```toml
[[rules]]
id = "my-new-secret"
description = "My new secret detection rule"
regex = '''(?i)(my[_-]?secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{32,})['"]?'''
keywords = ["my", "secret", "key"]
tags = ["key", "custom"]
secretGroup = 2
entropy = 3.0
```

### 2. Test the Rule

Create test cases in `tests/test_rules.py`:

```python
def test_my_new_secret():
    """Test detection of my new secret."""
    # True positive - should detect
    content = 'my_secret_key = "abc123def456ghi789jkl012mno345pqr"'
    findings = detector.detect(content)
    assert len(findings) == 1
    assert findings[0].rule_id == "my-new-secret"

    # False positive - should NOT detect
    content = 'my_secret_key = "placeholder"'
    findings = detector.detect(content)
    assert len(findings) == 0
```

### 3. Add Test Data

Add sample files to `testdata/` if needed:

```bash
testdata/
├── secrets/
│   └── my-new-secret.txt
└── expected/
    └── my-new-secret.json
```

### 4. Rule Guidelines

- **Unique ID**: Use kebab-case (e.g., `my-service-api-key`)
- **Description**: Clear, concise description
- **Keywords**: Add relevant keywords for pre-filtering
- **Regex**: Use named groups when possible
- **Entropy**: Set appropriate entropy threshold (typically 3.0-4.0)
- **False Positives**: Test thoroughly to minimize false positives
- **Tags**: Add relevant tags for categorization

### 5. Rule Quality Checklist

- [ ] Regex is efficient and not overly broad
- [ ] Keywords match the regex identifiers
- [ ] Entropy threshold is appropriate
- [ ] True positives are detected
- [ ] Common false positives are filtered
- [ ] Rule is documented with examples
- [ ] Tests cover edge cases

## Issue Guidelines

### Before Opening an Issue

1. **Search**: Check if the issue already exists
2. **Reproduce**: Ensure you can reproduce the problem
3. **Version**: Note the version you're using

### Issue Types

#### Bug Report

```markdown
**Description**
Clear description of the bug

**Steps to Reproduce**
1. Run command: `gitleaks dir ...`
2. See error: ...

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- Gitleaks version: 0.1.0
- Python version: 3.10.5
- OS: macOS 13.0

**Additional Context**
Any other relevant information
```

#### Feature Request

```markdown
**Description**
Clear description of the feature

**Use Case**
Why is this feature needed?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
Other approaches you've considered

**Additional Context**
Examples, screenshots, etc.
```

### Issue Labels

We use labels to categorize issues:

- `bug`: Something isn't working
- `feature`: New feature request
- `enhancement`: Improvement to existing feature
- `documentation`: Documentation improvement
- `good-first-issue`: Good for newcomers
- `help-wanted`: Extra attention needed

## Project Structure

Understanding the project structure helps with contributing:

```
gitleaks/
├── src/
│   └── gitleaks/
│       ├── __init__.py           # Package initialization
│       ├── __main__.py           # CLI entry point
│       ├── cli/                  # CLI commands
│       │   ├── __init__.py
│       │   ├── common.py         # Shared CLI utilities
│       │   ├── dir.py            # Directory scan command
│       │   ├── version.py        # Version command
│       │   └── diagnostics.py    # Diagnostics command
│       ├── config/               # Configuration management
│       │   ├── __init__.py
│       │   ├── models.py         # Pydantic models
│       │   ├── loader.py         # Config loading logic
│       │   └── gitleaks.toml     # Default rules
│       ├── detector/             # Detection engine
│       │   ├── __init__.py
│       │   ├── engine.py         # Core detection logic
│       │   ├── decode.py         # Encoding detection
│       │   └── utils.py          # Helper functions
│       ├── reporting/            # Report formatters
│       │   ├── __init__.py
│       │   ├── finding.py        # Finding data model
│       │   ├── json_reporter.py  # JSON output
│       │   ├── csv_reporter.py   # CSV output
│       │   ├── sarif_reporter.py # SARIF output
│       │   ├── junit_reporter.py # JUnit XML output
│       │   └── template_reporter.py # Template output
│       └── sources/              # Source providers
│           ├── __init__.py
│           ├── common.py         # Shared utilities
│           ├── fragment.py       # Content fragment model
│           ├── dir_source.py     # Directory scanning
│           └── archive_source.py # Archive handling
├── tests/                        # Test suite
│   ├── __init__.py
│   ├── conftest.py              # Pytest configuration
│   ├── test_detector.py
│   ├── test_config.py
│   └── ...
├── testdata/                     # Test fixtures
│   ├── secrets/
│   ├── expected/
│   └── archives/
├── pyproject.toml               # Project configuration
├── README.md                    # User documentation
├── CONTRIBUTING.md              # This file
└── LICENSE                      # License information
```

## Key Architecture Concepts

### Configuration Layer

- Uses Pydantic for validation
- Supports TOML format via `tomllib`
- Environment variable overrides
- Compatible with Go version configs

### Detection Engine

- Regex-based pattern matching
- Keyword pre-filtering for performance
- Entropy calculation for validation
- Support for encoded content

### Source Providers

- Pluggable architecture
- Support for directories, files, archives
- Future: git repos, stdin

### Reporting

- Multiple output formats
- Template-based custom reports
- Baseline comparison

## Getting Help

- **Documentation**: Check the [README](README.md)
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact maintainers for security issues

## Recognition

Contributors are recognized in:
- Git commit history
- Release notes
- Contributors list (coming soon)

## Code of Conduct

Be respectful and professional in all interactions. We follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Thank You!

Thank you for contributing to Gitleaks! Your efforts help make secret detection better for everyone.
