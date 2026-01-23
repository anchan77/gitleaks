# Gitleaks (Python)

```
┌─○───┐
│ │╲  │
│ │ ○ │
│ ○ ░ │
└─░───┘
```

[![License](https://img.shields.io/github/license/gitleaks/gitleaks.svg)](./LICENSE)

Gitleaks is a SAST tool for **detecting** secrets like passwords, API keys, and tokens in git repos, files, and more. This is a Python 3 implementation of Gitleaks, maintaining compatibility with the original Go version while providing a Python-native experience.

## Getting Started

Gitleaks can be installed using pip, Poetry, or Docker. It provides command-line tools for scanning directories, git repositories, and stdin for secrets.

### Prerequisites

- Python 3.10 or newer
- Git binary available in `PATH` (for git repository scanning)

### Installing

#### Via pip (recommended for users)

```bash
# Install from PyPI (when published)
pip install gitleaks

# Or install from source
pip install .
```

#### Via Poetry (recommended for development)

```bash
# Install Poetry if you don't have it
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Run gitleaks
poetry run gitleaks --help
```

#### Via Docker

```bash
# Build Docker image
docker build -t gitleaks:latest .

# Run gitleaks
docker run -v ${PWD}:/path gitleaks:latest dir /path
```

### Quick Start

```bash
# Scan current directory
gitleaks dir .

# Scan with verbose output
gitleaks dir -v .

# Scan and save JSON report
gitleaks dir --report-path report.json --report-format json .

# Scan a specific directory
gitleaks dir /path/to/scan
```

## Usage

```
Usage: gitleaks [OPTIONS] COMMAND [ARGS]...

  Gitleaks scans code, past or present, for secrets.

Options:
  --version                       Show the version and exit.
  -c, --config PATH               Config file path
  --exit-code INTEGER             Exit code when leaks have been encountered
  -r, --report-path TEXT          Report file (use "-" for stdout)
  -f, --report-format [json|csv|junit|sarif|template]
                                  Output format
  --report-template TEXT          Template file for custom reports
  -b, --baseline-path PATH        Path to baseline with issues that can be ignored
  -l, --log-level [trace|debug|info|warn|error|fatal]
                                  Log level
  -v, --verbose                   Show verbose output from scan
  --no-color                      Turn off color for verbose output
  --max-target-megabytes INTEGER  Files larger than this will be skipped
  --ignore-gitleaks-allow         Ignore gitleaks:allow comments
  --redact INTEGER                Redact secrets from logs and stdout (0-100%)
  --no-banner                     Suppress banner
  --enable-rule TEXT              Only enable specific rules by id
  -i, --gitleaks-ignore-path TEXT Path to .gitleaksignore file
  --max-decode-depth INTEGER      Allow recursive decoding up to this depth
  --max-archive-depth INTEGER     Allow scanning into nested archives
  --timeout INTEGER               Set a timeout in seconds
  --help                          Show this message and exit.

Commands:
  diagnostics  Display diagnostic information.
  dir          Scan directories or files for secrets.
  version      Display gitleaks version.
```

### Commands

There is currently one primary scanning mode: `dir` (directory scanning). Git repository scanning and stdin scanning will be added in future releases.

#### Dir

The `dir` command (aliases: `files`, `directory`) lets you scan directories and files.

**Examples:**

```bash
# Scan current directory
gitleaks dir .

# Scan specific directory with verbose output
gitleaks dir -v /path/to/directory

# Scan and generate JSON report
gitleaks dir --report-path findings.json --report-format json /path/to/scan

# Scan with custom config
gitleaks dir -c custom-config.toml /path/to/scan

# Scan only specific files
gitleaks dir /path/to/file1.py /path/to/file2.js
```

### Creating a Baseline

When scanning large repositories, you can use a baseline to ignore existing findings:

```bash
# Create baseline report
gitleaks dir --report-path baseline.json --report-format json .

# Scan with baseline (only new findings will be reported)
gitleaks dir --baseline-path baseline.json --report-path new-findings.json .
```

## Configuration

Gitleaks uses TOML configuration files to define detection rules and allowlists. The configuration format is compatible with the Go version of Gitleaks.

### Loading Configuration

The order of precedence for configuration loading:

1. `--config/-c` option:
   ```bash
   gitleaks dir --config /path/to/config.toml .
   ```

2. Environment variable `GITLEAKS_CONFIG` with file path:
   ```bash
   export GITLEAKS_CONFIG="/path/to/config.toml"
   gitleaks dir .
   ```

3. Environment variable `GITLEAKS_CONFIG_TOML` with file content:
   ```bash
   export GITLEAKS_CONFIG_TOML="$(cat config.toml)"
   gitleaks dir .
   ```

4. `.gitleaks.toml` file in the target path or current directory

If none of the above are used, gitleaks will use the default configuration with built-in rules.

### Configuration Format

Here's an example configuration file:

```toml
# Title for the configuration
title = "My Gitleaks Configuration"

# Extend the default configuration
[extend]
useDefault = true
disabledRules = ["generic-api-key"]

# Define custom rules
[[rules]]
id = "custom-secret"
description = "Custom secret pattern"
regex = '''(?i)custom[_-]?(secret|token|key)[_-]?[:=]\s*['"]?([a-zA-Z0-9_-]{32,})['"]?'''
keywords = ["custom", "secret"]
tags = ["custom", "secret"]

# Define allowlists
[[allowlists]]
description = "Ignore test files"
paths = [
  '''test/.*''',
  '''.*_test\.py$'''
]

[[allowlists]]
description = "Ignore specific patterns"
stopwords = ["example", "placeholder"]
```

### Configuration Features

#### Rules

Rules define patterns to detect secrets:

- **id**: Unique identifier for the rule
- **description**: Human-readable description
- **regex**: Regular expression pattern to match secrets
- **keywords**: Keywords for pre-filtering (improves performance)
- **tags**: Tags for categorization
- **secretGroup**: Regex capture group containing the secret (default: 0)
- **entropy**: Minimum Shannon entropy threshold
- **path**: Regex to match file paths

#### Allowlists

Allowlists suppress false positives:

- **description**: Human-readable description
- **paths**: Regex patterns to match file paths
- **commits**: Git commit hashes to ignore
- **regexes**: Patterns to match against findings
- **regexTarget**: Target for regex matching (match, secret, line)
- **stopwords**: Words that, if present in secret, will suppress the finding
- **condition**: "AND" or "OR" for combining criteria

#### gitleaks:allow Comments

You can suppress specific findings by adding `gitleaks:allow` comments:

```python
# This will not be flagged
api_key = "secret_key_12345"  # gitleaks:allow
```

#### .gitleaksignore

Create a `.gitleaksignore` file to ignore specific findings by their fingerprint:

```
# .gitleaksignore
abc123def456:path/to/file.py:rule-id:42
```

Each line should contain a fingerprint from a gitleaks report.

## Reporting Formats

Gitleaks supports multiple output formats:

### JSON (default)

```bash
gitleaks dir --report-path report.json --report-format json .
```

Example output:

```json
[
  {
    "Description": "AWS Access Key",
    "StartLine": 23,
    "EndLine": 23,
    "StartColumn": 15,
    "EndColumn": 35,
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config/aws.py",
    "SymlinkFile": "",
    "Commit": "",
    "Entropy": 3.5,
    "Author": "",
    "Email": "",
    "Date": "",
    "Message": "",
    "Tags": ["key", "aws"],
    "RuleID": "aws-access-token",
    "Fingerprint": "config/aws.py:aws-access-token:23"
  }
]
```

### CSV

```bash
gitleaks dir --report-path report.csv --report-format csv .
```

### SARIF

SARIF (Static Analysis Results Interchange Format) is useful for CI/CD integration:

```bash
gitleaks dir --report-path report.sarif --report-format sarif .
```

### JUnit XML

Useful for test result reporting systems:

```bash
gitleaks dir --report-path report.xml --report-format junit .
```

### Custom Templates

Use Jinja2 templates for custom output formats:

```bash
# Using a custom template file
gitleaks dir --report-path report.txt --report-template custom.tmpl .

# Using a built-in template
gitleaks dir --report-path report.txt --report-template basic .
```

Built-in templates:
- `basic`: Simple text format
- `leet`: Leet-speak format
- `myspace`: MySpace-style format
- `w98`: Windows 98 style
- `wxp`: Windows XP style

Create your own template using Jinja2 syntax:

```jinja2
# custom.tmpl
Found {{ findings|length }} secret(s):

{% for finding in findings %}
[{{ finding.RuleID }}] {{ finding.File }}:{{ finding.StartLine }}
  Secret: {{ finding.Secret }}
  Description: {{ finding.Description }}
{% endfor %}
```

## Archive Scanning

Gitleaks can scan inside archive files (zip, tar, gz, bz2, 7z, rar):

```bash
# Enable archive scanning (depth 1)
gitleaks dir --max-archive-depth 1 .

# Scan nested archives (depth 2)
gitleaks dir --max-archive-depth 2 .
```

Findings in archives will show the path with `!` separators:

```
File: data.zip!backup.tar!credentials.txt
```

Supported formats:
- ZIP (`.zip`)
- TAR (`.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`)
- GZIP (`.gz`)
- BZIP2 (`.bz2`)
- XZ/LZMA (`.xz`)
- 7-Zip (`.7z`)
- RAR (`.rar`)
- Zstandard (`.zst`)

## Decoding

Gitleaks can detect encoded secrets (base64, hex, percent-encoding):

```bash
# Enable decoding (depth 1)
gitleaks dir --max-decode-depth 1 .

# Support nested encoding (depth 2)
gitleaks dir --max-decode-depth 2 .
```

Decoded findings will include tags like `decoded:base64` and `decode-depth:1`.

## Exit Codes

- `0` - No leaks found
- `1` - Leaks or errors encountered
- Custom exit code via `--exit-code` flag

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/gitleaks.git
cd gitleaks

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Run tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=gitleaks --cov-report=html

# Run linters
poetry run black src tests
poetry run ruff check src tests
poetry run mypy src
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run specific test file
poetry run pytest tests/test_detector.py

# Run with verbose output
poetry run pytest -v

# Run with coverage report
poetry run pytest --cov=gitleaks --cov-report=term-missing
```

### Project Structure

```
gitleaks/
├── src/
│   └── gitleaks/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli/              # CLI commands
│       ├── config/           # Configuration management
│       ├── detector/         # Detection engine
│       ├── reporting/        # Report formatters
│       └── sources/          # Source providers (dir, git, stdin)
├── tests/                    # Test suite
├── testdata/                 # Test fixtures
├── pyproject.toml           # Project configuration
└── README.md                # This file
```

## Differences from Go Version

This Python implementation maintains compatibility with the Go version while introducing some differences:

### Implemented Features

- Directory scanning with recursive traversal
- Archive scanning (zip, tar, 7z, rar, etc.)
- Base64, hex, and percent-encoding detection
- Multiple report formats (JSON, CSV, SARIF, JUnit, templates)
- Configuration file support (compatible with Go version)
- Allowlists and baselines
- Custom rules and entropy validation
- Symlink support

### Coming Soon

- Git repository scanning
- Stdin scanning
- Additional optimizations and performance improvements

### Configuration Compatibility

The Python version is designed to work with existing `.gitleaks.toml` files from the Go version. Most configurations should work without modification.

## Performance

The Python implementation uses several optimizations:

- Compiled regex patterns cached for reuse
- Keyword pre-filtering to reduce regex evaluations
- Efficient line-by-line processing for large files
- Configurable file size limits
- Archive depth limits to prevent resource exhaustion

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

This Python implementation is based on the original [Gitleaks](https://github.com/gitleaks/gitleaks) project by Zachary Rice and contributors. We maintain compatibility with the original while providing a Python-native implementation.
