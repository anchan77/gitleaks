# Gitleaks Examples

This directory contains example configurations and templates for Gitleaks.

## Files

### Configuration Examples

- **custom-config.toml**: Example custom configuration showing:
  - How to extend the default configuration
  - How to define custom rules
  - How to create allowlists
  - How to use keywords and entropy thresholds

### Template Examples

- **custom-template.tmpl**: Example Jinja2 template showing:
  - How to create custom report formats
  - How to iterate over findings
  - How to format output with Jinja2 filters
  - How to add custom sections to reports

## Usage Examples

### Using a Custom Configuration

```bash
# Scan with custom config
gitleaks dir --config examples/custom-config.toml /path/to/scan

# Scan and generate report
gitleaks dir \
  --config examples/custom-config.toml \
  --report-path report.json \
  --report-format json \
  /path/to/scan
```

### Using a Custom Template

```bash
# Generate report with custom template
gitleaks dir \
  --report-path report.txt \
  --report-template examples/custom-template.tmpl \
  /path/to/scan

# You can also combine with custom config
gitleaks dir \
  --config examples/custom-config.toml \
  --report-path report.txt \
  --report-template examples/custom-template.tmpl \
  /path/to/scan
```

### Common Scanning Scenarios

#### Scan Current Directory

```bash
# Basic scan
gitleaks dir .

# Verbose output
gitleaks --verbose dir .

# With custom exit code
gitleaks --exit-code 2 dir .
```

#### Scan Specific Paths

```bash
# Scan multiple files
gitleaks dir file1.py file2.js file3.go

# Scan specific directory
gitleaks dir /path/to/source/code
```

#### Generate Different Report Formats

```bash
# JSON report
gitleaks dir --report-path report.json --report-format json .

# CSV report
gitleaks dir --report-path report.csv --report-format csv .

# SARIF report (for CI/CD integration)
gitleaks dir --report-path report.sarif --report-format sarif .

# JUnit XML (for test result systems)
gitleaks dir --report-path report.xml --report-format junit .
```

#### Using Baselines

```bash
# Step 1: Create initial baseline
gitleaks dir --report-path baseline.json .

# Step 2: Later scans only report new findings
gitleaks dir \
  --baseline-path baseline.json \
  --report-path new-findings.json \
  .
```

#### Scanning Archives

```bash
# Enable archive scanning (1 level deep)
gitleaks dir --max-archive-depth 1 .

# Scan nested archives (2 levels deep)
gitleaks dir --max-archive-depth 2 /path/with/archives
```

#### Detecting Encoded Secrets

```bash
# Enable decoding (base64, hex, percent-encoding)
gitleaks dir --max-decode-depth 1 .

# Support multiple encoding layers
gitleaks dir --max-decode-depth 2 .
```

#### Advanced Options

```bash
# Skip large files
gitleaks dir --max-target-megabytes 10 .

# Enable specific rules only
gitleaks dir \
  --enable-rule aws-access-token \
  --enable-rule github-pat \
  .

# Ignore gitleaks:allow comments
gitleaks dir --ignore-gitleaks-allow .

# Redact secrets in output (50%)
gitleaks dir --redact 50 --verbose .

# Set scan timeout
gitleaks dir --timeout 300 .
```

## Creating Your Own Rules

When creating custom rules, follow these guidelines:

### 1. Start with Keywords

Keywords improve performance by pre-filtering content:

```toml
[[rules]]
id = "my-service-token"
keywords = ["myservice", "token"]
```

### 2. Use Capture Groups

Use capture groups to extract the secret:

```toml
[[rules]]
id = "my-secret"
# Group 1 contains the actual secret
regex = '''myservice[_-]token[_-]?[:=]\s*['"]?([a-zA-Z0-9_-]{32,})['"]?'''
secretGroup = 1
```

### 3. Set Appropriate Entropy

Entropy helps filter out false positives:

```toml
[[rules]]
id = "high-entropy-secret"
regex = '''secret[:=]\s*['"]?([a-zA-Z0-9_-]{32,})['"]?'''
secretGroup = 1
# Require minimum entropy of 3.5
entropy = 3.5
```

### 4. Test Thoroughly

Always test your rules:

```bash
# Create test file
cat > test-secret.txt << 'EOF'
myservice_token = "abc123def456ghi789jkl012mno345pqr"
EOF

# Test your config
gitleaks dir --config my-config.toml test-secret.txt
```

## Creating Your Own Templates

Templates use Jinja2 syntax and have access to these variables:

- `findings`: List of finding objects
- Each finding has: `RuleID`, `Description`, `File`, `StartLine`, `EndLine`, `Match`, `Secret`, `Tags`, `Entropy`, `Fingerprint`, etc.

### Simple Template Example

```jinja2
{% for finding in findings %}
{{ finding.File }}:{{ finding.StartLine }} - {{ finding.RuleID }}
{% endfor %}
```

### Conditional Formatting

```jinja2
{% if findings %}
Found {{ findings|length }} secret(s)!
{% else %}
No secrets found.
{% endif %}
```

### Using Filters

```jinja2
{# Length #}
Total: {{ findings|length }}

{# Join #}
Tags: {{ finding.Tags|join(", ") }}

{# Format numbers #}
Entropy: {{ "%.2f"|format(finding.Entropy) }}
```

## Best Practices

1. **Start with defaults**: Extend the default configuration rather than starting from scratch
2. **Use allowlists**: Minimize false positives by allowlisting test files and examples
3. **Test rules**: Always test new rules with both positive and negative examples
4. **Version control**: Keep your configs in version control
5. **Regular updates**: Keep your Gitleaks installation and rules up to date
6. **Pre-commit hooks**: Set up pre-commit hooks to catch secrets before they're committed
7. **CI/CD integration**: Run Gitleaks in your CI/CD pipeline
8. **Baseline management**: Use baselines for large existing codebases

## Troubleshooting

### Rule not matching

If your rule isn't detecting secrets:

1. Check keywords match the content
2. Test the regex separately
3. Verify entropy threshold isn't too high
4. Check allowlists aren't excluding it
5. Enable verbose logging: `--verbose`

### Too many false positives

If you're getting too many false positives:

1. Add stopwords to filter common non-secrets
2. Increase entropy threshold
3. Make regex more specific
4. Add path-based allowlists
5. Use rule-specific allowlists

### Performance issues

If scanning is slow:

1. Add keywords to rules (pre-filtering)
2. Use `--max-target-megabytes` to skip large files
3. Limit archive depth with `--max-archive-depth`
4. Exclude unnecessary directories in allowlists
5. Consider running on smaller batches

## Additional Resources

- [Main README](../README.md) - Full documentation
- [Contributing Guide](../CONTRIBUTING.md) - Development guidelines
- [Default Configuration](../src/gitleaks/config/gitleaks.toml) - Built-in rules
- [Test Data](../testdata/) - Example test cases
