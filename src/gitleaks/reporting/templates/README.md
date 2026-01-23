# Gitleaks Report Templates

This directory contains Jinja2 templates for generating custom gitleaks reports.

## Built-in Templates

- `basic` (basic.html) - A clean, modern HTML report with dark mode support
- `leet` (leet.html) - LEET-speak styled report with matrix green on black theme
- `myspace` (myspace.html) - MySpace-inspired retro social media style
- `w98` (w98.html) - Windows 98 classic interface style
- `wxp` (wxp.html) - Windows XP Luna theme style

## Template Usage

To use a custom template when running gitleaks:

```bash
gitleaks detect --report-path=report.html --report-template=/path/to/template.html
```

To use a built-in template by name:

```bash
# Use the basic template (default)
gitleaks detect --report-path=report.html --report-format=template

# Use the leet template
gitleaks detect --report-path=report.html --report-template=leet

# Use the myspace template
gitleaks detect --report-path=report.html --report-template=myspace

# Use the w98 template
gitleaks detect --report-path=report.html --report-template=w98

# Use the wxp template
gitleaks detect --report-path=report.html --report-template=wxp
```

You can also specify built-in templates with the `.html` extension:

```bash
gitleaks detect --report-path=report.html --report-template=leet.html
```

## Template Variables

Templates receive a `findings` variable containing a list of finding dictionaries with the following fields:

- `rule_id` - The ID of the rule that matched
- `description` - Human-readable description of the rule
- `file` - Path to the file containing the secret
- `symlink_file` - Original symlink path (if applicable)
- `secret` - The extracted secret value (may be redacted)
- `match` - The full matched text
- `start_line` - Starting line number (1-indexed)
- `end_line` - Ending line number (1-indexed)
- `start_column` - Starting column number (1-indexed)
- `end_column` - Ending column number (1-indexed)
- `commit` - Git commit SHA (if from git source)
- `author` - Git commit author name
- `email` - Git commit author email
- `date` - Git commit date
- `message` - Git commit message
- `link` - URL to the finding in remote repository
- `entropy` - Shannon entropy of the secret
- `tags` - List of tags associated with the rule
- `fingerprint` - Unique identifier for deduplication

## Example Template

```jinja2
<!DOCTYPE html>
<html>
<head>
    <title>Gitleaks Report</title>
</head>
<body>
    <h1>Security Scan Results</h1>
    <p>Total findings: {{ findings|length }}</p>

    <table>
        <tr>
            <th>Rule</th>
            <th>File</th>
            <th>Line</th>
            <th>Secret</th>
        </tr>
        {% for finding in findings %}
        <tr>
            <td>{{ finding.rule_id }}</td>
            <td>{{ finding.file }}</td>
            <td>{{ finding.start_line }}</td>
            <td>{{ finding.secret }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
```

## Template Filters and Functions

Templates have access to standard Jinja2 filters and the following custom functions:

- `now()` - Returns the current UTC datetime for generating timestamps

## Converting Go Templates

If you have Go templates from the original gitleaks, here are the key conversions:

- `{{ . }}` → `{{ findings }}` (root context)
- `{{- range . }}...{{- end }}` → `{% for finding in findings %}...{% endfor %}`
- `{{.Field}}` → `{{ finding.field }}` (camelCase → snake_case)
- `{{- if .Field}}...{{- end}}` → `{% if finding.field %}...{% endif %}`
- `{{now | date "format"}}` → `{{ now().strftime('%format') }}`
- `{{len .}}` → `{{ findings|length }}`
