import pytest

from app.analysis import analyze_source, redact_secrets
from app.quality import evaluate_quality_gate


def test_python_ast_reports_unused_import_and_bare_except_with_locations():
    findings, summary = analyze_source("import os\ntry:\n    work()\nexcept:\n    pass\n", "python", "a.py")
    assert summary["syntax_valid"] is True
    assert [(item.rule_id, item.line) for item in findings] == [
        ("python.unused-import", 1),
        ("python.bare-except", 4),
    ]


def test_invalid_python_reports_syntax_location():
    findings, summary = analyze_source("def broken(:\n", "python", "bad.py")
    assert summary["syntax_valid"] is False
    assert findings[0].rule_id == "python.syntax-error"
    assert findings[0].line == 1


def test_detected_secret_is_redacted_and_deduplicated():
    findings, _ = analyze_source('token = "very-long-private-token"\n', "python", "secret.py")
    secret = next(item for item in findings if item.category == "security")
    assert secret.severity == "critical"
    assert "very-long-private-token" not in (secret.evidence or "")
    assert len({item.fingerprint for item in findings}) == len(findings)


def test_javascript_unbalanced_delimiter_and_quality_gate():
    findings, summary = analyze_source("function go() { return (1; }\n", "javascript", "a.js")
    assert summary["syntax_valid"] is False
    result = evaluate_quality_gate(findings, summary)
    assert result["passed"] is False
    assert "Syntax validation failed" in result["reasons"]


def test_javascript_uses_installed_eslint_and_reports_real_rule_locations():
    findings, summary = analyze_source("const unusedValue = 1;\n", "javascript", "sample.js")
    if "eslint" not in summary["analyzers"]:
        pytest.skip("The optional adjacent frontend ESLint installation is unavailable.")
    assert "eslint" in summary["analyzers"]
    unused = next(item for item in findings if item.rule_id.endswith("no-unused-vars"))
    assert unused.line == 1
    assert unused.column == 7


def test_secret_in_comment_is_not_hidden_from_detector():
    findings, _ = analyze_source("# password='example-secret-value'\n", "python", "a.py")
    assert any(item.category == "security" for item in findings)


def test_private_key_redaction_masks_multiline_material_and_preserves_line_count():
    source = "-----BEGIN PRIVATE KEY-----\nprivate-key-body-data\n-----END PRIVATE KEY-----\nprint('after')\n"
    redacted = redact_secrets(source)
    assert "private-key-body-data" not in redacted
    assert "[REDACTED]" in redacted
    assert len(source.splitlines()) == len(redacted.splitlines())


def test_secret_evidence_redacts_multiple_credentials_on_the_same_line():
    findings, _ = analyze_source(
        'token = "first-secret-value"; password = "second-secret-value"\n',
        "python",
        "secrets.py",
    )
    secret = next(item for item in findings if item.category == "security")
    assert "first-secret-value" not in (secret.evidence or "")
    assert "second-secret-value" not in (secret.evidence or "")


def test_python_ast_columns_are_one_based_unicode_character_positions():
    findings, summary = analyze_source("é = 1; import os\n", "python", "unicode.py")
    assert summary["syntax_valid"] is True
    unused = next(item for item in findings if item.rule_id == "python.unused-import")
    assert unused.column == 8
    assert unused.end_column == 17
