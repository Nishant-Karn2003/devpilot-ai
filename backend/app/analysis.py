import ast
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
SECRET_PATTERNS = (
    ("secret.aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "secret.generic-token",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ),
)


@dataclass(frozen=True)
class FindingData:
    file_path: str | None
    line: int | None
    column: int | None
    end_line: int | None
    end_column: int | None
    rule_id: str
    analyzer: str
    severity: str
    category: str
    title: str
    description: str
    evidence: str | None
    remediation: str | None
    origin: str = "deterministic"

    @property
    def fingerprint(self) -> str:
        canonical = f"{self.file_path}|{self.line}|{self.rule_id}|{self.title}"
        return hashlib.sha256(canonical.encode()).hexdigest()


def finding(**values) -> FindingData:
    return FindingData(**values)


def analyze_source(code: str, language: str, file_path: str) -> tuple[list[FindingData], dict]:
    findings: list[FindingData] = []
    lines = code.splitlines()
    syntax_error = None
    analyzers = ["python-ast", "secret-patterns"]

    if language == "python":
        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError as exc:
            syntax_error = {"line": exc.lineno, "column": exc.offset, "message": exc.msg}
            findings.append(
                finding(
                    file_path=file_path,
                    line=exc.lineno,
                    column=exc.offset,
                    end_line=None,
                    end_column=None,
                    rule_id="python.syntax-error",
                    analyzer="python-ast",
                    severity="high",
                    category="correctness",
                    title="Python syntax error",
                    description=exc.msg,
                    evidence=_line(lines, exc.lineno),
                    remediation="Correct the syntax at the reported location.",
                )
            )
        else:
            imported: dict[str, ast.AST] = {}
            used: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported[alias.asname or alias.name.split(".")[0]] = node
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name != "*":
                            imported[alias.asname or alias.name] = node
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    used.add(node.id)
                elif isinstance(node, ast.ExceptHandler) and node.type is None:
                    findings.append(
                        finding(
                            file_path=file_path,
                            line=node.lineno,
                            column=_python_column(lines, node.lineno, node.col_offset),
                            end_line=node.end_lineno,
                            end_column=_python_column(lines, node.end_lineno, node.end_col_offset),
                            rule_id="python.bare-except",
                            analyzer="python-ast",
                            severity="medium",
                            category="maintainability",
                            title="Bare except clause",
                            description="This handler catches every exception, including process-control exceptions.",
                            evidence=_line(lines, node.lineno),
                            remediation="Catch the specific exception types expected by this operation.",
                        )
                    )
            for name, node in imported.items():
                if name not in used:
                    findings.append(
                        finding(
                            file_path=file_path,
                            line=node.lineno,
                            column=_python_column(lines, node.lineno, node.col_offset),
                            end_line=node.end_lineno,
                            end_column=_python_column(lines, node.end_lineno, node.end_col_offset),
                            rule_id="python.unused-import",
                            analyzer="python-ast",
                            severity="low",
                            category="maintainability",
                            title=f"Unused import: {name}",
                            description="This imported name is not referenced in the module.",
                            evidence=_line(lines, node.lineno),
                            remediation="Remove the import if it is not required for module side effects.",
                        )
                    )
    else:
        eslint_findings, eslint_available = _run_eslint(code, language, file_path)
        if eslint_available:
            findings.extend(eslint_findings)
            syntax_error = next(
                (
                    {"line": item.line, "column": item.column, "message": item.description}
                    for item in eslint_findings
                    if item.rule_id == "eslint.syntax-error"
                ),
                None,
            )
            analyzers = ["eslint", "secret-patterns"]
        else:
            syntax_error = _check_js_delimiters(code)
            analyzers = ["source-validator", "secret-patterns"]
        if syntax_error and not eslint_available:
            findings.append(
                finding(
                    file_path=file_path,
                    line=syntax_error["line"],
                    column=syntax_error["column"],
                    end_line=None,
                    end_column=None,
                    rule_id=f"{language}.syntax-delimiter",
                    analyzer="source-validator",
                    severity="high",
                    category="correctness",
                    title="Unbalanced delimiter",
                    description=syntax_error["message"],
                    evidence=_line(lines, syntax_error["line"]),
                    remediation="Review matching brackets and string delimiters.",
                )
            )

    for number, line in enumerate(lines, 1):
        for rule, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    finding(
                        file_path=file_path,
                        line=number,
                        column=match.start() + 1,
                        end_line=number,
                        end_column=match.end() + 1,
                        rule_id=rule,
                        analyzer="secret-patterns",
                        severity="critical",
                        category="security",
                        title="Potential hard-coded secret",
                        description="A value matching a secret pattern was detected. The value is redacted.",
                        evidence=_redact_line(line)[:240],
                        remediation=(
                            "Revoke the credential, remove it from source control, and load it from a secret manager."
                        ),
                    )
                )
                break

    unique = {item.fingerprint: item for item in findings}
    ordered = sorted(unique.values(), key=lambda item: (item.line or 0, item.rule_id))
    return ordered, {
        "syntax_valid": syntax_error is None,
        "finding_count": len(ordered),
        "analyzers": analyzers,
    }


def _run_eslint(code: str, language: str, file_path: str) -> tuple[list[FindingData], bool]:
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    cli = frontend / "node_modules" / "eslint" / "bin" / "eslint.js"
    node = shutil.which("node")
    if not cli.is_file() or node is None:
        return [], False
    suffix = ".ts" if language == "typescript" else ".js"
    safe_name = Path(file_path).name
    if Path(safe_name).suffix.lower() not in {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
    }:
        safe_name = f"input{suffix}"
    try:
        result = subprocess.run(
            [node, str(cli), "--stdin", "--stdin-filename", safe_name, "--format", "json"],
            input=code,
            text=True,
            capture_output=True,
            timeout=10,
            cwd=frontend,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], False
    output = result.stdout[:200_000]
    try:
        report = json.loads(output)
        messages = report[0]["messages"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        return [], False
    findings = []
    for message in messages[:200]:
        line = message.get("line")
        column = message.get("column")
        rule_id = message.get("ruleId") or "syntax-error"
        severity = "high" if rule_id == "syntax-error" else ("medium" if message.get("severity") == 2 else "low")
        evidence = _line(code.splitlines(), line)
        findings.append(
            finding(
                file_path=file_path,
                line=line,
                column=column,
                end_line=message.get("endLine"),
                end_column=message.get("endColumn"),
                rule_id=f"eslint.{rule_id}",
                analyzer="eslint",
                severity=severity,
                category="correctness" if rule_id == "syntax-error" else "maintainability",
                title="JavaScript/TypeScript syntax error"
                if rule_id == "syntax-error"
                else str(message.get("message", "Lint finding"))[:255],
                description=str(message.get("message", "Lint finding"))[:1000],
                evidence=evidence,
                remediation="Review the ESLint diagnostic and update the source.",
            )
        )
    return findings, True


def _line(lines: list[str], number: int | None) -> str | None:
    if not number or not 0 < number <= len(lines):
        return None
    evidence = lines[number - 1].strip()
    return _redact_line(evidence)[:240]


def _redact_line(line: str) -> str:
    for _, pattern in SECRET_PATTERNS:
        line = pattern.sub("[REDACTED]", line)
    return line


def _python_column(lines: list[str], line_number: int | None, byte_offset: int | None) -> int | None:
    if line_number is None or byte_offset is None or not 0 < line_number <= len(lines):
        return None
    prefix = lines[line_number - 1].encode("utf-8")[:byte_offset]
    return len(prefix.decode("utf-8")) + 1


def redact_secrets(source: str) -> str:
    redacted_lines = []
    inside_private_key = False
    for line in source.splitlines(keepends=True):
        if inside_private_key:
            redacted_lines.append("[REDACTED]" + ("\n" if line.endswith("\n") else ""))
            if re.search(r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", line):
                inside_private_key = False
            continue
        if re.search(SECRET_PATTERNS[1][1], line):
            redacted_lines.append("[REDACTED]" + ("\n" if line.endswith("\n") else ""))
            inside_private_key = "-----END " not in line
            continue
        for _, pattern in SECRET_PATTERNS:
            line = pattern.sub("[REDACTED]", line)
        redacted_lines.append(line)
    return "".join(redacted_lines)


def _check_js_delimiters(code: str) -> dict | None:
    stack: list[tuple[str, int, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    quote: str | None = None
    escaped = False
    line = column = 1
    for char in code:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in ("'", '"', "`"):
            quote = char
        elif char in "([{":
            stack.append((char, line, column))
        elif char in ")]}":
            if not stack or stack[-1][0] != pairs[char]:
                return {
                    "line": line,
                    "column": column,
                    "message": "Unexpected or mismatched closing delimiter.",
                }
            stack.pop()
        if char == "\n":
            line, column = line + 1, 1
        else:
            column += 1
    if quote:
        return {"line": line, "column": column, "message": "Unterminated string literal."}
    if stack:
        opening, start_line, start_column = stack[-1]
        return {
            "line": start_line,
            "column": start_column,
            "message": f"Unclosed {opening} delimiter.",
        }
    return None
