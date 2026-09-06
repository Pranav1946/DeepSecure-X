import re
from typing import Any


class JavaScriptSecurityScanner:
    """
    Lightweight static security scanner for JavaScript source code.

    This scanner intentionally uses regex-based rules so it does not
    affect the existing Python scanner or require a JavaScript runtime.
    """

    RULES = [
        {
            "rule_id": "JS001",
            "name": "Dangerous eval() usage",
            "severity": "HIGH",
            "pattern": r"\beval\s*\(",
            "description": (
                "eval() executes dynamically constructed JavaScript and "
                "can lead to arbitrary code execution or XSS."
            ),
            "recommendation": (
                "Avoid eval(). Use explicit functions, JSON.parse(), "
                "or safer data-processing logic instead."
            ),
        },
        {
            "rule_id": "JS002",
            "name": "Dynamic Function constructor",
            "severity": "HIGH",
            "pattern": r"\bnew\s+Function\s*\(",
            "description": (
                "The Function constructor creates executable code from "
                "strings and may introduce code injection risks."
            ),
            "recommendation": (
                "Avoid new Function(). Replace dynamically generated "
                "code with normal functions or safe data structures."
            ),
        },
        {
            "rule_id": "JS003",
            "name": "Potential XSS through innerHTML",
            "severity": "HIGH",
            "pattern": r"\.innerHTML\s*=",
            "description": (
                "Assigning untrusted data to innerHTML can allow "
                "cross-site scripting attacks."
            ),
            "recommendation": (
                "Prefer textContent or safely sanitize untrusted HTML "
                "before inserting it into the DOM."
            ),
        },
        {
            "rule_id": "JS004",
            "name": "Potential XSS through document.write()",
            "severity": "MEDIUM",
            "pattern": r"\bdocument\.write\s*\(",
            "description": (
                "document.write() can insert attacker-controlled content "
                "into a web page."
            ),
            "recommendation": (
                "Avoid document.write(). Use safe DOM APIs such as "
                "textContent or createElement()."
            ),
        },
        {
            "rule_id": "JS005",
            "name": "String execution in setTimeout/setInterval",
            "severity": "MEDIUM",
            "pattern": r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]",
            "description": (
                "Passing a string to setTimeout() or setInterval() "
                "causes it to be evaluated as code."
            ),
            "recommendation": (
                "Pass a function callback instead of a string."
            ),
        },
        {
            "rule_id": "JS006",
            "name": "Potential command execution",
            "severity": "CRITICAL",
            "pattern": (
                r"(?:child_process\.(?:exec|execSync|spawn|spawnSync)"
                r"|require\s*\(\s*['\"]child_process['\"]\s*\))"
            ),
            "description": (
                "Node.js child_process APIs can execute operating-system "
                "commands and become dangerous when arguments are influenced "
                "by user input."
            ),
            "recommendation": (
                "Avoid shell execution where possible. If required, use "
                "strict allowlists and never pass unsanitized user input."
            ),
        },
        {
            "rule_id": "JS007",
            "name": "Hardcoded secret or API key",
            "severity": "HIGH",
            "pattern": (
                r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|"
                r"auth[_-]?token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
            ),
            "description": (
                "A possible credential or secret appears to be hardcoded "
                "inside the JavaScript source."
            ),
            "recommendation": (
                "Move secrets to environment variables or a secure "
                "secret-management system."
            ),
        },
        {
            "rule_id": "JS008",
            "name": "Sensitive data stored in localStorage",
            "severity": "MEDIUM",
            "pattern": (
                r"localStorage\.(?:setItem|set)\s*\("
            ),
            "description": (
                "localStorage is accessible to JavaScript running on the "
                "same origin and should not be used for highly sensitive data."
            ),
            "recommendation": (
                "Avoid storing passwords, long-lived tokens, or sensitive "
                "credentials in localStorage."
            ),
        },
        {
            "rule_id": "JS009",
            "name": "Insecure HTTP URL",
            "severity": "LOW",
            "pattern": r"https?://",
            "description": (
                "An HTTP URL may transmit data without transport encryption."
            ),
            "recommendation": (
                "Use HTTPS for network communication whenever possible."
            ),
        },
    ]

    def scan(self, code: str) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            return {
                "status": "error",
                "message": "JavaScript code cannot be empty.",
                "vulnerabilities_found": 0,
                "findings": [],
            }

        findings = []

        lines = code.splitlines()

        for rule in self.RULES:
            try:
                regex = re.compile(rule["pattern"])
            except re.error:
                continue

            for line_number, line in enumerate(lines, start=1):
                if regex.search(line):
                    findings.append({
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "recommendation": rule["recommendation"],
                        "line": line_number,
                        "evidence": line.strip(),
                        "code": line.strip(),
                    })


        return {
            "status": "completed",
            "language": "javascript",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }