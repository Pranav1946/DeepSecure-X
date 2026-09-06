import re
from typing import Any


class CSSSecurityScanner:
    """
    Static security scanner for Cascading Style Sheets (CSS).
    Performs static pattern-based vulnerability analysis without executing or rendering stylesheets.
    """

    RULES = [
        {
            "rule_id": "CSS-001",
            "name": "Legacy Dynamic CSS Expression",
            "severity": "HIGH",
            "pattern": r"(?i)\bexpression\s*\(",
            "description": (
                "CSS expression() allows arbitrary JavaScript execution in legacy browsers (IE) and is a known XSS vector."
            ),
            "recommendation": (
                "Remove CSS expressions and use standard CSS properties or modern calc() for computed values."
            ),
        },
        {
            "rule_id": "CSS-002",
            "name": "JavaScript URL in CSS Property",
            "severity": "HIGH",
            "pattern": r"(?i)url\s*\(\s*[\"']?\s*javascript:",
            "description": (
                "Referencing the javascript: pseudo-protocol in CSS url() can execute scripts in vulnerable rendering engines."
            ),
            "recommendation": (
                "Use standard resource URLs with https:// or base64 data URIs for embedded images."
            ),
        },
        {
            "rule_id": "CSS-003",
            "name": "Insecure HTTP External Resource",
            "severity": "LOW",
            "pattern": r"(?i)url\s*\(\s*[\"']?http://",
            "description": (
                "Loading fonts, background images, or assets over plaintext HTTP creates mixed-content security warnings."
            ),
            "recommendation": (
                "Use HTTPS for all external asset URLs referenced in CSS."
            ),
        },
        {
            "rule_id": "CSS-004",
            "name": "Insecure @import Over HTTP",
            "severity": "LOW",
            "pattern": r"(?i)@import\s+(?:url\s*\(\s*[\"']?http://|[\"']http://)",
            "description": (
                "Importing stylesheets over unencrypted HTTP allows network attackers to tamper with presentation and styles."
            ),
            "recommendation": (
                "Always use HTTPS for @import directives: @import url(\"https://...\");"
            ),
        },
        {
            "rule_id": "CSS-005",
            "name": "Potential CSS Data Exfiltration Pattern",
            "severity": "MEDIUM",
            "pattern": r"(?i)input\s*\[\s*(?:value|name|type)\s*[\^\$\*~]?=\s*[\"'][^\"']+[\"']\s*\]\s*\{[^}]*url\s*\(",
            "description": (
                "Combining input attribute selectors with external background URLs is a known technique for extracting sensitive form values."
            ),
            "recommendation": (
                "Avoid loading external background images based on input value states and enforce strict Content Security Policy (img-src)."
            ),
        },
    ]

    def scan(self, code: str) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            return {
                "status": "error",
                "message": "CSS code cannot be empty.",
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
                stripped = line.strip()
                # Ignore pure CSS comment lines
                if stripped.startswith("/*") and stripped.endswith("*/"):
                    continue

                if regex.search(line):
                    findings.append({
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "recommendation": rule["recommendation"],
                        "line": line_number,
                        "evidence": line.strip(),
                    })

        return {
            "status": "completed",
            "language": "css",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }
