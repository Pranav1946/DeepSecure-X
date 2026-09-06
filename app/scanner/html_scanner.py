import re
from typing import Any


class HTMLSecurityScanner:
    """
    Static security scanner for HTML documents and markup.
    Performs static pattern-based vulnerability analysis without executing or rendering source code.
    """

    RULES = [
        {
            "rule_id": "HTML-XSS-001",
            "name": "Dangerous javascript: Pseudo-Protocol URL",
            "severity": "HIGH",
            "pattern": r"(?i)\b(?:href|action|src|data|formaction)\s*=\s*[\"']\s*javascript:",
            "description": (
                "Using the javascript: pseudo-protocol in URLs (e.g. href or action) allows script execution upon user interaction."
            ),
            "recommendation": (
                "Use standard URL schemes (https://) and handle interaction using JavaScript event listeners in external scripts."
            ),
        },
        {
            "rule_id": "HTML-EVENT-001",
            "name": "Inline Event Handler",
            "severity": "MEDIUM",
            "pattern": r"(?i)\b(?:on(?:click|load|error|mouseover|focus|blur|change|submit|keydown|keyup|keypress|mouseenter))\s*=",
            "description": (
                "Inline event handlers mix presentation and logic, complicate Content Security Policy (CSP), and increase XSS risk."
            ),
            "recommendation": (
                "Attach event listeners unobtrusively in external JavaScript files using addEventListener()."
            ),
        },
        {
            "rule_id": "HTML-IFRAME-001",
            "name": "Iframe Missing sandbox Attribute",
            "severity": "MEDIUM",
            "pattern": r"(?i)<iframe\b(?![^>]*\bsandbox\b)[^>]*>",
            "description": (
                "Iframes without a sandbox attribute inherit full origin capabilities and can execute scripts, submit forms, or navigate the top frame."
            ),
            "recommendation": (
                "Add a restrictive sandbox attribute to iframes, e.g. sandbox=\"allow-scripts allow-same-origin\"."
            ),
        },
        {
            "rule_id": "HTML-TABNABBING-001",
            "name": "Reverse Tabnabbing (target='_blank' without noopener)",
            "severity": "LOW",
            "pattern": r"(?i)<a\b[^>]*\btarget\s*=\s*[\"']_blank[\"'](?![^>]*\brel\s*=\s*[\"'][^\"']*(?:noopener|noreferrer)[^\"']*[\"'])[^>]*>",
            "description": (
                "Opening external links with target='_blank' without rel='noopener noreferrer' allows the destination page to manipulate window.opener."
            ),
            "recommendation": (
                "Always add rel=\"noopener noreferrer\" when using target=\"_blank\" for external links."
            ),
        },
        {
            "rule_id": "HTML-MIXED-001",
            "name": "Insecure Mixed Content Resource",
            "severity": "MEDIUM",
            "pattern": r"(?i)<(?:script|link|iframe|embed)\b[^>]*(?:src|href)\s*=\s*[\"']http://",
            "description": (
                "Loading active subresources (scripts, stylesheets, frames) over unencrypted HTTP exposes pages to Man-in-the-Middle tampering."
            ),
            "recommendation": (
                "Load all active web resources exclusively over HTTPS."
            ),
        },
        {
            "rule_id": "HTML-FORM-001",
            "name": "Unencrypted Form Submission Action",
            "severity": "HIGH",
            "pattern": r"(?i)<form\b[^>]*\baction\s*=\s*[\"']http://",
            "description": (
                "Submitting form data over plaintext HTTP transmits potentially sensitive user input across the network unencrypted."
            ),
            "recommendation": (
                "Always specify secure HTTPS endpoints in form action attributes."
            ),
        },
        {
            "rule_id": "HTML-SINK-001",
            "name": "Potential DOM XSS Sink in Script Context",
            "severity": "HIGH",
            "pattern": r"(?i)\b(?:document\.write\s*\(|document\.writeln\s*\(|\.innerHTML\s*=|\.outerHTML\s*=)",
            "description": (
                "DOM manipulation sinks like document.write() and innerHTML can introduce XSS if assigned untrusted data."
            ),
            "recommendation": (
                "Use textContent, createElement(), or sanitize input with DOMPurify before inserting into DOM."
            ),
        },
    ]

    def scan(self, code: str) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            return {
                "status": "error",
                "message": "HTML code cannot be empty.",
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
                # Ignore pure HTML comment lines
                if stripped.startswith("<!--") and stripped.endswith("-->"):
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
            "language": "html",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }
