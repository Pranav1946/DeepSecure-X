import re
from typing import Any


class CSecurityScanner:
    """
    Static security scanner for C source code.
    Performs static pattern-based vulnerability analysis without executing source code.
    """

    RULES = [
        {
            "rule_id": "C-001",
            "name": "Dangerous gets() Usage",
            "severity": "CRITICAL",
            "pattern": r"\bgets\s*\(",
            "description": (
                "gets() is inherently vulnerable to buffer overflows as it does not "
                "perform boundary checks. Removed in C11."
            ),
            "recommendation": (
                "Replace gets() with fgets() specifying a maximum buffer limit."
            ),
        },
        {
            "rule_id": "C-002",
            "name": "Unsafe String Copy strcpy()",
            "severity": "HIGH",
            "pattern": r"\bstrcpy\s*\(",
            "description": (
                "strcpy() does not check destination buffer size and can lead to "
                "stack/heap buffer overflows."
            ),
            "recommendation": (
                "Use bounded string copying functions such as strncpy(), strlcpy(), or snprintf()."
            ),
        },
        {
            "rule_id": "C-003",
            "name": "Unsafe String Concatenation strcat()",
            "severity": "HIGH",
            "pattern": r"\bstrcat\s*\(",
            "description": (
                "strcat() does not verify destination buffer bounds before appending "
                "characters, risking buffer overflows."
            ),
            "recommendation": (
                "Use strncat() or strlcat() with explicit destination length calculation."
            ),
        },
        {
            "rule_id": "C-004",
            "name": "Unbounded sprintf()",
            "severity": "HIGH",
            "pattern": r"\bsprintf\s*\(",
            "description": (
                "sprintf() writes formatted output without buffer bounds checking, "
                "leading to buffer overflows."
            ),
            "recommendation": (
                "Use snprintf() and specify the maximum buffer size."
            ),
        },
        {
            "rule_id": "C-005",
            "name": "Unbounded vsprintf()",
            "severity": "HIGH",
            "pattern": r"\bvsprintf\s*\(",
            "description": (
                "vsprintf() writes unbounded variable-argument formatted data to a buffer."
            ),
            "recommendation": (
                "Use vsnprintf() with explicit buffer size bounds."
            ),
        },
        {
            "rule_id": "C-006",
            "name": "Unsafe scanf() String Format",
            "severity": "MEDIUM",
            "pattern": r"\b(?:scanf|sscanf|fscanf)\s*\([^)]*\"[^\"]*%s",
            "description": (
                "scanf() using %s format without a maximum width specifier can read "
                "unbounded input into a buffer."
            ),
            "recommendation": (
                "Specify a maximum width specifier (e.g. %49s) or use fgets()."
            ),
        },
        {
            "rule_id": "C-007",
            "name": "Command Injection via system()",
            "severity": "CRITICAL",
            "pattern": r"\bsystem\s*\(",
            "description": (
                "system() invokes a shell command. If input is untrusted or dynamic, "
                "it allows arbitrary shell command execution."
            ),
            "recommendation": (
                "Avoid system(). Use execve() or posix_spawn() with explicit argument arrays."
            ),
        },
        {
            "rule_id": "C-008",
            "name": "Command Execution via popen()",
            "severity": "HIGH",
            "pattern": r"\bpopen\s*\(",
            "description": (
                "popen() executes a shell pipeline and is vulnerable to command injection "
                "if arguments are untrusted."
            ),
            "recommendation": (
                "Use pipe() and fork()/execve() without invoking a system shell."
            ),
        },
        {
            "rule_id": "C-009",
            "name": "Format String Vulnerability",
            "severity": "HIGH",
            "pattern": r"\b(?:printf|fprintf|vprintf|vfprintf)\s*\(\s*(?!\"[^\"]*\")\s*[a-zA-Z_]",
            "description": (
                "Passing a non-constant string directly as the format argument can allow "
                "arbitrary memory disclosure or corruption."
            ),
            "recommendation": (
                "Always provide a string literal format specifier, e.g., printf(\"%s\", var)."
            ),
        },
        {
            "rule_id": "C-010",
            "name": "Hardcoded Secret or Credential",
            "severity": "HIGH",
            "pattern": (
                r"(?i)\b(?:char\s*\*|const\s+char\s*\*|char\s+\w+\[\s*\])\s*"
                r"\w*(?:password|passwd|secret|api_key|token|credential)\w*\s*=\s*\"[^\"]{6,}\""
            ),
            "description": (
                "A hardcoded password, token, or secret appears in source code."
            ),
            "recommendation": (
                "Load sensitive credentials from environment variables or a secure vault at runtime."
            ),
        },
        {
            "rule_id": "C-011",
            "name": "Insecure Pseudo-Random Number Generator",
            "severity": "LOW",
            "pattern": r"\brand\s*\(\s*\)",
            "description": (
                "rand() generates predictable pseudo-random sequences not suitable for security operations."
            ),
            "recommendation": (
                "Use cryptographic randomness such as /dev/urandom, getrandom(), or OpenSSL RAND_bytes()."
            ),
        },
    ]

    def scan(self, code: str) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            return {
                "status": "error",
                "message": "C code cannot be empty.",
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
                # Ignore pure comment lines
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
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
            "language": "c",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }
