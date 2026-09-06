import re
from typing import Any


class CppSecurityScanner:
    """
    Static security scanner for C++ source code.
    Performs static pattern-based vulnerability analysis without executing source code.
    """

    RULES = [
        {
            "rule_id": "CPP-001",
            "name": "Unsafe Legacy C String Function",
            "severity": "HIGH",
            "pattern": r"\b(?:strcpy|strcat|gets|sprintf|vsprintf)\s*\(",
            "description": (
                "Legacy C string manipulation functions do not perform bounds checking "
                "and can cause buffer overflow vulnerabilities."
            ),
            "recommendation": (
                "Use std::string, std::string_view, or std::format (C++20) instead of unsafe C string APIs."
            ),
        },
        {
            "rule_id": "CPP-002",
            "name": "Command Injection via system() / popen()",
            "severity": "CRITICAL",
            "pattern": r"\b(?:system|_wsystem|popen|_wpopen)\s*\(",
            "description": (
                "Executing system shell commands with user-influenced arguments can lead to arbitrary code execution."
            ),
            "recommendation": (
                "Avoid invoking shell interpreters. Use platform-specific process creation APIs with argument lists."
            ),
        },
        {
            "rule_id": "CPP-003",
            "name": "Format String Vulnerability",
            "severity": "HIGH",
            "pattern": r"\b(?:printf|fprintf|sprintf|snprintf)\s*\(\s*(?!\"[^\"]*\")\s*[a-zA-Z_]",
            "description": (
                "Passing a non-literal format string to formatting functions allows attackers to read or write memory."
            ),
            "recommendation": (
                "Always use string literals for format specifiers or adopt std::format (C++20) / std::print (C++23)."
            ),
        },
        {
            "rule_id": "CPP-004",
            "name": "Hardcoded Credential or Secret",
            "severity": "HIGH",
            "pattern": (
                r"(?i)\b(?:std::string|const\s+char\s*\*|char\s*\*|auto)\s+"
                r"\w*(?:password|passwd|secret|api_key|token|credential)\w*\s*=\s*\"[^\"]{6,}\""
            ),
            "description": (
                "Hardcoded credentials in C++ source code can be extracted through binary disassembly."
            ),
            "recommendation": (
                "Load credentials from environment variables or a secure key management system at runtime."
            ),
        },
        {
            "rule_id": "CPP-005",
            "name": "Insecure Pseudo-Random Generator",
            "severity": "LOW",
            "pattern": r"\b(?:std::rand|rand)\s*\(\s*\)",
            "description": (
                "rand() and std::rand() are deterministic PRNGs unsuitable for security tokens or crypto keys."
            ),
            "recommendation": (
                "Use <random> with std::random_device or cryptographic libraries (OpenSSL, Libsodium)."
            ),
        },
        {
            "rule_id": "CPP-006",
            "name": "Dangerous reinterpret_cast on Pointers",
            "severity": "MEDIUM",
            "pattern": r"\breinterpret_cast\s*<[^>]*\*\s*>",
            "description": (
                "reinterpret_cast bypasses type safety and can cause undefined behavior or memory corruption."
            ),
            "recommendation": (
                "Avoid reinterpret_cast. Use static_cast, dynamic_cast, or structured type hierarchies."
            ),
        },
        {
            "rule_id": "CPP-007",
            "name": "Raw Array Allocation without Smart Pointer",
            "severity": "MEDIUM",
            "pattern": r"\bnew\s+(?:char|int|byte|uint8_t)\s*\[\s*\w+\s*\]",
            "description": (
                "Raw array allocations with new[] risk memory leaks, double free, or buffer management bugs."
            ),
            "recommendation": (
                "Use std::vector or std::unique_ptr<T[]> to manage memory safely via RAII."
            ),
        },
    ]

    def scan(self, code: str) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            return {
                "status": "error",
                "message": "C++ code cannot be empty.",
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
            "language": "cpp",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }
