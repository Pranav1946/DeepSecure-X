import re
from typing import Any


class JavaSecurityScanner:
    """
    Static security scanner for Java source code.
    Performs static pattern-based vulnerability analysis without executing source code.
    """

    RULES = [
        {
            "rule_id": "JAVA-SQL-001",
            "name": "SQL Injection via Dynamic String Concatenation",
            "severity": "CRITICAL",
            "pattern": (
                r"(?i)(?:"
                r"\b(?:executeQuery|executeUpdate|execute|createNativeQuery)\s*\([^)]*\+\s*[a-zA-Z_]"
                r"|\bString\s+\w+\s*=\s*\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^\"]*\"\s*\+\s*[a-zA-Z_]"
                r")"
            ),
            "description": (
                "Constructing SQL statements dynamically with string concatenation allows SQL injection attacks."
            ),
            "recommendation": (
                "Use parameterized queries with PreparedStatement or JPA named parameters with bound values."
            ),
        },
        {
            "rule_id": "JAVA-CMD-001",
            "name": "Command Injection via Runtime / ProcessBuilder",
            "severity": "CRITICAL",
            "pattern": r"(?:Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\()",
            "description": (
                "Executing operating-system commands with user-influenced arguments can lead to arbitrary code execution."
            ),
            "recommendation": (
                "Avoid executing OS commands from Java. If required, validate arguments with a strict allowlist."
            ),
        },
        {
            "rule_id": "JAVA-DESERIALIZATION-001",
            "name": "Unsafe Object Deserialization",
            "severity": "CRITICAL",
            "pattern": r"(?:new\s+ObjectInputStream|ObjectInputStream\s+\w+|\.readObject\s*\(\s*\))",
            "description": (
                "Deserializing untrusted data with ObjectInputStream can result in remote code execution."
            ),
            "recommendation": (
                "Avoid standard Java serialization for untrusted data. Use JSON/Protobuf or implement SerialFilter."
            ),
        },
        {
            "rule_id": "JAVA-XXE-001",
            "name": "Potential XML External Entity (XXE) Injection",
            "severity": "HIGH",
            "pattern": r"(?:DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance)",
            "description": (
                "XML parsers may be vulnerable to XXE attacks if external entity resolution and DTDs are not disabled."
            ),
            "recommendation": (
                "Disable external DTDs: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"
            ),
        },
        {
            "rule_id": "JAVA-CRYPTO-001",
            "name": "Insecure / Weak Cryptographic Algorithm",
            "severity": "HIGH",
            "pattern": (
                r"(?i)(?:MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-1|SHA1|MD2|MD4)\""
                r"|Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|RC2|RC4|Blowfish|AES/ECB))"
            ),
            "description": (
                "Using obsolete cryptographic algorithms (MD5, SHA-1, DES, ECB mode) weakens confidentiality and integrity."
            ),
            "recommendation": (
                "Use SHA-256/SHA-3 for cryptographic hashing and AES-GCM (with authentication) for symmetric encryption."
            ),
        },
        {
            "rule_id": "JAVA-SECRET-001",
            "name": "Hardcoded Credential or API Key",
            "severity": "HIGH",
            "pattern": (
                r"(?i)\b(?:String|char\[\])\s+\w*(?:password|passwd|secret|api_key|token|credential)\w*\s*=\s*\"[^\"]{6,}\""
            ),
            "description": (
                "A hardcoded secret, token, or password was found in Java source code."
            ),
            "recommendation": (
                "Store sensitive credentials in external environment variables, AWS Secrets Manager, or HashiCorp Vault."
            ),
        },
        {
            "rule_id": "JAVA-PATH-001",
            "name": "Potential Path Traversal in File Operations",
            "severity": "HIGH",
            "pattern": r"(?:new\s+File|Paths\.get|new\s+FileInputStream|new\s+FileOutputStream)\s*\(\s*(?!\"[^\"]*\")\s*[a-zA-Z_]",
            "description": (
                "Opening file paths constructed from dynamic input without canonicalization can allow unauthorized directory traversal."
            ),
            "recommendation": (
                "Validate paths using file.getCanonicalPath() and confirm it starts with the intended base directory."
            ),
        },
        {
            "rule_id": "JAVA-TLS-001",
            "name": "Permissive TLS / Insecure Trust Manager",
            "severity": "CRITICAL",
            "pattern": r"(?i)(?:TrustAllCertificates|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})",
            "description": (
                "Disabling certificate or hostname verification enables Man-in-the-Middle (MitM) attacks."
            ),
            "recommendation": (
                "Never disable TLS verification in production. Use trusted CA certificates and default JVM trust stores."
            ),
        },
        {
            "rule_id": "JAVA-SSRF-001",
            "name": "Potential Server-Side Request Forgery (SSRF)",
            "severity": "HIGH",
            "pattern": r"(?:new\s+URL\s*\(\s*(?!\"https?://[^\"]*\")\s*[a-zA-Z_][^)]*\)\.openStream|new\s+URL\s*\([^)]*\)\.openConnection)",
            "description": (
                "Fetching URLs constructed from dynamic user input can expose internal network services to SSRF."
            ),
            "recommendation": (
                "Validate destination URLs against an allowlist and restrict access to private/loopback IP address ranges."
            ),
        },
        {
            "rule_id": "JAVA-RANDOM-001",
            "name": "Insecure Pseudo-Random Generator",
            "severity": "LOW",
            "pattern": r"\bnew\s+(?:java\.util\.)?Random\s*\(",
            "description": (
                "java.util.Random produces deterministic pseudo-random sequences not suitable for security-sensitive tokens."
            ),
            "recommendation": (
                "Use java.security.SecureRandom for cryptographic tokens, password resets, and session identifiers."
            ),
        },
    ]

    def scan(self, code: str) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            return {
                "status": "error",
                "message": "Java code cannot be empty.",
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
            "language": "java",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }
