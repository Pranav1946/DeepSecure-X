
SECURITY_RULES = {
    "SQL_INJECTION": {
        "severity": "HIGH",
        "description": "Possible SQL injection vulnerability detected.",
        "recommendation": "Use parameterized queries instead of string concatenation."
    },

    "COMMAND_INJECTION": {
        "severity": "CRITICAL",
        "description": "Possible command injection vulnerability detected.",
        "recommendation": "Avoid executing unsanitized user input with shell commands."
    },

    "HARDCODED_SECRET": {
        "severity": "CRITICAL",
        "description": "Possible hardcoded secret detected.",
        "recommendation": "Store secrets in environment variables or a secret manager."
    },

    "WEAK_HASH": {
        "severity": "MEDIUM",
        "description": "Weak hashing algorithm detected.",
        "recommendation": "Use a modern password hashing algorithm such as bcrypt or Argon2."
    },

    "DANGEROUS_EVAL": {
        "severity": "CRITICAL",
        "description": "Dangerous dynamic code execution detected.",
        "recommendation": "Avoid eval() and exec(). Use safer alternatives."
    },

    "UNSAFE_DESERIALIZATION": {
        "severity": "CRITICAL",
        "description": "Potentially unsafe object deserialization detected.",
        "recommendation": "Avoid unsafe deserialization of untrusted data."
    },

    "SHELL_TRUE": {
        "severity": "HIGH",
        "description": "subprocess is executed with shell=True.",
        "recommendation": "Avoid shell=True and pass commands as a list of arguments."
    },

    "INSECURE_YAML": {
        "severity": "HIGH",
        "description": "Potentially unsafe YAML loading detected.",
        "recommendation": "Use yaml.safe_load() instead of yaml.load()."
    },

    "INSECURE_RANDOM": {
        "severity": "MEDIUM",
        "description": "Cryptographically insecure random module detected.",
        "recommendation": "Use the secrets module for security-sensitive random values."
    }
}