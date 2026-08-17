import ast

from app.scanner.rules import SECURITY_RULES


class PythonSecurityScanner:

    def __init__(self):
        self.findings = []

    def scan(self, code: str):
        self.findings = []

        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return {
                "status": "error",
                "message": "Invalid Python syntax",
                "line": exc.lineno,
            }

        for node in ast.walk(tree):
            self._check_node(node)

        return {
            "status": "completed",
            "language": "python",
            "vulnerabilities_found": len(self.findings),
            "findings": self.findings,
        }

    def _check_node(self, node):

        if isinstance(node, ast.Call):
            self._check_sql_injection(node)
            self._check_command_injection(node)
            self._check_weak_hash(node)
            self._check_dangerous_eval(node)
            self._check_unsafe_deserialization(node)
            self._check_shell_true(node)
            self._check_insecure_yaml(node)

        if isinstance(node, ast.Assign):
            self._check_hardcoded_secret(node)

        if isinstance(node, ast.Import):
            self._check_insecure_random_import(node)

        if isinstance(node, ast.ImportFrom):
            self._check_insecure_random_import(node)

    def _add_finding(self, rule_id, node, evidence):

        rule = SECURITY_RULES[rule_id]

        self.findings.append({
            "rule_id": rule_id,
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": rule["recommendation"],
            "line": getattr(node, "lineno", None),
            "evidence": evidence,
        })

    # -----------------------------------------
    # SQL INJECTION
    # -----------------------------------------

    def _check_sql_injection(self, node):

        if not isinstance(node.func, ast.Attribute):
            return

        if node.func.attr not in {"execute", "executemany"}:
            return

        if not node.args:
            return

        argument = node.args[0]

        if isinstance(argument, (ast.JoinedStr, ast.BinOp)):
            self._add_finding(
                "SQL_INJECTION",
                node,
                "SQL query appears to be constructed dynamically."
            )
            return

        if isinstance(argument, ast.Name):
            self._add_finding(
                "SQL_INJECTION",
                node,
                f"SQL query variable '{argument.id}' may contain dynamically constructed SQL."
            )

    # -----------------------------------------
    # COMMAND INJECTION
    # -----------------------------------------

    def _check_command_injection(self, node):

        if not isinstance(node.func, ast.Attribute):
            return

        if node.func.attr not in {"system", "popen"}:
            return

        if not node.args:
            return

        argument = node.args[0]

        if isinstance(argument, (ast.Name, ast.JoinedStr, ast.BinOp)):
            self._add_finding(
                "COMMAND_INJECTION",
                node,
                "Command execution appears to use dynamic input."
            )

    # -----------------------------------------
    # WEAK HASH
    # -----------------------------------------

    def _check_weak_hash(self, node):

        if not isinstance(node.func, ast.Attribute):
            return

        if node.func.attr in {"md5", "sha1"}:
            self._add_finding(
                "WEAK_HASH",
                node,
                f"Weak hashing algorithm '{node.func.attr}' detected."
            )

    # -----------------------------------------
    # HARDCODED SECRET
    # -----------------------------------------

    def _check_hardcoded_secret(self, node):

        for target in node.targets:

            if not isinstance(target, ast.Name):
                continue

            name = target.id.lower()

            secret_keywords = {
                "password",
                "passwd",
                "secret",
                "api_key",
                "apikey",
                "token",
            }

            if any(keyword in name for keyword in secret_keywords):

                if isinstance(node.value, ast.Constant):

                    if (
                        isinstance(node.value.value, str)
                        and node.value.value
                    ):
                        self._add_finding(
                            "HARDCODED_SECRET",
                            node,
                            f"Possible hardcoded secret in variable '{target.id}'."
                        )

    # -----------------------------------------
    # DANGEROUS EVAL / EXEC
    # -----------------------------------------

    def _check_dangerous_eval(self, node):

        if not isinstance(node.func, ast.Name):
            return

        if node.func.id not in {"eval", "exec"}:
            return

        self._add_finding(
            "DANGEROUS_EVAL",
            node,
            f"Dangerous dynamic code execution using {node.func.id}()."
        )

    # -----------------------------------------
    # UNSAFE DESERIALIZATION
    # -----------------------------------------

    def _check_unsafe_deserialization(self, node):

        if not isinstance(node.func, ast.Attribute):
            return

        if node.func.attr not in {
            "loads",
            "load",
        }:
            return

        if not isinstance(node.func.value, ast.Name):
            return

        if node.func.value.id != "pickle":
            return

        self._add_finding(
            "UNSAFE_DESERIALIZATION",
            node,
            "pickle deserialization may execute malicious code when processing untrusted data."
        )

    # -----------------------------------------
    # SHELL=TRUE
    # -----------------------------------------

    def _check_shell_true(self, node):

        if not isinstance(node.func, ast.Attribute):
            return

        subprocess_methods = {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
        }

        if node.func.attr not in subprocess_methods:
            return

        for keyword in node.keywords:

            if keyword.arg == "shell":

                if (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    self._add_finding(
                        "SHELL_TRUE",
                        node,
                        "subprocess call uses shell=True."
                    )

    # -----------------------------------------
    # INSECURE YAML
    # -----------------------------------------

    def _check_insecure_yaml(self, node):

        if not isinstance(node.func, ast.Attribute):
            return

        if node.func.attr != "load":
            return

        if not isinstance(node.func.value, ast.Name):
            return

        if node.func.value.id != "yaml":
            return

        self._add_finding(
            "INSECURE_YAML",
            node,
            "yaml.load() may deserialize unsafe YAML content."
        )

    # -----------------------------------------
    # INSECURE RANDOM
    # -----------------------------------------

    def _check_insecure_random_import(self, node):

        if isinstance(node, ast.Import):

            for alias in node.names:

                if alias.name == "random":
                    self._add_finding(
                        "INSECURE_RANDOM",
                        node,
                        "Python random module detected. It is not suitable for security-sensitive random values."
                    )

        elif isinstance(node, ast.ImportFrom):

            if node.module == "random":
                self._add_finding(
                    "INSECURE_RANDOM",
                    node,
                    "Python random module detected. Use secrets for security-sensitive random values."
                )