from app.scanner.python_scanner import PythonSecurityScanner


scanner = PythonSecurityScanner()


def get_rule_ids(result):
    return [
        finding["rule_id"]
        for finding in result["findings"]
    ]


def test_clean_code():
    code = """
def greet(name):
    return f"Hello {name}"

print(greet("World"))
"""

    result = scanner.scan(code)

    assert result["status"] == "completed"
    assert result["vulnerabilities_found"] == 0


def test_hardcoded_secret():
    code = """
password = "admin123"
"""

    result = scanner.scan(code)

    assert "HARDCODED_SECRET" in get_rule_ids(result)


def test_command_injection():
    code = """
import os
os.system(user_input)
"""

    result = scanner.scan(code)

    assert "COMMAND_INJECTION" in get_rule_ids(result)


def test_dangerous_eval():
    code = """
eval(user_input)
"""

    result = scanner.scan(code)

    assert "DANGEROUS_EVAL" in get_rule_ids(result)


def test_weak_hash():
    code = """
import hashlib
hashlib.md5(password.encode())
"""

    result = scanner.scan(code)

    assert "WEAK_HASH" in get_rule_ids(result)


def test_unsafe_deserialization():
    code = """
import pickle

data = pickle.loads(user_data)
"""

    result = scanner.scan(code)

    assert "UNSAFE_DESERIALIZATION" in get_rule_ids(result)


def test_shell_true():
    code = """
import subprocess

subprocess.run(user_input, shell=True)
"""

    result = scanner.scan(code)

    assert "SHELL_TRUE" in get_rule_ids(result)


def test_insecure_yaml():
    code = """
import yaml

data = yaml.load(user_data)
"""

    result = scanner.scan(code)

    assert "INSECURE_YAML" in get_rule_ids(result)


def test_insecure_random():
    code = """
import random

token = random.randint(1000, 9999)
"""

    result = scanner.scan(code)

    assert "INSECURE_RANDOM" in get_rule_ids(result)


# ------------------------------------------------------------------------------
# JavaScript Scanner Tests
# ------------------------------------------------------------------------------

from app.scanner.javascript_scanner import JavaScriptSecurityScanner

js_scanner = JavaScriptSecurityScanner()


def get_js_rule_ids(result):
    return [finding["rule_id"] for finding in result["findings"]]


def test_js_clean_code():
    code = """
    function add(a, b) {
        return a + b;
    }
    console.log(add(2, 3));
    """
    result = js_scanner.scan(code)
    assert result["status"] == "completed"
    assert result["vulnerabilities_found"] == 0


def test_js_eval_and_inner_html():
    code = """
    eval(userInput);
    document.getElementById("box").innerHTML = untrustedHTML;
    """
    result = js_scanner.scan(code)
    assert result["status"] == "completed"
    rule_ids = get_js_rule_ids(result)
    assert "JS001" in rule_ids  # eval
    assert "JS003" in rule_ids  # innerHTML


def test_js_hardcoded_secret():
    code = """
    const apiKey = "api_key_secret_abcdef123456";
    """
    result = js_scanner.scan(code)
    assert "JS007" in get_js_rule_ids(result)


def test_js_child_process_command():
    code = """
    const { exec } = require('child_process');
    child_process.exec(userInput);
    """
    result = js_scanner.scan(code)
    assert "JS006" in get_js_rule_ids(result)