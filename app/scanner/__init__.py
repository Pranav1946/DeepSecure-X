from typing import Optional, Type

from app.scanner.python_scanner import PythonSecurityScanner
from app.scanner.javascript_scanner import JavaScriptSecurityScanner
from app.scanner.c_scanner import CSecurityScanner
from app.scanner.cpp_scanner import CppSecurityScanner
from app.scanner.java_scanner import JavaSecurityScanner
from app.scanner.html_scanner import HTMLSecurityScanner
from app.scanner.css_scanner import CSSSecurityScanner
from app.scanner.risk_engine import SecurityRiskEngine


# Centralized mapping of canonical language identifiers to their scanner classes
SUPPORTED_LANGUAGES: dict[str, Type] = {
    "python": PythonSecurityScanner,
    "javascript": JavaScriptSecurityScanner,
    "c": CSecurityScanner,
    "cpp": CppSecurityScanner,
    "java": JavaSecurityScanner,
    "html": HTMLSecurityScanner,
    "css": CSSSecurityScanner,
}

# Alias resolution mapping
LANGUAGE_ALIASES: dict[str, str] = {
    "py": "python",
    "python3": "python",
    "js": "javascript",
    "jsx": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "ts": "javascript",
    "tsx": "javascript",
    "c": "c",
    "h": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "hpp": "cpp",
    "hxx": "cpp",
    "java": "java",
    "html": "html",
    "htm": "html",
    "css": "css",
}

# File extension to canonical language mapping
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
}


def normalize_language(lang: Optional[str]) -> Optional[str]:
    """
    Normalizes a given language string or alias to its canonical language identifier.
    Returns None if the language is unsupported.
    """
    if not lang or not isinstance(lang, str):
        return None

    cleaned = lang.strip().lower()
    if cleaned in SUPPORTED_LANGUAGES:
        return cleaned

    return LANGUAGE_ALIASES.get(cleaned)


def detect_language(code: str) -> Optional[str]:
    """
    Best-effort automatic language detection for pasted source code.
    Returns canonical language name or None when confidence is too low.
    """
    import re

    text = code.strip()

    if not text:
        return None

    # HTML
    if re.search(
        r"<!DOCTYPE\s+html|<html\b|</html>|<head\b|<body\b|<a\b|<form\b|<img\b|<div\b|<script\b|<p\b|<span\b|<table\b|<button\b",
        text,
        re.I,
    ):
        return "html"

    # CSS
    if re.search(r"(^|[}\s])[-\w]+\s*:\s*[^;{}]+;", text):
        return "css"

    # Java
    if re.search(
        r"\b(public\s+class|private\s+class|protected\s+class)\b"
        r"|System\.out\.println\s*\("
        r"|\bimport\s+java\.",
        text,
    ):
        return "java"

    # C++ (checked before C because many valid C++ snippets also match generic C patterns)
    if re.search(
        r"\bstd::\w+"
        r"|\busing\s+namespace\s+std\b"
        r"|\bcout\s*<<"
        r"|\bendl\b",
        text,
    ):
        return "cpp"

    # C
    if re.search(
        r"#include\s*<stdio\.h>"
        r"|\bprintf\s*\("
        r"|\bscanf\s*\("
        r"|\bint\s+main\s*\(",
        text,
    ):
        return "c"

    # Python
    if re.search(
        r"^\s*(from\s+\w[\w.]*\s+import|import\s+\w+)"
        r"|\bdef\s+\w+\s*\("
        r"|\bif\s+__name__\s*=="
        r"|^\s*class\s+\w+\s*\(",
        text,
        re.M,
    ):
        return "python"

    # JavaScript
    if re.search(
        r"\b(?:const|let|var)\s+\w+"
        r"|\bconsole\.log\s*\("
        r"|=>"
        r"|\bfunction\s+\w+\s*\("
        r"|\bdocument\."
        r"|\bwindow\.",
        text,
    ):
        return "javascript"

    return None


def get_scanner_for_language(lang: str):
    """
    Retrieves an initialized scanner instance for the specified language.
    Returns None if the language is unsupported.
    """
    canonical = normalize_language(lang)
    if not canonical:
        return None

    scanner_cls = SUPPORTED_LANGUAGES.get(canonical)
    if scanner_cls:
        return scanner_cls()
    return None


__all__ = [
    "PythonSecurityScanner",
    "JavaScriptSecurityScanner",
    "CSecurityScanner",
    "CppSecurityScanner",
    "JavaSecurityScanner",
    "HTMLSecurityScanner",
    "CSSSecurityScanner",
    "SecurityRiskEngine",
    "SUPPORTED_LANGUAGES",
    "LANGUAGE_ALIASES",
    "EXTENSION_TO_LANGUAGE",
    "normalize_language",
    "detect_language",
    "get_scanner_for_language",
]
