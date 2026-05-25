"""
classifier.py — Attack pattern classifier for WAFisGoingOn.

Categorises a blocked payload into one of eight attack classes using
a two-stage approach:
  1. Fast regex pre-pass  (no ML cost, covers the obvious cases)
  2. Keyword-vector scoring fallback for ambiguous payloads

Attack classes
--------------
sql_injection       – SQL syntax, UNION, boolean/time-based blind
xss                 – Script injection, event handlers, javascript: URIs
path_traversal      – Directory traversal, /etc/passwd, Windows paths
command_injection   – Shell metacharacters, OS commands, backticks
ssrf                – Internal IP targets, cloud metadata endpoints
xxe                 – XML entity injection
template_injection  – Server-side template syntax (Jinja, Twig, Freemarker)
unknown             – Could not be confidently classified
"""

import re
from dataclasses import dataclass

# ── Attack class registry ──────────────────────────────────────────────────────

@dataclass
class AttackClass:
    name: str           # machine-readable key stored in DB
    label: str          # human-readable label shown in UI / report
    color: str          # hex colour for charts
    icon: str           # emoji for the dashboard


ATTACK_CLASSES: list[AttackClass] = [
    AttackClass("sql_injection",      "SQL Injection",        "#f87171", "🗄️"),
    AttackClass("xss",                "Cross-Site Scripting", "#fb923c", "📜"),
    AttackClass("path_traversal",     "Path Traversal",       "#fbbf24", "📂"),
    AttackClass("command_injection",  "Command Injection",    "#a78bfa", "💻"),
    AttackClass("ssrf",               "SSRF",                 "#60a5fa", "🌐"),
    AttackClass("xxe",                "XXE",                  "#34d399", "📄"),
    AttackClass("template_injection", "Template Injection",   "#f472b6", "🧩"),
    AttackClass("unknown",            "Unknown",              "#94a3b8", "❓"),
]

ATTACK_CLASS_MAP: dict[str, AttackClass] = {c.name: c for c in ATTACK_CLASSES}


# ── Regex rules (ordered; first match wins) ───────────────────────────────────

_RULES: list[tuple[str, re.Pattern]] = [
    ("sql_injection", re.compile(
        r"""(?ix)
        (\bUNION\b.*\bSELECT\b)
        | (\bSELECT\b.*\bFROM\b)
        | (\bDROP\b.*\bTABLE\b)
        | (\bINSERT\b.*\bINTO\b)
        | (\bDELETE\b.*\bFROM\b)
        | (\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d)
        | (--\s*$)
        | (/\*.*\*/)
        | (\bSLEEP\s*\()
        | (\bWAITFOR\s+DELAY\b)
        | (\bBENCHMARK\s*\()
        | (\bxp_cmdshell\b)
        | (\bLOAD_FILE\s*\()
        | (\bINTO\s+OUTFILE\b)
        | (\bINFORMATION_SCHEMA\b)
        | (admin\s*'?\s*--)
        """
    )),
    ("xss", re.compile(
        r"""(?ix)
        (<\s*script[\s>])
        | (</\s*script\s*>)
        | (javascript\s*:)
        | (\bon\w+\s*=)          # onerror=, onclick=, etc.
        | (<\s*img[^>]+src\s*=\s*x)
        | (<\s*svg[\s>])
        | (<\s*iframe[\s>])
        | (document\s*\.\s*cookie)
        | (alert\s*\()
        | (prompt\s*\()
        | (confirm\s*\()
        | (eval\s*\()
        | (base64_decode\s*\()
        """
    )),
    ("path_traversal", re.compile(
        r"""(?ix)
        (\.\./){2,}
        | (%2e%2e%2f){1,}
        | (/etc/(passwd|shadow|hosts|group))
        | (/proc/self)
        | (\\\\\.\.\\\\)
        | (C:\\\\Windows)
        | (%00)                  # null byte terminator
        """
    )),
    ("command_injection", re.compile(
        r"""(?ix)
        (;\s*(ls|dir|cat|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)
        | (\|\s*(cat|ls|dir|id|whoami|uname))
        | (`[^`]+`)              # backtick execution
        | (\$\([^)]+\))         # $(...) subshell
        | (cmd\.exe)
        | (/bin/(bash|sh|nc|ncat))
        | (<?php\s)
        | (system\s*\()
        | (passthru\s*\()
        | (exec\s*\()
        """
    )),
    ("xxe", re.compile(
        r"""(?ix)
        (<!ENTITY\b)
        | (\bSYSTEM\b.*['"](file|http|ftp|php|expect))
        | (\bPUBLIC\b\s+['"]-//)
        | (%xxe)
        | (<!DOCTYPE[^>]+\[)
        """
    )),
    ("ssrf", re.compile(
        r"""(?ix)
        (169\.254\.169\.254)     # AWS metadata
        | (metadata\.google\.internal)
        | (100\.100\.100\.200)   # Alibaba Cloud metadata
        | (192\.168\.\d+\.\d+)
        | (10\.\d+\.\d+\.\d+)
        | (172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)
        | (localhost)
        | (127\.\d+\.\d+\.\d+)
        | (file://)
        | (dict://)
        | (gopher://)
        """
    )),
    ("template_injection", re.compile(
        r'(\{\{.*?\}\})|(\{%.*?%\})|(\$\{.*?\})|(#\{.*?\})|(<%.*?%>)|(\[\[.*?\]\])',
        re.IGNORECASE
    )),
]


# ── Keyword scoring fallback ──────────────────────────────────────────────────
# Used when no regex fires but we still want a best-guess category.

_KEYWORDS: dict[str, list[str]] = {
    "sql_injection":      ["select", "union", "insert", "delete", "update", "drop",
                           "table", "where", "having", "sleep", "benchmark", "null"],
    "xss":                ["script", "alert", "onerror", "onclick", "javascript",
                           "cookie", "document", "window", "eval", "xss"],
    "path_traversal":     ["passwd", "shadow", "etc", "proc", "windows", "system32",
                           "traversal", "directory", "dotdot"],
    "command_injection":  ["bash", "shell", "exec", "system", "cmd", "whoami",
                           "uname", "wget", "curl", "netcat", "python", "perl"],
    "ssrf":               ["localhost", "metadata", "internal", "intranet", "ssrf",
                           "169", "192", "127"],
    "xxe":                ["entity", "doctype", "system", "public", "xml", "xxe"],
    "template_injection": ["template", "jinja", "twig", "freemarker", "velocity",
                           "expression", "render", "sandbox"],
}


def _keyword_score(text: str) -> dict[str, int]:
    text_lower = text.lower()
    return {
        cls: sum(1 for kw in kws if kw in text_lower)
        for cls, kws in _KEYWORDS.items()
    }


# ── Public classifier API ─────────────────────────────────────────────────────

def classify(payload: str) -> str:
    """
    Return the machine-readable attack class name for a given payload string.
    Always returns a string — falls back to "unknown" rather than raising.
    """
    if not payload or not payload.strip():
        return "unknown"

    # Stage 1: regex pre-pass
    for class_name, pattern in _RULES:
        if pattern.search(payload):
            return class_name

    # Stage 2: keyword scoring
    scores = _keyword_score(payload)
    best_class, best_score = max(scores.items(), key=lambda x: x[1])
    if best_score >= 2:
        return best_class

    return "unknown"


def classify_label(payload: str) -> str:
    """Return the human-readable label for a payload."""
    return ATTACK_CLASS_MAP.get(classify(payload), ATTACK_CLASS_MAP["unknown"]).label


def get_class_meta(class_name: str) -> AttackClass:
    return ATTACK_CLASS_MAP.get(class_name, ATTACK_CLASS_MAP["unknown"])
