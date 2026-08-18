import re


ANSI_ESCAPE = re.compile(
    r"(?:\x1B\][^\x07]*(?:\x07|\x1B\\))|"
    r"(?:\x1B[@-_][0-?]*[ -/]*[@-~])"
)
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s\"']+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)((?:api[_-]?key|access[_-]?token|token|secret|password|passwd|pwd)"
            r"\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(--(?:password|passwd|token|api-key|secret)(?:=|\s+))\S+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\bmysql\b[^\r\n]*?\s-p)(?!\s|$)\S+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"),
        r"\1[REDACTED]@",
    ),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[PRIVATE KEY REDACTED]",
    ),
)


def sanitize_terminal_text(text: str, max_chars: int = 12000) -> str:
    """Remove terminal control codes and common secrets before analysis or logging."""
    sanitized = ANSI_ESCAPE.sub("", text)
    sanitized = sanitized.replace("\r\n", "\n").replace("\r", "\n")
    sanitized = CONTROL_CHARACTERS.sub("", sanitized)

    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    if len(sanitized) > max_chars:
        sanitized = sanitized[-max_chars:]
    return sanitized
