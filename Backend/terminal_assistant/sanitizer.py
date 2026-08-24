"""Remove terminal control codes and redact secrets before analysis."""

import re


ANSI_ESCAPE = re.compile(
    # OSC sequences end at BEL or ESC + backslash. Excluding ESC from the
    # payload is important: a greedy `[^BEL]*` pattern can jump across several
    # QTerminal OSC messages and erase the command output between them.
    r"(?:\x1B\][^\x07\x1B]*(?:\x07|\x1B\\))|"
    r"(?:\x1B[@-_][0-?]*[ -/]*[@-~])|"
    # Application keypad mode is a two-byte escape emitted beside Kali prompts.
    r"(?:\x1B[=>])"
)
# Zsh syntax highlighting often rewinds the cursor and repaints the entire command
# in colour. A plain transcript records both versions consecutively; converting the
# rewind into a line boundary preserves the original command instead of joining it
# to its highlighted duplicate.
CURSOR_REWIND = re.compile(r"\x1B\[\d+D")
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


# Remove control sequences and redact likely secrets before terminal evidence reaches analysis or an LLM.
def sanitize_terminal_text(text: str, max_chars: int = 12000) -> str:
    """Perform the sanitize terminal text step of the terminal guidance pipeline.

    The operation works with sanitized evidence and does not execute a recommended
    security command.
    """
    sanitized = CURSOR_REWIND.sub("\n", text)
    sanitized = ANSI_ESCAPE.sub("", sanitized)
    sanitized = sanitized.replace("\r\n", "\n").replace("\r", "\n")
    sanitized = CONTROL_CHARACTERS.sub("", sanitized)

    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    if len(sanitized) > max_chars:
        sanitized = sanitized[-max_chars:]
    return sanitized
