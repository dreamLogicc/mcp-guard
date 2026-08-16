"""The audit trail: one line per tool call, plus the colouring for it.

Arguments are the point of an audit line and the risk in one — this gateway exists
because tool calls carry secrets around. So values are redacted by key name and
truncated by default, and printing them whole has to be asked for.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger("praxiom.audit")

ARGUMENT_MODES = ("none", "redacted", "full")
DEFAULT_ARGUMENT_WIDTH = 88

_SECRET_KEY = re.compile(
    r"token|secret|password|passwd|api[-_]?key|authorization|credential|cookie|private|session",
    re.IGNORECASE,
)
_REDACTED = "***"
_VALUE_WIDTH = 48

_COLORS = {
    "grey": "\033[90m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
}
_RESET = "\033[0m"

_color_enabled = False


def enable_color(enabled: bool) -> None:
    global _color_enabled
    _color_enabled = enabled


def paint(text: str, *styles: str) -> str:
    if not _color_enabled or not styles:
        return text
    prefix = "".join(_COLORS.get(style, "") for style in styles)
    return f"{prefix}{text}{_RESET}" if prefix else text


def shorten(text: str, width: int) -> str:
    """Drop the middle, not the tail.

    What identifies a path or URL lives at both ends — `/home/…/.ssh/id_rsa` says
    what was touched, `/home/very/long/prefix/…` says nothing.
    """
    if len(text) <= width:
        return text
    head = (width - 1) * 2 // 3
    return text[:head] + "…" + text[head + 1 - width :]


def redact(value: Any, *, key: str = "") -> Any:
    """Blank out anything whose key looks like a credential, shorten the rest."""
    if _SECRET_KEY.search(key):
        return _REDACTED
    if isinstance(value, dict):
        return {name: redact(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [redact(item, key=key) for item in value]
    if isinstance(value, str):
        return shorten(value, _VALUE_WIDTH)
    return value


def render_arguments(arguments: dict[str, Any], *, mode: str, width: int = DEFAULT_ARGUMENT_WIDTH) -> str:
    """Render call arguments for one log line."""
    if mode == "none" or not arguments:
        return ""
    payload = arguments if mode == "full" else redact(arguments)
    try:
        text = json.dumps(payload, ensure_ascii=False, default=str, separators=(", ", "="))
    except (TypeError, ValueError):  # pragma: no cover - default=str covers the usual cases
        text = str(payload)
    text = text.strip("{}")
    return text if mode == "full" else shorten(text, width)


def call(
    *,
    verdict: str,
    tool: str,
    arguments: str,
    detail: str = "",
    elapsed_ms: float | None = None,
    level: int = logging.INFO,
) -> None:
    """Emit one audit line. `verdict` is ALLOW / DENY / PASS / ERROR."""
    color = {"ALLOW": ("green",), "DENY": ("red", "bold"), "PASS": ("yellow",), "ERROR": ("magenta",)}
    parts = [f"{paint(verdict.ljust(5), *color.get(verdict, ()))} {paint(tool, 'bold')}"]
    if arguments:
        parts.append(paint(arguments, "grey"))
    if detail:
        parts.append(paint(detail, "cyan" if verdict in ("ALLOW", "PASS") else "yellow"))
    if elapsed_ms is not None:
        parts.append(paint(f"{elapsed_ms:.0f}ms", "grey"))
    logger.log(level, "  ".join(parts))


class Formatter(logging.Formatter):
    """Compact stderr format: time, then the message, with the level only when it matters.

    Audit lines carry their own verdict column, so repeating `INFO` in front of
    them would be noise.
    """

    def __init__(self) -> None:
        super().__init__(datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        stamp = paint(self.formatTime(record, self.datefmt), "grey")
        message = record.getMessage()
        if record.name == logger.name:
            line = f"{stamp}  {message}"
        else:
            source = record.name.removeprefix("praxiom.").removeprefix("praxiom")
            tag = paint(f"{source or 'guard'}", "blue")
            if record.levelno >= logging.WARNING:
                tag = paint(record.levelname.lower(), "red" if record.levelno >= logging.ERROR else "yellow")
            line = f"{stamp}  {paint('·', 'grey')} {tag} {message}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line
