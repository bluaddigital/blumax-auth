"""Logged exceptions never carry local variables (security fix, 2026-11-27).

structlog's built-in default renderer is `structlog.dev.ConsoleRenderer()`. When
`rich` is installed (it arrives with FastAPI/uvicorn extras) that renderer draws
exceptions with rich, and rich prints EVERY local variable of EVERY frame:
bearer tokens, decoded JWT claims, passwords, patient rows. Any process that
logs before, or without, configuring structlog gets that default. On 2026-11-27
IPD printed about 150 lines of locals for each database-connection error.

This module is the single place that decides how an exception is rendered:

* `exception_processor()`  - text traceback: type, message and stack frames.
  No locals. Same output shape as `structlog.processors.format_exc_info`, so
  JSON log consumers see no format change.
* `console_renderer()`     - the readable dev console, with a plain traceback
  instead of rich's locals-dumping one.
* `redact_sensitive_keys`  - masks fields whose name looks like a credential
  (Authorization, token, password, secret, cookie, claims).
* `install_safe_defaults()` - if nothing has configured structlog yet, installs
  a safe chain. `app/__init__.py` calls it, so every process that imports the
  package (API, workers, scripts, tests) is covered before its first log line.
  A later `setup_logging()` replaces it as before.

There is deliberately no switch to turn locals back on: a setting that can be
left on is a setting that will one day be on in production.

Imports nothing from the app, so importing it never loads settings.
"""
from __future__ import annotations

from typing import Any

import structlog

REDACTED = "[redacted]"

# Substring match on the lower-cased key, so `refresh_token`, `Authorization`,
# `initial_password` and `jwt_claims` are all caught without a list to maintain.
SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "cookie",
    "claims",
)


def is_sensitive_key(key: object) -> bool:
    lowered = str(key).lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def _redact(value: Any, depth: int) -> Any:
    if depth > 6:
        return value
    if isinstance(value, dict):
        return {k: (REDACTED if is_sensitive_key(k) else _redact(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact(v, depth + 1) for v in value)
    return value


def redact_sensitive_keys(_logger: Any, _method_name: str, event_dict: dict) -> dict:
    """structlog processor: mask credential-shaped fields, including inside nested dicts/lists."""
    for key in list(event_dict):
        if key == "event":
            continue
        if is_sensitive_key(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _redact(event_dict[key], 0)
    return event_dict


def exception_processor() -> Any:
    """Turn `exc_info` into a plain text traceback (type, message, frames) - never locals."""
    return structlog.processors.ExceptionRenderer()


def console_renderer(colors: bool = False) -> structlog.dev.ConsoleRenderer:
    """Readable console output for local development, with a traceback that has no locals."""
    return structlog.dev.ConsoleRenderer(colors=colors, exception_formatter=structlog.dev.plain_traceback)


def safe_default_processors() -> list[Any]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        redact_sensitive_keys,
        exception_processor(),
        console_renderer(colors=False),
    ]


def install_safe_defaults() -> None:
    """Replace structlog's locals-printing default, unless the app already configured structlog."""
    if structlog.is_configured():
        return
    structlog.configure(processors=safe_default_processors(), cache_logger_on_first_use=False)
