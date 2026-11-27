"""Security fix 2026-11-27: a logged exception never prints local variables.

Production tracebacks used to carry every local of every frame (bearer tokens, decoded JWT claims, patient rows):
structlog's default renderer draws exceptions with rich, and rich's show_locals is on. Each test below raises from a
function that holds a token in a local and asserts the token never reaches the log output, while the exception type,
message and the frame itself still do.
"""
from __future__ import annotations

import io
import logging
import re
from pathlib import Path

import pytest
import structlog

from app.core import log_safety

SECRET = "secret-xyz"


def _fail_holding_a_token() -> None:
    token = "secret-xyz"  # the local a traceback must never print
    claims = {"sub": "user-1", "jti": token}  # noqa: F841
    raise RuntimeError("database connection failed")


def _log_exception(log) -> None:
    try:
        _fail_holding_a_token()
    except RuntimeError:
        log.exception("unhandled_error")


def _assert_traceback_without_locals(text: str) -> None:
    assert SECRET not in text
    assert "RuntimeError" in text and "database connection failed" in text
    assert "_fail_holding_a_token" in text  # the stack frames are still there


def _capture_into(buf: io.StringIO) -> None:
    """Point the installed chain's output at `buf`, keeping its processors. structlog's default PrintLogger writes to
    the sys.stdout that existed when structlog was imported, so swapping sys.stdout alone does not reach it."""
    structlog.configure(logger_factory=structlog.PrintLoggerFactory(buf))


@pytest.fixture
def out():
    """A buffer to log into; logging config and root handlers are restored afterwards."""
    buf = io.StringIO()
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    saved_config = structlog.get_config() if structlog.is_configured() else None
    yield buf
    root.handlers, root.level = saved_handlers, saved_level
    if saved_config is None:
        structlog.reset_defaults()
    else:
        structlog.configure(**saved_config)


def test_unconfigured_process_gets_the_safe_default(out):
    """A worker or script that logs before (or without) setup_logging()."""
    structlog.reset_defaults()
    log_safety.install_safe_defaults()
    _capture_into(out)
    _log_exception(structlog.get_logger("worker"))
    _assert_traceback_without_locals(out.getvalue())


def test_importing_the_package_installs_the_safe_default(out):
    import importlib

    import app

    structlog.reset_defaults()
    importlib.reload(app)  # re-runs app/__init__.py, as the first import in a fresh process does
    assert structlog.is_configured()
    _capture_into(out)
    _log_exception(structlog.get_logger("script"))
    _assert_traceback_without_locals(out.getvalue())


def test_service_logging_hides_locals(out):
    """The chain app.main configures at import, re-run with stdout captured."""
    import importlib

    import app.main

    structlog.reset_defaults()
    importlib.reload(app.main)
    _capture_into(out)
    _log_exception(structlog.get_logger("auth"))
    _assert_traceback_without_locals(out.getvalue())


def test_sensitive_fields_are_redacted():
    event = log_safety.redact_sensitive_keys(
        None, "info", {"event": "x", "Authorization": "Bearer abc", "headers": {"authorization": "Bearer abc"},
                       "claims": {"sub": "u"}, "refresh_token": "t", "patient_count": 3},
    )
    assert "Bearer abc" not in repr(event) and "'sub'" not in repr(event) and "'t'" not in repr(event)
    assert event["patient_count"] == 3 and event["event"] == "x"


def test_no_code_turns_traceback_locals_back_on():
    root = Path(log_safety.__file__).resolve().parents[1]
    pattern = re.compile(r"show_locals\s*=\s*True|capture_locals\s*=\s*True|better_exceptions|rich\.traceback")
    offenders = [str(p) for p in root.rglob("*.py") if pattern.search(p.read_text(encoding="utf-8", errors="ignore"))]
    assert offenders == []
