"""Logging with a per-request trace id.

Every line logged while a message, session or containment is being handled carries `trace=<id>` (the message_id,
session_id or case_id), so `grep trace=M-1a2b3c` shows one message's whole path. Only masked text is ever logged:
never raw message text, PINs or API keys.
"""

from __future__ import annotations

import contextvars
import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager

_trace: contextvars.ContextVar[str] = contextvars.ContextVar("stayguard_trace", default="-")


class _TraceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.trace = _trace.get()
        return True


def setup_logging(level: str | None = None) -> None:
    """Idempotent: configures the 'stayguard' logger once."""
    log = logging.getLogger("stayguard")
    if getattr(log, "_stayguard_configured", False):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s trace=%(trace)s %(message)s"))
    handler.addFilter(_TraceFilter())
    log.addHandler(handler)
    log.setLevel(level or os.environ.get("STAYGUARD_LOG_LEVEL", "INFO"))
    log.propagate = False
    log._stayguard_configured = True  # type: ignore[attr-defined]


@contextmanager
def trace(trace_id: str) -> Iterator[None]:
    token = _trace.set(trace_id)
    try:
        yield
    finally:
        _trace.reset(token)


def current_trace() -> str:
    return _trace.get()
