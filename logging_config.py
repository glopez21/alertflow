"""Structured logging configuration for AlertFlow.

Provides a unified logging pipeline using structlog that supports two output
modes:

* **JSON** (default, ``ALERTFLOW_LOG_FORMAT=json``) — machine-parseable lines
  suitable for aggregation in ELK, Loki, CloudWatch, etc.
* **Console** (``ALERTFLOW_LOG_FORMAT=console``) — human-friendly colourised
  output for local development.

Key capabilities:

* Request-scoped correlation via ``structlog.contextvars`` — every log line
  produced within a request carries the same ``request_id``, making it trivial
  to trace a single request across async tasks and worker processes.
* ISO-8601 timestamps on every event for unambiguous chronological ordering.
* Level filtering driven by ``ALERTFLOW_LOG_LEVEL`` (default ``INFO``).
* An ASGI middleware (``RequestLoggingMiddleware``) that wraps each HTTP
  request/response cycle with start, complete, and error log entries,
  including duration in milliseconds.

All log output is written to *stderr* so that *stdout* remains clean for
application data (e.g. gRPC responses, CLI output).
"""

import logging
import os
import sys
import time
import uuid

import structlog


def setup_logging(level: str | None = None) -> None:
    """Initialise the structlog pipeline for the entire application.

    Should be called once at startup (before any logger is obtained) so that
    ``cache_logger_on_first_use`` can take effect.  Subsequent calls are
    harmless but redundant.

    Args:
        level: Explicit log-level override.  When *None* the level is read
            from ``ALERTFLOW_LOG_LEVEL``, falling back to ``INFO``.
    """
    log_level = level or os.environ.get("ALERTFLOW_LOG_LEVEL", "INFO")
    log_format = os.environ.get("ALERTFLOW_LOG_FORMAT", "json")

    # JSON for production (log aggregators); pretty console for development.
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    # Resolve the human-readable level name to its numeric value.
    # Guard against typos in the env-var — fall back to INFO when unrecognised.
    numeric_level = logging.getLevelName(log_level)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    structlog.configure(
        processors=[
            # Merge any per-coroutine context vars (e.g. request_id) into the
            # event dict so that every log line in the same request shares them.
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            # ISO timestamps make log lines sortable and parseable everywhere.
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        # FilteringBoundLogger drops events below the configured level before
        # any processor runs, keeping overhead minimal in production.
        wrapper_class=structlog.make_filtering_bound_logger(
            numeric_level
        ),
        context_class=dict,
        # stderr keeps stdout free for application-level output.
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "alertflow") -> structlog.stdlib.BoundLogger:
    """Return a named structured logger.

    The returned logger is thread-safe and may be cached in module-level
    variables.
    """
    return structlog.get_logger(name)


def generate_request_id() -> str:
    """Generate a short, URL-safe unique request identifier.

    Uses the first 12 hex characters (48 bits) of a UUID4, which gives
    ~2.8 × 10¹⁴ possible values — more than sufficient to avoid collisions
    in request-scoped correlation while keeping log lines compact.
    """
    return uuid.uuid4().hex[:12]


class RequestLoggingMiddleware:
    """ASGI middleware that logs every HTTP request and response.

    Designed as a transparent wrapper around any ASGI application.  It emits
    three log events per request:

    1. ``request.start`` — method, path, and generated ``request_id``.
    2. ``request.complete`` — same fields plus ``status`` and ``duration_ms``.
    3. ``request.error`` — emitted instead of *complete* when the downstream
       app raises an exception; includes the partial ``status_code`` if one
       was already sent.

    The ``request_id`` is injected into ``structlog.contextvars`` so that all
    log lines produced during the request (including from deeply nested
    helpers or async tasks that inherit the context) carry the same ID.

    Non-HTTP scopes (e.g. ``websocket``, ``lifespan``) are passed through
    untouched.
    """

    def __init__(self, app):
        self.app = app
        self.logger = get_logger("alertflow.http")

    async def __call__(self, scope, receive, send):
        # Only intercept plain HTTP; let WebSocket / lifespan pass through.
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Generate and bind a fresh request ID for the entire lifecycle.
        request_id = generate_request_id()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        method = scope.get("method", "")
        path = scope.get("path", "")
        # monotonic() is immune to wall-clock adjustments (NTP jumps, DST).
        start = time.monotonic()
        status_code = None

        self.logger.info("request.start", method=method, path=path, request_id=request_id)

        async def send_wrapper(message):
            """Intercept the ASGI ``send`` to capture the HTTP status code."""
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            duration = time.monotonic() - start
            self.logger.error(
                "request.error",
                method=method,
                path=path,
                # If the response headers were never sent, report 500.
                status=status_code or 500,
                duration_ms=round(duration * 1000, 2),
                request_id=request_id,
            )
            raise

        duration = time.monotonic() - start
        self.logger.info(
            "request.complete",
            method=method,
            path=path,
            status=status_code,
            duration_ms=round(duration * 1000, 2),
            request_id=request_id,
        )
