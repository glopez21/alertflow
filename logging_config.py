"""Structured JSON logging configuration."""

import logging
import os
import sys
import time
import uuid

import structlog


def setup_logging(level: str | None = None) -> None:
    """Configure structlog with JSON output for production, console for dev."""
    log_level = level or os.environ.get("ALERTFLOW_LOG_LEVEL", "INFO")
    log_format = os.environ.get("ALERTFLOW_LOG_FORMAT", "json")

    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    numeric_level = logging.getLevelName(log_level)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            numeric_level
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "alertflow") -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


def generate_request_id() -> str:
    """Generate a unique request ID."""
    return uuid.uuid4().hex[:12]


class RequestLoggingMiddleware:
    """HTTP request/response logging middleware."""

    def __init__(self, app):
        self.app = app
        self.logger = get_logger("alertflow.http")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        request_id = generate_request_id()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        method = scope.get("method", "")
        path = scope.get("path", "")
        start = time.monotonic()
        status_code = None

        self.logger.info("request.start", method=method, path=path, request_id=request_id)

        async def send_wrapper(message):
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
