"""Resilience helpers for external API calls in the AlertFlow pipeline.

Provides a thread-safe circuit breaker and a retry-with-backoff wrapper to
protect the system from cascading failures when downstream services (DNS
enrichment, VirusTotal lookups, etc.) become slow or unreachable.

Design notes
------------
- The circuit breaker is a classic three-state machine (CLOSED / OPEN /
  HALF_OPEN) with monotonic-time-based recovery.
- ``call_with_breaker`` composes retry logic *on top of* the breaker so
  callers get both transient-failure tolerance and fast-fail protection.
- All mutable breaker state is guarded by ``threading.Lock`` to support the
  ``ThreadPoolExecutor`` used in ``pipeline.py``.
"""

import logging
import time
import threading
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Finite-state labels for the circuit breaker state machine.

    - CLOSED:  Normal operation; requests flow through and failures are counted.
    - OPEN:    Failure threshold exceeded; all requests are fast-failed.
    - HALF_OPEN: Recovery timeout elapsed; a single probe request is allowed
      to test whether the downstream service has recovered.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Thread-safe circuit breaker state machine.

    CLOSED  -> failures accumulate -> OPEN (fast-fail all requests)
    OPEN    -> after recovery_timeout -> HALF_OPEN (allow one probe request)
    HALF_OPEN -> success -> CLOSED / failure -> OPEN
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
    ):
        """Initialize the circuit breaker.

        Args:
            name: Human-readable identifier, used in log messages and
                  ``get_breaker`` registry lookups.
            failure_threshold: Number of consecutive failures before the
                               breaker trips from CLOSED to OPEN.
            recovery_timeout: Seconds to stay OPEN before transitioning to
                              HALF_OPEN for a probe request.
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        # Lock serialises all state mutations -- required because callers
        # may invoke this breaker from multiple threads.
        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        # Monotonic timestamp of the most recent state transition; used to
        # compute whether the recovery window has elapsed.
        self._last_state_change = time.monotonic()

    @property
    def state(self) -> CircuitState:
        """Current state of the breaker, with automatic OPEN -> HALF_OPEN transition.

        When the breaker is OPEN, this property checks whether the recovery
        timeout has elapsed.  If so, it atomically transitions to HALF_OPEN
        so the next ``allow_request`` call will permit a single probe.

        Returns:
            The resolved ``CircuitState`` after any time-based transition.
        """
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_state_change
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._last_state_change = time.monotonic()
                    logger.warning(
                        "circuit_breaker.half_open name=%s elapsed=%.1fs",
                        self.name, elapsed,
                    )
            return self._state

    def allow_request(self) -> bool:
        """Return True if the request should proceed.

        - CLOSED: always allows.
        - HALF_OPEN: allows exactly one probe request.
        - OPEN: blocks all requests (fast-fail).

        Returns:
            ``True`` if the caller may execute the downstream request.
        """
        s = self.state  # triggers time-based transition check
        if s == CircuitState.CLOSED:
            return True
        if s == CircuitState.HALF_OPEN:
            return True
        # OPEN -- block
        return False

    def record_success(self):
        """Record a successful request and reset the failure counter.

        Always transitions back to CLOSED, which handles both the normal
        CLOSED path and the HALF_OPEN -> CLOSED recovery.  The counter
        reset ensures a single success after recovery fully heals the
        breaker.
        """
        with self._lock:
            prev = self._state
            self._failure_count = 0
            self._state = CircuitState.CLOSED
            self._last_state_change = time.monotonic()
            if prev != CircuitState.CLOSED:
                logger.info("circuit_breaker.closed name=%s", self.name)

    def record_failure(self):
        """Record a failed request and trip the breaker if threshold is met.

        The failure counter is monotonically increasing within a CLOSED
        window.  Once it reaches ``failure_threshold`` the breaker trips
        to OPEN, causing all subsequent requests to fast-fail until the
        recovery timeout elapses.
        """
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._last_state_change = time.monotonic()
                logger.error(
                    "circuit_breaker.open name=%s failures=%d threshold=%d",
                    self.name, self._failure_count, self.failure_threshold,
                )

    @property
    def failure_count(self) -> int:
        return self._failure_count

    def __repr__(self):
        return f"CircuitBreaker(name={self.name!r}, state={self.state.value}, failures={self._failure_count})"


class CircuitOpenError(Exception):
    """Raised when the circuit breaker is open and requests are blocked."""


# ---------------------------------------------------------------------------
# Per-service breakers (module-level singletons)
# ---------------------------------------------------------------------------

_breakers: dict[str, CircuitBreaker] = {}
_breakers_lock = threading.Lock()


def get_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a named circuit breaker (module-level singleton registry).

    Each unique ``name`` maps to exactly one ``CircuitBreaker`` instance,
    shared across all callers.  The first call with a given name creates
    the breaker; subsequent calls return the same instance (ignoring
    ``kwargs``).

    Args:
        name: Registry key for the breaker (e.g. ``"dns"``).
        **kwargs: Forwarded to ``CircuitBreaker.__init__`` on first creation.

    Returns:
        The shared ``CircuitBreaker`` for the given name.
    """
    with _breakers_lock:
        if name not in _breakers:
            _breakers[name] = CircuitBreaker(name=name, **kwargs)
        return _breakers[name]


def reset_breakers():
    """Reset all breakers (for testing).

    Clears the global registry so that subsequent ``get_breaker`` calls
    create fresh instances.  Must only be used in test teardown to avoid
    state leaking between test cases.
    """
    with _breakers_lock:
        _breakers.clear()


# ---------------------------------------------------------------------------
# Retry + circuit breaker helper
# ---------------------------------------------------------------------------

def call_with_breaker(
    breaker: CircuitBreaker,
    func,
    *args,
    retries: int = 3,
    backoff_base: float = 1.0,
    **kwargs,
):
    """Call *func* with retry logic and circuit-breaker protection.

    Execution flow:
    1. Check the breaker -- if OPEN, raise ``CircuitOpenError`` immediately.
    2. Attempt to call *func* up to *retries* times.
    3. On each transient failure, sleep for an exponentially increasing
       delay (``backoff_base * 2^(attempt-1)``) before retrying.
    4. On success, record success with the breaker and return the result.
    5. If all retries are exhausted, record a single failure with the
       breaker and re-raise the last exception.

    The exponential backoff prevents hammering a recovering service while
    keeping the total wait bounded (e.g. with base=0.5 and 3 retries:
    0.5s, 1.0s, 2.0s).

    Args:
        breaker: The ``CircuitBreaker`` instance to use for fast-fail.
        func: Callable to execute.
        *args: Positional arguments forwarded to *func*.
        retries: Maximum number of attempts (must be >= 1).
        backoff_base: Base delay in seconds for exponential backoff.
        **kwargs: Keyword arguments forwarded to *func*.

    Returns:
        The return value of *func* on success.

    Raises:
        CircuitOpenError: If the breaker is OPEN before the first attempt.
        Exception: Re-raised after all retries are exhausted.
    """
    if not breaker.allow_request():
        raise CircuitOpenError(
            f"Circuit breaker '{breaker.name}' is OPEN. "
            f"Fast-failing after {breaker.failure_count} failures. "
            f"Retry in {breaker.recovery_timeout}s."
        )

    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            result = func(*args, **kwargs)
            breaker.record_success()
            return result
        except CircuitOpenError:
            # Re-raise immediately -- don't swallow breaker-level blocks.
            raise
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "circuit_breaker.retry name=%s attempt=%d/%d error=%s",
                breaker.name, attempt, retries, exc,
            )
            if attempt < retries:
                # Exponential backoff: 1x, 2x, 4x ... of backoff_base
                delay = backoff_base * (2 ** (attempt - 1))
                time.sleep(delay)

    # All retries exhausted -- trip the breaker so future callers fast-fail
    # until the recovery window elapses.
    breaker.record_failure()
    raise last_exc
