"""Tests for resilience module -- circuit breaker and retry logic.

Validates circuit breaker state transitions (closed/open/half-open), failure
counting, recovery timeouts, breaker registry, and call_with_breaker retry
behavior including backoff and fast-fail when the circuit is open.
"""

import time

import pytest

from resilience import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    call_with_breaker,
    get_breaker,
    reset_breakers,
)


class TestCircuitBreaker:
    """Tests for CircuitBreaker state machine transitions."""

    def setup_method(self):
        reset_breakers()

    def test_starts_closed(self):
        """Verifies a new breaker starts in CLOSED state and allows requests."""
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=1.0)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold(self):
        """Verifies breaker transitions to OPEN after reaching the failure threshold."""
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=10.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_success_resets_failure_count(self):
        """Verifies a successful call resets the failure count and keeps breaker CLOSED."""
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=10.0)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_half_open_after_recovery_timeout(self):
        """Verifies breaker transitions from OPEN to HALF_OPEN after recovery timeout elapses."""
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_success_closes(self):
        """Verifies a successful call in HALF_OPEN state transitions back to CLOSED."""
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_failure_reopens(self):
        """Verifies a failed call in HALF_OPEN state transitions back to OPEN."""
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


class TestGetBreaker:
    """Tests for the get_breaker singleton registry."""

    def setup_method(self):
        reset_breakers()

    def test_singleton(self):
        """Verifies get_breaker returns the same instance for the same name."""
        a = get_breaker("my_service")
        b = get_breaker("my_service")
        assert a is b

    def test_different_names(self):
        """Verifies different names yield different breaker instances."""
        a = get_breaker("service_a")
        b = get_breaker("service_b")
        assert a is not b

    def test_reset_clears(self):
        """Verifies reset_breakers clears all breaker state in the registry."""
        get_breaker("test").record_failure()
        reset_breakers()
        fresh = get_breaker("test")
        assert fresh.failure_count == 0


class TestCallWithBreaker:
    """Tests for call_with_breaker retry wrapper."""

    def setup_method(self):
        reset_breakers()

    def test_success(self):
        """Verifies a successful callable returns its value through the breaker."""
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=10.0)
        result = call_with_breaker(cb, lambda: 42)
        assert result == 42

    def test_success_with_args(self):
        """Verifies positional arguments are forwarded to the callable."""
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=10.0)
        result = call_with_breaker(cb, lambda a, b: a + b, 10, 20)
        assert result == 30

    def test_retry_on_failure(self):
        """Verifies transient failures are retried and success resets failure count."""
        cb = CircuitBreaker("test", failure_threshold=5, recovery_timeout=10.0)
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) < 3:
                raise ConnectionError("transient")
            return "ok"

        result = call_with_breaker(cb, flaky, retries=3, backoff_base=0.01)
        assert result == "ok"
        assert len(attempts) == 3
        assert cb.failure_count == 0  # success reset it

    def test_all_retries_exhausted_raises(self):
        """Verifies the original exception is raised after all retries are exhausted."""
        cb = CircuitBreaker("test", failure_threshold=5, recovery_timeout=10.0)

        def always_fail():
            raise ConnectionError("down")

        with pytest.raises(ConnectionError):
            call_with_breaker(cb, always_fail, retries=2, backoff_base=0.01)
        assert cb.failure_count == 1

    def test_circuit_open_fast_fails(self):
        """Verifies CircuitOpenError is raised immediately when breaker is OPEN."""
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=10.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        with pytest.raises(CircuitOpenError):
            call_with_breaker(cb, lambda: "should not run")
