"""Global + per-host rate limiting and a run-wide request circuit breaker.

Nothing in the pipeline sends a request without first calling ``acquire(host)``.
The clock is injectable so the token-bucket behavior is deterministic in tests.
"""

from __future__ import annotations

import time
from threading import BoundedSemaphore, Lock
from typing import Callable

from .config import Limits
from .errors import CircuitBreakerTripped


class TokenBucket:
    """Classic token bucket. ``rate`` tokens/sec, burst up to ``capacity``."""

    def __init__(self, rate: float, capacity: float | None = None,
                 clock: Callable[[], float] = time.monotonic):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1.0, rate)
        self._tokens = self.capacity
        self._clock = clock
        self._updated = clock()
        self._lock = Lock()

    def _refill(self) -> None:
        now = self._clock()
        delta = now - self._updated
        if delta > 0:
            self._tokens = min(self.capacity, self._tokens + delta * self.rate)
            self._updated = now

    def try_acquire(self) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False

    def time_until_token(self) -> float:
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                return 0.0
            return (1 - self._tokens) / self.rate


class RateLimiter:
    """Per-host token buckets + a global concurrency semaphore + request cap.

    Enforces the *effective* limits (safe_mode applied). ``force_safe_mode``
    corresponds to the global ``--safe-mode`` CLI flag.
    """

    def __init__(self, limits: Limits, force_safe_mode: bool = False,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        eff = limits.effective(force_safe_mode=force_safe_mode)
        self.rps = eff.max_rps_per_host
        self.max_requests_per_run = eff.max_requests_per_run
        self.safe_mode = eff.safe_mode
        self._sema = BoundedSemaphore(eff.max_global_concurrency)
        self._concurrency = eff.max_global_concurrency
        self._buckets: dict[str, TokenBucket] = {}
        self._count = 0
        self._clock = clock
        self._sleep = sleep
        self._lock = Lock()

    @property
    def request_count(self) -> int:
        return self._count

    def _bucket_for(self, host: str) -> TokenBucket:
        with self._lock:
            b = self._buckets.get(host)
            if b is None:
                b = TokenBucket(self.rps, clock=self._clock)
                self._buckets[host] = b
            return b

    def _tick_counter(self) -> None:
        with self._lock:
            self._count += 1
            if self._count > self.max_requests_per_run:
                raise CircuitBreakerTripped(
                    f"run exceeded max_requests_per_run={self.max_requests_per_run}")

    def try_acquire(self, host: str) -> bool:
        """Non-blocking: consume one per-host token if available. Counts toward
        the circuit breaker only when a token is actually taken."""
        if self._bucket_for(host).try_acquire():
            self._tick_counter()
            return True
        return False

    def acquire(self, host: str, block: bool = True) -> bool:
        """Blocking by default: wait for a per-host token, then return True.
        Raises :class:`CircuitBreakerTripped` if the run cap is exceeded."""
        bucket = self._bucket_for(host)
        while True:
            if bucket.try_acquire():
                self._tick_counter()
                return True
            if not block:
                return False
            self._sleep(min(bucket.time_until_token(), 1.0))

    def charge(self, n: int = 1) -> None:
        """Account ``n`` requests against the run-wide circuit breaker without
        per-host pacing. Used for file-based tools that self-limit via their own
        ``-rl``/``-rate`` flag ({rps}) — we still want the breaker to count the
        batch so a huge target list can't slip past ``max_requests_per_run``."""
        with self._lock:
            self._count += max(0, n)
            if self._count > self.max_requests_per_run:
                raise CircuitBreakerTripped(
                    f"run exceeded max_requests_per_run={self.max_requests_per_run}")

    def concurrency_slot(self) -> "BoundedSemaphore":
        """Context manager for a global worker slot: ``with rl.concurrency_slot():``"""
        return _Slot(self._sema)


class _Slot:
    def __init__(self, sema: BoundedSemaphore):
        self._sema = sema

    def __enter__(self):
        self._sema.acquire()
        return self

    def __exit__(self, *exc):
        self._sema.release()
        return False
