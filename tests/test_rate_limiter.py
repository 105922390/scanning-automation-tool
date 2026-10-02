"""Deterministic rate-limiter tests using an injected, hand-advanced clock."""

import pytest

from reconpilot.config import Limits
from reconpilot.errors import CircuitBreakerTripped
from reconpilot.rate_limiter import RateLimiter, TokenBucket


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_token_bucket_burst_then_throttle():
    clk = FakeClock()
    b = TokenBucket(rate=2, capacity=2, clock=clk)
    assert b.try_acquire()      # burst 1
    assert b.try_acquire()      # burst 2
    assert not b.try_acquire()  # empty
    clk.advance(0.5)            # 0.5s * 2/s = 1 token
    assert b.try_acquire()
    assert not b.try_acquire()


def test_token_bucket_time_until_token():
    clk = FakeClock()
    b = TokenBucket(rate=4, capacity=1, clock=clk)
    assert b.try_acquire()
    # empty now; at 4/s the next token is 0.25s away
    assert b.time_until_token() == pytest.approx(0.25, abs=1e-6)


def _limits(rps, conc, cap=1000, safe=False):
    return Limits(max_rps_per_host=rps, max_global_concurrency=conc,
                  max_requests_per_run=cap, safe_mode=safe)


def test_safe_mode_halves_rate_and_concurrency():
    rl = RateLimiter(_limits(4, 8, safe=True))
    assert rl.rps == 2
    assert rl._concurrency == 4
    assert rl.safe_mode is True


def test_force_safe_mode_flag():
    rl = RateLimiter(_limits(4, 8, safe=False), force_safe_mode=True)
    assert rl.rps == 2 and rl._concurrency == 4


def test_per_host_buckets_are_independent():
    clk = FakeClock()
    rl = RateLimiter(_limits(1, 8), clock=clk)
    assert rl.try_acquire("a.acme.com")
    assert not rl.try_acquire("a.acme.com")   # a is throttled
    assert rl.try_acquire("b.acme.com")       # b has its own bucket


def test_counter_only_increments_on_success():
    clk = FakeClock()
    rl = RateLimiter(_limits(1, 8), clock=clk)
    rl.try_acquire("a.acme.com")              # success -> count 1
    rl.try_acquire("a.acme.com")              # throttled -> no count
    assert rl.request_count == 1


def test_circuit_breaker_trips_at_cap():
    clk = FakeClock()
    rl = RateLimiter(_limits(1000, 8, cap=3), clock=clk)
    for _ in range(3):
        rl.try_acquire("a.acme.com")
    with pytest.raises(CircuitBreakerTripped):
        rl.try_acquire("a.acme.com")


def test_blocking_acquire_waits_then_succeeds():
    clk = FakeClock()
    slept = []

    def fake_sleep(dt):
        slept.append(dt)
        clk.advance(dt)   # simulate time passing while "asleep"

    rl = RateLimiter(_limits(2, 8), clock=clk, sleep=fake_sleep)
    assert rl.acquire("a.acme.com")           # token available immediately
    assert rl.acquire("a.acme.com")           # capacity=2 default -> still ok
    assert rl.acquire("a.acme.com", block=True)  # must sleep then succeed
    assert slept and all(s > 0 for s in slept)


def test_concurrency_slot_limits_parallelism():
    rl = RateLimiter(_limits(1000, 2))
    s1 = rl.concurrency_slot(); s1.__enter__()
    s2 = rl.concurrency_slot(); s2.__enter__()
    # third acquire would block; verify the underlying semaphore is exhausted
    assert rl._sema.acquire(blocking=False) is False
    s1.__exit__()
    assert rl._sema.acquire(blocking=False) is True
    rl._sema.release()
    s2.__exit__()
