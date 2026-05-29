"""
SentinelFlow Rate Limiter
Token bucket implementation to throttle outbound requests.
"""

import asyncio
import time


class RateLimiter:
    """
    Async token bucket rate limiter.
    
    Allows up to `rate` requests per second with burst support.
    Callers must await `acquire()` before each request.
    """

    def __init__(self, rate: int = 100, burst: int = None):
        """
        Args:
            rate: Maximum requests per second.
            burst: Maximum burst size (defaults to rate).
        """
        self.rate = rate
        self.burst = burst or rate
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0):
        """Wait until a token is available, then consume it."""
        async with self._lock:
            await self._refill()

            if self._tokens < tokens:
                # Wait for enough tokens
                wait_time = (tokens - self._tokens) / self.rate
                await asyncio.sleep(wait_time)
                await self._refill()

            self._tokens = max(0, self._tokens - tokens)

    async def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def __repr__(self):
        return f"RateLimiter(rate={self.rate}/s, tokens={self._tokens:.1f})"
