"""
Rate limiting utilities for respectful web crawling.
"""

import asyncio
import time
import random
from typing import Dict, Optional
import logging
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiter."""
    max_requests_per_second: float = 10.0
    max_requests_per_minute: int = 600
    max_concurrent_requests: int = 50
    random_delay_range: tuple = (0.1, 0.5)
    burst_size: int = 10
    backoff_factor: float = 1.5


class TokenBucket:
    """Token bucket implementation for rate limiting."""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """
        Consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False if insufficient tokens
        """
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_refill

            # Refill tokens
            self.tokens = min(
                self.capacity,
                self.tokens + time_passed * self.refill_rate
            )
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait_for_tokens(self, tokens: int = 1):
        """Wait until enough tokens are available."""
        while not await self.consume(tokens):
            await asyncio.sleep(0.1)


class SlidingWindowCounter:
    """Sliding window counter for rate limiting."""

    def __init__(self, window_size: float, max_requests: int):
        """
        Initialize sliding window counter.

        Args:
            window_size: Window size in seconds
            max_requests: Maximum requests per window
        """
        self.window_size = window_size
        self.max_requests = max_requests
        self.requests: deque = deque()
        self._lock = asyncio.Lock()

    async def add_request(self) -> bool:
        """
        Add a request to the window.

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        async with self._lock:
            now = time.time()

            # Remove old requests outside the window
            while self.requests and self.requests[0] <= now - self.window_size:
                self.requests.popleft()

            # Check if we can add this request
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    async def wait_for_slot(self):
        """Wait until a slot is available in the window."""
        while not await self.add_request():
            await asyncio.sleep(0.1)


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on response patterns."""

    def __init__(self, config: RateLimiterConfig):
        """
        Initialize adaptive rate limiter.

        Args:
            config: Rate limiter configuration
        """
        self.config = config
        self.current_rate = config.max_requests_per_second
        self.min_rate = config.max_requests_per_second * 0.1
        self.max_rate = config.max_requests_per_second * 2.0

        # Rate limiters
        self.second_bucket = TokenBucket(
            capacity=config.burst_size,
            refill_rate=config.max_requests_per_second
        )
        self.minute_window = SlidingWindowCounter(
            window_size=60.0,
            max_requests=config.max_requests_per_minute
        )

        # Adaptive parameters
        self.success_count = 0
        self.error_count = 0
        self.last_adjustment = time.time()
        self.adjustment_interval = 30.0  # Adjust every 30 seconds

        # Concurrency control
        self.semaphore = asyncio.Semaphore(config.max_concurrent_requests)

        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """
        Acquire permission to make a request.

        This method blocks until a request slot is available.
        """
        # Wait for concurrent request slot
        await self.semaphore.acquire()

        try:
            # Wait for rate limiting
            await self.second_bucket.wait_for_tokens()
            await self.minute_window.wait_for_slot()

            # Add random delay for politeness
            if self.config.random_delay_range:
                delay = random.uniform(*self.config.random_delay_range)
                await asyncio.sleep(delay)

        except Exception as e:
            # Release semaphore on error
            self.semaphore.release()
            raise e

    async def release(self) -> None:
        """Release request slot."""
        self.semaphore.release()

    async def record_success(self, response_time: float) -> None:
        """
        Record a successful request.

        Args:
            response_time: Response time in seconds
        """
        async with self._lock:
            self.success_count += 1
            await self._adjust_rate(response_time, success=True)

    async def record_error(self, error_type: str = "unknown") -> None:
        """
        Record a failed request.

        Args:
            error_type: Type of error (timeout, http_error, etc.)
        """
        async with self._lock:
            self.error_count += 1
            await self._adjust_rate(0, success=False, error_type=error_type)

    async def _adjust_rate(self, response_time: float, success: bool, error_type: str = "unknown") -> None:
        """
        Adjust rate based on performance metrics.

        Args:
            response_time: Response time in seconds
            success: Whether the request was successful
            error_type: Type of error if unsuccessful
        """
        now = time.time()

        # Only adjust at intervals
        if now - self.last_adjustment < self.adjustment_interval:
            return

        total_requests = self.success_count + self.error_count
        if total_requests < 10:  # Need minimum data
            return

        success_rate = self.success_count / total_requests

        # Adjust based on success rate
        if success_rate > 0.9:  # High success rate
            # Increase rate gradually
            self.current_rate = min(
                self.max_rate,
                self.current_rate * 1.1
            )
        elif success_rate < 0.7:  # Low success rate
            # Decrease rate more aggressively
            self.current_rate = max(
                self.min_rate,
                self.current_rate / self.config.backoff_factor
            )

        # Adjust based on response times for successful requests
        if success and response_time > 5.0:  # Slow responses
            self.current_rate = max(
                self.min_rate,
                self.current_rate * 0.9
            )
        elif success and response_time < 1.0:  # Fast responses
            self.current_rate = min(
                self.max_rate,
                self.current_rate * 1.05
            )

        # Special handling for certain error types
        if error_type in ["timeout", "rate_limit", "blocked"]:
            self.current_rate = max(
                self.min_rate,
                self.current_rate / (self.config.backoff_factor * 2)
            )

        # Update rate limiters
        self.second_bucket.refill_rate = self.current_rate
        self.minute_window.max_requests = int(self.current_rate * 60)

        # Reset counters
        self.success_count = 0
        self.error_count = 0
        self.last_adjustment = now

        logger.debug(f"Adjusted rate to {self.current_rate:.2f} req/s (success rate: {success_rate:.2f})")

    def get_stats(self) -> Dict:
        """Get current rate limiter statistics."""
        return {
            'current_rate': self.current_rate,
            'success_count': self.success_count,
            'error_count': self.error_count,
            'available_tokens': self.second_bucket.tokens,
            'window_requests': len(self.minute_window.requests),
            'available_concurrent': self.semaphore._value
        }


class DomainSpecificLimiter:
    """Rate limiter that tracks and limits per-domain requests."""

    def __init__(self, global_limiter: AdaptiveRateLimiter, max_per_domain: int = 5):
        """
        Initialize domain-specific limiter.

        Args:
            global_limiter: Global rate limiter
            max_per_domain: Maximum requests per domain per minute
        """
        self.global_limiter = global_limiter
        self.max_per_domain = max_per_domain
        self.domain_limiters: Dict[str, SlidingWindowCounter] = {}

    async def acquire(self, domain: str) -> None:
        """
        Acquire permission for a specific domain.

        Args:
            domain: The domain to request
        """
        # Wait for global rate limit
        await self.global_limiter.acquire()

        # Get or create domain-specific limiter
        if domain not in self.domain_limiters:
            self.domain_limiters[domain] = SlidingWindowCounter(
                window_size=60.0,
                max_requests=self.max_per_domain
            )

        # Wait for domain-specific rate limit
        await self.domain_limiters[domain].wait_for_slot()

    async def release(self) -> None:
        """Release request slot."""
        await self.global_limiter.release()

    async def record_success(self, domain: str, response_time: float) -> None:
        """Record successful request."""
        await self.global_limiter.record_success(response_time)

    async def record_error(self, domain: str, error_type: str = "unknown") -> None:
        """Record failed request."""
        await self.global_limiter.record_error(error_type)


async def create_rate_limiter(config: Dict) -> DomainSpecificLimiter:
    """
    Create a rate limiter from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Configured rate limiter
    """
    # Extract rate limiting config
    perf_config = config.get('performance', {})
    politeness_config = config.get('politeness', {})

    limiter_config = RateLimiterConfig(
        max_requests_per_second=perf_config.get('max_requests_per_second', 10.0),
        max_requests_per_minute=perf_config.get('max_requests_per_second', 10) * 60,
        max_concurrent_requests=perf_config.get('concurrency', 50),
        random_delay_range=tuple(politeness_config.get('random_delay_range', [0.1, 0.5])),
        burst_size=min(20, perf_config.get('concurrency', 50) // 2)
    )

    global_limiter = AdaptiveRateLimiter(limiter_config)
    return DomainSpecificLimiter(global_limiter)