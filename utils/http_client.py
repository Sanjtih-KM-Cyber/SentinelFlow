"""
SentinelFlow HTTP Client
Shared aiohttp session factory with consistent headers, timeouts, and SSL handling.
"""

import ssl
from contextlib import asynccontextmanager
from typing import Optional

import aiohttp
import certifi

from core.config import Config

# Default headers mimicking a real browser to avoid trivial bot detection
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


@asynccontextmanager
async def create_session(config: Config, headers: dict = None):
    """
    Async context manager that yields a configured aiohttp session.
    
    Usage:
        async with create_session(config) as session:
            async with session.get(url) as resp:
                ...
    """
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}

    # SSL context — use certifi bundle but allow insecure for scope testing
    ssl_context = ssl.create_default_context(cafile=certifi.where())

    connector = aiohttp.TCPConnector(
        ssl=ssl_context,
        limit=100,
        limit_per_host=10,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    timeout = aiohttp.ClientTimeout(
        total=config.timeout,
        connect=10,
        sock_read=config.timeout,
    )

    async with aiohttp.ClientSession(
        headers=merged_headers,
        connector=connector,
        timeout=timeout,
        trust_env=True,  # Respect HTTP_PROXY env vars
        connector_owner=True,
    ) as session:
        yield session
