"""A small in-memory cache with expiry, so we never ask a service twice about the same IOC.

Lives inside one server process. With several processes or servers, use a shared cache (Redis).
"""
import time
from typing import Any


class TTLCache:
    def __init__(self, ttl_seconds: float = 6 * 3600, max_items: int = 10_000):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._data: dict[Any, tuple[float, Any]] = {}

    def get(self, key: Any) -> Any | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires, value = entry
        if time.monotonic() > expires:
            del self._data[key]
            return None
        return value

    def set(self, key: Any, value: Any) -> None:
        if len(self._data) >= self.max_items:
            self._data.pop(next(iter(self._data)))  # drop the oldest entry
        self._data[key] = (time.monotonic() + self.ttl, value)

    def clear(self) -> None:
        self._data.clear()
