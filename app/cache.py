"""
Small TTL cache for validated upstream answers.

Only the forwarding service calls :meth:`DnsCache.put`, and only after it has
verified the upstream endpoint, transaction ID, QR bit and complete question,
and after the answer passed the cacheability rules (NOERROR, not truncated,
non-empty answer set consisting solely of IN/A records owned by the queried
name).

The cache entry expires at the *smallest* TTL in its answer set.  On a hit the
caller receives the entry plus the whole-second age; TTLs are adjusted when the
response is built.  Hits never mutate the entry, so they cannot extend its life.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .dns import ResourceRecord


@dataclass(frozen=True)
class CacheEntry:
    key: str
    answers: tuple[ResourceRecord, ...]
    flags: int
    stored_at: float
    min_ttl: int

    @property
    def age(self) -> float:
        return time.monotonic() - self.stored_at


class DnsCache:
    """LRU cache keyed by case-insensitive domain name only."""

    def __init__(self, max_entries: int = 1024,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_entries = max(0, int(max_entries))
        self._clock = clock
        self._entries: "OrderedDict[str, CacheEntry]" = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.expired = 0

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()

    def keys(self) -> list[str]:
        return list(self._entries.keys())

    def get(self, key: str,
            now: Optional[float] = None) -> Optional[tuple[CacheEntry, int]]:
        """
        Return ``(entry, age_seconds)`` when a live entry exists, else ``None``.
        ``age_seconds`` is floored so TTL decrement uses whole seconds.
        """
        if now is None:
            now = self._clock()
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        age = now - entry.stored_at
        if age < 0:
            age = 0.0
        if age >= entry.min_ttl:
            del self._entries[key]
            self.expired += 1
            self.misses += 1
            return None
        self._entries.move_to_end(key)
        self.hits += 1
        return entry, int(age)

    def put(self, key: str, answers: Sequence[ResourceRecord], flags: int,
            now: Optional[float] = None) -> Optional[CacheEntry]:
        """
        Store a validated answer set.  Returns the entry on success or ``None``
        when the answer set has no positive TTL (nothing useful to cache).
        """
        if self.max_entries <= 0 or not answers:
            return None
        min_ttl = min(rr.ttl for rr in answers)
        if min_ttl <= 0:
            return None
        if now is None:
            now = self._clock()
        entry = CacheEntry(
            key=key,
            answers=tuple(answers),
            flags=flags,
            stored_at=now,
            min_ttl=int(min_ttl),
        )
        self._entries[key] = entry
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return entry
