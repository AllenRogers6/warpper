import time
from collections import OrderedDict


class ResponseCache:
    def __init__(self, max_size: int = 4096, max_ttl: int = 300):
        self._entries: OrderedDict = OrderedDict()
        self.max_size = max_size
        self.max_ttl = max_ttl
        self.hits = 0
        self.misses = 0

    def get(self, key):
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        response, expires_at = entry
        if expires_at < time.monotonic():
            del self._entries[key]
            self.misses += 1
            return None
        self._entries.move_to_end(key)
        self.hits += 1
        return response

    def put(self, key, response: bytes, ttl: int) -> None:
        if ttl <= 0:
            return
        ttl = min(ttl, self.max_ttl)
        expires_at = time.monotonic() + ttl
        if key in self._entries:
            del self._entries[key]
        self._entries[key] = (response, expires_at)
        while len(self._entries) > self.max_size:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        self._entries.clear()

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "size": len(self._entries),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hits / total if total else 0.0,
        }
