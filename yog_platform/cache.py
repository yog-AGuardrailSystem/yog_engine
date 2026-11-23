"""Decision cache.

Soundness rule: a cached answer may only be reused when *everything* that could change it is identical, so
the key covers the full request (including state), the policy hash and the state version.  Errors,
REQUIRE_APPROVAL results and traced requests are never cached.  A policy swap clears the cache.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional


def cache_key(request: dict, policy_hash: str) -> str:
    body = {k: v for k, v in request.items() if k != "request_id"}
    state = body.get("state") or {}
    version = state.get("version") if isinstance(state, dict) else None
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{policy_hash}|{version}|{data}".encode("utf-8")).hexdigest()


class DecisionCache:
    def __init__(self, max_entries: int = 1024, ttl: float = 30.0, clock: Callable[[], float] = time.monotonic):
        self._max, self._ttl, self._clock = max_entries, ttl, clock
        self._items: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = self.misses = 0

    def get(self, request: dict, policy_hash: str) -> Optional[dict]:
        key = cache_key(request, policy_hash)
        with self._lock:
            entry = self._items.get(key)
            if entry is None or self._clock() > entry[0]:
                if entry is not None:
                    del self._items[key]
                self.misses += 1
                return None
            self._items.move_to_end(key)
            self.hits += 1
            return copy.deepcopy(entry[1])

    def put(self, request: dict, policy_hash: str, result: dict, *, traced: bool = False) -> bool:
        if traced or "error" in result or result.get("decision") not in ("ALLOW", "DENY"):
            return False
        with self._lock:
            self._items[cache_key(request, policy_hash)] = (self._clock() + self._ttl, copy.deepcopy(result))
            while len(self._items) > self._max:
                self._items.popitem(last=False)
        return True

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
