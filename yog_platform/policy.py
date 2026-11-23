"""Loading policies safely: verify, stage, self-test, swap atomically, roll back on any failure.

:class:`PolicyManager` is the one place that decides which policy is in force.  A new bundle goes through
every check before it replaces the old one, and *nothing* is swapped if any step fails, so a bad, tampered,
stale or broken bundle can never leave the sidecar without a working policy or with a weaker one.
:class:`Syncer` pulls bundles from a registry (a directory or an HTTP base URL) into a manager.
"""
from __future__ import annotations

import datetime as _dt
import json
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .bundle import BundleError, VerifiedBundle, verify_bundle
from .engine import EngineError


class PolicyError(Exception):
    """A bundle that was refused; the previous policy stays in force."""


@dataclass(frozen=True)
class LoadedPolicy:
    engine: object
    policy_hash: str
    policy_version: int
    loaded_at: float
    source_map: list


class PolicyManager:
    def __init__(self, engine_factory: Callable[[str], object], trusted_keys: Mapping[str, bytes], *,
                 supported_language_version: int = 2, clock: Callable[[], float] = time.time,
                 on_swap: Optional[Callable[[LoadedPolicy], None]] = None):
        self._factory = engine_factory
        self._keys = dict(trusted_keys)
        self._language = supported_language_version
        self._clock = clock
        self._on_swap = on_swap
        self._lock = threading.Lock()
        self._current: Optional[LoadedPolicy] = None
        self.last_error: Optional[str] = None

    @property
    def current(self) -> Optional[LoadedPolicy]:
        with self._lock:
            return self._current

    def load_bundle(self, doc: dict) -> LoadedPolicy:
        """Verifies, stages and swaps in a bundle.  Raises :class:`PolicyError` and changes nothing on failure."""
        try:
            return self._load(doc)
        except (BundleError, EngineError, ValueError, KeyError, TypeError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError(str(exc)) from exc

    def _load(self, doc: dict) -> LoadedPolicy:
        with self._lock:
            floor = self._current.policy_version if self._current else 0
            now = _dt.datetime.fromtimestamp(self._clock(), _dt.timezone.utc)
        verified: VerifiedBundle = verify_bundle(doc, self._keys, now=now, min_policy_version=floor,
                                                 supported_language_version=self._language)
        engine = self._factory(verified.policy_text)               # compiles; raises on a bad policy
        try:
            self._self_test(engine, verified.manifest.get("self_tests", []))
        except Exception:
            engine.close()
            raise
        loaded = LoadedPolicy(engine=engine, policy_hash=verified.policy_hash,
                              policy_version=verified.policy_version, loaded_at=self._clock(),
                              source_map=verified.source_map)
        with self._lock:
            old, self._current = self._current, loaded
        self.last_error = None
        if old is not None:
            old.engine.close()                    # waits for any in-flight check on the old engine
        if self._on_swap is not None:
            self._on_swap(loaded)
        return loaded

    @staticmethod
    def _self_test(engine, tests) -> None:
        """Runs the bundle's own expectations on the staged engine before it can take traffic."""
        if not isinstance(tests, list):
            raise PolicyError("self_tests must be a list")
        for number, test in enumerate(tests, 1):
            result = engine.check(test["request"])
            got = result.get("decision", "ERROR" if "error" in result else None)
            if got != test["expect"]:
                raise PolicyError(f"self-test {number} failed: expected {test['expect']}, got {got}")

    def close(self) -> None:
        with self._lock:
            current, self._current = self._current, None
        if current is not None:
            current.engine.close()


class Syncer:
    """Pulls bundles from a registry into a :class:`PolicyManager`.

    The registry is a directory or an HTTP(S) base URL holding ``index.json``::

        {"channels": {"stable": {"bundle": "bundles/41.json", "policy_version": 41}}}
    """

    def __init__(self, manager: PolicyManager, base: str, channel: str = "stable", *, timeout: float = 5.0):
        self._manager, self._base, self._channel, self._timeout = manager, base.rstrip("/\\"), channel, timeout
        self.errors: list[str] = []

    def _fetch(self, relative: str) -> bytes:
        if "://" in self._base:
            with urllib.request.urlopen(f"{self._base}/{relative}", timeout=self._timeout) as response:
                return response.read(8 << 20)
        with open(f"{self._base}/{relative}", "rb") as handle:
            return handle.read(8 << 20)

    def sync_once(self) -> Optional[LoadedPolicy]:
        """Returns the newly loaded policy, or None when nothing changed or the sync failed (the old
        policy keeps serving; see ``errors``)."""
        try:
            index = json.loads(self._fetch("index.json"))
            entry = index["channels"][self._channel]
            current = self._manager.current
            if current is not None and int(entry["policy_version"]) <= current.policy_version:
                return None
            doc = json.loads(self._fetch(entry["bundle"]))
            return self._manager.load_bundle(doc)
        except (PolicyError, OSError, ValueError, KeyError, TypeError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
            return None
