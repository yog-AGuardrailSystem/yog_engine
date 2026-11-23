"""Hash-chained audit log (see docs/INTERFACES.md section 8).

Each record stores the hash of the one before it, so editing, deleting or reordering a record breaks every
hash after it.  A chain alone cannot detect that the *tail* was cut off, so :func:`verify` accepts the
``count`` and ``last_hash`` an operator recorded elsewhere (or the sidecar reports through ``/metrics``).
Records hold hashes of requests, not their contents, so the log does not store tool arguments or secrets.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Callable, Optional

GENESIS = "0" * 64


class AuditError(Exception):
    pass


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _link(prev_hash: str, record: dict) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + _canonical(record)).hexdigest()


class AuditLog:
    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        count, last = (0, GENESIS)
        if os.path.exists(path):
            count, last = verify(path)           # refuse to extend a log that is already damaged
        self._seq, self._prev = count, last

    @property
    def count(self) -> int:
        return self._seq

    @property
    def last_hash(self) -> str:
        return self._prev

    def append(self, fields: dict) -> dict:
        with self._lock:
            record = dict(fields)
            record.update(seq=self._seq + 1, ts=int(self._clock()), prev_hash=self._prev)
            record["hash"] = _link(self._prev, {k: v for k, v in record.items() if k != "hash"})
            line = json.dumps(record, sort_keys=True, ensure_ascii=False)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._seq, self._prev = record["seq"], record["hash"]
            return record


def verify(path: str, *, expected_count: Optional[int] = None,
           expected_last_hash: Optional[str] = None) -> tuple[int, str]:
    """Checks the whole chain; returns ``(record_count, last_hash)`` or raises :class:`AuditError`."""
    prev, seq = GENESIS, 0
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                raise AuditError(f"line {number}: blank line inside the log")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditError(f"line {number}: not valid JSON") from exc
            if record.get("seq") != seq + 1:
                raise AuditError(f"line {number}: sequence is {record.get('seq')}, expected {seq + 1}")
            if record.get("prev_hash") != prev:
                raise AuditError(f"line {number}: does not follow the previous record")
            body = {k: v for k, v in record.items() if k != "hash"}
            if record.get("hash") != _link(prev, body):
                raise AuditError(f"line {number}: record was modified")
            prev, seq = record["hash"], seq + 1
    if expected_count is not None and seq != expected_count:
        raise AuditError(f"log has {seq} records but {expected_count} were expected (truncated?)")
    if expected_last_hash is not None and prev != expected_last_hash:
        raise AuditError("the last record does not match the recorded hash")
    return seq, prev
