"""Engine backends: how the platform talks to the YOG C engine.

Two backends implement the same interface (``check(request) -> dict``):

* :class:`YogcEngine` keeps one ``yogc batch-json`` process open and exchanges JSON Lines with it.  It needs
  only the ``yogc`` executable and is the portable default.
* :class:`LibraryEngine` calls the shared library through the Python binding in-process.

Both are fail-closed.  A request-level problem (malformed JSON, an input type error) comes back as
``{"error": {...}}``; an infrastructure fault (crash, hang, closed engine) raises :class:`EngineError`.  Either
way the caller must treat it as DENY.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from typing import Optional


class EngineError(Exception):
    """The engine could not give an answer.  Callers must treat this as DENY."""


class YogcEngine:
    def __init__(self, yogc_path, policy_path: str, *, timeout: float = 5.0):
        # `yogc_path` is the executable, or a command prefix such as [python, script] (used in tests).
        self._yogc = list(yogc_path) if isinstance(yogc_path, (list, tuple)) else [yogc_path]
        self._policy = policy_path
        self._timeout = timeout
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._lines: "queue.Queue[Optional[str]]" = queue.Queue()
        self._closed = False
        validate = subprocess.run([*self._yogc, "validate", policy_path], capture_output=True, text=True)
        if validate.returncode != 0:
            raise EngineError(f"the policy does not compile: {(validate.stderr or validate.stdout).strip()}")
        self._start()

    # -- process management ---------------------------------------------------
    def _start(self) -> None:
        self._lines = queue.Queue()
        proc = subprocess.Popen([*self._yogc, "batch-json", self._policy], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                encoding="utf-8", bufsize=1)
        self._proc = proc

        def pump(stream, sink):
            for line in stream:
                sink.put(line)
            sink.put(None)                          # end of stream: the process exited

        threading.Thread(target=pump, args=(proc.stdout, self._lines), daemon=True).start()

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
            for stream in (proc.stdin, proc.stdout):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass

    # -- public ---------------------------------------------------------------
    def check(self, request: dict) -> dict:
        line = json.dumps(request, ensure_ascii=False, separators=(",", ":"))
        if "\n" in line or "\r" in line:                      # json.dumps never emits these; guard anyway
            raise EngineError("request contains a raw line break")
        with self._lock:
            if self._closed:
                raise EngineError("the engine is closed")
            if self._proc is None or self._proc.poll() is not None:
                self._kill()
                self._start()                                  # recover from a crash on the next call
            try:
                assert self._proc is not None and self._proc.stdin is not None
                self._proc.stdin.write(line + "\n")
                self._proc.stdin.flush()
                reply = self._lines.get(timeout=self._timeout)
            except (OSError, ValueError, queue.Empty) as exc:
                self._kill()                                   # a hung or broken process is never reused
                raise EngineError(f"the engine did not answer: {type(exc).__name__}") from exc
            if reply is None:
                self._kill()
                raise EngineError("the engine exited")
        try:
            result = json.loads(reply)
        except json.JSONDecodeError as exc:
            raise EngineError("the engine returned malformed output") from exc
        if not isinstance(result, dict):
            raise EngineError("the engine returned malformed output")
        return result

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._kill()


class LibraryEngine:
    """In-process engine using the ctypes binding (``bindings/python``)."""

    def __init__(self, policy_text: str):
        import yog                                              # the binding package, not the reference
        self._yog = yog
        self._policy = yog.Yog(policy_text)
        self._closed = False

    def check(self, request: dict) -> dict:
        if self._closed:
            raise EngineError("the engine is closed")
        try:
            outcome = self._policy.check_json(request)
        except self._yog.YogEvaluationError as exc:
            return {"error": {"message": str(exc), "line": 0, "column": 0}}
        return {"decision": outcome.decision, "reason": outcome.reason, "matched_line": outcome.matched_line,
                "policy_version": self._policy.policy_version,
                "obligations": [{"name": o.name, "args": list(o.args)} for o in outcome.obligations]}

    def close(self) -> None:
        self._closed = True
        self._policy.close()


def make_engine(policy_text: str, work_dir: str, *, yogc_path: Optional[str] = None, prefer: str = "yogc",
                timeout: float = 5.0):
    """Builds an engine for ``policy_text``.  ``prefer`` is ``"yogc"`` or ``"library"``."""
    if prefer == "library":
        return LibraryEngine(policy_text)
    if not yogc_path:
        raise EngineError("no yogc executable configured")
    os.makedirs(work_dir, exist_ok=True)
    path = os.path.join(work_dir, f"policy-{os.getpid()}-{threading.get_ident()}-{id(policy_text)}.yog")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(policy_text)
    return YogcEngine(yogc_path, path, timeout=timeout)
