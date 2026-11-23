"""Python binding for the YOG policy engine.

This is a thin ``ctypes`` wrapper over the public C ABI in
``yog/include/api/yog.h``.  It is a *binding*, not a reimplementation: the same
shared library the C tests use performs the parse, analysis and evaluation.

The shared library is found in this order:

1. the ``YOG_LIBRARY`` environment variable (absolute path);
2. ``yog/build-release`` then ``yog/build`` inside a source checkout;
3. the system loader's default search path.

Example::

    from yog import Yog

    policy = Yog('fact role(alice, admin)\\nallow can_access(User, R): role(User, admin)')
    assert policy.check('alice', 'can_access', 'db') == 'ALLOW'

A ``Yog`` object is immutable after compilation and every check builds its own
evaluator, so one instance may be shared between threads once ``limits`` has
been set.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading
from pathlib import Path
from typing import Optional, Tuple

__all__ = [
    "Yog",
    "YogCompileError",
    "YogEvaluationError",
    "ALLOW",
    "DENY",
    "library_path",
    "library_version",
    "__version__",
]

__version__ = "0.2.0a1"

ALLOW = "ALLOW"
DENY = "DENY"

_YOG_ALLOW = 0
_YOG_DENY = 1
_MESSAGE_SIZE = 192
_SIZEOF_SIZE_T = ctypes.sizeof(ctypes.c_size_t)


class YogCompileError(ValueError):
    """Raised when the policy source does not compile."""

    def __init__(self, message: str, line: int = 0, column: int = 0) -> None:
        super().__init__(f"{line}:{column}: {message}" if line else message)
        self.message = message
        self.line = line
        self.column = column


class YogEvaluationError(RuntimeError):
    """Raised when evaluation fails.  Callers must treat this as a DENY."""


class _YogError(ctypes.Structure):
    _fields_ = [
        ("line", ctypes.c_int),
        ("column", ctypes.c_int),
        ("message", ctypes.c_char * _MESSAGE_SIZE),
    ]


class _YogResult(ctypes.Structure):
    _fields_ = [
        ("decision", ctypes.c_int),
        ("reason", ctypes.c_char_p),
        ("trace", ctypes.c_char_p),
    ]


class _YogLimits(ctypes.Structure):
    _fields_ = [
        ("max_steps", ctypes.c_size_t),
        ("max_depth", ctypes.c_int),
    ]


def _candidate_paths() -> list[Path]:
    suffix = ".dll" if sys.platform == "win32" else ".so"
    names = [f"yog{suffix}"]
    if sys.platform == "darwin":
        names = ["libyog.dylib", "yog.dylib"]
    elif sys.platform != "win32":
        names = ["libyog.so", "yog.so"]

    candidates: list[Path] = []
    override = os.environ.get("YOG_LIBRARY")
    if override:
        candidates.append(Path(override))

    # bindings/python/yog/__init__.py -> repository root
    root = Path(__file__).resolve().parents[3]
    for build in ("build-release", "build", "build-asan"):
        for name in names:
            candidates.append(root / "yog" / build / name)
    return candidates


def library_path() -> str:
    """Return the shared library path that will be loaded."""
    for candidate in _candidate_paths():
        if candidate.is_file():
            return str(candidate)
    # Fall back to the system loader; ctypes raises OSError with a useful
    # message if the library really is missing.
    return "yog"


def _load() -> ctypes.CDLL:
    path = library_path()
    try:
        library = ctypes.CDLL(path)
    except OSError as error:  # pragma: no cover - environment dependent
        raise OSError(
            f"cannot load the YOG shared library ({path!r}). Build it with "
            "'cmake --build yog/build-release --target yog_shared' or set "
            "YOG_LIBRARY to its full path."
        ) from error

    library.yog_compile.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(_YogError)
    ]
    library.yog_compile.restype = ctypes.c_void_p
    library.yog_free.argtypes = [ctypes.c_void_p]
    library.yog_free.restype = None
    library.yog_set_limits.argtypes = [ctypes.c_void_p, _YogLimits]
    library.yog_set_limits.restype = None
    library.yog_get_limits.argtypes = [ctypes.c_void_p]
    library.yog_get_limits.restype = _YogLimits
    library.yog_check.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_bool,
        ctypes.POINTER(_YogResult),
        ctypes.POINTER(_YogError),
    ]
    library.yog_check.restype = ctypes.c_bool
    library.yog_result_free.argtypes = [ctypes.POINTER(_YogResult)]
    library.yog_result_free.restype = None
    library.yog_version.argtypes = []
    library.yog_version.restype = ctypes.c_char_p
    return library


_LIBRARY: Optional[ctypes.CDLL] = None
_LIBRARY_LOCK = threading.Lock()


def _library() -> ctypes.CDLL:
    global _LIBRARY
    with _LIBRARY_LOCK:
        if _LIBRARY is None:
            _LIBRARY = _load()
        return _LIBRARY


class Yog:
    """A compiled YOG policy."""

    def __init__(self, source: str, *, limits: Optional[Tuple[int, int]] = None) -> None:
        if not isinstance(source, str):
            raise TypeError("source must be str")
        encoded = source.encode("utf-8")
        error = _YogError()
        handle = _library().yog_compile(encoded, len(encoded), ctypes.byref(error))
        if not handle:
            message = error.message.decode("utf-8", "replace")
            raise YogCompileError(message, error.line, error.column)
        self._handle = handle
        if limits is not None:
            self.limits = limits

    def close(self) -> None:
        handle = getattr(self, "_handle", None)
        if handle:
            _library().yog_free(handle)
            self._handle = None

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "Yog":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def limits(self) -> Tuple[int, int]:
        """(max_steps, max_depth) currently in force."""
        raw = _library().yog_get_limits(self._require())
        return int(raw.max_steps), int(raw.max_depth)

    @limits.setter
    def limits(self, limits: Tuple[int, int]) -> None:
        steps, depth = limits
        _library().yog_set_limits(
            self._require(), _YogLimits(ctypes.c_size_t(steps), ctypes.c_int(depth))
        )

    def check(
        self,
        actor: str,
        action: str,
        resource: str,
        context: str = "",
        *,
        trace: bool = False,
    ) -> str:
        """Return ``"ALLOW"`` or ``"DENY"`` for one request.

        ``context`` is an optional ``;``-separated list of ground facts.  On an
        evaluation error this raises :class:`YogEvaluationError`; callers that
        need fail-closed behaviour must catch it and deny.
        """
        return self.evaluate(actor, action, resource, context, trace=trace)[0]

    def evaluate(
        self,
        actor: str,
        action: str,
        resource: str,
        context: str = "",
        *,
        trace: bool = False,
    ) -> Tuple[str, str]:
        """Return ``(decision, reason)`` for one request."""
        result = _YogResult()
        error = _YogError()
        ok = _library().yog_check(
            self._require(),
            _encode(actor),
            _encode(action),
            _encode(resource),
            _encode(context),
            bool(trace),
            ctypes.byref(result),
            ctypes.byref(error),
        )
        try:
            if not ok:
                message = error.message.decode("utf-8", "replace") or "evaluation failed"
                raise YogEvaluationError(message)
            decision = ALLOW if result.decision == _YOG_ALLOW else DENY
            reason = result.reason.decode("utf-8", "replace") if result.reason else ""
            return decision, reason
        finally:
            _library().yog_result_free(ctypes.byref(result))

    def _require(self):
        handle = getattr(self, "_handle", None)
        if not handle:
            raise ValueError("the policy is closed")
        return handle


def library_version() -> str:
    """Version string reported by the loaded shared library."""
    raw = _library().yog_version()
    return raw.decode("utf-8") if raw else ""


def _encode(value: str) -> bytes:
    if value is None:
        return b""
    return str(value).encode("utf-8")
