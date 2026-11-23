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
import json
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

__all__ = [
    "Yog",
    "Decision",
    "Obligation",
    "YogCompileError",
    "YogEvaluationError",
    "ALLOW",
    "DENY",
    "REQUIRE_APPROVAL",
    "library_path",
    "library_version",
    "__version__",
]

__version__ = "0.2.0a1"

ALLOW = "ALLOW"
DENY = "DENY"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

# Values of YogDecision in yog.h.  An unknown value is an error, never an ALLOW.
_DECISIONS = {0: ALLOW, 1: DENY, 2: REQUIRE_APPROVAL}
_MESSAGE_SIZE = 192
_SIZEOF_SIZE_T = ctypes.sizeof(ctypes.c_size_t)


@dataclass(frozen=True)
class Obligation:
    """Data the policy attaches to an ALLOW or REQUIRE_APPROVAL decision.

    YOG never performs an obligation: the enforcement point must, and must refuse the action if it cannot.
    """

    name: str
    args: Tuple[Union[str, int, bool], ...]


@dataclass(frozen=True)
class Decision:
    """The full outcome of one check."""

    decision: str                      # ALLOW, DENY or REQUIRE_APPROVAL
    reason: str
    matched_line: int
    obligations: Tuple[Obligation, ...]
    trace: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


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


class _YogObligationArg(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_int),            # 0 text, 1 integer, 2 boolean
        ("text", ctypes.c_char_p),
        ("integer", ctypes.c_longlong),
    ]


class _YogObligation(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("args", ctypes.POINTER(_YogObligationArg)),
        ("arg_count", ctypes.c_size_t),
    ]


class _YogResult(ctypes.Structure):
    # Must match YogResult in yog/include/api/yog.h field for field.
    _fields_ = [
        ("decision", ctypes.c_int),
        ("reason", ctypes.c_char_p),
        ("trace", ctypes.c_char_p),
        ("matched_line", ctypes.c_int),
        ("obligations", ctypes.POINTER(_YogObligation)),
        ("obligation_count", ctypes.c_size_t),
    ]


class _YogLimits(ctypes.Structure):
    _fields_ = [
        ("max_steps", ctypes.c_size_t),
        ("max_depth", ctypes.c_int),
        ("max_solutions", ctypes.c_size_t),
        ("max_millis", ctypes.c_size_t),
        ("max_memory", ctypes.c_size_t),
    ]


_RESOURCE_LIMIT_FIELDS = ("max_steps", "max_depth", "max_solutions", "max_millis", "max_memory")


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
    library.yog_check_json.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_bool,
        ctypes.POINTER(_YogResult),
        ctypes.POINTER(_YogError),
    ]
    library.yog_check_json.restype = ctypes.c_bool
    library.yog_result_to_json.argtypes = [ctypes.c_void_p, ctypes.POINTER(_YogResult)]
    library.yog_result_to_json.restype = ctypes.c_void_p
    library.yog_string_free.argtypes = [ctypes.c_void_p]
    library.yog_string_free.restype = None
    library.yog_policy_version.argtypes = [ctypes.c_void_p]
    library.yog_policy_version.restype = ctypes.c_int
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
        self.resource_limits = {"max_steps": steps, "max_depth": depth}

    @property
    def resource_limits(self) -> Dict[str, int]:
        """Every evaluation budget currently in force.

        Keys: ``max_steps``, ``max_depth``, ``max_solutions``, ``max_millis``
        and ``max_memory`` (bytes).  Exceeding any of them raises
        ``YogEvaluationError``, which callers must treat as DENY.
        """
        raw = _library().yog_get_limits(self._require())
        return {name: int(getattr(raw, name)) for name in _RESOURCE_LIMIT_FIELDS}

    @resource_limits.setter
    def resource_limits(self, limits: Dict[str, int]) -> None:
        """Update some budgets; keys not given keep their current value.
        A value of 0 restores the built-in default."""
        unknown = set(limits) - set(_RESOURCE_LIMIT_FIELDS)
        if unknown:
            raise ValueError(f"unknown limit(s): {', '.join(sorted(unknown))}")
        merged = self.resource_limits
        merged.update(limits)
        _library().yog_set_limits(self._require(), _YogLimits(**merged))

    def check(
        self,
        actor: str,
        action: str,
        resource: str,
        context: str = "",
        *,
        trace: bool = False,
    ) -> str:
        """Return ``"ALLOW"``, ``"DENY"`` or ``"REQUIRE_APPROVAL"`` for one request.

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
        outcome = self.decide(actor, action, resource, context, trace=trace)
        return outcome.decision, outcome.reason

    def decide(
        self,
        actor: str,
        action: str,
        resource: str,
        context: str = "",
        *,
        trace: bool = False,
    ) -> Decision:
        """Return the full :class:`Decision` (including obligations) for one request.

        ``context`` is parsed as policy text, so it must only ever contain values you trust.  For
        request data that comes from an agent or a user, use :meth:`check_json`.
        """
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
        return _finish(ok, result, error)

    def check_json(self, request: Union[str, bytes, Dict[str, Any]], *, trace: bool = False) -> Decision:
        """Check one request given as JSON (a dict, ``str`` or ``bytes``); see docs/INTERFACES.md.

        Values never pass through policy text, so this is the safe entry point for untrusted data.
        Raises :class:`YogEvaluationError` on a malformed request or an evaluation error, which callers
        must treat as DENY.
        """
        if isinstance(request, dict):
            request = json.dumps(request, ensure_ascii=False)
        data = request.encode("utf-8") if isinstance(request, str) else bytes(request)
        result = _YogResult()
        error = _YogError()
        ok = _library().yog_check_json(
            self._require(), data, len(data), bool(trace), ctypes.byref(result), ctypes.byref(error)
        )
        return _finish(ok, result, error)

    @property
    def policy_version(self) -> int:
        """The language version the policy declared with ``version N`` (1 when absent)."""
        return int(_library().yog_policy_version(self._require()))

    def _require(self):
        handle = getattr(self, "_handle", None)
        if not handle:
            raise ValueError("the policy is closed")
        return handle


def _finish(ok: bool, result: _YogResult, error: _YogError) -> Decision:
    """Converts a C result into a :class:`Decision` and always releases the C memory."""
    try:
        if not ok:
            message = error.message.decode("utf-8", "replace") or "evaluation failed"
            raise YogEvaluationError(message)
        decision = _DECISIONS.get(result.decision)
        if decision is None:
            raise YogEvaluationError(f"the library returned an unknown decision value {result.decision}")
        obligations = []
        for i in range(result.obligation_count):
            item = result.obligations[i]
            args: list = []
            for k in range(item.arg_count):
                arg = item.args[k]
                if arg.kind == 1:
                    args.append(int(arg.integer))
                elif arg.kind == 2:
                    args.append(bool(arg.integer))
                else:
                    args.append(arg.text.decode("utf-8", "replace") if arg.text else "")
            obligations.append(Obligation(item.name.decode("utf-8", "replace"), tuple(args)))
        return Decision(
            decision=decision,
            reason=result.reason.decode("utf-8", "replace") if result.reason else "",
            matched_line=int(result.matched_line),
            obligations=tuple(obligations),
            trace=result.trace.decode("utf-8", "replace") if result.trace else None,
        )
    finally:
        _library().yog_result_free(ctypes.byref(result))


def library_version() -> str:
    """Version string reported by the loaded shared library."""
    raw = _library().yog_version()
    return raw.decode("utf-8") if raw else ""


def _encode(value: str) -> bytes:
    if value is None:
        return b""
    return str(value).encode("utf-8")
