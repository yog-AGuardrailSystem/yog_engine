"""Argument-level information-flow (taint) tracking for YOG.

Tracks labeled sensitive values returned by source tools (e.g., ``credential``,
``pii``, ``secret``) and inspects outgoing tool-call arguments recursively.
When a tainted value appears in an argument (either as an exact match or as a
substring for tokens of length >= ``min_token_len``), this module emits:

* ``arg_tainted(ArgPath, Label)``
* ``arg_flow(SourceTool, ArgPath, Label)``

Policies can use these facts to block or require approval for data exfiltration
at argument granularity without breaking YOG's pure, stateless C core.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class TaintedValue:
    value: str
    label: str
    source_tool: str


def _iter_scalar_strings(obj: Any, prefix: str = "input") -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if isinstance(obj, str):
        if obj:
            out.append((prefix, obj))
    elif isinstance(obj, Mapping):
        for key, val in obj.items():
            out.extend(_iter_scalar_strings(val, f"{prefix}.{key}"))
    elif isinstance(obj, (list, tuple)):
        for idx, val in enumerate(obj):
            out.extend(_iter_scalar_strings(val, f"{prefix}.{idx}"))
    elif obj is not None and not isinstance(obj, bool):
        out.append((prefix, str(obj)))
    return out


class InfoFlowTracker:
    """Per-agent argument-level taint tracker."""

    def __init__(self, *, min_token_len: int = 6):
        self._min_token_len = max(1, int(min_token_len))
        self._tainted: Dict[str, List[TaintedValue]] = {}

    def record_output(self, agent: str, source_tool: str, output: Any, *, label: str = "sensitive") -> None:
        """Register string values from ``output`` under ``label`` for ``agent``."""
        bucket = self._tainted.setdefault(agent, [])
        for _, text in _iter_scalar_strings(output, prefix="output"):
            if len(text) >= self._min_token_len:
                item = TaintedValue(value=text, label=label, source_tool=source_tool)
                if item not in bucket:
                    bucket.append(item)

    def clear(self, agent: Optional[str] = None) -> None:
        if agent is None:
            self._tainted.clear()
        else:
            self._tainted.pop(agent, None)

    def tainted_values(self, agent: str) -> List[TaintedValue]:
        return list(self._tainted.get(agent, ()))

    def inspect_arguments(self, agent: str, arguments: Mapping[str, Any]) -> List[dict]:
        """Return ``arg_tainted`` and ``arg_flow`` facts for any tainted argument."""
        entries = self._tainted.get(agent)
        if not entries:
            return []

        facts: List[dict] = []
        seen_tainted = set()
        seen_flow = set()

        for arg_path, arg_text in _iter_scalar_strings(arguments, prefix="input"):
            for entry in entries:
                if entry.value in arg_text:
                    tk = (arg_path, entry.label)
                    if tk not in seen_tainted:
                        seen_tainted.add(tk)
                        facts.append({"predicate": "arg_tainted", "args": [arg_path, entry.label]})
                    fk = (entry.source_tool, arg_path, entry.label)
                    if fk not in seen_flow:
                        seen_flow.add(fk)
                        facts.append({
                            "predicate": "arg_flow",
                            "args": [entry.source_tool, arg_path, entry.label],
                        })
        return facts
