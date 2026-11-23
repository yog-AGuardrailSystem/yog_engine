"""Extractor golden tests: every case in tests/golden/extractors/*.json must match exactly."""
import json
from pathlib import Path

import pytest

from yog_platform import extractors

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "extractors"
FIELD = {"sql": "query", "shell": "command", "http": "url", "k8s": "manifest"}


def cases():
    out = []
    for kind in sorted(FIELD):
        for case in json.loads((GOLDEN / f"{kind}.json").read_text(encoding="utf-8")):
            out.append(pytest.param(kind, case, id=f"{kind}: {case['name']}"))
    return out


@pytest.mark.parametrize("kind,case", cases())
def test_golden(kind, case):
    assert extractors.extract(kind, case["input"], FIELD[kind]) == case["expected"]


def test_unknown_extractor_raises_instead_of_skipping_analysis():
    with pytest.raises(KeyError):
        extractors.extract("sqll", {"query": "SELECT 1"}, "query")


@pytest.mark.parametrize("kind,junk", [(k, j) for k in FIELD for j in
                                       ("", "\x00", "'" * 50, "$(" * 200, "a" * 200_000, "\udc80", "%" * 300, "{" * 500)])
def test_hostile_input_never_raises(kind, junk):
    out = extractors.extract(kind, {FIELD[kind]: junk}, FIELD[kind])
    assert isinstance(out[kind]["parsed"], bool)
