"""Every manifest must describe the same release as the C header."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _header_version() -> str:
    text = (ROOT / "yog" / "include" / "api" / "yog.h").read_text(encoding="utf-8")
    match = re.search(r'#define YOG_VERSION_STRING "([^"]+)"', text)
    assert match, "YOG_VERSION_STRING missing from yog.h"
    return match.group(1)


def _pep440(semver: str) -> str:
    # 0.2.0-alpha.1 -> 0.2.0a1, 0.2.0-beta.2 -> 0.2.0b2, 0.2.0-rc.1 -> 0.2.0rc1
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?", semver)
    assert match, f"unsupported version {semver!r}"
    base, tag, number = match.groups()
    if tag is None:
        return base
    return base + {"alpha": "a", "beta": "b", "rc": "rc"}[tag] + number


def _toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def test_cmake_project_version_matches_header() -> None:
    text = (ROOT / "yog" / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"project\(yog VERSION (\d+\.\d+\.\d+)", text)
    assert match, "project(yog VERSION x.y.z) missing"
    assert _header_version().startswith(match.group(1))


def test_python_packages_match_header() -> None:
    expected = _pep440(_header_version())
    assert _toml(ROOT / "pyproject.toml")["project"]["version"] == expected
    assert _toml(ROOT / "bindings" / "python" / "pyproject.toml")["project"]["version"] == expected
    binding = (ROOT / "bindings" / "python" / "yog" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{expected}"' in binding


def test_rust_crate_matches_header() -> None:
    assert _toml(ROOT / "bindings" / "rust" / "Cargo.toml")["package"]["version"] == _header_version()
