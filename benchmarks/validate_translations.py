#!/usr/bin/env python3
"""Validate each engine's generated translation with its official checker.

This is separate from semantic equivalence: a translation can compile and still
mean the wrong thing.  Here we only prove that the artifacts are accepted by the
engine's own parser/validator.

* OPA    -- ``opa check policy.rego``
* Cedar  -- ``cedar validate`` against a generated JSON schema
* YOG    -- ``yogc validate corpus.yog``
* Casbin -- no official static validator; recorded as unsupported

Usage:
    python benchmarks/validate_translations.py [--profiles common full] [--sizes ...]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
CORPUS = HERE / "generated"
RESULTS = HERE / "results"
TRANSLATIONS = RESULTS / "translations"
EXE = ".exe" if os.name == "nt" else ""

sys.path.insert(0, str(HERE / "adapters"))
from corpus import build_model, corpus_file, parse_facts  # noqa: E402


def folder(profile: str, size: str) -> str:
    return size if profile == "full" else f"common-{size}"


def find_opa() -> str | None:
    found = shutil.which("opa")
    if found:
        return found
    local = ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")
    return str(local) if local.exists() else None


def find_cedar() -> str | None:
    found = shutil.which("cedar")
    if found:
        return found
    local = Path.home() / ".cargo" / "bin" / ("cedar.exe" if os.name == "nt" else "cedar")
    return str(local) if local.exists() else None


def find_yogc() -> str | None:
    local = ROOT / "yog" / "build-release" / f"yogc{EXE}"
    return str(local) if local.exists() else None


def cedar_schema(profile: str) -> dict:
    user_attributes = {"clearance": {"type": "Long"}} if profile == "full" else {}
    resource_attributes = {
        "public": {"type": "Boolean"},
        "owner": {"type": "Entity", "name": "Team"},
    }
    if profile == "full":
        resource_attributes["classification"] = {"type": "Long"}
    return {
        "": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": ["Role", "Team"],
                    "shape": {"type": "Record", "attributes": user_attributes},
                },
                "Role": {"shape": {"type": "Record", "attributes": {}}},
                "Team": {"shape": {"type": "Record", "attributes": {}}},
                "Resource": {
                    "shape": {"type": "Record", "attributes": resource_attributes}
                },
            },
            "actions": {
                "can_access": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Resource"],
                        "context": {"type": "Record", "attributes": {}},
                    }
                }
            },
        }
    }


def run(command: list[str]) -> tuple[bool, str]:
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output[-2000:]


def display_tool(value: str | None) -> str | None:
    """Record a tool by name only, so the artifact is machine-independent."""
    if value is None:
        return None
    name = Path(value).name
    return name[:-4] if name.lower().endswith(".exe") else name


def clean(text: str) -> str:
    """Strip the absolute checkout prefix from validator output."""
    root = str(ROOT)
    for prefix in (root + "\\", root + "/", root):
        text = text.replace(prefix, "")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", default=["common", "full"],
                        choices=["common", "full"])
    parser.add_argument("--sizes", nargs="+", default=["small", "medium", "large"],
                        choices=["small", "medium", "large"])
    args = parser.parse_args()

    opa = find_opa()
    cedar = find_cedar()
    yogc = find_yogc()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": {"opa": display_tool(opa), "cedar": display_tool(cedar),
                  "yogc": display_tool(yogc)},
        "results": {},
    }

    for profile in args.profiles:
        report["results"][profile] = {}
        for size in args.sizes:
            entry = {}
            corpus = corpus_file(CORPUS, profile, size)

            if yogc:
                ok, output = run([yogc, "validate", str(corpus)])
                entry["yog"] = {"ok": ok, "output": clean(output)}

            opa_target = TRANSLATIONS / "opa" / folder(profile, size) / "policy.rego"
            if opa and opa_target.exists():
                ok, output = run([opa, "check", str(opa_target)])
                entry["opa"] = {"ok": ok, "output": clean(output)}

            cedar_target = TRANSLATIONS / "cedar" / folder(profile, size)
            if cedar and (cedar_target / "policy.cedar").exists():
                schema_path = cedar_target / "schema.json"
                schema_path.write_text(
                    json.dumps(cedar_schema(profile), indent=2) + "\n", encoding="utf-8")
                ok, output = run([
                    cedar, "validate", "--schema", str(schema_path),
                    "--schema-format", "json",
                    "--policies", str(cedar_target / "policy.cedar"),
                ])
                entry["cedar"] = {"ok": ok, "output": clean(output)}
                alt_policy = cedar_target / "policy_alt.cedar"
                if alt_policy.exists():
                    alt_ok, alt_output = run([
                        cedar, "validate", "--schema", str(schema_path),
                        "--schema-format", "json",
                        "--policies", str(alt_policy),
                    ])
                    entry["cedar-alt"] = {"ok": alt_ok, "output": clean(alt_output)}

            casbin_target = TRANSLATIONS / "casbin" / folder(profile, size) / "model.conf"
            entry["casbin"] = {
                "ok": None,
                "output": "no official static validator; model is exercised by "
                          "the semantic-equivalence workload" if casbin_target.exists() else "",
            }

            report["results"][profile][size] = entry
            summary = {name: value["ok"] for name, value in entry.items()}
            print(f"{profile}/{size}: {summary}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "validation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Translation validation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "Official validators only. Validation proves the artifact is accepted by",
        "the engine; it does not prove semantic equivalence, which is measured in",
        "`equivalence.md`.",
        "",
        "| Profile | Size | YOG `validate` | OPA `check` | Cedar `validate` | Cedar alt `validate` | Casbin |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    def mark(value: dict | None) -> str:
        if value is None:
            return "not run"
        if value["ok"] is None:
            return "n/a"
        return "pass" if value["ok"] else "FAIL"

    for profile, sizes in report["results"].items():
        for size, entry in sizes.items():
            lines.append(
                f"| {profile} | {size} | {mark(entry.get('yog'))} | "
                f"{mark(entry.get('opa'))} | {mark(entry.get('cedar'))} | "
                f"{mark(entry.get('cedar-alt'))} | {mark(entry.get('casbin'))} |"
            )
    lines.append("")
    (RESULTS / "validation.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {RESULTS / 'validation.json'}")
    print(f"wrote {RESULTS / 'validation.md'}")
    failures = [entry for sizes in report["results"].values()
                for entry in sizes.values()
                for value in entry.values() if value.get("ok") is False]
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
