"""Signed policy bundles (see docs/INTERFACES.md section 5).

A bundle carries the policy files, a manifest that names each file's SHA-256, and an Ed25519 signature over
the canonical manifest.  Verification fails closed: any problem raises :class:`BundleError` and nothing is
loaded.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Optional

from . import ed25519
from .imports import expand_imports

FORMAT = "yog-bundle-1"
ENTRY = "main.yog"


class BundleError(Exception):
    """A bundle that must not be loaded."""


def canonical(obj) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_time(text: str) -> _dt.datetime:
    try:
        return _dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except (TypeError, ValueError) as exc:
        raise BundleError(f"bad timestamp {text!r} (use YYYY-MM-DDTHH:MM:SSZ)") from exc


def build_bundle(files: Mapping[str, str], *, policy_version: int, key_id: str, secret: bytes,
                 created: str, not_after: str, language_version: int = 2) -> dict:
    """Creates and signs a bundle.  Run offline; the sidecar only verifies."""
    if ENTRY not in files:
        raise BundleError(f"a bundle needs an entry file named {ENTRY}")
    manifest = {
        "policy_version": policy_version,
        "created": created,
        "not_after": not_after,
        "engine_language_version": language_version,
        "key_id": key_id,
        "files": {name: _sha256(text.encode("utf-8")) for name, text in sorted(files.items())},
    }
    signature = ed25519.sign(secret, canonical(manifest))
    return {"format": FORMAT, "manifest": manifest, "files": dict(files),
            "signature": base64.b64encode(signature).decode("ascii")}


@dataclass(frozen=True)
class VerifiedBundle:
    manifest: dict
    policy_text: str       # entry file with imports expanded
    policy_hash: str       # SHA-256 of the canonical manifest
    policy_version: int
    source_map: list       # [(file, line)] per line of policy_text


def verify_bundle(doc, trusted_keys: Mapping[str, bytes], *, now: Optional[_dt.datetime] = None,
                  min_policy_version: int = 0, supported_language_version: int = 2) -> VerifiedBundle:
    """Verifies a bundle document and returns the policy ready to compile."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BundleError("unknown bundle format")
    manifest, files, signature = doc.get("manifest"), doc.get("files"), doc.get("signature")
    if not isinstance(manifest, dict) or not isinstance(files, dict) or not isinstance(signature, str):
        raise BundleError("malformed bundle")

    key_id = manifest.get("key_id")
    public = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if public is None:
        raise BundleError(f"bundle is signed with an unknown key {key_id!r}")
    try:
        raw_signature = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleError("signature is not valid base64") from exc
    if not ed25519.verify(public, canonical(manifest), raw_signature):
        raise BundleError("signature does not verify")

    # From here the manifest is authentic; still validate every field before trusting it.
    not_after = _parse_time(manifest.get("not_after"))
    _parse_time(manifest.get("created"))
    if now > not_after:
        raise BundleError(f"bundle expired at {manifest['not_after']}")
    version = manifest.get("policy_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise BundleError("policy_version must be a non-negative integer")
    if version < min_policy_version:
        raise BundleError(f"downgrade refused: policy_version {version} is older than {min_policy_version}")
    language = manifest.get("engine_language_version")
    if not isinstance(language, int) or language > supported_language_version:
        raise BundleError(f"bundle needs language version {language}; this engine supports "
                          f"{supported_language_version}")

    declared = manifest.get("files")
    if not isinstance(declared, dict) or set(declared) != set(files):
        raise BundleError("the files in the bundle do not match the manifest")
    for name, text in files.items():
        if not isinstance(text, str):
            raise BundleError(f"file {name!r} is not text")
        if _sha256(text.encode("utf-8")) != declared[name]:
            raise BundleError(f"file {name!r} does not match its manifest hash")
    if ENTRY not in files:
        raise BundleError(f"the bundle has no {ENTRY}")

    expanded, source_map = expand_imports(files, ENTRY)
    return VerifiedBundle(manifest=manifest, policy_text=expanded, policy_hash=_sha256(canonical(manifest)),
                          policy_version=version, source_map=source_map)
