"""Kubernetes manifest extractor (JSON manifests; convert YAML to JSON before calling)."""
from __future__ import annotations

import json


def _containers(spec: dict):
    for key in ("containers", "initContainers"):
        for c in spec.get(key) or []:
            if isinstance(c, dict):
                yield c


def _pod_spec(doc: dict) -> dict:
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    if doc.get("kind") == "Pod":
        return spec
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    if isinstance(template.get("spec"), dict):
        return template["spec"]
    job = spec.get("jobTemplate") if isinstance(spec.get("jobTemplate"), dict) else {}
    inner = job.get("spec", {}).get("template", {}).get("spec") if isinstance(job.get("spec"), dict) else None
    return inner if isinstance(inner, dict) else {}


def extract(arguments: dict, field: str = "manifest") -> dict:
    manifest = arguments.get(field)
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except ValueError:
            return {"k8s": {"parsed": False}}
    if not isinstance(manifest, dict):
        return {"k8s": {"parsed": False}}
    docs = manifest.get("items") if manifest.get("kind") == "List" and isinstance(manifest.get("items"), list) else [manifest]
    kinds, names, namespaces, images, caps = set(), set(), set(), [], set()
    privileged = host_network = host_pid = host_path = run_as_root = escalation = latest = False
    for doc in docs:
        if not isinstance(doc, dict):
            return {"k8s": {"parsed": False}}
        kinds.add(str(doc.get("kind", "")).lower())
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        names.add(str(meta.get("name", "")))
        namespaces.add(str(meta.get("namespace", "default")))
        spec = _pod_spec(doc)
        host_network = host_network or bool(spec.get("hostNetwork"))
        host_pid = host_pid or bool(spec.get("hostPID"))
        for volume in spec.get("volumes") or []:
            host_path = host_path or (isinstance(volume, dict) and "hostPath" in volume)
        pod_security = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
        for c in _containers(spec):
            image = str(c.get("image", ""))
            images.append(image)
            tail = image.rsplit("/", 1)[-1]
            if "@" not in image:                       # a digest pins the image; otherwise no tag means :latest
                tag = tail.split(":", 1)[1] if ":" in tail else "latest"
                latest = latest or tag == "latest"
            context = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}
            privileged = privileged or bool(context.get("privileged"))
            escalation = escalation or context.get("allowPrivilegeEscalation") is True
            user = context.get("runAsUser", pod_security.get("runAsUser"))
            non_root = context.get("runAsNonRoot", pod_security.get("runAsNonRoot"))
            run_as_root = run_as_root or user == 0 or (user is None and non_root is not True)
            added = (context.get("capabilities") or {}).get("add") if isinstance(context.get("capabilities"), dict) else []
            caps.update(str(x).upper() for x in added or [])
    return {"k8s": {
        "parsed": True,
        "kind": sorted(kinds),
        "namespace": sorted(namespaces),
        "name": sorted(n for n in names if n),
        "image": sorted(set(images)),
        "privileged": privileged,
        "host_network": host_network,
        "host_pid": host_pid,
        "host_path": host_path,
        "run_as_root": run_as_root,
        "allow_privilege_escalation": escalation,
        "latest_tag": latest,
        "capability_added": sorted(caps),
    }}
