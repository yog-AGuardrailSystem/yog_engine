"""Command line for the platform tools:  python -m yog_platform <command> ...

  fmt FILE...                 format policies in place (--check: exit 1 if any file would change)
  analyze FILE                static analysis (--json, --strict, --known-obligations a,b)
  test FILE.yogtest           run policy tests with clause coverage (--yogc PATH to use the C engine)
  diff OLD NEW --requests F   show requests whose decision changes between two policies
  bundle keygen|build|verify  create keys, sign bundles, verify them
  serve                       run the sidecar
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import threading
from typing import Optional

from . import analysis, bundle, ed25519, format as yogformat, testing


def _engine_factory(yogc: Optional[str]):
    if yogc:
        from .engine import make_engine
        import tempfile
        work = tempfile.mkdtemp(prefix="yog-tool-")
        return lambda text: make_engine(text, work, yogc_path=yogc)
    from .pdp import ReferencePDP
    return ReferencePDP


def cmd_fmt(args) -> int:
    changed = 0
    for path in args.files:
        with open(path, encoding="utf-8", newline="") as handle:
            source = handle.read()
        formatted = yogformat.format_source(source)
        if not yogformat.same_meaning(source, formatted):
            print(f"{path}: formatting would change the meaning of the policy; not touching it", file=sys.stderr)
            return 2
        if formatted != source:
            changed += 1
            if args.check:
                print(f"would reformat {path}")
            else:
                with open(path, "w", encoding="utf-8", newline="") as handle:
                    handle.write(formatted)
                print(f"reformatted {path}")
    return 1 if (args.check and changed) else 0


def cmd_analyze(args) -> int:
    with open(args.file, encoding="utf-8") as handle:
        source = handle.read()
    known = args.known_obligations.split(",") if args.known_obligations else None
    findings = analysis.analyze(source, known_obligations=known)
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"{args.file}:{f['line']}: {f['severity']} {f['code']}: {f['message']}")
        print(f"{len(findings)} finding(s)")
    errors = any(f["severity"] == "error" for f in findings)
    return 1 if errors or (args.strict and findings) else 0


def cmd_test(args) -> int:
    report = testing.run_tests(args.file, _engine_factory(args.yogc))
    for r in report.results:
        print(("PASS " if r.passed else "FAIL ") + r.name + ("" if r.passed else f": {r.message}"))
    for line, kind in report.uncovered:
        print(f"uncovered: {kind} clause at line {line}")
    print(f"{sum(r.passed for r in report.results)}/{len(report.results)} passed, {len(report.uncovered)} uncovered clause(s)")
    return 0 if report.passed else 1


def cmd_diff(args) -> int:
    with open(args.old, encoding="utf-8") as a, open(args.new, encoding="utf-8") as b, \
            open(args.requests, encoding="utf-8") as c:
        old, new, requests = a.read(), b.read(), json.load(c)
    changes = testing.diff_policies(old, new, requests, _engine_factory(args.yogc))
    print(json.dumps(changes, indent=2))
    print(f"{len(changes)} of {len(requests)} request(s) changed", file=sys.stderr)
    return 1 if changes and args.fail_on_change else 0


# ------------------------------------------------------------------ bundles

def _read_hex(path: str) -> bytes:
    with open(path, encoding="ascii") as handle:
        return bytes.fromhex(handle.read().strip())


def cmd_bundle(args) -> int:
    if args.action == "keygen":
        secret = os.urandom(32)
        os.makedirs(args.out, exist_ok=True)
        secret_path = os.path.join(args.out, f"{args.key_id}.secret")
        public_path = os.path.join(args.out, f"{args.key_id}.public")
        with open(secret_path, "w", encoding="ascii") as handle:
            handle.write(secret.hex() + "\n")
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
        with open(public_path, "w", encoding="ascii") as handle:
            handle.write(ed25519.public_key(secret).hex() + "\n")
        print(f"wrote {secret_path} (keep offline) and {public_path} (give to sidecars)")
        return 0
    if args.action == "build":
        files = {}
        for root, _, names in os.walk(args.dir):
            for name in names:
                if name.endswith(".yog"):
                    full = os.path.join(root, name)
                    with open(full, encoding="utf-8", newline="") as handle:
                        files[os.path.relpath(full, args.dir).replace(os.sep, "/")] = handle.read().replace("\r\n", "\n")
        now = dt.datetime.now(dt.timezone.utc)
        self_tests = None
        if args.self_tests:
            with open(args.self_tests, encoding="utf-8") as handle:
                self_tests = json.load(handle)
        doc = bundle.build_bundle(files, policy_version=args.version, key_id=args.key_id, secret=_read_hex(args.key),
                                  created=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  not_after=(now + dt.timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  self_tests=self_tests)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2)
        print(f"wrote {args.out}: {len(files)} file(s), policy_version {args.version}")
        return 0
    if args.action == "verify":
        with open(args.file, encoding="utf-8") as handle:
            doc = json.load(handle)
        keys = {}
        for spec in args.pub:
            key_id, _, path = spec.partition(":")
            keys[key_id] = _read_hex(path)
        verified = bundle.verify_bundle(doc, keys)
        print(f"ok: policy_version {verified.policy_version}, policy_hash {verified.policy_hash}")
        return 0
    return 2


def cmd_serve(args) -> int:
    from .audit import AuditLog
    from .cache import DecisionCache
    from .engine import make_engine
    from .policy import PolicyManager, Syncer
    from .sidecar import Sidecar, make_server
    import tempfile

    keys = {}
    for spec in args.pub:
        key_id, _, path = spec.partition(":")
        keys[key_id] = _read_hex(path)
    work = tempfile.mkdtemp(prefix="yog-sidecar-")
    manager = PolicyManager(lambda text: make_engine(text, work, yogc_path=args.yogc, prefer=args.engine), keys)
    if args.bundle:
        with open(args.bundle, encoding="utf-8") as handle:
            manager.load_bundle(json.load(handle))
    audit = AuditLog(args.audit) if args.audit else None
    sidecar = Sidecar(manager, audit=audit, cache=DecisionCache(ttl=args.cache_ttl) if args.cache_ttl > 0 else None,
                      trusted_bundle_dir=args.bundle_dir, shadow=args.shadow)
    if args.registry:
        syncer = Syncer(manager, args.registry, args.channel)
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                loaded = syncer.sync_once()
                if loaded is not None and sidecar.cache:
                    sidecar.cache.clear()
                stop.wait(args.sync_interval)
        threading.Thread(target=loop, daemon=True).start()
    server = make_server(sidecar, args.host, args.port)
    print(f"yog sidecar listening on http://{args.host}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m yog_platform", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fmt"); p.add_argument("files", nargs="+"); p.add_argument("--check", action="store_true")
    p.set_defaults(run=cmd_fmt)
    p = sub.add_parser("analyze"); p.add_argument("file"); p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true"); p.add_argument("--known-obligations")
    p.set_defaults(run=cmd_analyze)
    p = sub.add_parser("test"); p.add_argument("file"); p.add_argument("--yogc")
    p.set_defaults(run=cmd_test)
    p = sub.add_parser("diff"); p.add_argument("old"); p.add_argument("new"); p.add_argument("--requests", required=True)
    p.add_argument("--yogc"); p.add_argument("--fail-on-change", action="store_true")
    p.set_defaults(run=cmd_diff)

    p = sub.add_parser("bundle"); p.set_defaults(run=cmd_bundle)
    bsub = p.add_subparsers(dest="action", required=True)
    q = bsub.add_parser("keygen"); q.add_argument("--out", required=True); q.add_argument("--key-id", required=True)
    q = bsub.add_parser("build"); q.add_argument("--dir", required=True); q.add_argument("--version", type=int, required=True)
    q.add_argument("--key", required=True); q.add_argument("--key-id", required=True); q.add_argument("--out", required=True)
    q.add_argument("--days", type=int, default=90); q.add_argument("--self-tests")
    q = bsub.add_parser("verify"); q.add_argument("file"); q.add_argument("--pub", action="append", required=True,
                                                                         help="KEY_ID:PUBLIC_KEY_FILE")

    p = sub.add_parser("serve"); p.set_defaults(run=cmd_serve)
    p.add_argument("--bundle"); p.add_argument("--pub", action="append", required=True, help="KEY_ID:PUBLIC_KEY_FILE")
    p.add_argument("--yogc"); p.add_argument("--engine", choices=["yogc", "library"], default="yogc")
    p.add_argument("--audit"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8787)
    p.add_argument("--cache-ttl", type=float, default=30.0); p.add_argument("--bundle-dir")
    p.add_argument("--shadow", action="store_true", help="log-only: record decisions, answer ALLOW (see docs/OPERATIONS.md)")
    p.add_argument("--registry"); p.add_argument("--channel", default="stable"); p.add_argument("--sync-interval", type=float, default=30.0)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (bundle.BundleError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
