"""hostproof command line."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from .model import LocalExecutor
from .runner import ALL_CHECKS, Context, build_bundle, collection_meta, run_checks, verify_bundle
from .sprinto import REGIONS, SprintoClient, SprintoError, plan_uploads

ICON = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "error": "ERR ", "not_applicable": "N/A "}


class KubectlFixture:
    """Answers `kubectl get <res> ... -o json` from <dir>/<res>.json; everything else
    goes to the real local executor. Lets the K8s checks run without a cluster."""

    def __init__(self, inner, directory: str):
        self.inner, self.dir = inner, Path(directory)

    def run(self, argv):
        if argv[:2] == ["kubectl", "get"]:
            f = self.dir / f"{argv[2]}.json"
            return (0, f.read_text(), "") if f.exists() else (1, "", f"no fixture {f}")
        return self.inner.run(argv)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def make_context(args) -> Context:
    ex = LocalExecutor()
    kubectl = None
    if getattr(args, "k8s_fixture", None):
        ex, kubectl = KubectlFixture(ex, args.k8s_fixture), ["kubectl"]
    elif getattr(args, "k8s", False):
        kubectl = shlex.split(args.kubectl)
    return Context(ex=ex, kubectl=kubectl)


def print_table(results):
    w = max(len(r.check_id) for r in results)
    for r in results:
        print(f"{ICON[r.status]}  {r.check_id:<{w}}  {','.join(r.soc2):<11} {','.join(r.iso27001):<13} {r.detail}")
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print("\n" + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))


def add_run_args(p):
    p.add_argument("--k8s", action="store_true", help="also run Kubernetes checks via kubectl")
    p.add_argument("--kubectl", default="kubectl", help='kubectl command, e.g. "kubectl --context prod"')
    p.add_argument("--k8s-fixture", metavar="DIR", help="read kubectl JSON from DIR instead of a cluster")
    p.add_argument("--only", nargs="+", metavar="CHECK_ID")


def client_from(args) -> SprintoClient:
    token = os.environ.get("SPRINTO_API_TOKEN")
    if not token:
        sys.exit("set SPRINTO_API_TOKEN to your Sprinto Developer API key")
    return SprintoClient(token, base_url=args.base_url or REGIONS[args.region])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hostproof", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("checks", help="list checks and their control mappings")

    p = sub.add_parser("run", help="run checks and print results")
    add_run_args(p)
    p.add_argument("--json", action="store_true")
    p.add_argument("--bundle", metavar="ZIP", help="also write an evidence bundle")

    p = sub.add_parser("upload", help="run checks and push one bundle per Sprinto monitor")
    add_run_args(p)
    p.add_argument("--monitors", required=True, help='JSON map {"<monitor_pk>": ["check_id", ...]}')
    p.add_argument("--region", choices=REGIONS, default="us")
    p.add_argument("--base-url", help="override the Sprinto base URL")
    p.add_argument("--dry-run", action="store_true", help="show what would be sent; send nothing")

    p = sub.add_parser("monitors", help="list Sprinto monitors (pk, name, type)")
    p.add_argument("--region", choices=REGIONS, default="us")
    p.add_argument("--base-url")

    p = sub.add_parser("verify", help="check a bundle against its sha256 manifest")
    p.add_argument("zip")

    args = ap.parse_args(argv)

    if args.cmd == "checks":
        for c in ALL_CHECKS:
            print(f"{c.check_id:<28} SOC2 {','.join(c.soc2):<11} ISO {','.join(c.iso27001):<13} {c.title}")
        return 0

    if args.cmd == "verify":
        bad = verify_bundle(Path(args.zip).read_bytes())
        print("manifest OK" if not bad else "MODIFIED: " + ", ".join(bad))
        return 1 if bad else 0

    if args.cmd == "monitors":
        for m in client_from(args).list_monitors():
            print(f"{m['pk']}  {m.get('monitorType', ''):<12} {m['name']}")
        return 0

    ctx = make_context(args)
    results = run_checks(ctx, args.only)

    if args.cmd == "run":
        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print_table(results)
        if args.bundle:
            Path(args.bundle).write_bytes(build_bundle(results))
            print(f"\nwrote {args.bundle}", file=sys.stderr)
        return 1 if any(r.status == "fail" for r in results) else 0

    # upload
    monitor_map = json.loads(Path(args.monitors).read_text())
    plan = plan_uploads(results, monitor_map)
    meta = collection_meta()
    client = None if args.dry_run else client_from(args)
    failed = 0
    for pk, rs in plan:
        data = build_bundle(rs, meta)
        name = f"hostproof-{meta['host']}-{meta['collected_at'][:10]}.zip"
        status = ", ".join(f"{r.check_id}={r.status}" for r in rs)
        if args.dry_run:
            print(f"[dry-run] POST /api/v1/uploadEvidence monitor_pk={pk} files={name} ({len(data)} bytes): {status}")
            continue
        try:
            client.upload_evidence(pk, [(name, data)])
            print(f"uploaded {name} to monitor {pk}: {status}")
        except SprintoError as e:
            failed += 1
            print(f"error: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
