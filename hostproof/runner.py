"""Run checks and build an evidence bundle Sprinto accepts (.zip)."""

from __future__ import annotations

import hashlib
import io
import json
import platform
import socket
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .checks import k8s, linux
from .model import CheckResult, Executor, LocalExecutor

ALL_CHECKS = linux.CHECKS + k8s.CHECKS
BY_ID = {c.check_id: c for c in ALL_CHECKS}


@dataclass
class Context:
    ex: Executor = field(default_factory=LocalExecutor)
    kubectl: list[str] | None = None  # e.g. ["kubectl"] or ["kubectl", "--context", "prod"]


def select(only: list[str] | None = None, include_k8s: bool = False):
    if only:
        unknown = [i for i in only if i not in BY_ID]
        if unknown:
            raise KeyError(f"unknown check ids: {unknown}")
        return [BY_ID[i] for i in only]
    return [c for c in ALL_CHECKS if c.scope == "linux" or include_k8s]


def run_checks(ctx: Context, only: list[str] | None = None) -> list[CheckResult]:
    return [c.run(ctx) for c in select(only, include_k8s=bool(ctx.kubectl))]


def summary_markdown(results: list[CheckResult], meta: dict) -> str:
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines = [
        f"# Evidence: {meta['host']}",
        "",
        f"Collected {meta['collected_at']} by hostproof {meta['collector_version']} "
        f"on {meta['os']}.",
        "",
        "Result counts: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())),
        "",
        "| Check | Status | SOC 2 | ISO 27001:2022 | Detail |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.check_id} | {r.status} | {', '.join(r.soc2)} | {', '.join(r.iso27001)} | "
                     f"{r.detail.replace('|', '/')} |")
    lines += ["", "Control mappings are suggestions; your auditor confirms them.",
              "Raw command output for each check is in raw/<check_id>.txt."]
    return "\n".join(lines) + "\n"


def collection_meta() -> dict:
    return {
        "host": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "collector_version": __version__,
    }


def build_bundle(results: list[CheckResult], meta: dict | None = None) -> bytes:
    """A zip with summary.md, results.json, raw/<check>.txt and a sha256 manifest,
    so an auditor can tell whether a file was edited after collection."""
    meta = meta or collection_meta()
    files: dict[str, bytes] = {
        "summary.md": summary_markdown(results, meta).encode(),
        "results.json": json.dumps({"meta": meta, "results": [r.to_dict() for r in results]},
                                   indent=2).encode(),
    }
    for r in results:
        raw = [f"# {r.check_id}: {r.title}", f"# status: {r.status}", f"# {r.detail}", ""]
        for e in r.evidence:
            raw += [e.source + (f"   (exit {e.exit_code})" if e.exit_code is not None else ""), e.output, ""]
        files[f"raw/{r.check_id}.txt"] = "\n".join(raw).encode()
    manifest = {"meta": meta, "sha256": {n: hashlib.sha256(b).hexdigest() for n, b in sorted(files.items())}}
    files["manifest.json"] = json.dumps(manifest, indent=2).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))  # stable bytes for same input
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


def verify_bundle(data: bytes) -> list[str]:
    """Return the names of files whose hash no longer matches the manifest."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        manifest = json.loads(z.read("manifest.json"))
        return [n for n, h in manifest["sha256"].items() if hashlib.sha256(z.read(n)).hexdigest() != h]
