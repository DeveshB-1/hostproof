"""MCP server: lets an agent (Claude, Cursor, ...) collect host evidence and push it to Sprinto.

Sprinto's own MCP server works on workspace records (controls, risks, evidence
already in Sprinto). This one runs where Sprinto's cloud integrations can't reach:
on a self-hosted Linux box or next to a cluster's kubectl.

Uploading is two-step on purpose: `upload_evidence` returns a preview unless
confirm=true, so the agent has to show the human what will be sent first.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

from .model import LocalExecutor
from .runner import ALL_CHECKS, Context, build_bundle, collection_meta, run_checks
from .sprinto import REGIONS, SprintoClient, SprintoError

mcp = MCPServer("hostproof")


def _ctx(include_k8s: bool) -> Context:
    kubectl = shlex.split(os.environ.get("HOSTPROOF_KUBECTL", "kubectl")) if include_k8s else None
    ex = LocalExecutor()
    fixture = os.environ.get("HOSTPROOF_K8S_FIXTURE")
    if include_k8s and fixture:
        from .cli import KubectlFixture
        ex, kubectl = KubectlFixture(ex, fixture), ["kubectl"]
    return Context(ex=ex, kubectl=kubectl)


def _client() -> SprintoClient:
    token = os.environ.get("SPRINTO_API_TOKEN")
    if not token:
        raise SprintoError("SPRINTO_API_TOKEN is not set")
    base = os.environ.get("SPRINTO_BASE_URL") or REGIONS[os.environ.get("SPRINTO_REGION", "us")]
    return SprintoClient(token, base_url=base)


@mcp.tool()
def list_checks() -> list[dict]:
    """List every check with its SOC 2 and ISO 27001:2022 control mapping."""
    return [{"check_id": c.check_id, "title": c.title, "scope": c.scope, "soc2": c.soc2,
             "iso27001": c.iso27001} for c in ALL_CHECKS]


@mcp.tool()
def run_compliance_checks(include_k8s: bool = False, check_ids: list[str] | None = None) -> dict:
    """Run read-only checks on this host (and the cluster, if include_k8s) and return
    pass/fail per check with the raw evidence behind each verdict."""
    results = run_checks(_ctx(include_k8s or any(i.startswith("k8s.") for i in check_ids or [])), check_ids)
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return {"counts": counts, "results": [r.to_dict() for r in results]}


@mcp.tool()
def write_evidence_bundle(path: str, include_k8s: bool = False, check_ids: list[str] | None = None) -> dict:
    """Run checks and write a zip (summary.md, results.json, raw/*.txt, sha256 manifest) to path."""
    results = run_checks(_ctx(include_k8s), check_ids)
    data = build_bundle(results)
    Path(path).write_bytes(data)
    return {"path": path, "bytes": len(data), "checks": [f"{r.check_id}={r.status}" for r in results]}


@mcp.tool()
def list_sprinto_monitors() -> list[dict]:
    """List monitors in the Sprinto workspace (pk, name, monitorType) to choose an upload target."""
    return _client().list_monitors()


@mcp.tool()
def upload_evidence(monitor_pk: str, check_ids: list[str], confirm: bool = False) -> dict:
    """Run the given checks, bundle them, and upload the zip to a Sprinto monitor.
    Without confirm=true this only returns a preview; show it to the user first."""
    include_k8s = any(i.startswith("k8s.") for i in check_ids)
    results = run_checks(_ctx(include_k8s), check_ids)
    meta = collection_meta()
    data = build_bundle(results, meta)
    name = f"hostproof-{meta['host']}-{meta['collected_at'][:10]}.zip"
    preview = {"monitor_pk": monitor_pk, "file": name, "bytes": len(data),
               "checks": [f"{r.check_id}={r.status}: {r.detail}" for r in results]}
    if not confirm:
        return {"sent": False, "preview": preview, "note": "call again with confirm=true to upload"}
    resp = _client().upload_evidence(monitor_pk, [(name, data)])
    return {"sent": True, "preview": preview, "response": resp}


def main():
    mcp.run()


if __name__ == "__main__":
    main()
