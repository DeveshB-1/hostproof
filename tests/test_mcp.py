"""Starts the real MCP server over stdio and talks to it with the MCP Python client."""

import json
import os
import sys
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).parent.parent


async def _session_calls():
    env = dict(os.environ, HOSTPROOF_K8S_FIXTURE=str(ROOT / "tests/fixtures/k8s"), PYTHONPATH=str(ROOT))
    env.pop("SPRINTO_API_TOKEN", None)
    params = StdioServerParameters(command=sys.executable, args=["-m", "hostproof.mcp_server"], env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        tools = sorted(t.name for t in (await s.list_tools()).tools)
        checks = await s.call_tool("run_compliance_checks", {"check_ids": ["k8s.cluster_admin_bindings"]})
        preview = await s.call_tool("upload_evidence", {"monitor_pk": "pk-1", "check_ids": ["k8s.image_pinning"]})
        return tools, checks, preview


def _json(res):
    return json.loads(res.content[0].text)


def test_mcp_server_tools_and_preview_gate():
    tools, checks, preview = anyio.run(_session_calls)
    assert tools == ["list_checks", "list_sprinto_monitors", "run_compliance_checks", "upload_evidence",
                     "write_evidence_bundle"]
    res = _json(checks)["results"][0]
    assert res["status"] == "fail" and "alice@acme.example" in res["detail"]
    p = _json(preview)
    assert p["sent"] is False and p["preview"]["checks"][0].startswith("k8s.image_pinning=warn")
