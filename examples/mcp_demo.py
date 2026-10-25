"""Drive the hostproof MCP server the way an agent would: list tools, run checks,
ask for an upload preview, then confirm it. Point SPRINTO_BASE_URL at the mock
(python -m tests.mock_sprinto) or leave it unset to use app.sprinto.com."""

import json
import os
import sys
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent


async def main(monitor_pk: str):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    params = StdioServerParameters(command=sys.executable, args=["-m", "hostproof.mcp_server"], env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        print("tools:", ", ".join(t.name for t in (await s.list_tools()).tools))
        res = await s.call_tool("list_sprinto_monitors", {})
        mons = (getattr(res, "structured_content", None) or getattr(res, "structuredContent", None) or {}).get("result") or [json.loads(c.text) for c in res.content]
        print("monitors:", [m["name"] for m in mons])
        args = {"monitor_pk": monitor_pk, "check_ids": ["linux.ssh_root_login", "linux.ssh_password_auth"]}
        pv = json.loads((await s.call_tool("upload_evidence", args)).content[0].text)
        print("preview (sent=%s):" % pv["sent"])
        for c in pv["preview"]["checks"]:
            print("  ", c)
        done = json.loads((await s.call_tool("upload_evidence", {**args, "confirm": True})).content[0].text)
        print("confirmed: sent=%s response=%s" % (done["sent"], done["response"]))


if __name__ == "__main__":
    anyio.run(main, sys.argv[1])
