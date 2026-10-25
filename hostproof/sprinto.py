"""Client for Sprinto's documented evidence endpoints.

Upload: POST {base}/api/v1/uploadEvidence, multipart/form-data, header `api-token`,
fields `monitor_pk` and `files` (repeatable, up to 10).
  https://docs.sprinto.com/api-reference/upload-evidence-api
Monitor lookup: GraphQL `query { monitors { nodes { pk name monitorType } } }` at
{base}/dev-api/graphql. Both endpoints share a limit of 10 requests per minute per
key and per IP; going over blocks access for 10 minutes, so the client spaces calls.
  https://docs.sprinto.com/api-reference/sprinto-developer-api
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable

REGIONS = {
    "us": "https://app.sprinto.com",
    "eu": "https://eu.sprinto.com",
    "in": "https://in.sprinto.com",
    "au": "https://au.sprinto.com",
}
MAX_FILES = 10
MIN_INTERVAL_S = 6.5  # 10 req/min, with a little slack


class SprintoError(RuntimeError):
    pass


def encode_multipart(fields: list[tuple[str, str]], files: list[tuple[str, str, bytes]]) -> tuple[bytes, str]:
    boundary = "hostproof-" + uuid.uuid4().hex
    out = bytearray()
    for name, value in fields:
        out += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
    for name, filename, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                f"Content-Type: application/zip\r\n\r\n").encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


@dataclass
class SprintoClient:
    api_token: str
    base_url: str = REGIONS["us"]
    timeout: int = 60
    min_interval: float = MIN_INTERVAL_S
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    _last: float | None = field(default=None, repr=False)

    def _throttle(self):
        if self._last is not None:
            wait = self.min_interval - (self.clock() - self._last)
            if wait > 0:
                self.sleep(wait)
        self._last = self.clock()

    def _send(self, req: urllib.request.Request) -> tuple[int, dict]:
        self._throttle()
        req.add_header("api-token", self.api_token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except ValueError:  # HTML error page from a proxy or the wrong host
                import re
                text = " ".join(re.sub(r"<[^>]+>|\{[^}]*\}", " ", body.decode(errors="replace")).split())
                return e.code, {"success": False, "error": f"non-JSON response: {text[:200]}"}

    def upload_evidence(self, monitor_pk: str, files: list[tuple[str, bytes]]) -> dict:
        if not files or len(files) > MAX_FILES:
            raise SprintoError(f"upload takes 1 to {MAX_FILES} files, got {len(files)}")
        body, ctype = encode_multipart([("monitor_pk", monitor_pk)], [("files", n, d) for n, d in files])
        req = urllib.request.Request(self.base_url.rstrip("/") + "/api/v1/uploadEvidence", data=body,
                                     method="POST", headers={"Content-Type": ctype})
        status, payload = self._send(req)
        if status not in (200, 201) or not payload.get("success"):
            err = payload.get("error")
            msg = err.get("message") if isinstance(err, dict) else err
            raise SprintoError(f"upload to monitor {monitor_pk} failed (HTTP {status}): {msg}")
        return payload

    def list_monitors(self) -> list[dict]:
        q = {"query": "query { monitors { nodes { pk name monitorType } } }"}
        req = urllib.request.Request(self.base_url.rstrip("/") + "/dev-api/graphql",
                                     data=json.dumps(q).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        status, payload = self._send(req)
        if status != 200 or payload.get("errors"):
            raise SprintoError(f"monitor lookup failed (HTTP {status}): {payload.get('errors') or payload}")
        return payload["data"]["monitors"]["nodes"]


def plan_uploads(results, monitor_map: dict[str, list[str]]) -> list[tuple[str, list]]:
    """monitor_map: {monitor_pk: [check_id, ...]} -> [(monitor_pk, [CheckResult, ...])].
    Monitors whose checks were not run are skipped."""
    by_id = {r.check_id: r for r in results}
    plan = []
    for pk, ids in monitor_map.items():
        rs = [by_id[i] for i in ids if i in by_id]
        if rs:
            plan.append((pk, rs))
    return plan
