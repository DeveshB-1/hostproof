"""A local stand-in for Sprinto's evidence endpoints, built from the public docs.
It enforces what the docs state: the `api-token` header, multipart fields
`monitor_pk` + `files` (max 10), the 201/400/401 response shapes, and the
GraphQL monitor query. It is a mock: no real Sprinto workspace is involved."""

import json
import threading
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "test-token"
MONITORS = [{"pk": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "name": "SSH hardening on servers", "monitorType": "CUSTOM"},
            {"pk": "16fd2706-8baf-433b-82eb-8c7fada847da", "name": "Encryption at rest", "monitorType": "CUSTOM"}]


class Handler(BaseHTTPRequestHandler):
    uploads: list = []

    def log_message(self, *a):
        pass

    def _reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.headers.get("api-token") != TOKEN:
            return self._reply(401, {"success": False, "error": {"message": "api-token not found"}})
        if self.path == "/dev-api/graphql":
            q = json.loads(body)["query"]
            assert "monitors" in q
            return self._reply(200, {"data": {"monitors": {"nodes": MONITORS}}})
        if self.path != "/api/v1/uploadEvidence":
            return self._reply(404, {"success": False, "error": "not found"})
        msg = BytesParser(policy=default).parsebytes(
            b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + body)
        fields, files = {}, []
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if part.get_filename():
                files.append((name, part.get_filename(), part.get_payload(decode=True)))
            else:
                fields[name] = part.get_content().strip()
        pk = fields.get("monitor_pk")
        if not files or any(n != "files" for n, _, _ in files) or len(files) > 10:
            return self._reply(400, {"success": False, "error": "files field required (max 10)"})
        if pk not in {m["pk"] for m in MONITORS}:
            return self._reply(400, {"success": False, "error": f"Monitor with pk {pk} not found."})
        Handler.uploads.append({"monitor_pk": pk, "files": files})
        return self._reply(201, {"success": True, "error": ""})


def start():
    Handler.uploads = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock Sprinto on http://127.0.0.1:{port} (token: {TOKEN})", flush=True)
    srv.serve_forever()
