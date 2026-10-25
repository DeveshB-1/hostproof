# hostproof

SOC 2 and ISO 27001 evidence from self-hosted Linux servers and Kubernetes clusters, pushed into Sprinto monitors through Sprinto's Upload Evidence API. It ships as a CLI and as an MCP server, so an agent can run the checks and file the evidence too.

## Why this exists

Sprinto's cloud integrations cover AWS, GCP and Azure accounts. They can't see inside a bare-metal box in a colo, an on-prem RHEL fleet, or a k3s cluster behind a VPN. For those, Sprinto's docs point to the [Upload Evidence API](https://docs.sprinto.com/api-reference/upload-evidence-api): you collect the proof yourself and POST it to a monitor.

hostproof is the "collect it yourself" part. It runs read-only checks where Sprinto can't reach, maps each one to the controls an auditor asks about, packs the raw output into a zip with a sha256 manifest, and uploads one bundle per monitor.

Sprinto already has an [official MCP server](https://docs.sprinto.com/sprinto-ai/sprinto-mcp). It works on records already inside a Sprinto workspace (controls, risks, policies, evidence). hostproof's MCP server sits on the host and produces new evidence, so the two work side by side.

## What it checks

```
$ hostproof checks
linux.ssh_root_login         SOC2 CC6.1       ISO A.8.2,A.8.5   SSH root login is disabled
linux.ssh_password_auth      SOC2 CC6.1       ISO A.8.5         SSH password authentication is disabled
linux.firewall               SOC2 CC6.6       ISO A.8.20        Host firewall is active
linux.disk_encryption        SOC2 CC6.1,CC6.7 ISO A.8.24        Data filesystems are encrypted at rest
linux.time_sync              SOC2 CC7.2       ISO A.8.17        Clock is synchronized to NTP
linux.audit_logging          SOC2 CC7.2       ISO A.8.15        Audit logging is enabled and persistent
linux.password_aging         SOC2 CC6.1       ISO A.5.17        Local password maximum age is enforced
linux.uid0_accounts          SOC2 CC6.2,CC6.3 ISO A.8.2         No extra UID 0 accounts
linux.auto_updates           SOC2 CC7.1       ISO A.8.8         Automatic security updates are enabled
k8s.privileged_containers    SOC2 CC6.8       ISO A.8.9         No privileged or host-namespace workload containers
k8s.run_as_non_root          SOC2 CC6.8       ISO A.8.9         Workload containers run as non-root
k8s.network_policies         SOC2 CC6.6       ISO A.8.22        Namespaces default-deny ingress traffic
k8s.cluster_admin_bindings   SOC2 CC6.3       ISO A.8.2         cluster-admin is not granted to people or app service accounts
k8s.image_pinning            SOC2 CC8.1       ISO A.8.32        Workload images are pinned to a tag or digest
k8s.resource_limits          SOC2 A1.1        ISO A.8.6         Workload containers set resource limits
```

ISO IDs are Annex A of ISO/IEC 27001:2022. The mappings are my suggestions; the auditor has the final say.

A few details that are easy to get wrong:

- **sshd uses the first value it reads**, and `Include` expands in place. On most distros the drop-in directory is included at the top of `sshd_config`, so a drop-in beats the main file. hostproof follows the same order and reports when a value is the OpenSSH default rather than set explicitly.
- **No root needed.** If `sshd -T` fails without root, hostproof parses the config files instead. Firewall and audit checks read service state through `systemctl`.
- **Pod specs contain secrets.** Env values in pod JSON often hold passwords. Kubernetes evidence stores only the findings (pod and container names), never the raw spec, and Secrets are never listed. A test plants `DB_PASSWORD=hunter2...` in a fixture pod and checks it never reaches the bundle.

## Quickstart

```bash
uv sync                        # or: pip install -e '.[mcp]'
uv run hostproof run           # Linux checks on this machine
uv run hostproof run --k8s --kubectl "kubectl --context prod"
uv run hostproof run --bundle evidence.zip
uv run hostproof verify evidence.zip
```

Pushing to Sprinto:

```bash
export SPRINTO_API_TOKEN=...   # your Sprinto Developer API key
uv run hostproof monitors      # pk, type and name of each monitor
cp examples/monitors.json monitors.json   # map monitor pks to check ids
uv run hostproof upload --monitors monitors.json --dry-run
uv run hostproof upload --monitors monitors.json --region in   # us | eu | in | au
```

MCP server (Claude Desktop, Claude Code, Cursor):

```json
{
  "mcpServers": {
    "hostproof": {
      "command": "uv",
      "args": ["--directory", "/path/to/hostproof", "run", "hostproof-mcp"],
      "env": { "SPRINTO_API_TOKEN": "...", "SPRINTO_REGION": "us", "HOSTPROOF_KUBECTL": "kubectl" }
    }
  }
}
```

Tools: `list_checks`, `run_compliance_checks`, `write_evidence_bundle`, `list_sprinto_monitors`, `upload_evidence`. `upload_evidence` returns a preview and sends nothing unless it's called again with `confirm=true`, so the agent has to show a person what's about to land in the audit trail.

## Sprinto API details used

From Sprinto's public docs:

- `POST {base}/api/v1/uploadEvidence`, `multipart/form-data`, header `api-token`, fields `monitor_pk` and `files` (repeatable, up to 10). Success is `201 {"success": true, "error": ""}`; a bad token is `401` with `"api-token not found"`.
- Monitor lookup: GraphQL `query { monitors { nodes { pk name monitorType } } }` on `{base}/dev-api/graphql`.
- Rate limit: 10 requests per minute per key and per IP, and going over blocks access for 10 minutes. The client waits 6.5 s between calls, which is why the two-monitor upload below takes 6.6 s.

The evidence bundle is a `.zip`, one of the formats Sprinto lists for evidence files.

## Demo run

These are real runs on my Arch Linux laptop (not a hardened server, so it fails several checks). Output is pasted as it came out, trimmed only where marked `...`.

```
$ hostproof run
WARN  linux.ssh_root_login     CC6.1       A.8.2,A.8.5   PermitRootLogin prohibit-password (OpenSSH default): root can still log in with a key
FAIL  linux.ssh_password_auth  CC6.1       A.8.5         PasswordAuthentication yes (OpenSSH default): password logins are accepted
PASS  linux.firewall           CC6.6       A.8.20        host firewall service active: firewalld
FAIL  linux.disk_encryption    CC6.1,CC6.7 A.8.24        unencrypted mounted filesystems: nvme1n1p2 (ext4) on /
PASS  linux.time_sync          CC7.2       A.8.17        system clock is NTP-synchronized
WARN  linux.audit_logging      CC7.2       A.8.15        auditd is not running; only persistent journald logs exist
FAIL  linux.password_aging     CC6.1       A.5.17        PASS_MAX_DAYS 99999 (policy: <= 90)
PASS  linux.uid0_accounts      CC6.2,CC6.3 A.8.2         root is the only UID 0 account
FAIL  linux.auto_updates       CC7.1       A.8.8         no dnf-automatic or unattended-upgrades unit is enabled

4 fail, 3 pass, 2 warn
```

Kubernetes checks against the cluster fixture in `tests/fixtures/k8s` (kubectl `-o json` output for 4 namespaces, 4 pods, 2 NetworkPolicies and 4 ClusterRoleBindings; see "What's mocked"):

```
$ hostproof run --k8s-fixture tests/fixtures/k8s --only k8s.privileged_containers k8s.run_as_non_root k8s.network_policies k8s.cluster_admin_bindings k8s.image_pinning k8s.resource_limits
FAIL  k8s.privileged_containers   CC6.8       A.8.9         2 privileged or host-namespace findings: web/debug-shell:shell, web/debug-shell (hostNetwork/hostPID)
FAIL  k8s.run_as_non_root         CC6.8       A.8.9         2 container(s) may run as root (no runAsNonRoot / non-zero runAsUser): web/frontend-5c7d8b-qwert:nginx, web/debug-shell:shell
FAIL  k8s.network_policies        CC6.6       A.8.22        namespaces without a default-deny ingress NetworkPolicy: default, web
FAIL  k8s.cluster_admin_bindings  CC6.3       A.8.2         non-system subjects bound to cluster-admin: User/alice@acme.example via alice-admin, ServiceAccount/deployer via ci-deployer
WARN  k8s.image_pinning           CC8.1       A.8.32        2 container(s) on :latest or untagged images: web/frontend-5c7d8b-qwert:nginx (nginx:latest), web/debug-shell:shell (busybox)
WARN  k8s.resource_limits         A1.1        A.8.6         1 container(s) without CPU/memory limits: web/frontend-5c7d8b-qwert:nginx

4 fail, 2 warn
```

The bundle, and the tamper check:

```
$ hostproof run --bundle out/evidence.zip    # same table as above
$ hostproof verify out/evidence.zip
manifest OK
$ unzip -l out/evidence.zip
     1273  summary.md
    18366  results.json
     3913  raw/linux.ssh_root_login.txt
     ...   (one raw/<check>.txt per check)
     1273  manifest.json
```

Upload over real HTTP to the local mock of Sprinto's endpoints (`python -m tests.mock_sprinto 18765`):

```
$ hostproof upload --monitors out/monitors.json --dry-run
[dry-run] POST /api/v1/uploadEvidence monitor_pk=7c9e6679-7425-40de-944b-e07fc1f90ae7 files=hostproof-demo-host-2026-10-25.zip (6711 bytes): linux.ssh_root_login=warn, linux.ssh_password_auth=fail
[dry-run] POST /api/v1/uploadEvidence monitor_pk=16fd2706-8baf-433b-82eb-8c7fada847da files=hostproof-demo-host-2026-10-25.zip (1876 bytes): linux.disk_encryption=fail

$ time SPRINTO_API_TOKEN=test-token hostproof upload --monitors out/monitors.json --base-url http://127.0.0.1:18765
uploaded hostproof-demo-host-2026-10-25.zip to monitor 7c9e6679-7425-40de-944b-e07fc1f90ae7: linux.ssh_root_login=warn, linux.ssh_password_auth=fail
uploaded hostproof-demo-host-2026-10-25.zip to monitor 16fd2706-8baf-433b-82eb-8c7fada847da: linux.disk_encryption=fail
real	0m6.657s

$ SPRINTO_API_TOKEN=bad hostproof upload --monitors out/monitors.json --base-url http://127.0.0.1:18765 --only linux.disk_encryption
error: upload to monitor 16fd2706-8baf-433b-82eb-8c7fada847da failed (HTTP 401): api-token not found
```

The MCP flow, driven by the MCP Python client over stdio (`examples/mcp_demo.py`):

```
tools: list_checks, run_compliance_checks, write_evidence_bundle, list_sprinto_monitors, upload_evidence
monitors: ['SSH hardening on servers', 'Encryption at rest']
preview (sent=False):
   linux.ssh_root_login=warn: PermitRootLogin prohibit-password (OpenSSH default): root can still log in with a key
   linux.ssh_password_auth=fail: PasswordAuthentication yes (OpenSSH default): password logins are accepted
confirmed: sent=True response={'success': True, 'error': ''}
```

## Tests

```
$ uv run pytest -q
.........................                                                [100%]
25 passed in 3.85s
```

They cover hardened and weak hosts through a fixture executor, sshd `Include` ordering, the Kubernetes checks, secret redaction, bundle determinism and tamper detection, multipart bytes surviving the upload intact, 400/401 handling, the 10-file cap, rate-limit spacing, and a real stdio session with the MCP server.

## What's mocked

- **Sprinto.** I don't have a Sprinto workspace or API token, so uploads went to `tests/mock_sprinto.py`, a local server written from the public docs (header name, field names, the 10-file cap, response shapes). The real call path is the same code with `--region` instead of `--base-url`. Two things I couldn't confirm from the docs: whether the GraphQL endpoint takes the same `api-token` header as the upload endpoint, and whether `/api/v1/uploadEvidence` lives on the `eu.`, `in.` and `au.` hosts too (the docs show it only on `app.sprinto.com`).
- **Kubernetes.** I tried to start k3s in rootless podman for a live cluster, but this machine doesn't delegate the cpuset cgroup to user sessions, so it exited at startup. The K8s checks ran against hand-written kubectl JSON fixtures instead. Point `--kubectl` at a real cluster and the same code runs.
- **Linux.** Not mocked. The demo above is this laptop.

## Layout

```
hostproof/checks/linux.py   9 host checks
hostproof/checks/k8s.py     6 cluster checks
hostproof/runner.py         run checks, build and verify the zip bundle
hostproof/sprinto.py        Sprinto client (upload, monitor lookup, rate limit)
hostproof/cli.py            hostproof run | upload | monitors | verify | checks
hostproof/mcp_server.py     MCP tools
tests/mock_sprinto.py       local stand-in for Sprinto's evidence endpoints
```

MIT licensed.
