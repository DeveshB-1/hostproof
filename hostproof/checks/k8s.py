"""Read-only Kubernetes checks over `kubectl get ... -o json`.

Evidence stores a summary of findings, never the raw pod JSON: pod specs carry
env values, and those often hold credentials. Secrets are never listed.
"""

from __future__ import annotations

import json

from ..model import ERROR, FAIL, NA, PASS, WARN, Check, Evidence

SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease"}


def kget(ctx, resource: str, all_ns: bool = True):
    argv = ctx.kubectl + ["get", resource] + (["-A"] if all_ns else []) + ["-o", "json"]
    rc, out, err = ctx.ex.run(argv)
    cmd = "$ " + " ".join(argv)
    if rc != 0:
        raise RuntimeError(f"{cmd} failed: {(err or out).strip()[:300]}")
    return json.loads(out).get("items", []), cmd


def _containers(pod):
    spec = pod.get("spec", {})
    return (spec.get("initContainers") or []) + (spec.get("containers") or [])


def _name(obj):
    m = obj.get("metadata", {})
    return f"{m.get('namespace', '')}/{m.get('name', '')}".lstrip("/")


def _workload_pods(ctx):
    pods, cmd = kget(ctx, "pods")
    return [p for p in pods if p.get("metadata", {}).get("namespace") not in SYSTEM_NS], cmd


def check_privileged(ctx):
    pods, cmd = _workload_pods(ctx)
    bad = []
    for p in pods:
        for c in _containers(p):
            sc = c.get("securityContext") or {}
            if sc.get("privileged") or sc.get("allowPrivilegeEscalation") is True:
                bad.append(f"{_name(p)}:{c['name']}")
        if p.get("spec", {}).get("hostNetwork") or p.get("spec", {}).get("hostPID"):
            bad.append(f"{_name(p)} (hostNetwork/hostPID)")
    ev = [Evidence(cmd, f"{len(pods)} workload pods scanned; flagged: {bad or 'none'}")]
    if bad:
        return FAIL, f"{len(bad)} privileged or host-namespace findings: " + ", ".join(bad), ev
    return PASS, f"no privileged containers in {len(pods)} workload pods", ev


def check_run_as_non_root(ctx):
    pods, cmd = _workload_pods(ctx)
    bad = []
    for p in pods:
        pod_sc = p.get("spec", {}).get("securityContext") or {}
        for c in _containers(p):
            sc = c.get("securityContext") or {}
            non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            uid = sc.get("runAsUser", pod_sc.get("runAsUser"))
            if not (non_root is True or (uid is not None and uid != 0)):
                bad.append(f"{_name(p)}:{c['name']}")
    ev = [Evidence(cmd, f"{len(pods)} workload pods scanned; may run as root: {bad or 'none'}")]
    if bad:
        return FAIL, f"{len(bad)} container(s) may run as root (no runAsNonRoot / non-zero runAsUser): " \
            + ", ".join(bad), ev
    return PASS, f"all containers in {len(pods)} workload pods are pinned to non-root", ev


def check_network_policies(ctx):
    nss, cmd1 = kget(ctx, "namespaces", all_ns=False)
    pols, cmd2 = kget(ctx, "networkpolicies")
    names = [n["metadata"]["name"] for n in nss if n["metadata"]["name"] not in SYSTEM_NS]
    default_deny = set()
    for p in pols:
        spec = p.get("spec", {})
        if spec.get("podSelector", {}) in ({}, {"matchLabels": {}}) and "Ingress" in spec.get("policyTypes", ["Ingress"]) \
                and not spec.get("ingress"):
            default_deny.add(p["metadata"]["namespace"])
    missing = [n for n in names if n not in default_deny]
    ev = [Evidence(cmd1 + "\n" + cmd2,
                   f"namespaces: {names}; default-deny ingress present in: {sorted(default_deny) or 'none'}")]
    if not names:
        return NA, "no workload namespaces", ev
    if missing:
        return FAIL, "namespaces without a default-deny ingress NetworkPolicy: " + ", ".join(missing), ev
    return PASS, "every workload namespace has a default-deny ingress NetworkPolicy", ev


def check_cluster_admin(ctx):
    crbs, cmd = kget(ctx, "clusterrolebindings", all_ns=False)
    bad = []
    for b in crbs:
        if b.get("roleRef", {}).get("name") != "cluster-admin":
            continue
        for s in b.get("subjects") or []:
            n = s.get("name", "")
            if n.startswith("system:") or s.get("namespace") == "kube-system":
                continue
            bad.append(f"{s.get('kind')}/{n} via {b['metadata']['name']}")
    ev = [Evidence(cmd, f"{len(crbs)} ClusterRoleBindings scanned; non-system cluster-admin: {bad or 'none'}")]
    if bad:
        return FAIL, "non-system subjects bound to cluster-admin: " + ", ".join(bad), ev
    return PASS, "cluster-admin is bound only to system subjects", ev


def check_image_pinning(ctx):
    pods, cmd = _workload_pods(ctx)
    bad = []
    for p in pods:
        for c in _containers(p):
            img = c.get("image", "")
            last = img.rsplit("/", 1)[-1]
            if "@sha256:" in img:
                continue
            if ":" not in last or last.endswith(":latest"):
                bad.append(f"{_name(p)}:{c['name']} ({img})")
    ev = [Evidence(cmd, f"unpinned images: {bad or 'none'}")]
    if bad:
        return WARN, f"{len(bad)} container(s) on :latest or untagged images: " + ", ".join(bad), ev
    return PASS, "all workload images use a fixed tag or digest", ev


def check_resource_limits(ctx):
    pods, cmd = _workload_pods(ctx)
    bad = [f"{_name(p)}:{c['name']}" for p in pods for c in (p.get("spec", {}).get("containers") or [])
           if not (c.get("resources") or {}).get("limits")]
    ev = [Evidence(cmd, f"containers without limits: {bad or 'none'}")]
    if bad:
        return WARN, f"{len(bad)} container(s) without CPU/memory limits: " + ", ".join(bad), ev
    return PASS, "all workload containers set resource limits", ev


def _wrap(fn):
    def inner(ctx):
        if not ctx.kubectl:
            return NA, "Kubernetes checks not requested (pass --k8s)", []
        try:
            return fn(ctx)
        except RuntimeError as e:
            return ERROR, str(e), []
    return inner


CHECKS = [
    Check("k8s.privileged_containers", "No privileged or host-namespace workload containers",
          ["CC6.8"], ["A.8.9"], _wrap(check_privileged), "k8s"),
    Check("k8s.run_as_non_root", "Workload containers run as non-root", ["CC6.8"], ["A.8.9"],
          _wrap(check_run_as_non_root), "k8s"),
    Check("k8s.network_policies", "Namespaces default-deny ingress traffic", ["CC6.6"], ["A.8.22"],
          _wrap(check_network_policies), "k8s"),
    Check("k8s.cluster_admin_bindings", "cluster-admin is not granted to people or app service accounts",
          ["CC6.3"], ["A.8.2"], _wrap(check_cluster_admin), "k8s"),
    Check("k8s.image_pinning", "Workload images are pinned to a tag or digest", ["CC8.1"], ["A.8.32"],
          _wrap(check_image_pinning), "k8s"),
    Check("k8s.resource_limits", "Workload containers set resource limits", ["A1.1"], ["A.8.6"],
          _wrap(check_resource_limits), "k8s"),
]
