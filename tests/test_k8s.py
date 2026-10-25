from hostproof.runner import run_checks

K8S = ["k8s.privileged_containers", "k8s.run_as_non_root", "k8s.network_policies",
       "k8s.cluster_admin_bindings", "k8s.image_pinning", "k8s.resource_limits"]


def by_id(ctx):
    return {r.check_id: r for r in run_checks(ctx, K8S)}


def test_privileged_and_host_network_flagged(cluster):
    r = by_id(cluster)["k8s.privileged_containers"]
    assert r.status == "fail"
    assert "web/debug-shell:shell" in r.detail and "hostNetwork" in r.detail
    assert "coredns" not in r.detail  # kube-system is skipped


def test_run_as_non_root(cluster):
    r = by_id(cluster)["k8s.run_as_non_root"]
    assert r.status == "fail"
    assert "payments" not in r.detail  # pod-level runAsNonRoot is honoured
    assert "web/frontend-5c7d8b-qwert:nginx" in r.detail


def test_network_policy_default_deny(cluster):
    r = by_id(cluster)["k8s.network_policies"]
    assert r.status == "fail"
    # web has a policy, but it allows traffic and selects one app, so it's not default-deny
    assert r.detail.endswith("default, web")


def test_cluster_admin_bindings(cluster):
    r = by_id(cluster)["k8s.cluster_admin_bindings"]
    assert r.status == "fail"
    assert "User/alice@acme.example via alice-admin" in r.detail
    assert "ServiceAccount/deployer via ci-deployer" in r.detail
    assert "system:masters" not in r.detail


def test_image_pinning_and_limits(cluster):
    rs = by_id(cluster)
    assert "nginx:latest" in rs["k8s.image_pinning"].detail and "busybox" in rs["k8s.image_pinning"].detail
    assert "payments" not in rs["k8s.image_pinning"].detail  # digest-pinned
    assert rs["k8s.resource_limits"].detail.endswith("web/frontend-5c7d8b-qwert:nginx")


def test_pod_env_secrets_never_reach_evidence(cluster):
    for r in run_checks(cluster, K8S):
        blob = r.detail + "".join(e.output for e in r.evidence)
        assert "hunter2" not in blob


def test_kubectl_failure_is_error_not_crash(hardened):
    hardened.kubectl = ["kubectl"]  # fixture executor has no kubectl -> exit 127
    r = run_checks(hardened, ["k8s.privileged_containers"])[0]
    assert r.status == "error" and "failed" in r.detail
