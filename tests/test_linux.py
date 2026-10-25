from hostproof.runner import run_checks


def status(results):
    return {r.check_id: r.status for r in results}


def test_hardened_host_passes_everything(hardened):
    s = status(run_checks(hardened))
    assert set(s.values()) == {"pass"}, s


def test_weak_host_fails_with_reasons(weak):
    rs = {r.check_id: r for r in run_checks(weak)}
    assert rs["linux.ssh_root_login"].status == "fail"
    # PasswordAuthentication unset -> OpenSSH default yes
    assert rs["linux.ssh_password_auth"].status == "fail"
    assert "OpenSSH default" in rs["linux.ssh_password_auth"].detail
    assert rs["linux.disk_encryption"].status == "fail"
    assert "sda1 (ext4) on /" in rs["linux.disk_encryption"].detail
    assert rs["linux.uid0_accounts"].detail.endswith("toor")
    assert rs["linux.audit_logging"].status == "fail"
    assert rs["linux.password_aging"].status == "fail"
    assert rs["linux.auto_updates"].status == "fail"


def test_dropin_overrides_main_config_first_value_wins(hardened):
    # main file says yes, but the Include comes first and the drop-in says no
    rs = {r.check_id: r for r in run_checks(hardened, ["linux.ssh_root_login"])}
    assert rs["linux.ssh_root_login"].status == "pass"
    assert any("50-hardening.conf" in e.source for e in rs["linux.ssh_root_login"].evidence)


def test_every_result_carries_evidence(weak):
    for r in run_checks(weak):
        assert r.evidence, r.check_id
        assert r.soc2 and r.iso27001


def test_passwd_evidence_only_keeps_uid0_lines(weak):
    r = run_checks(weak, ["linux.uid0_accounts"])[0]
    assert "bob" not in r.evidence[0].output


def test_k8s_checks_are_na_without_flag(hardened):
    rs = run_checks(hardened, ["k8s.run_as_non_root"])
    assert rs[0].status == "not_applicable"
