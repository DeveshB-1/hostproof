import io
import json
import zipfile

import pytest

from hostproof import cli
from hostproof.runner import build_bundle, run_checks, verify_bundle
from hostproof.sprinto import SprintoClient, SprintoError, plan_uploads

from . import mock_sprinto as mock


@pytest.fixture
def server():
    srv, url = mock.start()
    yield url
    srv.shutdown()


def client(url, token=mock.TOKEN):
    return SprintoClient(token, base_url=url, min_interval=0)


def test_upload_reaches_monitor_with_valid_bundle(server, weak):
    data = build_bundle(run_checks(weak))
    pk = mock.MONITORS[0]["pk"]
    assert client(server).upload_evidence(pk, [("ev.zip", data)]) == {"success": True, "error": ""}
    up = mock.Handler.uploads[-1]
    assert up["monitor_pk"] == pk
    name, fname, body = up["files"][0]
    assert (name, fname) == ("files", "ev.zip")
    assert body == data and verify_bundle(body) == []  # bytes survive multipart intact


def test_bad_token_and_unknown_monitor(server):
    with pytest.raises(SprintoError, match="HTTP 401.*api-token not found"):
        client(server, "wrong").upload_evidence(mock.MONITORS[0]["pk"], [("a.zip", b"x")])
    with pytest.raises(SprintoError, match="HTTP 400.*not found"):
        client(server).upload_evidence("nope", [("a.zip", b"x")])


def test_file_count_limit():
    with pytest.raises(SprintoError):
        SprintoClient("t").upload_evidence("pk", [(f"{i}.zip", b"x") for i in range(11)])


def test_list_monitors(server):
    assert [m["name"] for m in client(server).list_monitors()] == [m["name"] for m in mock.MONITORS]


def test_rate_limit_spacing():
    t = [100.0]
    slept = []
    c = SprintoClient("t", clock=lambda: t[0], sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s)))
    c._throttle()
    t[0] += 1.0
    c._throttle()
    assert slept == [pytest.approx(5.5)]  # 6.5s spacing keeps under 10 req/min


def test_plan_groups_checks_per_monitor(weak):
    rs = run_checks(weak)
    plan = plan_uploads(rs, {"m1": ["linux.ssh_root_login", "linux.ssh_password_auth"], "m2": ["k8s.nope"]})
    assert [(pk, [r.check_id for r in v]) for pk, v in plan] == [
        ("m1", ["linux.ssh_root_login", "linux.ssh_password_auth"])]


def test_cli_upload_end_to_end(server, tmp_path, monkeypatch, capsys):
    m = tmp_path / "monitors.json"
    m.write_text(json.dumps({mock.MONITORS[1]["pk"]: ["linux.disk_encryption", "linux.time_sync"]}))
    monkeypatch.setenv("SPRINTO_API_TOKEN", mock.TOKEN)
    rc = cli.main(["upload", "--monitors", str(m), "--base-url", server,
                   "--only", "linux.disk_encryption", "linux.time_sync"])
    assert rc == 0
    up = mock.Handler.uploads[-1]
    z = zipfile.ZipFile(io.BytesIO(up["files"][0][2]))
    ids = [r["check_id"] for r in json.loads(z.read("results.json"))["results"]]
    assert ids == ["linux.disk_encryption", "linux.time_sync"]
    assert "uploaded hostproof-" in capsys.readouterr().out


def test_cli_dry_run_sends_nothing(server, tmp_path, monkeypatch, capsys):
    m = tmp_path / "monitors.json"
    m.write_text(json.dumps({mock.MONITORS[0]["pk"]: ["linux.time_sync"]}))
    monkeypatch.delenv("SPRINTO_API_TOKEN", raising=False)
    assert cli.main(["upload", "--monitors", str(m), "--base-url", server, "--dry-run"]) == 0
    assert mock.Handler.uploads == []
    assert "[dry-run] POST /api/v1/uploadEvidence" in capsys.readouterr().out
