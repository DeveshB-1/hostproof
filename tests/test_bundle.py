import io
import json
import zipfile

from hostproof.runner import build_bundle, run_checks, verify_bundle

META = {"host": "web-01", "os": "Linux 6.1", "collected_at": "2026-10-25T10:00:00Z", "collector_version": "0.1.0"}


def test_bundle_contents_and_manifest(weak):
    data = build_bundle(run_checks(weak), META)
    z = zipfile.ZipFile(io.BytesIO(data))
    names = set(z.namelist())
    assert {"summary.md", "results.json", "manifest.json", "raw/linux.disk_encryption.txt"} <= names
    assert verify_bundle(data) == []
    summary = z.read("summary.md").decode()
    assert "| linux.ssh_root_login | fail | CC6.1 | A.8.2, A.8.5 |" in summary
    assert json.loads(z.read("results.json"))["meta"]["host"] == "web-01"


def test_bundle_is_deterministic(weak):
    rs = run_checks(weak)
    assert build_bundle(rs, META) == build_bundle(rs, META)


def test_tampering_is_detected(weak):
    data = build_bundle(run_checks(weak), META)
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for n in src.namelist():
            body = src.read(n)
            if n == "results.json":
                body = body.replace(b'"fail"', b'"pass"')
            out.writestr(n, body)
    assert verify_bundle(buf.getvalue()) == ["results.json"]
