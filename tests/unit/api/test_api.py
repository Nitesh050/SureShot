import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from sureshot.api.deps import get_runner, get_store
from sureshot.api.main import create_app
from sureshot.api.store import ScanRecord, ScanSource, ScanOptions, ScanStatus, ScanStore, now


class _RecordingRunner:
    def __init__(self):
        self.submitted = []

    def submit(self, scan_id):
        self.submitted.append(scan_id)

    def shutdown(self):
        pass


@pytest.fixture
def env(tmp_path):
    store = ScanStore(tmp_path)
    runner = _RecordingRunner()
    app = create_app()
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_runner] = lambda: runner
    return TestClient(app), store, runner


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
    return buf.getvalue()


def test_url_scan_is_queued_and_submitted(env):
    client, store, runner = env
    resp = client.post("/api/scans", json={"repo_url": "https://github.com/acme/api/tree/dev"})
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["source"]["label"] == "acme/api"
    assert body["source"]["ref"] == "dev"
    assert runner.submitted == [body["id"]]
    assert store.get(body["id"]) is not None


def test_url_scan_rejects_unsupported_host(env):
    client, _, runner = env
    resp = client.post("/api/scans", json={"repo_url": "https://evil.internal/acme/api"})
    assert resp.status_code == 400
    assert runner.submitted == []


def test_unknown_scanner_rejected(env):
    client, _, _ = env
    resp = client.post("/api/scans", json={"repo_url": "https://github.com/a/b",
                                           "scanners": ["nmap"]})
    assert resp.status_code == 400


def test_upload_scan_saves_archive(env):
    client, store, runner = env
    resp = client.post(
        "/api/scans/upload",
        files={"file": ("shop.zip", _zip_bytes(), "application/zip")},
        data={"scanners": "semgrep,trivy", "triage": "false"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["source"] == {"kind": "upload", "label": "shop", "url": None, "ref": None,
                              "commit": None, "filename": "shop.zip"}
    assert body["options"]["scanners"] == ["semgrep", "trivy"]
    assert body["options"]["triage"] is False
    assert (store.data_dir / body["id"] / "upload.bin").is_file()
    assert runner.submitted == [body["id"]]


def test_upload_rejects_wrong_extension(env):
    client, _, runner = env
    resp = client.post("/api/scans/upload", files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert resp.status_code == 400
    assert runner.submitted == []


def test_findings_require_completed_scan(env):
    client, store, _ = env
    record = store.add(ScanRecord(id="abc", created_at=now(), options=ScanOptions(),
                                  source=ScanSource(kind="upload", label="x")))
    assert client.get(f"/api/scans/{record.id}/findings").status_code == 409


def test_findings_merge_snippets(env):
    client, store, _ = env
    store.add(ScanRecord(id="done", created_at=now(), options=ScanOptions(),
                         status=ScanStatus.COMPLETED, source=ScanSource(kind="upload", label="x")))
    scan_dir = store.dir_for("done")
    (scan_dir / "report.json").write_text(json.dumps(
        {"issues": [{"finding": {"instance_id": "i1"}}, {"finding": {"instance_id": "i2"}}]}))
    (scan_dir / "snippets.json").write_text(json.dumps({"i1": {"context": "x = 1", "context_start": 3}}))

    issues = client.get("/api/scans/done/findings").json()["issues"]
    assert issues[0]["snippet"]["context"] == "x = 1"
    assert issues[1]["snippet"] is None


def test_report_download_and_missing_format(env):
    client, store, _ = env
    store.add(ScanRecord(id="done", created_at=now(), options=ScanOptions(),
                         status=ScanStatus.COMPLETED, source=ScanSource(kind="url", label="acme/api")))
    (store.dir_for("done") / "report.sarif").write_text("{}")

    resp = client.get("/api/scans/done/report/sarif")
    assert resp.status_code == 200
    assert "sureshot-acme-api-done.sarif" in resp.headers["content-disposition"]
    assert client.get("/api/scans/done/report/pdf").status_code == 404
    assert client.get("/api/scans/done/report/exe").status_code == 422


def test_store_marks_interrupted_scans_failed_on_reload(tmp_path):
    store = ScanStore(tmp_path)
    store.add(ScanRecord(id="r1", created_at=now(), options=ScanOptions(),
                         status=ScanStatus.RUNNING, source=ScanSource(kind="upload", label="x")))
    reloaded = ScanStore(tmp_path).get("r1")
    assert reloaded.status is ScanStatus.FAILED
    assert "interrupted" in reloaded.error


def test_capabilities_lists_registered_scanners(env):
    client, _, _ = env
    names = {s["name"] for s in client.get("/api/capabilities").json()["scanners"]}
    assert names == {"semgrep", "trivy", "codeql"}


def test_progress_triage_reports_completion_and_preserves_order():
    from sureshot.api.runner import _ProgressTriage

    class _Finding:
        def __init__(self, i):
            self.instance_id = f"f{i}"

    class _Engine:
        def triage(self, finding, snippet):
            return finding.instance_id

    reports = []
    wrapped = _ProgressTriage(_Engine(), lambda done, total: reports.append((done, total)))
    out = wrapped.triage_batch(tuple(_Finding(i) for i in range(3)), {})
    assert out == ("f0", "f1", "f2")
    assert reports[-1] == (3, 3)
