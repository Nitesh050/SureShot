import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from sureshot.engine.ingest.unpack import ArchiveFormat, detect_format, unpack
from sureshot.engine.ingest.safety import UnsafeArchiveError


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", "print(1)")
    return buf.getvalue()


def _targz_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"print(1)"
        info = tarfile.TarInfo("app/main.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_detects_zip_from_magic():
    assert detect_format(io.BytesIO(_zip_bytes())) is ArchiveFormat.ZIP


def test_detects_gzip_from_magic():
    assert detect_format(io.BytesIO(_targz_bytes())) is ArchiveFormat.TAR


def test_detection_ignores_filename_extension(tmp_path: Path):
    """A .zip that is really a tarball must still unpack correctly."""
    archive = tmp_path / "repo.zip"
    archive.write_bytes(_targz_bytes())
    root = tmp_path / "out"
    report = unpack(archive, root)
    assert (root / "app/main.py").read_text() == "print(1)"
    assert report.files == 1


def test_unknown_magic_rejected(tmp_path: Path):
    archive = tmp_path / "repo.zip"
    archive.write_bytes(b"not an archive at all")
    with pytest.raises(UnsafeArchiveError, match="unrecognized"):
        unpack(archive, tmp_path / "out")


def test_detection_does_not_consume_the_stream():
    stream = io.BytesIO(_zip_bytes())
    detect_format(stream)
    assert stream.tell() == 0


def test_unpack_zip_end_to_end(tmp_path: Path):
    archive = tmp_path / "repo.zip"
    archive.write_bytes(_zip_bytes())
    root = tmp_path / "out"
    report = unpack(archive, root)
    assert (root / "app/main.py").read_text() == "print(1)"
    assert report.total_bytes == 8


def test_safety_limits_still_apply(tmp_path: Path):
    from sureshot.engine.ingest.safety import ExtractionLimits

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(20):
            zf.writestr(f"f{i}.py", "x")
    archive = tmp_path / "repo.zip"
    archive.write_bytes(buf.getvalue())
    with pytest.raises(UnsafeArchiveError, match="file count"):
        unpack(archive, tmp_path / "out", ExtractionLimits(max_files=5))