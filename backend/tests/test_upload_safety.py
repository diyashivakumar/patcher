import io
import stat
import zipfile

import pytest

from app.config import get_settings
from app.services import storage


@pytest.fixture(autouse=True)
def _tmp_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "STORAGE_DIR", tmp_path / "storage")


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            if isinstance(data, zipfile.ZipInfo):
                zf.writestr(data, b"x")
            else:
                zf.writestr(name, data)
    return buf.getvalue()


def test_valid_zip_extracts_and_skips_secrets():
    data = make_zip({"app/main.py": "print('hi')\n", "app/.env": "SECRET=1", "app/key.pem": "x",
                     "app/logo.png": "x", "app/__pycache__/m.py": "x"})
    count, size, skipped = storage.extract_upload("p1", data)
    assert count == 1
    assert (storage.source_dir("p1") / "app" / "main.py").is_file()
    assert not (storage.source_dir("p1") / "app" / ".env").exists()
    reasons = {s["path"]: s["reason"] for s in skipped}
    assert "secret" in reasons["app/.env"] and "secret" in reasons["app/key.pem"]
    assert "app/logo.png" in reasons


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/abs/evil.py", "C:/evil.py"])
def test_path_traversal_rejected(name):
    with pytest.raises(storage.UploadRejected, match="traversal"):
        storage.extract_upload("p2", make_zip({name: "x"}))


def test_symlink_rejected():
    info = zipfile.ZipInfo("link.py")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(storage.UploadRejected, match="Symbolic"):
        storage.extract_upload("p3", make_zip({"link.py": info}))


def test_zip_bomb_rejected():
    with pytest.raises(storage.UploadRejected, match="ZIP bomb"):
        storage.extract_upload("p4", make_zip({"big.py": "#" * 5_000_000}))


def test_not_a_zip_rejected():
    with pytest.raises(storage.UploadRejected, match="not a ZIP"):
        storage.extract_upload("p5", b"hello world")


def test_oversize_rejected(monkeypatch):
    monkeypatch.setattr(get_settings(), "MAX_UPLOAD_MB", 0)
    with pytest.raises(storage.UploadRejected, match="larger than"):
        storage.extract_upload("p6", make_zip({"a.py": "x"}))


def test_zip_without_python_rejected():
    with pytest.raises(storage.UploadRejected, match="no Python"):
        storage.extract_upload("p7", make_zip({"readme.md": "x"}))


def test_safe_join_blocks_escape(tmp_path):
    with pytest.raises(storage.UploadRejected):
        storage.safe_join(tmp_path, "../outside.txt")
