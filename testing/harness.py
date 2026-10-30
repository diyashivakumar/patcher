"""Test harness: loads a copy of the practice app and gives tests a Flask test client.

Isolation guarantees (what this module is responsible for):
  * Every phase gets a brand-new SQLite file seeded from fixtures/seed/*.sql
    inside a temporary directory. The original fixture DB is never touched.
  * Outbound network connections are blocked for the whole process
    (see block_network). The Flask test client never opens sockets.
  * The app is loaded from an explicit directory under a unique module name,
    so an original copy and a patched copy can be loaded side by side.
"""
import hashlib
import importlib.util
import socket
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SEED = REPO_ROOT / "fixtures" / "seed" / "student_portal.sql"

# Synthetic actors. Tokens match fixtures/seed/student_portal.sql.
ACTORS = {
    "anonymous": None,
    "alice": "tok-alice-SYNTHETIC",        # student, owns doc 1 (private)
    "bob": "tok-bob-SYNTHETIC",            # student, owns doc 2 (private)
    "ms_rivera": "tok-rivera-SYNTHETIC",   # teacher assigned to alice
    "mr_okafor": "tok-okafor-SYNTHETIC",   # teacher with no assigned students
}


class NetworkBlockedError(RuntimeError):
    pass


_network_blocked = False


def block_network():
    """Refuse every outbound IP connection made from this process."""
    global _network_blocked
    if _network_blocked:
        return

    def _deny(*_args, **_kwargs):
        raise NetworkBlockedError("Network access is disabled inside the PatchProof test harness")

    original_connect = socket.socket.connect

    def _guarded_connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            _deny()
        return original_connect(self, address)

    socket.socket.connect = _guarded_connect
    socket.create_connection = _deny
    _network_blocked = True


def load_app_module(app_dir):
    """Import <app_dir>/app.py under a unique module name and return the module."""
    app_dir = Path(app_dir).resolve()
    app_file = app_dir / "app.py"
    if not app_file.is_file():
        raise FileNotFoundError(f"No app.py found in {app_dir}")
    name = "patchproof_fixture_" + hashlib.sha1(str(app_dir).encode()).hexdigest()[:12]
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, app_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "create_app"):
        raise AttributeError(f"{app_file} does not define create_app(config)")
    return module


@contextmanager
def fixture_client(app_dir, seed_file=DEFAULT_SEED):
    """Yield a Flask test client for the app in app_dir, backed by a fresh seeded DB."""
    with tempfile.TemporaryDirectory(prefix="patchproof-db-") as tmp:
        db_path = Path(tmp) / "portal.sqlite3"
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(Path(seed_file).read_text(encoding="utf-8"))
            conn.commit()
        finally:
            conn.close()

        module = load_app_module(app_dir)
        app = module.create_app({"DATABASE": str(db_path), "TESTING": False})
        # TESTING=False so unhandled errors become real HTTP 500 responses, as a user would see.
        app.config["PROPAGATE_EXCEPTIONS"] = False
        yield app.test_client()


def call(client, method, path, actor="anonymous", params=None):
    """Make a request as a synthetic actor and return (response, evidence dict)."""
    headers = {}
    token = ACTORS[actor]
    if token:
        headers["X-User-Token"] = token
    response = client.open(path, method=method, headers=headers, query_string=params or {})
    body = response.get_data(as_text=True)
    evidence = {
        "request": {"method": method, "path": path, "params": params or {}, "actor": actor},
        "response": {"status_code": response.status_code, "body_excerpt": body[:600]},
    }
    return response, evidence


def json_or_none(response):
    try:
        return response.get_json(silent=True)
    except Exception:  # noqa: BLE001 - malformed body is treated as "no JSON"
        return None
