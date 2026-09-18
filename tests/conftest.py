import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _opa_reachable(url: str) -> bool:
    from urllib.parse import urlparse
    p = urlparse(url)
    host, port = p.hostname or "127.0.0.1", p.port or 8181
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    db_path = tmp_path / "cybercity.db"
    monkeypatch.setenv("FIREWALL_DB", str(db_path))
    monkeypatch.setenv("OPA_URL", os.environ.get("OPA_URL", "http://127.0.0.1:8181"))
    # Reload modules that captured DB_PATH at import time.
    import importlib
    import app.db as _db, app.auth as _auth, app.tools as _t, app.assistant as _a, app.gateway as _g, app.main as _m
    for mod in (_db, _auth, _t, _a, _g, _m):
        importlib.reload(mod)
    import seed as seed_mod
    importlib.reload(seed_mod)
    _db.reset_db()
    seed_mod.seed()
    _t.SENT_RESETS.clear()
    yield


@pytest.fixture
def opa_url():
    url = os.environ.get("OPA_URL", "http://127.0.0.1:8181")
    if not _opa_reachable(url):
        pytest.skip(f"OPA not reachable at {url}; start it via docker-compose or run.sh")
    return url
