"""Shared pytest fixtures for isolated SQLite test storage and live test server."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest
import uvicorn

from app.main import app


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point AUDIT_DB_PATH to an isolated temporary SQLite file per test."""
    db_file = tmp_path / "test_audit_history.db"
    monkeypatch.setenv("AUDIT_DB_PATH", str(db_file))
    return db_file


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def live_server_url() -> Iterator[str]:
    """Run the FastAPI app in a background uvicorn thread for live Playwright testing."""
    port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        server.should_exit = True
        raise RuntimeError("Live test server failed to start in time")

    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5.0)
