"""Session fixtures for the framework conformance harness (task #29).

One real ``verity-server`` process per pytest session (ephemeral port, against
``VERITY_TEST_DSN``), one fresh tenant per test module with two disjoint
principal-token sets: team A ``[1]`` and team B ``[2]``. Every adapter module
drives the REAL framework machinery against that server and asserts Verity's
differentiated guarantee — scoping isolation — through the framework's own API.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

E2E_DIR = Path(__file__).resolve().parent
REPO_ROOT = E2E_DIR.parent.parent
DEFAULT_DSN = "postgres://verity:verity@localhost:5433/verity"
ADMIN_TOKEN = "e2e-admin-token"
#: First boot may download the MiniLM query encoder (~23MB) before listening.
STARTUP_TIMEOUT = 300.0


def pytest_collection_modifyitems(items):
    """Belt-and-braces: everything in this package carries the e2e marker,
    so a future module cannot accidentally leak into the default mock run."""
    for item in items:
        if Path(str(item.fspath)).is_relative_to(E2E_DIR):
            item.add_marker(pytest.mark.e2e)


@pytest.fixture(scope="session")
def verity_bin() -> Path:
    """Locate (or build) the server binary: ``VERITY_BIN`` override, else
    ``target/release/verity``, built via cargo if missing."""
    override = os.environ.get("VERITY_BIN")
    if override:
        binary = Path(override)
        if not binary.is_file():
            pytest.fail(f"VERITY_BIN={override} does not exist")
        return binary
    binary = REPO_ROOT / "target" / "release" / "verity"
    if not binary.is_file():
        subprocess.run(
            ["cargo", "build", "--release", "-p", "verity-server"],
            cwd=REPO_ROOT,
            check=True,
        )
    return binary


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def verity_server(verity_bin: Path, tmp_path_factory: pytest.TempPathFactory):
    """Spawn the server on an ephemeral port, wait for /healthz, kill at
    session end. Admin surfaces run bearer-gated (not dev mode) so the e2e
    exercises the same auth path production connectors use."""
    dsn = os.environ.get("VERITY_TEST_DSN", DEFAULT_DSN)
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    log_path = tmp_path_factory.mktemp("server") / "verity.log"
    env = dict(os.environ, VERITY_ADMIN_TOKEN=ADMIN_TOKEN)
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            [str(verity_bin), "--dsn", dsn, "--listen", f"127.0.0.1:{port}"],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while True:
            if proc.poll() is not None:
                pytest.fail(
                    f"verity server exited during startup (rc={proc.returncode}); "
                    f"dsn={dsn}\n{log_path.read_text()[-4000:]}"
                )
            try:
                if httpx.get(f"{url}/healthz", timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                proc.kill()
                pytest.fail(
                    f"verity server not healthy within {STARTUP_TIMEOUT}s; "
                    f"dsn={dsn}\n{log_path.read_text()[-4000:]}"
                )
            time.sleep(0.2)
        yield SimpleNamespace(url=url, admin_token=ADMIN_TOKEN, dsn=dsn)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def tenant(verity_server, request: pytest.FixtureRequest):
    """A fresh tenant per test module, with two principal-token sets:
    team A -> ``[1]``, team B -> ``[2]`` (deterministic on a fresh tenant —
    the server allocates ``max(token)+1`` starting from 1)."""
    name = f"e2e-{request.module.__name__}-{uuid.uuid4().hex[:8]}"
    headers = {"Authorization": f"Bearer {verity_server.admin_token}"}
    with httpx.Client(base_url=verity_server.url, headers=headers, timeout=30.0) as client:
        created = client.post("/v1/admin/tenants", json={"name": name})
        created.raise_for_status()
        tenant_id = created.json()["tenant_id"]
        minted = client.post(
            "/v1/admin/principals",
            json={"tenant_id": tenant_id, "principals": ["team-a", "team-b"]},
        )
        minted.raise_for_status()
        mappings = minted.json()["mappings"]
    assert mappings == {"team-a": 1, "team-b": 2}, (
        f"fresh tenant should mint team-a=1, team-b=2, got {mappings!r}"
    )
    return SimpleNamespace(
        url=verity_server.url,
        tenant_id=tenant_id,
        admin_token=verity_server.admin_token,
        team_a=[mappings["team-a"]],
        team_b=[mappings["team-b"]],
    )
