import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="stayguard-test-")
os.environ["STAYGUARD_DB"] = str(Path(_tmp) / "test.db")
os.environ.pop("STAYGUARD_ANTHROPIC_API_KEY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def engine():
    from stayguard.engine import Engine
    return Engine()


@pytest.fixture(scope="session")
def service(engine):
    from stayguard.service import Service
    return Service(engine)


@pytest.fixture(scope="session")
def client(service):
    from fastapi.testclient import TestClient
    from stayguard import api
    api._svc = service
    with TestClient(api.app) as c:
        yield c
