import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="stayguard-test-")
os.environ["STAYGUARD_DB"] = str(Path(_tmp) / "test.db")
os.environ["STAYGUARD_DEMO_MODE"] = "1"
# Offline, deterministic: small checked-in data snapshot and a throwaway model directory.
os.environ["STAYGUARD_DATA_RAW"] = str(Path(__file__).resolve().parent / "fixtures" / "raw")
os.environ["STAYGUARD_MODELS"] = str(Path(_tmp) / "models")
for _k in ("STAYGUARD_ANTHROPIC_API_KEY", "STAYGUARD_GEMINI_API_KEY", "STAYGUARD_JUDGE_PROVIDER"):
    os.environ.pop(_k, None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


_ENGINES: list = []


@pytest.fixture(scope="session")
def engine():
    from stayguard.engine import Engine

    e = Engine()
    _ENGINES.append(e)
    return e


@pytest.fixture(autouse=True)
def _isolate_shared_engine():
    """The session-wide engine is shared for speed; a test that trips its circuit breaker (degraded-path tests) must
    not leave it open for the next test."""
    yield
    for e in _ENGINES:
        from stayguard.judges import CircuitBreaker, OfflineJudge

        e.breaker = CircuitBreaker()
        if not isinstance(e.judge, OfflineJudge):
            e.judge = OfflineJudge()
        e.metrics.reset()


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
