import pytest
from fastapi.testclient import TestClient

from remediation_rag.api.app import create_app
from remediation_rag.clients.jev import JevResponseError
from remediation_rag.config import Settings
from remediation_rag.container import Container
from remediation_rag.service import RemediationService, RuntimeInfo

PY_CODE = (
    "def f(cursor, name):\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
)


@pytest.fixture
def client():
    with TestClient(create_app(Settings(_env_file=None))) as c:
        yield c


def test_health_reports_runtime_mode(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["runtime"]["app_mode"] == "offline"
    assert "MOCK" in body["runtime"]["jev"]


def test_examples_are_served(client):
    examples = client.get("/api/examples").json()
    assert {e["id"] for e in examples} >= {"py-psycopg-fstring", "out-of-scope-chat"}


def test_remediation_round_trip(client):
    response = client.post(
        "/api/remediations", json={"code": PY_CODE, "language": "python", "framework": "psycopg"}
    )
    assert response.status_code == 200
    body = response.json()
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert body["status"] == "shipped"
    assert "%s" in body["patch"]["patched_code"]
    assert {"groundedness", "security_correctness", "framework_fit"} <= body["scores"].keys()
    assert body["trace"][0]["node"] == "intent_gate"


def test_validation_errors(client):
    assert client.post("/api/remediations", json={"code": ""}).status_code == 422
    assert (
        client.post("/api/remediations", json={"code": "x", "language": "cobol"}).status_code == 422
    )


def test_oversized_code_is_rejected():
    settings = Settings(_env_file=None, max_input_code_chars=10)
    with TestClient(create_app(settings)) as c:
        assert c.post("/api/remediations", json={"code": "x" * 11}).status_code == 413


def test_jev_outage_maps_to_502():
    class BrokenService(RemediationService):
        async def remediate(self, request, *, request_id=None):
            raise JevResponseError("down", 503)

    async def factory(settings: Settings) -> Container:
        runtime = RuntimeInfo(
            app_mode="t", jev="t", generator="t", vector_store="t", embeddings="t", warnings=[]
        )
        return Container(service=BrokenService(None, settings, runtime))

    with TestClient(create_app(Settings(_env_file=None), factory)) as c:
        response = c.post("/api/remediations", json={"code": "x"})
    assert response.status_code == 502
    assert response.json()["error"] == "decision_service_unavailable"
