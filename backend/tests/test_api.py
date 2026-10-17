import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.schemas import AIReviewItem, AIReviewResponse

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base.metadata.create_all(engine)


@pytest.fixture()
def client(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr("app.main.SessionLocal", TestingSession)
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def register(client, email="dev@example.test"):
    email = email.replace(".test", ".com")
    response = client.post("/api/auth/register", json={"email": email, "password": "correct-horse-battery"})
    assert response.status_code == 201
    return response.json()["access_token"]


def test_registration_requires_auth_for_analyses_and_persists_analysis(client):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "import os\n",
            "language": "python",
            "file_name": "sample.py",
        },
    )
    assert response.status_code == 202
    analysis_id = response.json()["id"]
    report = client.get(f"/api/analyses/{analysis_id}", headers=headers)
    assert report.status_code == 200
    assert report.json()["status"] == "completed"
    assert report.json()["findings"][0]["rule_id"] == "python.unused-import"
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 401


def test_analyses_are_isolated_between_users(client):
    first = register(client)
    second = register(client, "second@example.com")
    headers = {"Authorization": f"Bearer {first}"}
    submitted = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "print('ok')",
            "language": "python",
        },
    ).json()
    response = client.get(f"/api/analyses/{submitted['id']}", headers={"Authorization": f"Bearer {second}"})
    assert response.status_code == 404


def test_diff_upload_analyzes_additions_without_repository_access(client):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/diffs",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "diff": "diff --git a/new.py b/new.py\n+++ b/new.py\n@@ -0,0 +1 @@\n+import os\n",
        },
    )
    assert response.status_code == 202
    assert response.json()["mode"] == "diff"
    report = client.get(f"/api/analyses/{response.json()['id']}", headers=headers).json()
    assert report["findings"][0]["file_path"] == "new.py"


def test_quality_gate_threshold_is_configurable_per_analysis(client):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    report = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "try:\n    pass\nexcept:\n    pass\n",
            "language": "python",
            "fail_on_severity": "medium",
        },
    ).json()
    final = client.get(f"/api/analyses/{report['id']}", headers=headers).json()
    assert final["gate_threshold"] == "medium"
    assert final["quality_gate"]["threshold"] == "medium"
    assert final["quality_gate"]["passed"] is False


def test_source_filename_and_diff_paths_reject_traversal(client):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    source = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "print('x')",
            "language": "python",
            "file_name": "..\\outside.py",
        },
    )
    assert source.status_code == 422
    diff = client.post(
        "/api/diffs",
        headers=headers,
        json={
            "diff": "diff --git a/../outside.py b/../outside.py\n+++ b/../outside.py\n@@ -0,0 +1 @@\n+print('x')\n",
        },
    )
    assert diff.status_code == 422


def test_login_rejects_wrong_password(client):
    register(client)
    response = client.post("/api/auth/login", json={"email": "dev@example.com", "password": "not-the-right-password"})
    assert response.status_code == 401


def test_health_correlates_requests_with_validated_request_ids(client):
    response = client.get("/health", headers={"X-Request-ID": "request-123"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "request-123"

    invalid = client.get("/health", headers={"X-Request-ID": "x" * 65})
    assert invalid.status_code == 200
    assert invalid.headers["X-Request-ID"] != "x" * 65
    assert len(invalid.headers["X-Request-ID"]) == 36


def test_api_rejects_oversized_http_request_bodies_before_json_parsing(client):
    response = client.post(
        "/api/auth/login",
        content=b"x" * 4_000_001,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body exceeds the configured size limit"


def test_patch_suggestion_is_persisted_but_never_applied(client):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    report = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "import os\nprint('ready')\n",
            "language": "python",
            "file_name": "sample.py",
        },
    ).json()
    finding = client.get(f"/api/analyses/{report['id']}", headers=headers).json()["findings"][0]
    result = client.post(
        f"/api/analyses/{report['id']}/patch-suggestions",
        params={"finding_id": finding["id"]},
        headers=headers,
    )
    assert result.status_code == 201
    suggestion = result.json()
    assert "-import os" in suggestion["patch"]
    assert suggestion["status"] == "pending"
    decided = client.patch(
        f"/api/patch-suggestions/{suggestion['id']}",
        headers=headers,
        json={"decision": "accepted"},
    )
    assert decided.status_code == 200
    updated_report = client.get(f"/api/analyses/{report['id']}", headers=headers).json()
    assert updated_report["findings"]
    assert updated_report["patch_suggestions"][0]["status"] == "accepted"


def test_ai_review_validates_evidence_and_persists_suggestions(client, monkeypatch):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    report = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "def get_value(items):\n    return items[0]\n",
            "language": "python",
        },
    ).json()

    def fake_review(code, language):
        assert "items[0]" in code
        assert language == "python"
        return AIReviewResponse(
            findings=[
                AIReviewItem(
                    title="Empty input may fail",
                    description="The sequence can be empty before indexing.",
                    severity="medium",
                    category="correctness",
                    line=2,
                    evidence="return items[0]",
                    remediation="Check whether the sequence contains an element before indexing.",
                )
            ]
        )

    monkeypatch.setattr("app.main.request_review", fake_review)
    result = client.post(f"/api/analyses/{report['id']}/ai-review", headers=headers)
    assert result.status_code == 200
    assert result.json()["added_findings"] == 1
    final = client.get(f"/api/analyses/{report['id']}", headers=headers).json()
    assert any(item["origin"] == "ai" for item in final["findings"])


def test_ai_review_refuses_unmatched_evidence(client, monkeypatch):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    report = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "print('safe')\n",
            "language": "python",
        },
    ).json()
    monkeypatch.setattr(
        "app.main.request_review",
        lambda *_: AIReviewResponse(
            findings=[
                AIReviewItem(
                    title="Unsupported claim",
                    description="An example deliberately mismatched to source.",
                    severity="low",
                    category="correctness",
                    line=1,
                    evidence="other()",
                    remediation="Check the source for evidence before accepting this claim.",
                )
            ]
        ),
    )
    result = client.post(f"/api/analyses/{report['id']}/ai-review", headers=headers)
    assert result.status_code == 502


def test_ai_review_redacts_secrets_before_provider_and_before_persistence(client, monkeypatch):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    secret = "long-private-token-value"
    report = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": f'token = "{secret}"\n',
            "language": "python",
        },
    ).json()

    def fake_review(code, language):
        assert secret not in code
        assert "[REDACTED]" in code
        return AIReviewResponse(
            findings=[
                AIReviewItem(
                    title="Review redacted configuration",
                    description="The credential should not be committed.",
                    severity="high",
                    category="security",
                    line=1,
                    evidence="[REDACTED]",
                    remediation="Load credentials from a secret manager.",
                )
            ]
        )

    monkeypatch.setattr("app.main.request_review", fake_review)
    response = client.post(f"/api/analyses/{report['id']}/ai-review", headers=headers)
    assert response.status_code == 200
    persisted = client.get(f"/api/analyses/{report['id']}", headers=headers).json()
    assert all(secret not in str(item) for item in persisted["findings"])


def test_ai_review_fails_clearly_when_provider_is_unconfigured(client):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    report = client.post(
        "/api/analyses",
        headers=headers,
        json={
            "code": "print('no provider')",
            "language": "python",
        },
    ).json()
    response = client.post(f"/api/analyses/{report['id']}/ai-review", headers=headers)
    assert response.status_code == 503


def test_dependency_scan_inventory_and_vulnerability_results_are_persisted(client, monkeypatch):
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    monkeypatch.setattr(
        "app.main.query_osv",
        lambda _inventory: [
            {
                "package_name": "sample-package",
                "resolved_version": "1.2.3",
                "id": "OSV-TEST-1",
                "aliases": ["CVE-2099-0002"],
                "summary": "A mocked record from the vulnerability service.",
                "severity": "high",
                "modified": None,
                "references": [],
            }
        ],
    )
    response = client.post(
        "/api/dependency-scans",
        headers=headers,
        json={
            "ecosystem": "python",
            "manifest": "sample-package>=1",
            "lockfile": "sample-package==1.2.3",
        },
    )
    assert response.status_code == 202
    scan_id = response.json()["id"]
    report = client.get(f"/api/dependency-scans/{scan_id}", headers=headers).json()
    assert report["status"] == "completed"
    assert report["inventory"][0]["resolved_version"] == "1.2.3"
    assert report["vulnerabilities"][0]["id"] == "OSV-TEST-1"
    other_user = {"Authorization": f"Bearer {register(client, 'other@example.com')}"}
    assert client.get(f"/api/dependency-scans/{scan_id}", headers=other_user).status_code == 404
