import json

import pytest

from app.dependencies import ManifestError, inspect_manifest, query_osv


def test_python_inventory_combines_manifest_with_exact_resolved_lock():
    inventory, warnings = inspect_manifest(
        "python",
        "requests>=2.0\nunsafe @ https://example.invalid/file.whl\n",
        "requests==2.32.4\n",
    )
    assert inventory == [
        {
            "name": "requests",
            "declared_spec": ">=2.0",
            "resolved_version": "2.32.4",
            "direct": True,
            "ecosystem": "PyPI",
        }
    ]
    assert warnings


def test_npm_lock_inventory_includes_transitive_and_multiple_versions():
    manifest = json.dumps({"dependencies": {"@scope/lib": "^2.0.0"}})
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/@scope/lib": {"version": "2.1.0"},
                "node_modules/child": {"version": "1.0.0"},
                "node_modules/@scope/lib/node_modules/child": {"version": "2.0.0"},
            },
        }
    )
    inventory, warnings = inspect_manifest("npm", manifest, lock)
    children = [item for item in inventory if item["name"] == "child"]
    assert {(item["resolved_version"], item["direct"]) for item in children} == {
        ("1.0.0", False),
        ("2.0.0", False),
    }
    package = next(item for item in inventory if item["name"] == "@scope/lib")
    assert (package["resolved_version"], package["direct"]) == ("2.1.0", True)
    assert warnings == []


def test_unsupported_npm_lock_format_and_malformed_requirements_fail_clearly():
    with pytest.raises(ManifestError, match="versions 2 and 3"):
        inspect_manifest("npm", '{"dependencies":{}}', '{"lockfileVersion":1,"dependencies":{}}')
    with pytest.raises(ManifestError, match="line 1"):
        inspect_manifest("python", "not a valid requirement !!!")


def test_osv_results_use_database_identifiers_and_reported_severity(monkeypatch):
    inventory, _ = inspect_manifest("python", "sample-package==1.2.3")
    response_body = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "OSV-EXAMPLE-1",
                        "aliases": ["CVE-2099-0001"],
                        "summary": "A test advisory supplied by the mocked database.",
                        "database_specific": {"severity": "HIGH"},
                        "modified": "2026-10-01T00:00:00Z",
                        "references": [{"url": "https://osv.dev/vulnerability/OSV-EXAMPLE-1"}],
                    }
                ],
            }
        ],
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _limit):
            return json.dumps(response_body).encode()

    class FakeOpener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.osv.dev/v1/querybatch"
            assert timeout == 15
            sent = json.loads(request.data)
            assert sent["queries"][0]["version"] == "1.2.3"
            return FakeResponse()

    monkeypatch.setattr("app.dependencies.build_opener", lambda *_: FakeOpener())
    findings = query_osv(inventory)
    assert findings[0]["id"] == "OSV-EXAMPLE-1"
    assert findings[0]["aliases"] == ["CVE-2099-0001"]
    assert findings[0]["severity"] == "high"


def test_no_resolved_versions_skip_network(monkeypatch):
    inventory, _ = inspect_manifest("python", "sample-package>=1")
    monkeypatch.setattr(
        "app.dependencies.build_opener",
        lambda *_args, **_kwargs: pytest.fail("Unresolved versions must not query vulnerability data"),
    )
    assert query_osv(inventory) == []
