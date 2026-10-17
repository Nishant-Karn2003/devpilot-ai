import json
import logging
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from packaging.requirements import InvalidRequirement, Requirement

logger = logging.getLogger("devpilot.dependencies")


class ManifestError(ValueError):
    pass


class VulnerabilityServiceError(Exception):
    pass


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, new_url):
        return None


def inspect_manifest(ecosystem: str, manifest: str, lockfile: str | None = None) -> tuple[list[dict], list[str]]:
    if ecosystem == "python":
        return _python_inventory(manifest, lockfile)
    if ecosystem == "npm":
        return _npm_inventory(manifest, lockfile)
    raise ManifestError("Unsupported dependency ecosystem")


def _python_inventory(manifest: str, lockfile: str | None) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    direct = _parse_requirements(manifest, "manifest", warnings)
    locked = _parse_requirements(lockfile, "lockfile", warnings) if lockfile else {}
    inventory = []
    for key, item in direct.items():
        resolved = locked.get(key, {}).get("resolved_version") or item["resolved_version"]
        inventory.append({**item, "resolved_version": resolved, "direct": True, "ecosystem": "PyPI"})
    for key, item in locked.items():
        if key not in direct:
            inventory.append({**item, "direct": False, "ecosystem": "PyPI"})
    if not lockfile:
        warnings.append("No lockfile supplied; only exact-pinned requirements can be vulnerability-scanned.")
    return sorted(inventory, key=lambda item: item["name"].casefold()), warnings


def _parse_requirements(text: str | None, source: str, warnings: list[str]) -> dict[str, dict]:
    parsed: dict[str, dict] = {}
    for number, raw_line in enumerate((text or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", ".")) or "://" in line:
            warnings.append(f"Ignored unsupported {source} entry at line {number}.")
            continue
        line = line.split(" #", maxsplit=1)[0].strip()
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise ManifestError(f"Invalid {source} requirement at line {number}.") from exc
        if requirement.url:
            warnings.append(f"Ignored direct URL dependency at line {number}; registry metadata is not trusted.")
            continue
        key = _normalize_name(requirement.name)
        exact = _exact_version(str(requirement.specifier))
        item = {
            "name": requirement.name,
            "declared_spec": str(requirement.specifier) or "*",
            "resolved_version": exact,
        }
        if source == "manifest" or key not in parsed or exact:
            parsed[key] = item
    return parsed


def _exact_version(specifier: str) -> str | None:
    match = re.fullmatch(r"==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)", specifier)
    return match.group(1) if match else None


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _npm_inventory(manifest: str, lockfile: str | None) -> tuple[list[dict], list[str]]:
    try:
        package = json.loads(manifest)
    except json.JSONDecodeError as exc:
        raise ManifestError("The npm manifest must be valid JSON.") from exc
    if not isinstance(package, dict):
        raise ManifestError("The npm manifest must be a JSON object.")
    direct: dict[str, str] = {}
    for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        entries = package.get(group, {})
        if not isinstance(entries, dict):
            raise ManifestError(f"The {group} manifest field must be an object.")
        for name, version in entries.items():
            if not isinstance(name, str) or not isinstance(version, str):
                raise ManifestError("Dependency names and declared versions must be strings.")
            direct[name] = version

    warnings = []
    resolved: list[tuple[str, str, bool]] = []
    if lockfile:
        try:
            lock = json.loads(lockfile)
        except json.JSONDecodeError as exc:
            raise ManifestError("The npm lockfile must be valid JSON.") from exc
        if not isinstance(lock, dict) or lock.get("lockfileVersion", 0) not in (2, 3):
            raise ManifestError("Only npm package-lock versions 2 and 3 are supported.")
        packages = lock.get("packages", {})
        if not isinstance(packages, dict):
            raise ManifestError("The npm lockfile packages field must be an object.")
        for location, entry in packages.items():
            if not location or not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
                continue
            marker = "node_modules/"
            name = location.rsplit(marker, maxsplit=1)[-1] if marker in location else ""
            if name and not name.startswith(".") and not name.startswith(".."):
                resolved.append((name, entry["version"], location == f"node_modules/{name}"))
    else:
        warnings.append("No package-lock supplied; dependency versions are declared ranges, not resolved versions.")

    inventory = [
        {
            "name": name,
            "declared_spec": direct.get(name, ""),
            "resolved_version": None,
            "direct": True,
            "ecosystem": "npm",
        }
        for name in direct
        if not any(dependency_name == name and is_direct for dependency_name, _, is_direct in resolved)
    ]
    inventory.extend(
        {
            "name": name,
            "declared_spec": direct.get(name, ""),
            "resolved_version": version,
            "direct": name in direct and is_direct,
            "ecosystem": "npm",
        }
        for name, version, is_direct in set(resolved)
    )
    if len(inventory) > 500:
        raise ManifestError("A dependency scan is limited to 500 package records.")
    return sorted(inventory, key=lambda item: (item["name"].casefold(), item["resolved_version"] or "")), warnings


def query_osv(inventory: list[dict]) -> list[dict]:
    resolved = [item for item in inventory if item.get("resolved_version")]
    if not resolved:
        return []
    if len(resolved) > 500:
        raise VulnerabilityServiceError("Dependency scan exceeds the supported package limit")
    payload = {
        "queries": [
            {
                "package": {"name": item["name"], "ecosystem": item["ecosystem"]},
                "version": item["resolved_version"],
            }
            for item in resolved
        ]
    }
    request = Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        # This URL is a fixed HTTPS constant and never comes from a manifest.
        with build_opener(_NoRedirectHandler).open(request, timeout=15) as response:
            raw = response.read(2_000_001)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        logger.warning("OSV lookup failed error_type=%s", type(exc).__name__)
        raise VulnerabilityServiceError("The OSV vulnerability database could not be reached.") from exc
    if len(raw) > 2_000_000:
        raise VulnerabilityServiceError("The OSV vulnerability response exceeded the size limit.")
    try:
        results = json.loads(raw)["results"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise VulnerabilityServiceError("The OSV vulnerability service returned invalid data.") from exc
    if not isinstance(results, list) or len(results) != len(resolved):
        raise VulnerabilityServiceError("The OSV vulnerability service returned an incomplete response.")

    findings = []
    for dependency, result in zip(resolved, results, strict=True):
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                raise VulnerabilityServiceError("The OSV vulnerability service returned an invalid record.")
            database_specific = vulnerability.get("database_specific", {})
            severity = (
                database_specific.get("severity", "unspecified")
                if isinstance(database_specific, dict)
                else "unspecified"
            )
            findings.append(
                {
                    "package_name": dependency["name"],
                    "resolved_version": dependency["resolved_version"],
                    "id": vulnerability["id"],
                    "aliases": [value for value in vulnerability.get("aliases", []) if isinstance(value, str)][:20],
                    "summary": str(
                        vulnerability.get("summary") or "No summary supplied by the vulnerability database."
                    )[:1000],
                    "severity": str(severity).lower()[:30],
                    "modified": vulnerability.get("modified"),
                    "references": [
                        ref["url"]
                        for ref in vulnerability.get("references", [])
                        if isinstance(ref, dict) and isinstance(ref.get("url"), str)
                    ][:10],
                }
            )
    return findings
