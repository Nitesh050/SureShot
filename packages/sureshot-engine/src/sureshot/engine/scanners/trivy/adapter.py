from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, Package, SecretRef, SecurityFinding
from sureshot.domain.scan import ToolRecord

_CWE_PATTERN = re.compile(r"^CWE-\d+$")

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class AdapterError(Exception):
    """Trivy output could not be converted into SecurityFindings."""


def _map_severity(raw: Any) -> Severity:
    return _SEVERITY_MAP.get(str(raw or "").upper(), Severity.INFO)


def _clean_cwe_ids(raw: Any) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(cwe for cwe in raw if isinstance(cwe, str) and _CWE_PATTERN.match(cwe))


def _relative_path(target: str) -> str:
    """Trivy's fs scanner already reports Target relative to the scan root."""
    path = Path(str(target).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise AdapterError(f"trivy reported a path outside the scan root: {target}")
    return path.as_posix()


def _require(payload: dict, key: str, where: str) -> Any:
    if key not in payload:
        raise AdapterError(f"trivy {where} is missing required field {key!r}")
    return payload[key]


def _package_locations(packages: list[dict]) -> dict[str, tuple[int, int]]:
    """Map a package's identifier UID to the line range it was declared on."""
    locations: dict[str, tuple[int, int]] = {}
    for pkg in packages:
        uid = (pkg.get("Identifier") or {}).get("UID")
        locs = pkg.get("Locations") or []
        if uid and locs:
            locations[uid] = (locs[0].get("StartLine", 1), locs[0].get("EndLine", 1))
    return locations


def _adapt_vulnerability(
    vuln: dict,
    file_path: str,
    locations: dict[str, tuple[int, int]],
    tool: ToolRecord,
) -> SecurityFinding:
    vuln_id = str(_require(vuln, "VulnerabilityID", "vulnerability"))
    pkg_name = str(_require(vuln, "PkgName", "vulnerability"))
    installed = str(_require(vuln, "InstalledVersion", "vulnerability"))
    uid = (vuln.get("PkgIdentifier") or {}).get("UID")
    start, end = locations.get(uid, (1, 1))

    return SecurityFinding(
        tool=tool.name,
        tool_version=tool.version,
        rule_id=vuln_id,
        domain=Domain.SCA,
        title=str(vuln.get("Title") or vuln_id),
        description=str(vuln.get("Description") or "").strip(),
        severity=_map_severity(vuln.get("Severity")),
        cwe_ids=_clean_cwe_ids(vuln.get("CweIDs")),
        cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
        location=Location(file_path=file_path, line_start=max(start, 1), line_end=max(end, start, 1)),
        package=Package(
            name=pkg_name,
            installed_version=installed,
            fixed_version=vuln.get("FixedVersion") or None,
        ),
        raw={
            "vendor_ids": vuln.get("VendorIDs"),
            "references": vuln.get("References"),
            "primary_url": vuln.get("PrimaryURL"),
        },
    )


def _adapt_secret(secret: dict, file_path: str, tool: ToolRecord) -> SecurityFinding:
    rule_id = str(_require(secret, "RuleID", "secret"))
    start = int(secret.get("StartLine", 1) or 1)
    end = int(secret.get("EndLine", start) or start)

    return SecurityFinding(
        tool=tool.name,
        tool_version=tool.version,
        rule_id=rule_id,
        domain=Domain.SECRET,
        title=str(secret.get("Title") or rule_id),
        description=f"{secret.get('Category', 'secret')} detected by Trivy",
        severity=_map_severity(secret.get("Severity")),
        location=Location(
            file_path=file_path, line_start=max(start, 1), line_end=max(end, start, 1)
        ),
        # Trivy masks the match itself before it ever reaches us, so there is no
        # real value to fingerprint — last_four stays empty rather than faked.
        secret=SecretRef(kind=rule_id, last_four=""),
        raw={},
    )


def adapt_results(payload: dict[str, Any], tool: ToolRecord) -> tuple[SecurityFinding, ...]:
    """Convert a parsed `trivy fs --format json` report into normalized findings."""
    findings: list[SecurityFinding] = []

    for index, result in enumerate(payload.get("Results") or []):
        try:
            file_path = _relative_path(_require(result, "Target", "result"))
            locations = _package_locations(result.get("Packages") or [])

            for vuln in result.get("Vulnerabilities") or []:
                findings.append(_adapt_vulnerability(vuln, file_path, locations, tool))

            for secret in result.get("Secrets") or []:
                findings.append(_adapt_secret(secret, file_path, tool))
        except AdapterError as exc:
            raise AdapterError(f"result at index {index}: {exc}") from exc
        except Exception as exc:
            raise AdapterError(f"result at index {index}: {exc}") from exc

    return tuple(findings)
