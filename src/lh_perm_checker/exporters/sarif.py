# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.exporters.sarif
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 exporter for GitHub Security and enterprise CI/CD workflows.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lh_perm_checker.constants import SARIF_RULES_CATALOG
from lh_perm_checker.models import ScanResult

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def export_sarif(result: ScanResult, output_path: Path | None = None, indent: int = 2) -> str:
    """Export scan findings to standard OASIS SARIF v2.1.0 JSON format.

    Args:
        result: The ScanResult containing detected findings.
        output_path: Optional destination file path.
        indent: Indentation level for pretty-printing.

    Returns:
        Serialized SARIF JSON string.
    """
    # Build list of rules used in this tool
    rules: list[dict[str, Any]] = list(SARIF_RULES_CATALOG)

    sarif_results: list[dict[str, Any]] = []
    for finding in result.findings:
        # Convert path to standard file:// URI format
        p = Path(finding.path)
        try:
            resolved_uri = p.resolve().as_uri()
        except (ValueError, OSError):
            resolved_uri = f"file://{finding.path}"

        item: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": finding.severity.sarif_level,
            "message": {
                "text": f"{finding.message} Remediation: {finding.remediation}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": resolved_uri,
                        },
                    },
                },
            ],
            "properties": {
                "category": finding.category.value,
                "severity": finding.severity.value,
                "modeOctal": finding.mode_octal,
                "ownerUid": finding.owner_uid,
                "ownerUser": finding.owner_user,
                "groupGid": finding.group_gid,
                "groupName": finding.group_name,
                "remediation": finding.remediation,
                "details": finding.details,
            },
        }
        sarif_results.append(item)

    sarif_payload: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-perm-checker",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perm-checker",
                        "rules": rules,
                    },
                },
                "results": sarif_results,
            },
        ],
    }

    sarif_str = json.dumps(sarif_payload, indent=indent)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(sarif_str, encoding="utf-8")

    return sarif_str
