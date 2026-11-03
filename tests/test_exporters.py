# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for Exporters: Rich table, JSON, and OASIS SARIF v2.1.0 formats.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import json
from pathlib import Path

from lh_perm_checker.exporters.json_export import export_json
from lh_perm_checker.exporters.sarif import export_sarif
from lh_perm_checker.exporters.table import render_table
from lh_perm_checker.models import (
    Finding,
    FindingCategory,
    ScanResult,
    ScanSummary,
    Severity,
)


def _create_sample_result() -> ScanResult:
    """Create a sample ScanResult with findings for exporter testing."""
    summary = ScanSummary(
        scanned_targets=10,
        scanned_directories=2,
        scanned_files=8,
        findings_count=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        info_count=0,
        execution_time_seconds=0.042,
    )
    findings = [
        Finding(
            rule_id="LH-PERM-001",
            rule_name="RiskySuidBinary",
            category=FindingCategory.SUID_SGID,
            severity=Severity.CRITICAL,
            path="/usr/bin/vim",
            message="Known GTFOBins binary with SUID bit set.",
            remediation="chmod u-s /usr/bin/vim",
            mode=0o104755,
            mode_octal="04755",
            owner_uid=0,
            owner_user="root",
            group_gid=0,
            group_name="root",
        ),
        Finding(
            rule_id="LH-PERM-004",
            rule_name="WorldWritableFile",
            category=FindingCategory.WORLD_WRITABLE,
            severity=Severity.HIGH,
            path="/etc/world.conf",
            message="File is world-writable.",
            remediation="chmod o-w /etc/world.conf",
            mode=0o100666,
            mode_octal="00666",
            owner_uid=0,
            owner_user="root",
            group_gid=0,
            group_name="root",
        ),
    ]
    return ScanResult(
        command="scan",
        target_path="/",
        summary=summary,
        findings=findings,
        errors=["Sample non-fatal warning"],
        timestamp="2026-11-04T00:00:00Z",
    )


def test_table_renderer_with_findings(tmp_path: Path) -> None:
    """Test rendering results as a Rich terminal table."""
    result = _create_sample_result()
    out_file = tmp_path / "table.txt"
    rendered = render_table(result, output_path=out_file)

    assert "Logihertz Linux Permission Checker" in rendered
    assert "LH-PERM-001" in rendered
    assert "LH-PERM-004" in rendered
    assert "CRITICAL: 1" in rendered
    assert "HIGH: 1" in rendered
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == rendered


def test_table_renderer_clean() -> None:
    """Test rendering clean scan results."""
    summary = ScanSummary(scanned_targets=5, scanned_files=5)
    result = ScanResult(
        command="scan",
        target_path="/safe",
        summary=summary,
        findings=[],
        errors=[],
        timestamp="2026-11-04T00:00:00Z",
    )
    rendered = render_table(result)
    assert "Clean!" in rendered


def test_json_exporter(tmp_path: Path) -> None:
    """Test exporting results to structured JSON."""
    result = _create_sample_result()
    out_file = tmp_path / "results.json"
    json_str = export_json(result, output_path=out_file)

    parsed = json.loads(json_str)
    assert parsed["command"] == "scan"
    assert parsed["summary"]["findings_count"] == 2
    assert len(parsed["findings"]) == 2
    assert parsed["findings"][0]["rule_id"] == "LH-PERM-001"
    assert out_file.exists()


def test_sarif_exporter(tmp_path: Path) -> None:
    """Test exporting findings into OASIS SARIF v2.1.0 format."""
    result = _create_sample_result()
    out_file = tmp_path / "results.sarif"
    sarif_str = export_sarif(result, output_path=out_file)

    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-perm-checker"
    assert len(run["results"]) == 2

    first_res = run["results"][0]
    assert first_res["ruleId"] == "LH-PERM-001"
    assert first_res["level"] == "error"
    assert "uri" in first_res["locations"][0]["physicalLocation"]["artifactLocation"]
    assert out_file.exists()
