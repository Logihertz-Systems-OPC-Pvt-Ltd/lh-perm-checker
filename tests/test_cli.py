# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for Typer CLI commands: lh-perm scan, audit-system, and audit-ssh.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from typer.testing import CliRunner

from lh_perm_checker.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    """Test CLI base help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "lh-perm" in result.stdout
    assert "scan" in result.stdout
    assert "audit-system" in result.stdout
    assert "audit-ssh" in result.stdout


def test_cli_scan_table_output(tmp_path: Path) -> None:
    """Test scan command with table output."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello", encoding="utf-8")
    os.chmod(test_file, 0o644)

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "table"])
    assert result.exit_code == 0
    assert "Logihertz Linux Permission Checker" in result.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    """Test scan command with json output printed to stdout."""
    test_file = tmp_path / "world.txt"
    test_file.write_text("hello world", encoding="utf-8")
    os.chmod(test_file, 0o666)

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["command"] == "scan"
    assert data["summary"]["findings_count"] >= 1


def test_cli_scan_output_file(tmp_path: Path) -> None:
    """Test scan command saving to output file in SARIF format."""
    sarif_out = tmp_path / "output.sarif"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "sarif", "--output", str(sarif_out)],
    )
    assert result.exit_code == 0
    assert sarif_out.exists()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"


def test_cli_scan_with_allowlist(tmp_path: Path) -> None:
    """Test scan command with custom allowlist JSON."""
    allowlist_file = tmp_path / "allowlist.json"
    allowlist_file.write_text(json.dumps(["/usr/bin/passwd"]), encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--allowlist", str(allowlist_file)],
    )
    assert result.exit_code == 0


def test_cli_scan_missing_allowlist(tmp_path: Path) -> None:
    """Test scan command with missing allowlist file exits with code 2."""
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--allowlist", str(tmp_path / "missing.json")],
    )
    assert result.exit_code == 2


def test_cli_audit_system(tmp_path: Path) -> None:
    """Test audit-system command targeting a mock root."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    passwd = etc_dir / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    os.chmod(passwd, 0o644)

    result = runner.invoke(
        app,
        ["audit-system", "--root", str(tmp_path), "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["command"] == "audit-system"


def test_cli_audit_ssh(tmp_path: Path) -> None:
    """Test audit-ssh command targeting mock SSH directory."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    key = ssh_dir / "id_ed25519"
    key.write_text("mock key", encoding="utf-8")
    os.chmod(key, 0o600)

    result = runner.invoke(
        app,
        ["audit-ssh", str(ssh_dir), "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["command"] == "audit-ssh"


def test_cli_exit_code_flag(tmp_path: Path) -> None:
    """Test --exit-code flag raises exit code 1 when security findings exist."""
    insecure = tmp_path / "insecure.txt"
    insecure.write_text("bad permissions", encoding="utf-8")
    os.chmod(insecure, 0o666)

    # Without --exit-code: exits 0
    res_clean = runner.invoke(app, ["scan", str(tmp_path)])
    assert res_clean.exit_code == 0

    # With --exit-code: exits 1 due to findings
    res_strict = runner.invoke(app, ["scan", str(tmp_path), "--exit-code"])
    assert res_strict.exit_code == 1
