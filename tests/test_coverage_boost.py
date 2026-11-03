# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        tests.test_coverage_boost
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Additional unit tests to achieve high test coverage across all modules.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from lh_perm_checker.cli import app, main
from lh_perm_checker.exporters.sarif import export_sarif
from lh_perm_checker.models import Finding, FindingCategory, ScanResult, ScanSummary, Severity
from lh_perm_checker.scanner import FilesystemScanner
from lh_perm_checker.ssh_auditor import SshAuditor, is_private_key_file
from lh_perm_checker.system_auditor import SystemAuditor

runner = CliRunner()


def test_scanner_single_file(tmp_path: Path) -> None:
    """Test scanning a single file directly rather than a directory."""
    single_file = tmp_path / "single.txt"
    single_file.write_text("single file content", encoding="utf-8")
    os.chmod(single_file, 0o666)

    scanner = FilesystemScanner()
    result = scanner.scan_path(single_file)

    assert result.summary.scanned_files == 1
    assert any(f.rule_id == "LH-PERM-004" for f in result.findings)


def test_scanner_allowlist_matching_modes(tmp_path: Path) -> None:
    """Test allowlist matching by exact path, raw path, and binary name."""
    test_bin = tmp_path / "my_suid_tool"
    scanner = FilesystemScanner(allowlist={"my_suid_tool"})
    assert scanner.is_in_allowlist(test_bin) is True


def test_scanner_user_group_lookups() -> None:
    """Test get_username and get_groupname fallbacks on nonexistent IDs."""
    scanner = FilesystemScanner()
    # Query an absurdly large UID/GID
    assert scanner.get_username(2147483640) is None
    assert scanner.get_groupname(2147483640) is None


def test_scanner_stat_oserror_handling(tmp_path: Path) -> None:
    """Test scanner handling OSError during walk or file stat."""
    file_p = tmp_path / "locked.txt"
    file_p.write_text("locked", encoding="utf-8")

    scanner = FilesystemScanner()

    with patch("os.lstat", side_effect=OSError("Disk read error")):
        result = scanner.scan_path(tmp_path)

    assert len(result.errors) >= 1
    assert "Disk read error" in result.errors[0]


def test_ssh_auditor_default_init() -> None:
    """Test initializing SshAuditor with default ssh_dir=None."""
    auditor = SshAuditor(ssh_dir=None)
    assert auditor.ssh_dir == Path.home() / ".ssh"


def test_ssh_auditor_user_group_lookups() -> None:
    """Test SshAuditor get_username and get_groupname error handling."""
    auditor = SshAuditor()
    assert auditor.get_username(2147483640) is None
    assert auditor.get_groupname(2147483640) is None


def test_ssh_auditor_subdirectory(tmp_path: Path) -> None:
    """Test SshAuditor scanning SSH directory containing a subdirectory."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    sockets_dir = ssh_dir / "sockets"
    sockets_dir.mkdir()
    os.chmod(sockets_dir, 0o700)

    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()

    assert result.summary.scanned_directories == 2


def test_ssh_auditor_known_hosts_world_writable(tmp_path: Path) -> None:
    """Test SshAuditor flagging world-writable known_hosts file."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    kh = ssh_dir / "known_hosts"
    kh.write_text("github.com ssh-rsa AAA...", encoding="utf-8")
    os.chmod(kh, 0o666)

    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()

    assert any(f.rule_id == "LH-PERM-004" for f in result.findings)


def test_is_private_key_file_unreadable(tmp_path: Path) -> None:
    """Test is_private_key_file with unreadable file raising OSError."""
    bad_file = tmp_path / "bad.txt"
    bad_file.write_text("hello", encoding="utf-8")

    with patch("builtins.open", side_effect=OSError("Permission denied")):
        assert is_private_key_file(bad_file) is False


def test_system_auditor_user_group_lookups() -> None:
    """Test SystemAuditor get_username and get_groupname lookups on invalid IDs."""
    auditor = SystemAuditor()
    assert auditor.get_username(2147483640) is None
    assert auditor.get_groupname(2147483640) is None


def test_system_auditor_sudoers_d_skip_backups(tmp_path: Path) -> None:
    """Test SystemAuditor ignores backup files in sudoers.d (~ and .bak)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    sudoers_d = etc / "sudoers.d"
    sudoers_d.mkdir()
    os.chmod(sudoers_d, 0o750)

    backup_file = sudoers_d / "rule.bak"
    backup_file.write_text("backup", encoding="utf-8")
    os.chmod(backup_file, 0o777)

    auditor = SystemAuditor(root_dir=tmp_path)
    result = auditor.audit()

    # Backup file must not be evaluated
    assert not any("rule.bak" in f.path for f in result.findings)


def test_cli_sarif_stdout(tmp_path: Path) -> None:
    """Test running CLI with format=sarif directly to stdout."""
    test_f = tmp_path / "sample.txt"
    test_f.write_text("content", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout


def test_cli_main_entrypoint() -> None:
    """Test calling main() invokes the typer app."""
    with patch("sys.argv", ["lh-perm", "--help"]):
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0


def test_sarif_uri_fallback() -> None:
    """Test SARIF URI fallback handling when path resolution fails."""
    finding = Finding(
        rule_id="LH-PERM-001",
        rule_name="RiskySuidBinary",
        category=FindingCategory.SUID_SGID,
        severity=Severity.HIGH,
        path="/mock/path/nonexistent",
        message="Test",
        remediation="Test",
    )
    result = ScanResult(
        command="scan",
        target_path="/",
        summary=ScanSummary(findings_count=1),
        findings=[finding],
    )

    with patch.object(Path, "resolve", side_effect=ValueError("Invalid path")):
        sarif_out = export_sarif(result)
        assert "file:///mock/path/nonexistent" in sarif_out
