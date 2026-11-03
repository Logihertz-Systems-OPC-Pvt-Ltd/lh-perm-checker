# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        tests.test_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for FilesystemScanner: SUID/SGID, world-writable files, and orphans.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

from lh_perm_checker.models import Severity
from lh_perm_checker.scanner import FilesystemScanner, load_allowlist


def test_load_allowlist_default() -> None:
    """Test loading default allowlist when path is None."""
    allowlist = load_allowlist(None)
    assert "/usr/bin/passwd" in allowlist
    assert len(allowlist) > 5


def test_load_allowlist_from_json_list(tmp_path: Path) -> None:
    """Test loading allowlist from a JSON array."""
    custom_list = ["/usr/bin/custom_suid", "/opt/bin/tool"]
    allow_file = tmp_path / "allowlist.json"
    allow_file.write_text(json.dumps(custom_list), encoding="utf-8")

    loaded = load_allowlist(allow_file)
    assert "/usr/bin/custom_suid" in loaded
    assert "/opt/bin/tool" in loaded


def test_load_allowlist_from_json_dict(tmp_path: Path) -> None:
    """Test loading allowlist from a JSON dictionary."""
    data = {"allowed_binaries": ["/bin/custom_binary"]}
    allow_file = tmp_path / "allowlist.json"
    allow_file.write_text(json.dumps(data), encoding="utf-8")

    loaded = load_allowlist(allow_file)
    assert "/bin/custom_binary" in loaded


def test_load_allowlist_missing_file() -> None:
    """Test that missing allowlist file raises FileNotFoundError."""
    try:
        load_allowlist(Path("/path/to/nonexistent/allowlist.json"))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")


def test_scan_clean_directory(tmp_path: Path) -> None:
    """Test scanning a clean directory with safe permissions."""
    safe_file = tmp_path / "safe.txt"
    safe_file.write_text("safe content", encoding="utf-8")
    os.chmod(safe_file, 0o644)

    scanner = FilesystemScanner()
    result = scanner.scan_path(tmp_path)

    assert result.command == "scan"
    assert result.summary.scanned_files >= 1
    # Only standard safe files, so 0 high/critical findings
    high_crit = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(high_crit) == 0


def test_scan_world_writable_file(tmp_path: Path) -> None:
    """Test detecting world-writable files (0002 bit)."""
    ww_file = tmp_path / "world_writable.sh"
    ww_file.write_text("#!/bin/sh\necho test\n", encoding="utf-8")
    os.chmod(ww_file, 0o666)

    scanner = FilesystemScanner()
    result = scanner.scan_path(tmp_path)

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-004" in rule_ids

    ww_findings = [f for f in result.findings if f.rule_id == "LH-PERM-004"]
    assert len(ww_findings) >= 1
    assert "world_writable.sh" in ww_findings[0].path
    assert ww_findings[0].severity == Severity.HIGH


def test_scan_world_writable_dir_without_sticky_bit(tmp_path: Path) -> None:
    """Test detecting world-writable directory lacking sticky bit."""
    shared_dir = tmp_path / "public_share"
    shared_dir.mkdir()
    os.chmod(shared_dir, 0o777)

    scanner = FilesystemScanner()
    result = scanner.scan_path(tmp_path)

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-005" in rule_ids

    sticky_findings = [f for f in result.findings if f.rule_id == "LH-PERM-005"]
    assert len(sticky_findings) >= 1
    assert "public_share" in sticky_findings[0].path


def test_scan_world_writable_dir_with_sticky_bit(tmp_path: Path) -> None:
    """Test that a world-writable directory with sticky bit set is NOT flagged."""
    sticky_dir = tmp_path / "sticky_share"
    sticky_dir.mkdir()
    os.chmod(sticky_dir, 0o1777)

    scanner = FilesystemScanner()
    result = scanner.scan_path(sticky_dir)

    sticky_findings = [f for f in result.findings if f.rule_id == "LH-PERM-005"]
    assert len(sticky_findings) == 0


def test_scan_gtfobins_risky_suid_binary(tmp_path: Path) -> None:
    """Test detecting GTFOBins risky SUID binaries using mocked stat."""
    vim_bin = tmp_path / "vim"
    vim_bin.write_text("mock binary", encoding="utf-8")

    # Create mock stat result with SUID bit (04755) and root ownership (uid=0)
    fake_stat = MagicMock(spec=os.stat_result)
    fake_stat.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
    fake_stat.st_uid = 0
    fake_stat.st_gid = 0

    scanner = FilesystemScanner(allowlist=set())

    with (
        patch("os.lstat", return_value=fake_stat),
        patch("os.stat", return_value=fake_stat),
        patch.object(scanner, "get_username", return_value="root"),
        patch.object(scanner, "get_groupname", return_value="root"),
    ):
        findings = scanner.analyze_stat(vim_bin, fake_stat, is_dir=False)

    rule_ids = [f.rule_id for f in findings]
    assert "LH-PERM-001" in rule_ids

    risky_finding = next(f for f in findings if f.rule_id == "LH-PERM-001")
    assert risky_finding.severity == Severity.CRITICAL
    assert "GTFOBins" in risky_finding.message
    assert "vim" in risky_finding.message


def test_all_core_gtfobins_flagged(tmp_path: Path) -> None:
    """Test all core GTFOBins binaries mentioned in SPEC.md:
    vim, find, python, bash, nmap, docker.
    """
    core_bins = ["vim", "find", "python", "bash", "nmap", "docker"]
    scanner = FilesystemScanner(allowlist=set())

    for b_name in core_bins:
        b_path = tmp_path / b_name
        fake_stat = MagicMock(spec=os.stat_result)
        fake_stat.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
        fake_stat.st_uid = 0
        fake_stat.st_gid = 0

        with (
            patch.object(scanner, "get_username", return_value="root"),
            patch.object(scanner, "get_groupname", return_value="root"),
        ):
            findings = scanner.analyze_stat(b_path, fake_stat, is_dir=False)

        assert any(f.rule_id == "LH-PERM-001" for f in findings), f"Failed for {b_name}"


def test_scan_unallowlisted_suid_and_sgid(tmp_path: Path) -> None:
    """Test detecting non-GTFOBins SUID and SGID binaries not in allowlist."""
    scanner = FilesystemScanner(allowlist=set())

    # 1. Benign SUID
    app_bin = tmp_path / "custom_app"
    fake_stat_suid = MagicMock(spec=os.stat_result)
    fake_stat_suid.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
    fake_stat_suid.st_uid = 1000
    fake_stat_suid.st_gid = 1000

    with (
        patch.object(scanner, "get_username", return_value="user"),
        patch.object(scanner, "get_groupname", return_value="user"),
    ):
        findings_suid = scanner.analyze_stat(app_bin, fake_stat_suid, is_dir=False)

    assert any(f.rule_id == "LH-PERM-002" for f in findings_suid)

    # 2. Benign SGID
    fake_stat_sgid = MagicMock(spec=os.stat_result)
    fake_stat_sgid.st_mode = stat.S_IFREG | stat.S_ISGID | 0o755
    fake_stat_sgid.st_uid = 1000
    fake_stat_sgid.st_gid = 1000

    with (
        patch.object(scanner, "get_username", return_value="user"),
        patch.object(scanner, "get_groupname", return_value="user"),
    ):
        findings_sgid = scanner.analyze_stat(app_bin, fake_stat_sgid, is_dir=False)

    assert any(f.rule_id == "LH-PERM-003" for f in findings_sgid)
    # --------------------------------------------------------------------------
    # --- Rule LH-PERM-002: SUID Binary Detected Not in Approved Allowlist (HIGH) ---
    # Evaluates security posture against suid binary detected not in approved
    # allowlist.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_scan_allowlisted_suid_not_flagged(tmp_path: Path) -> None:
    """Test that allowlisted SUID binaries are not flagged under LH-PERM-002."""
    passwd_path = tmp_path / "passwd"
    scanner = FilesystemScanner(allowlist={"passwd", str(passwd_path)})

    fake_stat = MagicMock(spec=os.stat_result)
    fake_stat.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
    fake_stat.st_uid = 0
    fake_stat.st_gid = 0

    with (
        patch.object(scanner, "get_username", return_value="root"),
        patch.object(scanner, "get_groupname", return_value="root"),
    ):
        findings = scanner.analyze_stat(passwd_path, fake_stat, is_dir=False)

    assert not any(f.rule_id == "LH-PERM-002" for f in findings)


def test_scan_orphaned_uid_and_gid(tmp_path: Path) -> None:
    """Test detecting orphaned UIDs and GIDs."""
    file_path = tmp_path / "orphaned.dat"
    file_path.write_text("data", encoding="utf-8")

    fake_stat = MagicMock(spec=os.stat_result)
    fake_stat.st_mode = stat.S_IFREG | 0o644
    fake_stat.st_uid = 99999
    fake_stat.st_gid = 88888

    scanner = FilesystemScanner()

    with (
        patch.object(scanner, "get_username", return_value=None),
        patch.object(scanner, "get_groupname", return_value=None),
    ):
        findings = scanner.analyze_stat(file_path, fake_stat, is_dir=False, include_orphans=True)

    rule_ids = [f.rule_id for f in findings]
    assert "LH-PERM-006" in rule_ids
    assert "LH-PERM-007" in rule_ids


def test_scan_nonexistent_target() -> None:
    """Test scanning a non-existent path records an error cleanly."""
    scanner = FilesystemScanner()
    result = scanner.scan_path(Path("/nonexistent/target/path"))

    assert len(result.errors) >= 1
    assert result.summary.errors_count >= 1
    assert len(result.findings) == 0
