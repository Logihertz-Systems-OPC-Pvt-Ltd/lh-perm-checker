# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        tests.test_system_auditor
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for SystemAuditor: checking CIS permission masks on critical system files.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from lh_perm_checker.models import Severity
from lh_perm_checker.system_auditor import SystemAuditor


def test_system_audit_clean_environment(tmp_path: Path) -> None:
    """Test auditing a properly hardened system root with CIS compliant permissions."""
    etc = tmp_path / "etc"
    etc.mkdir()

    passwd = etc / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    os.chmod(passwd, 0o644)

    shadow = etc / "shadow"
    shadow.write_text("root:*:19000:0:99999:7:::\n", encoding="utf-8")
    os.chmod(shadow, 0o640)

    sudoers = etc / "sudoers"
    sudoers.write_text("root ALL=(ALL:ALL) ALL\n", encoding="utf-8")
    os.chmod(sudoers, 0o440)

    crontab = etc / "crontab"
    crontab.write_text("# crontab\n", encoding="utf-8")
    os.chmod(crontab, 0o600)

    auditor = SystemAuditor(root_dir=tmp_path)

    with (
        patch.object(auditor, "get_username", return_value="root"),
        patch.object(auditor, "get_groupname", return_value="root"),
        patch("os.stat") as mock_stat,
    ):
        # Setup mock stat returns for root owned files
        def side_effect(path: Path | str, *args: object, **kwargs: object) -> object:
            real_st = os.lstat(path)
            # Create a mock with uid 0, gid 0 and real file mode
            return type(
                "MockStat",
                (),
                {
                    "st_mode": real_st.st_mode,
                    "st_uid": 0,
                    "st_gid": 0,
                },
            )()

        mock_stat.side_effect = side_effect
        result = auditor.audit()

    assert result.command == "audit-system"
    assert len(result.findings) == 0


def test_system_audit_insecure_shadow_permissions(tmp_path: Path) -> None:
    """Test detecting world-readable shadow file (mode 0644 violates 0640 mask)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    shadow = etc / "shadow"
    shadow.write_text("root:*:19000:0:99999:7:::\n", encoding="utf-8")
    os.chmod(shadow, 0o644)

    auditor = SystemAuditor(root_dir=tmp_path)

    with (
        patch.object(auditor, "get_username", return_value="root"),
        patch.object(auditor, "get_groupname", return_value="shadow"),
    ):
        result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-010" in rule_ids

    shadow_finding = next(f for f in result.findings if f.rule_id == "LH-PERM-010")
    assert shadow_finding.severity == Severity.CRITICAL
    assert "shadow" in shadow_finding.path


def test_system_audit_insecure_passwd_permissions(tmp_path: Path) -> None:
    """Test detecting world-writable passwd file (mode 0666)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    passwd = etc / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    os.chmod(passwd, 0o666)

    auditor = SystemAuditor(root_dir=tmp_path)

    with (
        patch.object(auditor, "get_username", return_value="root"),
        patch.object(auditor, "get_groupname", return_value="root"),
    ):
        result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-010" in rule_ids


def test_system_audit_insecure_ownership(tmp_path: Path) -> None:
    """Test detecting critical system file not owned by root (UID 1000)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    sudoers = etc / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    os.chmod(sudoers, 0o440)

    auditor = SystemAuditor(root_dir=tmp_path)

    with (
        patch.object(auditor, "get_username", return_value="attacker"),
        patch.object(auditor, "get_groupname", return_value="attacker"),
        patch("os.stat") as mock_stat,
    ):
        real_st = os.lstat(sudoers)
        mock_res = type(
            "MockStat",
            (),
            {
                "st_mode": real_st.st_mode,
                "st_uid": 1000,
                "st_gid": 1000,
            },
        )()
        mock_stat.return_value = mock_res

        result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-011" in rule_ids

    owner_finding = next(f for f in result.findings if f.rule_id == "LH-PERM-011")
    assert owner_finding.severity == Severity.HIGH
    assert "UID 1000" in owner_finding.message


def test_system_audit_sudoers_d_directory(tmp_path: Path) -> None:
    """Test auditing files in /etc/sudoers.d/."""
    etc = tmp_path / "etc"
    etc.mkdir()
    sudoers_d = etc / "sudoers.d"
    sudoers_d.mkdir()
    os.chmod(sudoers_d, 0o750)

    rule_file = sudoers_d / "custom_rule"
    rule_file.write_text("user ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    # Insecure mode: 0666 (should be 0440)
    os.chmod(rule_file, 0o666)

    auditor = SystemAuditor(root_dir=tmp_path)

    with (
        patch.object(auditor, "get_username", return_value="root"),
        patch.object(auditor, "get_groupname", return_value="root"),
        patch("os.stat") as mock_stat,
    ):

        def side_effect(path: Path | str, *args: object, **kwargs: object) -> object:
            p = Path(path)
            real_st = os.lstat(p)
            return type(
                "MockStat",
                (),
                {
                    "st_mode": real_st.st_mode,
                    "st_uid": 0,
                    "st_gid": 0,
                },
            )()

        mock_stat.side_effect = side_effect
        result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-010" in rule_ids
