# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        tests.test_ssh_auditor
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for SshAuditor: checking SSH directory and key permissions.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from lh_perm_checker.models import Severity
from lh_perm_checker.ssh_auditor import SshAuditor, is_private_key_file


def test_is_private_key_file_patterns(tmp_path: Path) -> None:
    """Test private key detection via filename patterns and headers."""
    # Standard filenames
    assert is_private_key_file(tmp_path / "id_rsa") is True
    assert is_private_key_file(tmp_path / "id_ed25519") is True
    assert is_private_key_file(tmp_path / "server.pem") is True
    assert is_private_key_file(tmp_path / "backup.key") is True

    # Public keys must NOT be detected as private keys
    assert is_private_key_file(tmp_path / "id_rsa.pub") is False
    assert is_private_key_file(tmp_path / "id_ed25519.pub") is False

    # Detection via file content header
    custom_key = tmp_path / "my_custom_secret"
    custom_key.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...")
    assert is_private_key_file(custom_key) is True


def test_ssh_audit_clean_directory(tmp_path: Path) -> None:
    """Test auditing a properly configured SSH directory with safe permissions."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    priv_key = ssh_dir / "id_rsa"
    priv_key.write_text("private key", encoding="utf-8")
    os.chmod(priv_key, 0o600)

    pub_key = ssh_dir / "id_rsa.pub"
    pub_key.write_text("ssh-rsa AAAAB3NzaC1yc2E...", encoding="utf-8")
    os.chmod(pub_key, 0o644)

    auth_keys = ssh_dir / "authorized_keys"
    auth_keys.write_text("ssh-rsa AAAAB3NzaC1yc2E...", encoding="utf-8")
    os.chmod(auth_keys, 0o600)

    config = ssh_dir / "config"
    config.write_text("Host *\n  ServerAliveInterval 60\n", encoding="utf-8")
    os.chmod(config, 0o600)

    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()

    assert result.command == "audit-ssh"
    assert len(result.findings) == 0


def test_ssh_audit_insecure_dir_perms(tmp_path: Path) -> None:
    """Test detecting SSH directory permissions looser than 0700 (e.g. 0755 or 0777)."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o755)

    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-020" in rule_ids

    dir_finding = next(f for f in result.findings if f.rule_id == "LH-PERM-020")
    assert dir_finding.severity == Severity.HIGH
    assert "0700" in dir_finding.remediation


def test_ssh_audit_insecure_private_key(tmp_path: Path) -> None:
    """Test detecting world-readable private key (mode 0644 violates 0600 mask)."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    priv_key = ssh_dir / "id_ed25519"
    priv_key.write_text("private key content", encoding="utf-8")
    os.chmod(priv_key, 0o644)

    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-021" in rule_ids

    key_finding = next(f for f in result.findings if f.rule_id == "LH-PERM-021")
    assert key_finding.severity == Severity.CRITICAL
    assert "id_ed25519" in key_finding.message


def test_ssh_audit_insecure_authorized_keys(tmp_path: Path) -> None:
    """Test detecting world-writable authorized_keys (mode 0666)."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    auth_keys = ssh_dir / "authorized_keys"
    auth_keys.write_text("ssh-rsa AAAAB3NzaC1yc2E...", encoding="utf-8")
    os.chmod(auth_keys, 0o666)

    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-022" in rule_ids

    auth_finding = next(f for f in result.findings if f.rule_id == "LH-PERM-022")
    assert auth_finding.severity == Severity.CRITICAL


def test_ssh_audit_wrong_owner(tmp_path: Path) -> None:
    """Test detecting SSH file owned by wrong UID (mocked)."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    os.chmod(ssh_dir, 0o700)

    priv_key = ssh_dir / "id_rsa"
    priv_key.write_text("secret", encoding="utf-8")
    os.chmod(priv_key, 0o600)

    auditor = SshAuditor(ssh_dir=ssh_dir, expected_uid=1000)

    # Mock os.stat returning uid 1001 for id_rsa
    with patch("os.stat") as mock_stat:

        def side_effect(path: Path | str, *args: object, **kwargs: object) -> object:
            p = Path(path)
            real_st = os.lstat(p)
            uid = 1000 if p == ssh_dir else 1001
            return type(
                "MockStat",
                (),
                {
                    "st_mode": real_st.st_mode,
                    "st_uid": uid,
                    "st_gid": uid,
                },
            )()

        mock_stat.side_effect = side_effect
        result = auditor.audit()

    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-PERM-023" in rule_ids


def test_ssh_audit_nonexistent_directory() -> None:
    """Test auditing non-existent SSH directory."""
    auditor = SshAuditor(ssh_dir=Path("/nonexistent/.ssh"))
    result = auditor.audit()

    assert len(result.errors) >= 1
    assert len(result.findings) == 0
