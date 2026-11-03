# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.ssh_auditor
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Auditor for SSH configuration directories, private keys, and authorized_keys.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

from lh_perm_checker.models import (
    Finding,
    FindingCategory,
    ScanResult,
    ScanSummary,
    Severity,
)

# Known private key filename patterns (excluding .pub files)
PRIVATE_KEY_PATTERNS = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_xmss",
    "identity",
}


def is_private_key_file(file_path: Path) -> bool:
    """Determine whether a file is an SSH private key by name pattern or header."""
    if file_path.suffix == ".pub":
        return False

    name = file_path.name.lower()
    if name in PRIVATE_KEY_PATTERNS:
        return True

    for prefix in PRIVATE_KEY_PATTERNS:
        if name.startswith(prefix) and not name.endswith(".pub"):
            return True

    if name.endswith(".pem") or name.endswith(".key"):
        return True

    # Check file content header if readable
    try:
        with open(file_path, "rb") as f:
            header = f.read(128)
            if b"-----BEGIN" in header and b"PRIVATE KEY" in header:
                return True
    except OSError:
        pass

    return False


class SshAuditor:
    """Audits SSH directories, private keys, authorized_keys, and configuration files."""

    def __init__(self, ssh_dir: Path | None = None, expected_uid: int | None = None) -> None:
        """Initialize SSH auditor for given SSH directory."""
        if ssh_dir is None:
            self.ssh_dir = Path.home() / ".ssh"
        else:
            self.ssh_dir = Path(ssh_dir).expanduser()
        self.expected_uid = expected_uid

    def get_username(self, uid: int) -> str | None:
        """Resolve numeric UID to username."""
        try:
            return pwd.getpwuid(uid).pw_name
        except (KeyError, OSError, ValueError):
            return None

    def get_groupname(self, gid: int) -> str | None:
        """Resolve numeric GID to group name."""
        try:
            return grp.getgrgid(gid).gr_name
        except (KeyError, OSError, ValueError):
            return None

    def audit(self) -> ScanResult:
        """Perform comprehensive audit of SSH directory and its contents."""
        start_time = time.perf_counter()
        summary = ScanSummary()
        findings: list[Finding] = []
        errors: list[str] = []

        if not self.ssh_dir.exists():
            errors.append(f"SSH directory does not exist: {self.ssh_dir}")
            summary.errors_count = len(errors)
            summary.execution_time_seconds = time.perf_counter() - start_time
            return ScanResult(
                command="audit-ssh",
                target_path=str(self.ssh_dir),
                summary=summary,
                findings=[],
                errors=errors,
                timestamp=datetime.now(UTC).isoformat(),
            )

        try:
            dir_st = os.stat(self.ssh_dir)
        except OSError as err:
            errors.append(f"Cannot stat SSH directory {self.ssh_dir}: {err}")
            summary.errors_count = len(errors)
            summary.execution_time_seconds = time.perf_counter() - start_time
            return ScanResult(
                command="audit-ssh",
                target_path=str(self.ssh_dir),
                summary=summary,
                findings=[],
                errors=errors,
                timestamp=datetime.now(UTC).isoformat(),
            )

        summary.scanned_targets += 1
        summary.scanned_directories += 1

        target_uid = self.expected_uid if self.expected_uid is not None else dir_st.st_uid
        dir_username = self.get_username(dir_st.st_uid)
        dir_groupname = self.get_groupname(dir_st.st_gid)

        # 1. Audit SSH directory itself
        dir_mode = dir_st.st_mode
        dir_octal = f"0{dir_mode & 0o7777:04o}"
        # SSH dir must be directory and permissions <= 0700 (no group/other access)
        if (dir_mode & 0o077) != 0:
            findings.append(
                Finding(
                    rule_id="LH-PERM-020",
                    rule_name="InsecureSshDirPerms",
                    category=FindingCategory.SSH_CONFIG,
                    severity=Severity.HIGH,
                    path=str(self.ssh_dir),
                    message=(
                        f"SSH directory '{self.ssh_dir}' has permissions {dir_octal}. "
                        "Expected maximum permissions are 0700 (drwx------)."
                    ),
                    remediation=f"chmod 0700 {self.ssh_dir}",
                    mode=dir_mode,
                    mode_octal=dir_octal,
                    owner_uid=dir_st.st_uid,
                    owner_user=dir_username,
                    group_gid=dir_st.st_gid,
                    group_name=dir_groupname,
                    details={"forbidden_bits": f"0{(dir_mode & 0o077):04o}"},
                )
            )

        # Directory ownership check
        if self.expected_uid is not None and dir_st.st_uid != self.expected_uid:
            findings.append(
                Finding(
                    rule_id="LH-PERM-023",
                    rule_name="InsecureSshFileOwner",
                    category=FindingCategory.SSH_CONFIG,
                    severity=Severity.HIGH,
                    path=str(self.ssh_dir),
                    message=(
                        f"SSH directory '{self.ssh_dir}' is owned by UID {dir_st.st_uid}, "
                        f"expected target UID {self.expected_uid}."
                    ),
                    remediation=f"chown {self.expected_uid} {self.ssh_dir}",
                    mode=dir_mode,
                    mode_octal=dir_octal,
                    owner_uid=dir_st.st_uid,
                    owner_user=dir_username,
                    group_gid=dir_st.st_gid,
                    group_name=dir_groupname,
                )
            )

        # 2. Audit entries in SSH directory
        try:
            entries = sorted(self.ssh_dir.iterdir())
        except OSError as err:
            errors.append(f"Cannot read directory entries in {self.ssh_dir}: {err}")
            entries = []

        for item in entries:
            summary.scanned_targets += 1
            try:
                st = os.stat(item)
            except OSError as err:
                errors.append(f"Cannot stat {item}: {err}")
                continue

            if stat.S_ISDIR(st.st_mode):
                summary.scanned_directories += 1
                continue

            summary.scanned_files += 1
            mode = st.st_mode
            octal_str = f"0{mode & 0o7777:04o}"
            username = self.get_username(st.st_uid)
            groupname = self.get_groupname(st.st_gid)

            # Ownership check on files
            if st.st_uid != target_uid:
                findings.append(
                    Finding(
                        rule_id="LH-PERM-023",
                        rule_name="InsecureSshFileOwner",
                        category=FindingCategory.SSH_CONFIG,
                        severity=Severity.HIGH,
                        path=str(item),
                        message=(
                            f"SSH file '{item.name}' is owned by UID {st.st_uid} "
                            f"({username or 'unknown'}), expected UID {target_uid}."
                        ),
                        remediation=f"chown {target_uid} {item}",
                        mode=mode,
                        mode_octal=octal_str,
                        owner_uid=st.st_uid,
                        owner_user=username,
                        group_gid=st.st_gid,
                        group_name=groupname,
                    )
                )

            # Private key check
            if is_private_key_file(item):
                # Private keys must be max 0600 (or 0400). Group/other access strictly forbidden
                if (mode & 0o077) != 0:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-021",
                            rule_name="InsecureSshPrivateKey",
                            category=FindingCategory.SSH_CONFIG,
                            severity=Severity.CRITICAL,
                            path=str(item),
                            message=(
                                f"SSH private key '{item.name}' has insecure permissions "
                                f"{octal_str}. Private keys must not be accessible by "
                                f"group or other users."
                            ),
                            remediation=f"chmod 0600 {item}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                            details={"forbidden_bits": f"0{(mode & 0o077):04o}"},
                        )
                    )
            # authorized_keys check
            elif item.name in ("authorized_keys", "authorized_keys2"):
                # CIS specifies max 0600. Group/world writable is critical vulnerability.
                if (mode & 0o022) != 0:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-022",
                            rule_name="InsecureSshAuthorizedKeys",
                            category=FindingCategory.SSH_CONFIG,
                            severity=Severity.CRITICAL,
                            path=str(item),
                            message=(
                                f"authorized_keys file '{item.name}' is writable by group or "
                                f"others ({octal_str}). Attackers can append unauthorized keys."
                            ),
                            remediation=f"chmod 0600 {item}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                            details={"writable_by_others": True},
                        )
                    )
                elif (mode & 0o077) != 0:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-022",
                            rule_name="InsecureSshAuthorizedKeys",
                            category=FindingCategory.SSH_CONFIG,
                            severity=Severity.HIGH,
                            path=str(item),
                            message=(
                                f"authorized_keys file '{item.name}' has permissions {octal_str}. "
                                "CIS benchmark requires 0600 (-rw-------)."
                            ),
                            remediation=f"chmod 0600 {item}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                            details={"exceeds_cis_mask": True},
                        )
                    )
            # Other configuration files (config, known_hosts)
            elif item.name in ("config", "known_hosts", "known_hosts.old"):
                # Must not be group or world writable
                if (mode & 0o022) != 0:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-004",
                            rule_name="WorldWritableFile",
                            category=FindingCategory.SSH_CONFIG,
                            severity=Severity.HIGH,
                            path=str(item),
                            message=(
                                f"SSH file '{item.name}' has group or world write bits set "
                                f"({octal_str})."
                            ),
                            remediation=f"chmod 0644 {item}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                        )
                    )

        summary.execution_time_seconds = time.perf_counter() - start_time
        summary.errors_count = len(errors)
        summary.update_from_findings(findings)

        return ScanResult(
            command="audit-ssh",
            target_path=str(self.ssh_dir),
            summary=summary,
            findings=findings,
            errors=errors,
            timestamp=datetime.now(UTC).isoformat(),
        )
