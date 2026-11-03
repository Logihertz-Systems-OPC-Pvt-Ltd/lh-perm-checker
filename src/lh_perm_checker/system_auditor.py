# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.system_auditor
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Auditor for Linux critical system configuration files against CIS benchmarks.

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
from typing import Any

from lh_perm_checker.constants import CRITICAL_SYSTEM_FILES
from lh_perm_checker.models import (
    Finding,
    FindingCategory,
    ScanResult,
    ScanSummary,
    Severity,
)


class SystemAuditor:
    """Audits system credential and configuration files against CIS benchmark masks."""

    def __init__(self, root_dir: Path | None = None) -> None:
        """Initialize system auditor with root directory (defaulting to /)."""
        self.root_dir: Path = Path(root_dir) if root_dir is not None else Path("/")

    def _resolve_path(self, rel_system_path: str) -> Path:
        """Resolve a standard system path (e.g. /etc/passwd) against the target root."""
        clean = rel_system_path.lstrip("/")
        return self.root_dir / clean

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
        """Perform comprehensive audit on critical system files and directories."""
        start_time = time.perf_counter()
        summary = ScanSummary()
        findings: list[Finding] = []
        errors: list[str] = []

        # Audit standard critical system paths
        for sys_path_str, spec in CRITICAL_SYSTEM_FILES.items():
            target = self._resolve_path(sys_path_str)
            summary.scanned_targets += 1

            if not target.exists():
                # If checking host root and shadow/gshadow does not exist, or custom root
                continue

            try:
                st = os.stat(target)
            except OSError as err:
                errors.append(f"Cannot stat {target}: {err}")
                continue

            is_dir = stat.S_ISDIR(st.st_mode)
            if is_dir:
                summary.scanned_directories += 1
            else:
                summary.scanned_files += 1

            findings.extend(self._audit_node(sys_path_str, target, st, spec))

            # Audit directory children for sudoers.d and cron directories
            if is_dir:
                self._audit_directory_children(target, spec, summary, findings, errors)

        summary.execution_time_seconds = time.perf_counter() - start_time
        summary.errors_count = len(errors)
        summary.update_from_findings(findings)

        return ScanResult(
            command="audit-system",
            target_path=str(self.root_dir),
            summary=summary,
            findings=findings,
            errors=errors,
            timestamp=datetime.now(UTC).isoformat(),
        )

    def _audit_node(
        self,
        display_path: str,
        target_path: Path,
        st: os.stat_result,
        spec: dict[str, Any],
    ) -> list[Finding]:
        """Check an individual system file or directory against CIS specifications."""
        node_findings: list[Finding] = []
        mode = st.st_mode
        # Octal representation (e.g. 00644 or 00755)
        octal_str = f"0{mode & 0o7777:04o}"
        max_mode = spec["max_mode"]
        expected_uids: set[int] = spec.get("expected_uids", {0})
        expected_gids: set[int] = spec.get("expected_gids", {0})
        criticality_str = spec.get("criticality", "HIGH")
        severity = getattr(Severity, criticality_str, Severity.HIGH)

        username = self.get_username(st.st_uid)
        groupname = self.get_groupname(st.st_gid)

        # 1. Permission Mask Check
        # A file violates the max mask if any bit outside max_mode is set in permissions
        effective_mode = mode & 0o7777
        forbidden_bits = effective_mode & (~max_mode & 0o7777)

        if forbidden_bits != 0:
            max_mode_octal = f"0{max_mode:04o}"
            node_findings.append(
                Finding(
                    rule_id="LH-PERM-010",
                    rule_name="InsecureSystemFilePerms",
                    category=FindingCategory.SYSTEM_FILE,
                    severity=severity,
                    path=str(target_path),
                    message=(
                        f"Critical system file '{display_path}' permissions ({octal_str}) "
                        f"exceed CIS maximum allowed mask ({max_mode_octal}). "
                        f"Forbidden bits: 0{forbidden_bits:04o}."
                    ),
                    remediation=f"chmod {max_mode_octal} {target_path}",
                    mode=mode,
                    mode_octal=octal_str,
                    owner_uid=st.st_uid,
                    owner_user=username,
                    group_gid=st.st_gid,
                    group_name=groupname,
                    details={
                        "display_path": display_path,
                        "current_mode": octal_str,
                        "max_allowed_mode": max_mode_octal,
                        "forbidden_bits": f"0{forbidden_bits:04o}",
                    },
                )
            )

        # 2. Ownership Check (UID & GID)
        if st.st_uid not in expected_uids:
            node_findings.append(
                Finding(
                    rule_id="LH-PERM-011",
                    rule_name="InsecureSystemFileOwner",
                    category=FindingCategory.SYSTEM_FILE,
                    severity=Severity.HIGH,
                    path=str(target_path),
                    message=(
                        f"Critical system file '{display_path}' is owned by UID {st.st_uid} "
                        f"({username or 'unknown'}), expected one of {expected_uids} (root)."
                    ),
                    remediation=f"chown 0 {target_path}",
                    mode=mode,
                    mode_octal=octal_str,
                    owner_uid=st.st_uid,
                    owner_user=username,
                    group_gid=st.st_gid,
                    group_name=groupname,
                    details={"expected_uids": list(expected_uids)},
                )
            )

        if st.st_gid not in expected_gids:
            node_findings.append(
                Finding(
                    rule_id="LH-PERM-011",
                    rule_name="InsecureSystemFileOwner",
                    category=FindingCategory.SYSTEM_FILE,
                    severity=Severity.HIGH,
                    path=str(target_path),
                    message=(
                        f"Critical system file '{display_path}' belongs to GID {st.st_gid} "
                        f"({groupname or 'unknown'}), expected one of {expected_gids}."
                    ),
                    remediation=f"chgrp 0 {target_path}",
                    mode=mode,
                    mode_octal=octal_str,
                    owner_uid=st.st_uid,
                    owner_user=username,
                    group_gid=st.st_gid,
                    group_name=groupname,
                    details={"expected_gids": list(expected_gids)},
                )
            )

        return node_findings

    def _audit_directory_children(
        self,
        directory_path: Path,
        dir_spec: dict[str, Any],
        summary: ScanSummary,
        findings: list[Finding],
        errors: list[str],
    ) -> None:
        """Inspect entries inside specialized configuration directories (e.g. /etc/sudoers.d)."""
        try:
            entries = sorted(directory_path.iterdir())
        except OSError as err:
            errors.append(f"Cannot list directory {directory_path}: {err}")
            return

        is_sudoers_d = directory_path.name == "sudoers.d"

        for child in entries:
            # Skip editor temporary/backup files (e.g. ~ or .bak)
            if child.name.endswith("~") or child.name.endswith(".bak"):
                continue

            try:
                st = os.stat(child)
            except OSError as err:
                errors.append(f"Cannot stat {child}: {err}")
                continue

            if stat.S_ISDIR(st.st_mode):
                summary.scanned_directories += 1
                child_spec = {
                    "max_mode": 0o750 if is_sudoers_d else 0o700,
                    "expected_uids": dir_spec.get("expected_uids", {0}),
                    "expected_gids": dir_spec.get("expected_gids", {0}),
                    "criticality": "HIGH",
                }
            else:
                summary.scanned_files += 1
                child_spec = {
                    "max_mode": 0o440 if is_sudoers_d else 0o700,
                    "expected_uids": dir_spec.get("expected_uids", {0}),
                    "expected_gids": dir_spec.get("expected_gids", {0}),
                    "criticality": "CRITICAL" if is_sudoers_d else "HIGH",
                }

            display = f"{directory_path.name}/{child.name}"
            findings.extend(self._audit_node(display, child, st, child_spec))
