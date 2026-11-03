# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Filesystem scanner for SUID/SGID binaries, world-writable files, and orphans.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

from lh_perm_checker.constants import (
    DEFAULT_SUID_ALLOWLIST,
    RISKY_SUID_BINARIES,
)
from lh_perm_checker.models import (
    Finding,
    FindingCategory,
    ScanResult,
    ScanSummary,
    Severity,
)


def load_allowlist(allowlist_path: Path | None) -> set[str]:
    """Load SUID/SGID allowlist from a JSON file, or return the default allowlist.

    The JSON file may be a list of paths/names, or a dictionary containing an
    'allowed_binaries' or 'allowed' key.
    """
    if allowlist_path is None:
        return set(DEFAULT_SUID_ALLOWLIST)

    if not allowlist_path.exists():
        raise FileNotFoundError(f"Allowlist file not found: {allowlist_path}")

    with open(allowlist_path, encoding="utf-8") as f:
        data = json.load(f)

    result_set: set[str] = set()
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                result_set.add(item)
    elif isinstance(data, dict):
        entries = (
            data.get("allowed_binaries") or data.get("allowed") or data.get("suid_allowlist") or []
        )
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, str):
                    result_set.add(item)
        elif isinstance(entries, dict):
            result_set.update(str(k) for k in entries.keys())
    return result_set


class FilesystemScanner:
    """Audits filesystem hierarchies for SUID/SGID binaries, permission risks, and orphans."""

    def __init__(self, allowlist: set[str] | None = None) -> None:
        """Initialize the scanner with an optional custom allowlist."""
        self.allowlist: set[str] = (
            allowlist if allowlist is not None else set(DEFAULT_SUID_ALLOWLIST)
        )
        self._user_cache: dict[int, str | None] = {}
        self._group_cache: dict[int, str | None] = {}
        self._load_system_principals()

    def _load_system_principals(self) -> None:
        """Pre-populate cached user and group identities from the system databases."""
        try:
            for p in pwd.getpwall():
                self._user_cache[p.pw_uid] = p.pw_name
        except (AttributeError, KeyError, OSError):
            pass

        try:
            for g in grp.getgrall():
                self._group_cache[g.gr_gid] = g.gr_name
        except (AttributeError, KeyError, OSError):
            pass

    def get_username(self, uid: int) -> str | None:
        """Resolve numeric UID to username, using cache with dynamic fallback."""
        if uid in self._user_cache:
            return self._user_cache[uid]
        try:
            name = pwd.getpwuid(uid).pw_name
            self._user_cache[uid] = name
            return name
        except (KeyError, OSError, ValueError):
            self._user_cache[uid] = None
            return None

    def get_groupname(self, gid: int) -> str | None:
        """Resolve numeric GID to group name, using cache with dynamic fallback."""
        if gid in self._group_cache:
            return self._group_cache[gid]
        try:
            name = grp.getgrgid(gid).gr_name
            self._group_cache[gid] = name
            return name
        except (KeyError, OSError, ValueError):
            self._group_cache[gid] = None
            return None

    def is_in_allowlist(self, file_path: Path) -> bool:
        """Determine whether a file path or binary name matches the allowlist."""
        resolved = str(file_path.resolve()) if file_path.exists() else str(file_path)
        raw_str = str(file_path)
        name = file_path.name

        return resolved in self.allowlist or raw_str in self.allowlist or name in self.allowlist

    def scan_path(
        self,
        target_path: Path,
        include_orphans: bool = True,
        follow_symlinks: bool = False,
    ) -> ScanResult:
        """Scan a path or directory tree for permission anomalies and security risks.

        Args:
            target_path: Root filesystem path or single file to analyze.
            include_orphans: Whether to flag unowned UIDs and GIDs.
            follow_symlinks: Whether to traverse symbolic links.

        Returns:
            ScanResult containing all discovered findings and summary metrics.
        """
        start_time = time.perf_counter()
        summary = ScanSummary()
        findings: list[Finding] = []
        errors: list[str] = []

        target = Path(target_path)
        if not target.exists() and not target.is_symlink():
            errors.append(f"Target path does not exist: {target}")
            summary.errors_count = len(errors)
            summary.execution_time_seconds = time.perf_counter() - start_time
            return ScanResult(
                command="scan",
                target_path=str(target),
                summary=summary,
                findings=[],
                errors=errors,
                timestamp=datetime.now(UTC).isoformat(),
            )

        # Single file analysis
        if not target.is_dir():
            summary.scanned_targets += 1
            summary.scanned_files += 1
            try:
                st = os.stat(target) if follow_symlinks else os.lstat(target)
                findings.extend(
                    self.analyze_stat(
                        target,
                        st,
                        is_dir=False,
                        include_orphans=include_orphans,
                    )
                )
            except OSError as err:
                errors.append(f"Cannot stat {target}: {err}")
        else:
            summary.scanned_targets += 1
            # First analyze the root directory itself
            try:
                root_st = os.stat(target) if follow_symlinks else os.lstat(target)
                summary.scanned_directories += 1
                findings.extend(
                    self.analyze_stat(
                        target,
                        root_st,
                        is_dir=True,
                        include_orphans=include_orphans,
                    )
                )
            except OSError as err:
                errors.append(f"Cannot stat root dir {target}: {err}")

            # Walk directory tree
            for root, dirs, files in os.walk(
                target,
                topdown=True,
                followlinks=follow_symlinks,
                onerror=lambda err: errors.append(str(err)),
            ):
                root_p = Path(root)

                # Check subdirectories
                for d in dirs:
                    summary.scanned_directories += 1
                    d_path = root_p / d
                    try:
                        st = os.stat(d_path) if follow_symlinks else os.lstat(d_path)
                        findings.extend(
                            self.analyze_stat(
                                d_path,
                                st,
                                is_dir=True,
                                include_orphans=include_orphans,
                            )
                        )
                    except OSError as err:
                        errors.append(f"Cannot stat dir {d_path}: {err}")

                # Check files
                for f in files:
                    summary.scanned_files += 1
                    f_path = root_p / f
                    try:
                        st = os.stat(f_path) if follow_symlinks else os.lstat(f_path)
                        findings.extend(
                            self.analyze_stat(
                                f_path,
                                st,
                                is_dir=False,
                                include_orphans=include_orphans,
                            )
                        )
                    except OSError as err:
                        errors.append(f"Cannot stat file {f_path}: {err}")

        summary.execution_time_seconds = time.perf_counter() - start_time
        summary.errors_count = len(errors)
        summary.update_from_findings(findings)

        return ScanResult(
            command="scan",
            target_path=str(target),
            summary=summary,
            findings=findings,
            errors=errors,
            timestamp=datetime.now(UTC).isoformat(),
        )

    def analyze_stat(
        self,
        path: Path,
        st: os.stat_result,
        is_dir: bool,
        include_orphans: bool = True,
    ) -> list[Finding]:
        """Analyze a filesystem node's stat result for permission issues."""
        findings: list[Finding] = []
        mode = st.st_mode
        # Ensure 4 or 5 digit octal format with leading zero (e.g. 04755 or 00777)
        octal_str = f"0{mode & 0o7777:04o}"

        username = self.get_username(st.st_uid)
        groupname = self.get_groupname(st.st_gid)

        # 1. SUID & SGID Detection
        has_suid = bool(mode & stat.S_ISUID)
        has_sgid = bool(mode & stat.S_ISGID)

        if not is_dir and (has_suid or has_sgid):
            bin_name = path.name.lower()
            is_gtfobins = bin_name in RISKY_SUID_BINARIES
            in_allowlist = self.is_in_allowlist(path)

            if is_gtfobins:
                threat_desc = RISKY_SUID_BINARIES[bin_name]
                msg = (
                    f"Binary '{path.name}' has {'SUID' if has_suid else 'SGID'} set "
                    f"and is a known GTFOBins privilege escalation risk: {threat_desc}"
                )
                severity = Severity.CRITICAL if (has_suid or st.st_uid == 0) else Severity.HIGH
                findings.append(
                    Finding(
                        rule_id="LH-PERM-001",
                        rule_name="RiskySuidBinary",
                        category=FindingCategory.SUID_SGID,
                        severity=severity,
                        path=str(path),
                        message=msg,
                        remediation=f"Remove SUID/SGID bit: chmod u-s,g-s {path}",
                        mode=mode,
                        mode_octal=octal_str,
                        owner_uid=st.st_uid,
                        owner_user=username,
                        group_gid=st.st_gid,
                        group_name=groupname,
                        details={
                            "suid": has_suid,
                            "sgid": has_sgid,
                            "gtfobins": True,
                            "threat": threat_desc,
                        },
                    )
                )
            elif not in_allowlist:
                if has_suid:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-002",
                            rule_name="UnallowlistedSuid",
                            category=FindingCategory.SUID_SGID,
                            severity=Severity.HIGH,
                            path=str(path),
                            message=(
                                f"SUID binary '{path}' (mode {octal_str}) is not present "
                                "in the baseline allowlist."
                            ),
                            remediation=f"Verify requirement or remove SUID bit: chmod u-s {path}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                            details={"suid": True, "sgid": has_sgid},
                        )
                    )
                elif has_sgid:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-003",
                            rule_name="UnallowlistedSgid",
                            category=FindingCategory.SUID_SGID,
                            severity=Severity.MEDIUM,
                            path=str(path),
                            message=(
                                f"SGID binary '{path}' (mode {octal_str}) is not present "
                                "in the baseline allowlist."
                            ),
                            remediation=f"Verify requirement or remove SGID bit: chmod g-s {path}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                            details={"suid": False, "sgid": True},
                        )
                    )

        # 2. World-Writable Files and Sticky Bit Checking
        is_world_writable = bool(mode & stat.S_IWOTH)

        if is_world_writable:
            if is_dir:
                has_sticky_bit = bool(mode & stat.S_ISVTX)
                if not has_sticky_bit:
                    findings.append(
                        Finding(
                            rule_id="LH-PERM-005",
                            rule_name="WorldWritableDirNoSticky",
                            category=FindingCategory.STICKY_BIT,
                            severity=Severity.HIGH,
                            path=str(path),
                            message=(
                                f"Directory '{path}' is world-writable ({octal_str}) but missing "
                                "the sticky bit (01000). Users may delete or rename others' files."
                            ),
                            remediation=f"Enable sticky bit or revoke world write: chmod +t {path}",
                            mode=mode,
                            mode_octal=octal_str,
                            owner_uid=st.st_uid,
                            owner_user=username,
                            group_gid=st.st_gid,
                            group_name=groupname,
                            details={"world_writable": True, "sticky_bit": False},
                        )
                    )
            else:
                findings.append(
                    Finding(
                        rule_id="LH-PERM-004",
                        rule_name="WorldWritableFile",
                        category=FindingCategory.WORLD_WRITABLE,
                        severity=Severity.HIGH,
                        path=str(path),
                        message=(
                            f"File '{path}' is world-writable ({octal_str}). Any unprivileged user "
                            "can modify or corrupt this file."
                        ),
                        remediation=f"Revoke world-write permission: chmod o-w {path}",
                        mode=mode,
                        mode_octal=octal_str,
                        owner_uid=st.st_uid,
                        owner_user=username,
                        group_gid=st.st_gid,
                        group_name=groupname,
                        details={"world_writable": True},
                    )
                )

        # 3. Orphaned UID / GID Detection
        if include_orphans:
            if username is None:
                findings.append(
                    Finding(
                        rule_id="LH-PERM-006",
                        rule_name="OrphanedUid",
                        category=FindingCategory.ORPHAN,
                        severity=Severity.MEDIUM,
                        path=str(path),
                        message=(
                            f"Resource '{path}' is owned by UID {st.st_uid}, which does not "
                            "exist in the system user database."
                        ),
                        remediation=f"Assign valid ownership: chown <user> {path}",
                        mode=mode,
                        mode_octal=octal_str,
                        owner_uid=st.st_uid,
                        owner_user=None,
                        group_gid=st.st_gid,
                        group_name=groupname,
                        details={"orphaned_uid": st.st_uid},
                    )
                )

            if groupname is None:
                findings.append(
                    Finding(
                        rule_id="LH-PERM-007",
                        rule_name="OrphanedGid",
                        category=FindingCategory.ORPHAN,
                        severity=Severity.LOW,
                        path=str(path),
                        message=(
                            f"Resource '{path}' belongs to GID {st.st_gid}, which does not "
                            "exist in the system group database."
                        ),
                        remediation=f"Assign valid group: chgrp <group> {path}",
                        mode=mode,
                        mode_octal=octal_str,
                        owner_uid=st.st_uid,
                        owner_user=username,
                        group_gid=st.st_gid,
                        group_name=None,
                        details={"orphaned_gid": st.st_gid},
                    )
                )

        return findings
