# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models for lh-perm-checker findings, summaries, and scan results.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Finding severity levels aligned with security standards."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def sarif_level(self) -> str:
        """Map severity to OASIS SARIF v2.1.0 result level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping[self]

    @property
    def rich_color(self) -> str:
        """Rich formatting color tag for terminal output."""
        mapping = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "blue",
        }
        return mapping[self]


class OutputFormat(StrEnum):
    """Supported output formats for audit and scan reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class FindingCategory(StrEnum):
    """Categorization of filesystem security findings."""

    SUID_SGID = "SUID/SGID Binary"
    WORLD_WRITABLE = "World-Writable Resource"
    STICKY_BIT = "Sticky Bit Violation"
    ORPHAN = "Orphaned File"
    SYSTEM_FILE = "Critical System File"
    SSH_CONFIG = "SSH Configuration & Keys"


@dataclass
class Finding:
    """Represents an individual security finding detected during auditing."""

    rule_id: str
    rule_name: str
    category: FindingCategory
    severity: Severity
    path: str
    message: str
    remediation: str
    mode: int | None = None
    mode_octal: str | None = None
    owner_uid: int | None = None
    owner_user: str | None = None
    group_gid: int | None = None
    group_name: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding into a serializable dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "path": self.path,
            "message": self.message,
            "remediation": self.remediation,
            "mode": self.mode,
            "mode_octal": self.mode_octal,
            "owner_uid": self.owner_uid,
            "owner_user": self.owner_user,
            "group_gid": self.group_gid,
            "group_name": self.group_name,
            "details": self.details,
        }


@dataclass
class ScanSummary:
    """Aggregated counters and metrics from a scan or audit session."""

    scanned_targets: int = 0
    scanned_directories: int = 0
    scanned_files: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    errors_count: int = 0
    execution_time_seconds: float = 0.0

    def update_from_findings(self, findings: list[Finding]) -> None:
        """Update severity counters given a list of findings."""
        self.findings_count = len(findings)
        self.critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in findings if f.severity == Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """Convert summary counters into a serializable dictionary."""
        return {
            "scanned_targets": self.scanned_targets,
            "scanned_directories": self.scanned_directories,
            "scanned_files": self.scanned_files,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "errors_count": self.errors_count,
            "execution_time_seconds": round(self.execution_time_seconds, 4),
        }


@dataclass
class ScanResult:
    """Complete results of an execution, including findings and metadata."""

    command: str
    target_path: str
    summary: ScanSummary
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result into a serializable dictionary."""
        return {
            "command": self.command,
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
