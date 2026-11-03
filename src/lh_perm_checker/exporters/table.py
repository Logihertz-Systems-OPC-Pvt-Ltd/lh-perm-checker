# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Terminal table renderer using Rich for clean security auditing reports.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_perm_checker.models import ScanResult


def render_table(result: ScanResult, output_path: Path | None = None) -> str:
    """Render scan and audit results as a rich, color-coded terminal table.

    If output_path is provided, writes the ANSI formatted text to the file.
    Always returns the rendered string.
    """
    string_io = io.StringIO()
    # console configured for terminal rendering
    console = Console(file=string_io, force_terminal=True, width=120)

    # 1. Summary Header
    summary = result.summary
    header_text = Text()
    header_text.append("Logihertz Linux Permission Checker\n", style="bold cyan")
    header_text.append(f"Command: {result.command}  |  Target: {result.target_path}\n", style="dim")
    header_text.append(
        f"Scanned: {summary.scanned_targets} targets "
        f"({summary.scanned_directories} dirs, {summary.scanned_files} files) in "
        f"{summary.execution_time_seconds:.3f}s\n"
    )

    badge_text = Text("Severities: ")
    badge_text.append(f" CRITICAL: {summary.critical_count} ", style="bold white on red")
    badge_text.append(" ")
    badge_text.append(f" HIGH: {summary.high_count} ", style="bold black on bright_red")
    badge_text.append(" ")
    badge_text.append(f" MEDIUM: {summary.medium_count} ", style="bold black on yellow")
    badge_text.append(" ")
    badge_text.append(f" LOW: {summary.low_count} ", style="bold black on cyan")
    badge_text.append(" ")
    badge_text.append(f" INFO: {summary.info_count} ", style="bold white on blue")

    console.print(
        Panel(
            Text.assemble(header_text, badge_text),
            title="[bold blue]Audit Summary[/bold blue]",
            border_style="blue",
        )
    )

    # 2. Findings Table
    if not result.findings:
        console.print(
            Panel(
                "[bold green]✓ Clean![/bold green] No security or permission issues detected.",
                border_style="green",
            )
        )
    else:
        table = Table(
            title=f"Security Findings ({len(result.findings)} detected)",
            title_style="bold magenta",
            show_header=True,
            header_style="bold underline",
            border_style="dim",
            expand=True,
        )
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule ID", justify="center", width=14)
        table.add_column("Target Path", style="bold", overflow="fold")
        table.add_column("Mode", justify="center", width=8)
        table.add_column("Owner:Group", justify="center", width=16)
        table.add_column("Finding & Remediation", overflow="fold")

        for f in result.findings:
            sev_style = f.severity.rich_color
            sev_badge = f"[{sev_style}]{f.severity.value}[/{sev_style}]"

            owner = f"{f.owner_user or f.owner_uid}:{f.group_name or f.group_gid}"
            desc = Text()
            desc.append(f"{f.message}\n")
            desc.append(f"Fix: {f.remediation}", style="italic green")

            table.add_row(
                sev_badge,
                f.rule_id,
                f.path,
                f.mode_octal or "-",
                owner,
                desc,
            )

        console.print(table)

    # 3. Errors encountered during scan (if any)
    if result.errors:
        err_text = Text("\n".join(f"• {e}" for e in result.errors[:10]), style="red")
        if len(result.errors) > 10:
            err_text.append(f"\n... and {len(result.errors) - 10} more errors.", style="dim")
        console.print(
            Panel(
                err_text,
                title=f"[bold red]Scan Warnings/Errors ({len(result.errors)})[/bold red]",
                border_style="red",
            )
        )

    output_str = string_io.getvalue()
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Write clean plain-text/ANSI to file
        output_path.write_text(output_str, encoding="utf-8")

    return output_str
