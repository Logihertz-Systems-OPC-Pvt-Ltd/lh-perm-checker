# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command Line Interface (lh-perm) for Logihertz Linux permission auditor.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from lh_perm_checker.exporters.json_export import export_json
from lh_perm_checker.exporters.sarif import export_sarif
from lh_perm_checker.exporters.table import render_table
from lh_perm_checker.models import OutputFormat, ScanResult
from lh_perm_checker.scanner import FilesystemScanner, load_allowlist
from lh_perm_checker.ssh_auditor import SshAuditor
from lh_perm_checker.system_auditor import SystemAuditor

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-perm",
    help=(
        "Linux filesystem permission and SUID/SGID binary auditor by Logihertz Systems OPC Pvt Ltd."
    ),
    add_completion=False,
    no_args_is_help=True,
)


def _output_result(
    result: ScanResult,
    fmt: OutputFormat,
    output_path: Path | None,
    exit_code_on_findings: bool = False,
) -> None:
    """Format and dispatch scan results according to specified output format."""
    if fmt == OutputFormat.TABLE:
        rendered = render_table(result, output_path=output_path)
        if output_path is None:
            sys.stdout.write(rendered)
            sys.stdout.flush()
    elif fmt == OutputFormat.JSON:
        rendered = export_json(result, output_path=output_path)
        if output_path is None:
            sys.stdout.write(rendered + "\n")
            sys.stdout.flush()
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(result, output_path=output_path)
        if output_path is None:
            sys.stdout.write(rendered + "\n")
            sys.stdout.flush()

    if exit_code_on_findings and result.summary.findings_count > 0:
        raise typer.Exit(code=1)


@app.command(name="scan")
def scan_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Filesystem path or directory tree to scan for permission issues.",
            exists=True,
            resolve_path=True,
        ),
    ],
    allowlist: Annotated[
        Path | None,
        typer.Option(
            "--allowlist",
            "-a",
            help="Path to custom SUID/SGID baseline allowlist JSON file.",
        ),
    ] = None,
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional destination file path to save report.",
        ),
    ] = None,
    orphans: Annotated[
        bool,
        typer.Option(
            "--orphans/--no-orphans",
            help="Audit for orphaned UIDs and GIDs.",
        ),
    ] = True,
    follow_symlinks: Annotated[
        bool,
        typer.Option(
            "--follow-symlinks",
            help="Follow symbolic links during filesystem traversal.",
        ),
    ] = False,
    exit_code: Annotated[
        bool,
        typer.Option(
            "--exit-code",
            help="Exit with non-zero code if security findings are detected.",
        ),
    ] = False,
) -> None:
    """Scan filesystem trees for SUID/SGID binaries, world-writable files, and orphans."""
    try:
        loaded_allowlist = load_allowlist(allowlist)
    except FileNotFoundError as err:
        typer.secho(f"Error loading allowlist: {err}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from err

    scanner = FilesystemScanner(allowlist=loaded_allowlist)
    result = scanner.scan_path(
        target_path=path,
        include_orphans=orphans,
        follow_symlinks=follow_symlinks,
    )
    _output_result(result, format, output, exit_code_on_findings=exit_code)


@app.command(name="audit-system")
def audit_system_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            "-r",
            help="Root directory to audit (default: /). Useful for chroot/mock audits.",
            exists=True,
            resolve_path=True,
        ),
    ] = Path("/"),
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional destination file path to save report.",
        ),
    ] = None,
    exit_code: Annotated[
        bool,
        typer.Option(
            "--exit-code",
            help="Exit with non-zero code if security findings are detected.",
        ),
    ] = False,
) -> None:
    """Audit critical system and credential paths against strict CIS permission masks."""
    auditor = SystemAuditor(root_dir=root)
    result = auditor.audit()
    _output_result(result, format, output, exit_code_on_findings=exit_code)


@app.command(name="audit-ssh")
def audit_ssh_command(
    ssh_dir: Annotated[
        Path | None,
        typer.Argument(
            help="Path to SSH directory to audit (default: ~/.ssh).",
        ),
    ] = None,
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional destination file path to save report.",
        ),
    ] = None,
    exit_code: Annotated[
        bool,
        typer.Option(
            "--exit-code",
            help="Exit with non-zero code if security findings are detected.",
        ),
    ] = False,
) -> None:
    """Audit SSH configuration directory, private keys, and authorized_keys."""
    auditor = SshAuditor(ssh_dir=ssh_dir)
    result = auditor.audit()
    _output_result(result, format, output, exit_code_on_findings=exit_code)


def main() -> None:
    """CLI entrypoint function for lh-perm."""
    app()


if __name__ == "__main__":
    main()
