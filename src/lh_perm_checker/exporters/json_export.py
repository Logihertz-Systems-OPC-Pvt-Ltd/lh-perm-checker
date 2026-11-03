# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.exporters.json_export
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""JSON exporter for structured machine-readable security audit results.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

import json
from pathlib import Path

from lh_perm_checker.models import ScanResult


def export_json(result: ScanResult, output_path: Path | None = None, indent: int = 2) -> str:
    """Export scan results into a structured JSON string and optionally save to file.

    Args:
        result: The ScanResult object to serialize.
        output_path: Optional destination file path.
        indent: Indentation level for pretty-printing.

    Returns:
        Serialized JSON string.
    """
    data = result.to_dict()
    json_str = json.dumps(data, indent=indent)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
