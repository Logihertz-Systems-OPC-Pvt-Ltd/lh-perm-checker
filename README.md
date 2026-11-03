# lh-perm-checker

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perm-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perm-checker/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise filesystem permissions & privilege auditor developed by **Logihertz Systems (OPC) Private Limited**.

Scans POSIX file permission manifests, /etc/sudoers policies, /etc/passwd & /etc/shadow modes, world-writable directories, and SUID/SGID binaries to detect GTFOBins privilege escalation paths and broken ownership.

---

## Key Features

- **SUID/SGID GTFOBins Auditing**: Flags privileged binaries listed in GTFOBins that allow trivial shell escapes or root privilege escalation.
- **World-Writable File & Directory Scanning**: Identifies world-writable system files and directories missing the sticky bit (`+t`).
- **Orphaned Ownership Detection**: Detects files owned by UIDs or GIDs that no longer exist in the system user/group database.
- **CIS Benchmark Compliance**: Audits critical system configuration files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) against CIS permission masks.
- **SSH Security Audit**: Audits `~/.ssh` directories, private key permissions (ensuring mode 0600 or tighter), and authorized_keys files.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-PERM-001` | `CRITICAL` | Known GTFOBins binary with SUID/SGID bit set allowing trivial privilege escalation |
| `LH-PERM-002` | `HIGH` | SUID binary detected that is not present in approved system allowlist |
| `LH-PERM-003` | `MEDIUM` | SGID binary detected that is not present in approved system allowlist |
| `LH-PERM-004` | `HIGH` | Regular file is world-writable by unauthorized users (other write bit enabled) |
| `LH-PERM-005` | `HIGH` | World-writable directory missing sticky bit (+t) allowing arbitrary file tampering |
| `LH-PERM-006` | `MEDIUM` | Orphaned file UID lacking associated system account in /etc/passwd |
| `LH-PERM-010` | `CRITICAL` | Critical system configuration file permissions violate CIS benchmark mask |
| `LH-PERM-011` | `HIGH` | System binary or configuration file owned by non-root user |
| `LH-PERM-020` | `HIGH` | User SSH directory permissions looser than 0700 |
| `LH-PERM-021` | `CRITICAL` | SSH private key file readable or writable by group or others (mode > 0600) |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perm-checker.git
cd lh-perm-checker

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-perm` (also accessible via `lh-perm`).

```bash
# Scan a directory tree for insecure permissions and SUID binaries
lh-perm scan /usr/bin/

# Audit critical system files against CIS benchmarks
lh-perm audit-system /etc/

# Audit SSH directory and key permissions
lh-perm audit-ssh ~/.ssh/ --format json

# Export findings to OASIS SARIF v2.1.0
lh-perm scan / --format sarif --output perm-results.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
