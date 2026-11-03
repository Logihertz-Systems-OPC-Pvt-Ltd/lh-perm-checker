# Security Rules Reference: lh-perm-checker

An enterprise linux permissions & suid/sgid security auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-perm-checker`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-PERM-001` | `CRITICAL` | Privilege Escalation | Known GTFOBins Binary with SUID/SGID Bit Set |
| `LH-PERM-002` | `HIGH` | Privilege Escalation | SUID Binary Detected Not in Approved Allowlist |
| `LH-PERM-003` | `MEDIUM` | Privilege Escalation | SGID Binary Detected Not in Approved Allowlist |
| `LH-PERM-004` | `HIGH` | Filesystem Security | Regular File is World-Writable by Unauthorized Users |
| `LH-PERM-005` | `HIGH` | Filesystem Security | World-Writable Directory Missing Sticky Bit |
| `LH-PERM-006` | `MEDIUM` | Account Hygiene | Orphaned File UID Lacking Associated System Account |
| `LH-PERM-010` | `CRITICAL` | System Hardening | Critical System Configuration Violates CIS Benchmark Mask |
| `LH-PERM-011` | `HIGH` | Ownership | System Binary or Configuration File Owned by Non-Root User |
| `LH-PERM-020` | `HIGH` | SSH Security | User SSH Directory Permissions Looser Than 0700 |
| `LH-PERM-021` | `CRITICAL` | SSH Security | SSH Private Key File Readable by Group or Others |

---

## Granular Rule Specifications

### `LH-PERM-001`: Known GTFOBins Binary with SUID/SGID Bit Set

- **Severity**: `CRITICAL`
- **Category**: `Privilege Escalation`
- **Description**: Known GTFOBins binary (vim, nmap, find, bash) has SUID bit set, permitting root shell escapes.
- **Remediation**: Remove SUID/SGID bits using chmod u-s,g-s <path> unless strictly required for unprivileged operation.

---

### `LH-PERM-002`: SUID Binary Detected Not in Approved Allowlist

- **Severity**: `HIGH`
- **Category**: `Privilege Escalation`
- **Description**: SUID binary found on system that is not registered in enterprise baseline allowlist.
- **Remediation**: Audit binary provenance and remove unauthorized SUID permission.

---

### `LH-PERM-003`: SGID Binary Detected Not in Approved Allowlist

- **Severity**: `MEDIUM`
- **Category**: `Privilege Escalation`
- **Description**: SGID binary found on system that is not registered in enterprise baseline allowlist.
- **Remediation**: Audit binary group permissions and remove unnecessary SGID bit.

---

### `LH-PERM-004`: Regular File is World-Writable by Unauthorized Users

- **Severity**: `HIGH`
- **Category**: `Filesystem Security`
- **Description**: System file has other write bit enabled (e.g. mode 0666 or 0777).
- **Remediation**: Remove world write permissions using chmod o-w <path>.

---

### `LH-PERM-005`: World-Writable Directory Missing Sticky Bit

- **Severity**: `HIGH`
- **Category**: `Filesystem Security`
- **Description**: World-writable directory lacks sticky bit (+t), allowing users to delete each other's files.
- **Remediation**: Set sticky bit using chmod +t <directory> on world-writable directories like /tmp.

---

### `LH-PERM-006`: Orphaned File UID Lacking Associated System Account

- **Severity**: `MEDIUM`
- **Category**: `Account Hygiene`
- **Description**: File owner UID does not exist in /etc/passwd.
- **Remediation**: Reassign ownership to valid system user (chown root:root) or remove orphaned file.

---

### `LH-PERM-010`: Critical System Configuration Violates CIS Benchmark Mask

- **Severity**: `CRITICAL`
- **Category**: `System Hardening`
- **Description**: System files (/etc/passwd, /etc/shadow, /etc/sudoers) have insecure permissions.
- **Remediation**: Apply CIS benchmark permissions (chmod 644 /etc/passwd, chmod 000 /etc/shadow).

---

### `LH-PERM-011`: System Binary or Configuration File Owned by Non-Root User

- **Severity**: `HIGH`
- **Category**: `Ownership`
- **Description**: System binary in /usr/bin or config in /etc owned by non-root user.
- **Remediation**: Reassign ownership strictly to root:root using chown root:root <path>.

---

### `LH-PERM-020`: User SSH Directory Permissions Looser Than 0700

- **Severity**: `HIGH`
- **Category**: `SSH Security`
- **Description**: SSH directory (~/.ssh) permissions allow group or other users to read/write.
- **Remediation**: Set restrictive permissions on SSH directory using chmod 700 ~/.ssh.

---

### `LH-PERM-021`: SSH Private Key File Readable by Group or Others

- **Severity**: `CRITICAL`
- **Category**: `SSH Security`
- **Description**: Private key file (~/.ssh/id_rsa, id_ed25519) has permissions looser than 0600.
- **Remediation**: Enforce strict private key permissions using chmod 600 ~/.ssh/id_*.

---
