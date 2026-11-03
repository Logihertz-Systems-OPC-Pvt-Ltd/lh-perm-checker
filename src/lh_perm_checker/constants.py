# ==============================================================================
# Product:       lh-perm-checker (lh-perm)
# Module:        src.lh_perm_checker.constants
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Constants, rule definitions, GTFOBins risky binary catalogs, and CIS masks.

Developed by Logihertz Systems OPC Pvt Ltd.
"""

from __future__ import annotations

from typing import Any

# GTFOBins-style binaries known to enable privilege escalation or shell escapes when SUID/SGID.
# Explicitly includes: vim, find, python, bash, nmap, docker, as specified in SPEC.md.
RISKY_SUID_BINARIES: dict[str, str] = {
    # Core spec binaries
    "vim": "Spawns interactive shell via ':!/bin/sh' or modifies arbitrary files.",
    "vi": "Spawns interactive shell via ':!sh' or modifies arbitrary files.",
    "view": "Read arbitrary files or spawn shell via internal command execution.",
    "find": "Executes arbitrary commands with elevated privileges via '-exec' flag.",
    "python": "Executes arbitrary system commands or Python code via 'import os; os.setuid(0)'.",
    "python3": "Executes arbitrary system commands or Python code via 'import os; os.setuid(0)'.",
    "python2": "Executes arbitrary system commands or Python code via 'import os; os.setuid(0)'.",
    "bash": "Direct root shell invocation with '-p' flag preserving elevated effective UID.",
    "sh": "Direct root shell invocation with '-p' flag preserving elevated effective UID.",
    "dash": "Spawns subshell retaining SUID privileges.",
    "zsh": "Spawns subshell retaining SUID privileges.",
    "nmap": "Executes arbitrary scripts via '--script' or interactive shell mode.",
    "docker": "Container escape and arbitrary host filesystem mount.",
    # Additional high-risk GTFOBins binaries
    "awk": "Executes arbitrary system commands via 'BEGIN {system(\"/bin/sh\")}'.",
    "gawk": "Executes arbitrary system commands via 'BEGIN {system(\"/bin/sh\")}'.",
    "mawk": "Executes arbitrary system commands via 'BEGIN {system(\"/bin/sh\")}'.",
    "perl": "Executes arbitrary system calls via 'perl -e 'exec \"/bin/sh\";''.",
    "ruby": "Executes arbitrary system commands via 'exec \"/bin/sh\"'.",
    "tar": "Executes arbitrary checkpoints via '--checkpoint-action=exec=/bin/sh'.",
    "cp": "Overwrites sensitive files like /etc/passwd or /etc/shadow with arbitrary contents.",
    "mv": "Moves or overwrites sensitive configuration files and binaries.",
    "less": "Escapes to interactive shell via '!/bin/sh'.",
    "more": "Escapes to interactive shell via '!/bin/sh'.",
    "nano": "Spawns shell or reads/writes arbitrary root files.",
    "pico": "Spawns shell or reads/writes arbitrary root files.",
    "sed": "Executes commands via 'e' command or overwrites arbitrary files.",
    "sudo": "Privilege escalation vector if misconfigured.",
    "gdb": "Executes arbitrary shell commands via '-ex '!sh''.",
    "env": "Executes arbitrary commands via 'env /bin/sh -p'.",
    "pkexec": "Can be manipulated for local privilege escalation.",
    "strace": "Executes commands or attaches to privileged processes.",
    "ltrace": "Executes commands or attaches to privileged processes.",
    "systemctl": "Loads malicious service units or launches interactive pager shell.",
    "journalctl": "Launches interactive pager shell escaping to root.",
    "tee": "Appends malicious accounts directly to /etc/passwd.",
    "chmod": "Allows modifying permissions on /etc/shadow or /etc/sudoers.",
    "chown": "Allows changing ownership of sensitive system files to unprivileged user.",
    "curl": "Downloads malicious scripts or uploads sensitive files to remote server.",
    "wget": "Downloads malicious payloads or overwrites system files.",
    "nc": "Opens arbitrary reverse or bind shell connections.",
    "ncat": "Opens arbitrary reverse or bind shell connections.",
    "netcat": "Opens arbitrary reverse or bind shell connections.",
    "socat": "Establishes bi-directional communication channels and root shells.",
    "busybox": "Provides multi-call binary with built-in root shells and utilities.",
    "xargs": "Executes arbitrary binaries with elevated privileges via '-a /dev/null sh'.",
    "dd": "Reads or writes raw disk blocks, /etc/shadow, or master boot records.",
    "openssl": "Reads arbitrary files or writes raw bytes to sensitive locations.",
    "base64": "Reads sensitive files bypassing file access controls via decoding.",
    "git": "Executes arbitrary pager or hook commands escaping to root.",
    "make": "Executes arbitrary shell targets with elevated privileges.",
    "gcc": "Compiles and executes arbitrary C payloads with elevated privileges.",
    "g++": "Compiles and executes arbitrary C++ payloads with elevated privileges.",
    "editor": "Interactive editor shell escape.",
    "node": "Executes arbitrary JavaScript or child processes as root.",
    "php": "Executes arbitrary PHP code and system calls.",
    "lua": "Executes arbitrary OS calls via os.execute.",
    "tclsh": "Executes arbitrary commands via 'exec /bin/sh'.",
    "expect": "Spawns interactive shell as root.",
    "taskset": "Executes arbitrary binaries with custom CPU affinity.",
    "timeout": "Executes arbitrary binaries with timeout wrapper.",
    "flock": "Executes arbitrary binaries under file lock.",
    "ionice": "Executes arbitrary binaries with specified I/O scheduling class.",
    "nice": "Executes arbitrary binaries with modified priority.",
}

# Standard baseline allowlist for common benign Linux SUID/SGID binaries.
DEFAULT_SUID_ALLOWLIST: set[str] = {
    # Standard authentication & account management
    "/usr/bin/passwd",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/expiry",
    # Mount and unmount utilities
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/bin/mount",
    "/bin/umount",
    "/bin/su",
    # Cron and scheduling
    "/usr/bin/crontab",
    "/usr/bin/at",
    # Polkit and D-Bus helpers
    "/usr/bin/pkexec",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/libexec/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    # SSH and PAM helpers
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/sbin/unix_chkpwd",
    "/sbin/unix_chkpwd",
    # Network tools
    "/usr/bin/ping",
    "/bin/ping",
}

# CIS Benchmark rules for critical system files.
# Specifies maximum allowed octal permission masks and ownership.
CRITICAL_SYSTEM_FILES: dict[str, dict[str, Any]] = {
    "/etc/passwd": {
        "max_mode": 0o644,
        "description": "User account database",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "HIGH",
    },
    "/etc/shadow": {
        "max_mode": 0o640,
        "description": "User password hash database",
        "expected_uids": {0},
        "expected_gids": {0, 42},  # 42 is typical 'shadow' group in Debian/Ubuntu
        "criticality": "CRITICAL",
    },
    "/etc/gshadow": {
        "max_mode": 0o640,
        "description": "Group password hash database",
        "expected_uids": {0},
        "expected_gids": {0, 42},
        "criticality": "CRITICAL",
    },
    "/etc/group": {
        "max_mode": 0o644,
        "description": "Group account database",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "HIGH",
    },
    "/etc/sudoers": {
        "max_mode": 0o440,
        "description": "Sudoers privilege specification",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "CRITICAL",
    },
    "/etc/crontab": {
        "max_mode": 0o600,
        "description": "System crontab table",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "HIGH",
    },
    "/etc/cron.hourly": {
        "max_mode": 0o700,
        "is_dir": True,
        "description": "Hourly cron jobs directory",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "MEDIUM",
    },
    "/etc/cron.daily": {
        "max_mode": 0o700,
        "is_dir": True,
        "description": "Daily cron jobs directory",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "MEDIUM",
    },
    "/etc/cron.weekly": {
        "max_mode": 0o700,
        "is_dir": True,
        "description": "Weekly cron jobs directory",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "MEDIUM",
    },
    "/etc/cron.monthly": {
        "max_mode": 0o700,
        "is_dir": True,
        "description": "Monthly cron jobs directory",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "MEDIUM",
    },
    "/etc/cron.d": {
        "max_mode": 0o700,
        "is_dir": True,
        "description": "Cron daemon spool directory",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "MEDIUM",
    },
    "/etc/sudoers.d": {
        "max_mode": 0o750,
        "is_dir": True,
        "description": "Additional sudoers configuration directory",
        "expected_uids": {0},
        "expected_gids": {0},
        "criticality": "HIGH",
    },
}

# SARIF Rules Catalog with comprehensive descriptions and remediation guidance.
SARIF_RULES_CATALOG: list[dict[str, Any]] = [
    {
        "id": "LH-PERM-001",
        "name": "RiskySuidBinary",
        "shortDescription": {"text": "Known GTFOBins privilege escalation SUID binary detected"},
        "fullDescription": {
            "text": (
                "An executable binary with SUID or SGID permissions set was identified as a known "
                "GTFOBins privilege escalation binary (e.g. vim, find, python, "
                "bash, nmap, docker). Any unprivileged user can leverage this binary to escape "
                "restrictions, read sensitive files, or execute commands as the binary's owner."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Remove the SUID/SGID bit using 'chmod u-s,g-s <path>' or restrict execution."
        },
    },
    {
        "id": "LH-PERM-002",
        "name": "UnallowlistedSuid",
        "shortDescription": {"text": "SUID binary detected not in baseline allowlist"},
        "fullDescription": {
            "text": (
                "An executable file has the SUID (04000) bit set and is not documented in the "
                "approved baseline allowlist. SUID binaries run with the privileges of their owner "
                "and represent potential attack surfaces."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Verify necessity of SUID bit; remove using 'chmod u-s <path>' if unneeded."
        },
    },
    {
        "id": "LH-PERM-003",
        "name": "UnallowlistedSgid",
        "shortDescription": {"text": "SGID binary detected not in baseline allowlist"},
        "fullDescription": {
            "text": (
                "An executable file has the SGID (02000) bit set and is not documented in the "
                "approved baseline allowlist. SGID binaries run with group privileges."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Verify necessity of SGID bit; remove using 'chmod g-s <path>' if unneeded."
        },
    },
    {
        "id": "LH-PERM-004",
        "name": "WorldWritableFile",
        "shortDescription": {"text": "File is writable by all users (world-writable)"},
        "fullDescription": {
            "text": (
                "A regular file or special device has world-writable permissions (0002). Any local "
                "user or compromised process on the system can modify or truncate its content."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Remove world-write permissions using 'chmod o-w <path>'."},
    },
    {
        "id": "LH-PERM-005",
        "name": "WorldWritableDirNoSticky",
        "shortDescription": {"text": "World-writable directory missing sticky bit"},
        "fullDescription": {
            "text": (
                "A directory has world-writable permissions (0002) but lacks the sticky bit "
                "(01000). Without the sticky bit, any user on the system can delete or rename "
                "files belonging to other users within this directory."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Add the sticky bit using 'chmod +t <path>' or remove world-write access."
        },
    },
    {
        "id": "LH-PERM-006",
        "name": "OrphanedUid",
        "shortDescription": {"text": "File owner UID does not exist on the system"},
        "fullDescription": {
            "text": (
                "The file or directory is owned by a numeric UID that has no matching account in "
                "/etc/passwd. If an account is created in the future with this UID, that user will "
                "automatically inherit ownership."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": (
                "Assign ownership to an active user using 'chown <user> <path>' or delete the file."
            )
        },
    },
    {
        "id": "LH-PERM-007",
        "name": "OrphanedGid",
        "shortDescription": {"text": "File group GID does not exist on the system"},
        "fullDescription": {
            "text": (
                "The file or directory belongs to a numeric GID that has no matching "
                "group in /etc/group. New groups created with this GID will inherit access."
            )
        },
        "defaultConfiguration": {"level": "note"},
        "help": {"text": "Assign group ownership using 'chgrp <group> <path>'."},
    },
    {
        "id": "LH-PERM-010",
        "name": "InsecureSystemFilePerms",
        "shortDescription": {"text": "Critical system file violates CIS permission mask"},
        "fullDescription": {
            "text": (
                "A critical system file (such as /etc/passwd, /etc/shadow, /etc/sudoers, or "
                "/etc/crontab) has permissions more permissive than mandated by CIS Benchmarks."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": (
                "Harden file permissions to match CIS recommendations (e.g. 0640 for /etc/shadow)."
            )
        },
    },
    {
        "id": "LH-PERM-011",
        "name": "InsecureSystemFileOwner",
        "shortDescription": {"text": "Critical system file has invalid owner or group"},
        "fullDescription": {
            "text": (
                "A critical system configuration file is not owned by root (UID 0) or designated "
                "system service group."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Reset ownership to root:root using 'chown root:root <path>'."},
    },
    {
        "id": "LH-PERM-020",
        "name": "InsecureSshDirPerms",
        "shortDescription": {"text": "SSH directory permissions too permissive"},
        "fullDescription": {
            "text": (
                "The SSH directory (.ssh) has permissions looser than 0700. Group or world users "
                "may list, read, or place files into the SSH configuration directory."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Enforce strict directory permissions using 'chmod 0700 <ssh-dir>'."},
    },
    {
        "id": "LH-PERM-021",
        "name": "InsecureSshPrivateKey",
        "shortDescription": {"text": "SSH private key accessible by group or others"},
        "fullDescription": {
            "text": (
                "An SSH private key file is readable or writable by group or other users. "
                "OpenSSH will typically reject keys with insecure permissions."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Protect private key with 'chmod 0600 <key-file>' (or 0400 for read-only)."
        },
    },
    {
        "id": "LH-PERM-022",
        "name": "InsecureSshAuthorizedKeys",
        "shortDescription": {"text": "SSH authorized_keys permissions too permissive"},
        "fullDescription": {
            "text": (
                "The authorized_keys file permissions allow group or others to read or modify "
                "keys. Modification allows unauthorized users to inject public keys."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Harden authorized_keys with 'chmod 0600 <authorized_keys>'."},
    },
    {
        "id": "LH-PERM-023",
        "name": "InsecureSshFileOwner",
        "shortDescription": {"text": "SSH key or configuration file has incorrect owner"},
        "fullDescription": {
            "text": (
                "An SSH configuration file, private key, or directory is not owned by the "
                "target user or is orphaned."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": ("Transfer ownership to the correct user using 'chown <user>:<user> <file>'.")
        },
    },
]
