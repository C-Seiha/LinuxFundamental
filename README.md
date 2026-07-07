# System Hardening Auditor

A Bash automation script that performs an end-to-end security audit of a Linux system. It checks for common misconfigurations across seven modules and produces a timestamped plain-text report.

---

## Table of Contents

1. [How the Script Works](#how-the-script-works)
2. [Usage](#usage)
3. [Dependencies](#dependencies)
4. [Output](#output)
5. [Example Output](#example-output)
6. [References](#references)

---

## How the Script Works

The script is structured around a **module pipeline**: each module is an independent function that audits one security domain, writes findings using a shared `log()` helper, and exits cleanly even if its target (e.g. a missing config file) is absent. A summary is generated at the end by counting `[PASS]`, `[WARN]`, and `[FAIL]` entries in the report file.

### Execution Flow

```
main()
  │
  ├── parse_args()          Parse -o, -i, -s, -h flags
  ├── check_root()          Abort if not run as root
  ├── validate_output_dir() Create/check output directory
  ├── detect_interface()    Auto-detect NIC (if -i not given)
  ├── check_dependencies()  Verify nmap, ss, find, awk, grep, stat
  │
  ├── audit_open_ports()    MODULE 1 — nmap SYN scan on localhost
  ├── audit_suid_sgid()     MODULE 2 — find SUID/SGID binaries
  ├── audit_ssh_config()    MODULE 3 — parse /etc/ssh/sshd_config
  ├── audit_world_writable()MODULE 4 — find world-writable paths
  ├── audit_password_policy()MODULE 5 — login.defs + shadow checks
  ├── audit_firewall()      MODULE 6 — UFW / iptables / nftables
  ├── audit_sudoers()       MODULE 7 — /etc/sudoers risk analysis
  │
  └── generate_summary()    Count PASS/WARN/FAIL and print totals
```

### Error Handling Strategy

| Mechanism | Purpose |
|---|---|
| `set -euo pipefail` | Abort on unhandled errors, unbound variables, pipe failures |
| `check_root()` | Validates UID before any privileged operation |
| `check_dependencies()` | Halts with install instructions if tools are missing |
| `validate_output_dir()` | Ensures the report destination is writable |
| `die()` function | Prints to `stderr` and exits non-zero on any fatal error |
| Per-module guards | Each module checks for its target file/tool and logs `WARN` + returns if absent |
| `|| true` on counters | Prevents `set -e` from aborting on zero-match `grep` counts |

### Security Controls Audited

| Module | What It Checks |
|---|---|
| 1 — Open Ports | nmap SYN scan; flags high-risk ports (21, 23, 25, 111, 445…) |
| 2 — SUID/SGID | Finds setuid binaries outside a known-good whitelist |
| 3 — SSH Config | 10 sshd_config directives (root login, key-only auth, X11, idle timeout…) |
| 4 — World-Writable | Files/dirs with `o+w`; sticky-bit directories are excluded |
| 5 — Password Policy | login.defs aging rules; empty passwords; non-root UID 0 accounts |
| 6 — Firewall | UFW active state; iptables INPUT default policy; nftables chains |
| 7 — Sudoers | NOPASSWD entries; ALL=(ALL) rules; sudoers file permission (440) |

---

## Usage

```bash
# Basic audit (auto-detects interface, saves report to ./audit_reports/)
sudo ./hardening_audit.sh

# Specify output directory and network interface
sudo ./hardening_audit.sh -o /var/log/audits -i eth0

# Silent mode (no terminal colour output, report still written)
sudo ./hardening_audit.sh -s -o /tmp/reports

# Show help
sudo ./hardening_audit.sh -h
```

### Flags

| Flag | Argument | Default | Description |
|---|---|---|---|
| `-o` | `DIR` | `./audit_reports` | Directory where the report file is saved |
| `-i` | `IFACE` | auto-detected | Network interface used for the nmap port scan |
| `-s` | — | off | Silent mode: suppress colour terminal output |
| `-h` | — | — | Show help and exit |

### Make the script executable

```bash
chmod +x hardening_audit.sh
sudo ./hardening_audit.sh
```

---

## Dependencies

All tools listed below are pre-installed on **Kali Linux**. On Ubuntu/Debian, install any missing ones with the command shown.

| Tool | Package | Used For |
|---|---|---|
| `nmap` | `nmap` | SYN port scan (Module 1) |
| `ss` | `iproute2` | Socket statistics (Module 6 fallback) |
| `find` | `findutils` | SUID/SGID and world-writable file search |
| `awk` | `gawk` | Parsing config files and command output |
| `grep` | `grep` | Pattern matching across files |
| `stat` | `coreutils` | Reading file permission octets |
| `ip` | `iproute2` | Auto-detecting the default network interface |
| `iptables` | `iptables` | Reading firewall rules (Module 6) |
| `ufw` | `ufw` | Firewall status check (Module 6) |

**Install missing dependencies on Kali / Debian / Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y nmap iproute2 findutils gawk grep coreutils iptables ufw
```

**Verify with shellcheck (optional but recommended):**

```bash
sudo apt-get install -y shellcheck
shellcheck hardening_audit.sh
```

---

## Output

### Report File

A plain-text report is saved to:

```
<OUTPUT_DIR>/hardening_audit_<hostname>_<YYYYMMDD_HHMMSS>.txt
```

**Example path:**

```
./audit_reports/hardening_audit_kali_20241105_143022.txt
```

### Log Levels

Each line in the report and terminal is prefixed with a level tag:

| Tag | Meaning |
|---|---|
| `[INFO]` | Neutral information (interface used, counts found) |
| `[PASS]` | Check passed — configuration is secure |
| `[WARN]` | Potential risk — review and decide if remediation is needed |
| `[FAIL]` | Clear misconfiguration — remediation recommended |
| `[HEAD]` | Section header / divider |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Audit completed successfully (report written) |
| `1` | Fatal error (not root, missing dep, bad argument, unwritable output dir) |

---

## Example Output

Below is a representative excerpt from a real audit run. Actual output will vary based on the target system's configuration.

```
╔══════════════════════════════════════════════╗
║     SYSTEM HARDENING AUDITOR v1.0.0          ║
║     Host: kali                               ║
╚══════════════════════════════════════════════╝

[INFO] Using network interface: eth0
[INFO] All required dependencies found.

=================================================================
  MODULE 1 — Open Port Scan (nmap)
=================================================================
[INFO] Running SYN scan on eth0. This may take a moment...
[INFO] Open ports detected: 3
[INFO]   PORT     STATE SERVICE
[INFO]   22/tcp   open  ssh
[INFO]   80/tcp   open  http
[INFO]   3306/tcp open  mysql
[WARN]   High-risk port open: 3306 — consider closing if unused.

=================================================================
  MODULE 2 — SUID / SGID File Enumeration
=================================================================
[PASS] Known SUID binary: /usr/bin/sudo
[PASS] Known SUID binary: /usr/bin/passwd
[WARN] Unexpected SUID binary: /opt/custom/mytool — review manually.
[FAIL] 1 unexpected SUID file(s) found — review the WARN entries above.

=================================================================
  MODULE 3 — SSH Configuration Hardening
=================================================================
[PASS] PermitRootLogin = no — Root login should be disabled
[FAIL] PasswordAuthentication = yes (expected: no) — Password auth should be disabled (use keys)
[PASS] PermitEmptyPasswords = no — Empty passwords must be denied
[PASS] Protocol = 2 — Must use SSH protocol version 2
[WARN] X11Forwarding not set (default may apply)
[PASS] MaxAuthTries = 3 — Limit authentication attempts
[INFO] SSH audit complete. PASS: 4 | FAIL: 1

=================================================================
  MODULE 5 — Password & Account Policy
=================================================================
[PASS] PASS_MAX_DAYS = 90 (≤ 90 days)
[WARN] PASS_MIN_DAYS = 0 — consider setting to ≥ 1
[PASS] PASS_WARN_AGE = 7 (≥ 7 days)
[PASS] No accounts with empty passwords found.
[PASS] No unexpected UID 0 accounts.

=================================================================
  MODULE 6 — Firewall Status
=================================================================
[FAIL] UFW firewall is inactive — enable with: ufw enable
[WARN] iptables INPUT default policy: ACCEPT — consider setting to DROP

=================================================================
  AUDIT SUMMARY
=================================================================
[INFO] Host      : kali
[INFO] Interface : eth0
[INFO] Timestamp : 20241105_143022
[PASS] Checks passed : 14
[WARN] Warnings      : 6
[FAIL] Checks failed : 3
[INFO] Full report saved to: ./audit_reports/hardening_audit_kali_20241105_143022.txt
```

---

## References

1. **CIS Benchmarks — Linux** — Center for Internet Security hardening guidelines for Debian/Ubuntu/RHEL.
   https://www.cisecurity.org/cis-benchmarks

2. **NIST SP 800-123** — Guide to General Server Security, National Institute of Standards and Technology.
   https://csrc.nist.gov/publications/detail/sp/800-123/final

3. **nmap Reference Guide** — Official documentation for nmap scan types, flags, and output formats.
   https://nmap.org/book/man.html

4. **sshd_config(5) man page** — OpenSSH daemon configuration reference.
   https://man.openbsd.org/sshd_config

5. **Bash Reference Manual** — GNU Project; covers `set -euo pipefail`, parameter expansion, and built-ins.
   https://www.gnu.org/software/bash/manual/bash.html

6. **ShellCheck** — Static analysis tool for shell scripts; enforces POSIX/bash best practices.
   https://www.shellcheck.net

7. **Linux PAM Documentation** — Pluggable Authentication Modules for password policy enforcement.
   https://linux-pam.org/Linux-PAM-html/

8. **UFW (Uncomplicated Firewall) Manual** — Ubuntu community documentation.
   https://help.ubuntu.com/community/UFW

9. **OWASP Linux Hardening Cheat Sheet** — Practical checklist for securing Linux servers.
   https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

10. **The Linux Command Line** — William Shotts; reference for shell scripting fundamentals and `find`, `awk`, `grep` usage.
    https://linuxcommand.org/tlcl.php
