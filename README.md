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
  ├── check_dependencies()  Verify "nmap" "ss" "ip" "find" "awk" "grep" "cut" "stat" "id" "hostname" "date" "basename" "sort" "head" "tail" "tr" "systemctl"
  ├── detect_interface()    Auto-detect NIC (if -i not given)
  │
  ├── audit_open_ports()    MODULE 1 — nmap SYN scan on the selected interface IP
  ├── audit_suid_sgid()     MODULE 2 — find SUID/SGID binaries
  ├── audit_ssh_config()    MODULE 3 — parse /etc/ssh/sshd_config
  ├── audit_world_writable()MODULE 4 — find world-writable paths
  ├── audit_password_policy()MODULE 5 — login.defs + shadow checks
  ├── audit_firewall()      MODULE 6 — UFW / iptables / nftables / firewalld
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
| 3 — SSH Config | 9 sshd_config directives (root login, key-only auth, X11, idle timeout…) |
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
║     SYSTEM HARDENING AUDITOR v1.0.0         ║
║     Host: kali                              ║
╚══════════════════════════════════════════════╝

[INFO] All required dependencies found.
[INFO] Using network interface: eth0
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 1 — Open Port Scan (nmap)
[HEAD] =================================================================
[INFO] Running SYN scan on eth0. This may take a moment...
[INFO] Open ports detected: 3
[INFO]   PORT   STATE SERVICE
[INFO]   21/tcp open  ftp
[INFO]   22/tcp open  ssh
[INFO]   80/tcp open  http
[INFO] 
[INFO] Listening sockets according to ss:
[INFO]   tcp LISTEN 0      128    0.0.0.0:22 0.0.0.0:*
[INFO]   tcp LISTEN 0      511          *:80       *:*
[INFO]   tcp LISTEN 0      128       [::]:22    [::]:*
[INFO]   tcp LISTEN 0      32           *:21       *:*
[FAIL] High-risk port open: 21 — consider closing if unused.
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 2 — SUID / SGID File Enumeration
[HEAD] =================================================================
[INFO] Searching for SUID files (may take a moment)...
^[[B^[[B^[[B^[[B^[[B^[[B^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[B^[[B^[[B^[[B^[[[PASS] Known SUID binary: /usr/bin/chfn
[PASS] Known SUID binary: /usr/bin/chsh
[WARN] Unexpected SUID binary: /usr/bin/fusermount3 — review manually.
[PASS] Known SUID binary: /usr/bin/gpasswd
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_hak5_wifi_coconut — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_linux_bluetooth — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_linux_wifi — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_nrf_51822 — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_nrf_52840 — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_nrf_mousejack — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_nxp_kw41z — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_rz_killerbee — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_ti_cc_2531 — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_ti_cc_2540 — review manually.
[WARN] Unexpected SUID binary: /usr/bin/kismet_cap_ubertooth_one — review manually.
[PASS] Known SUID binary: /usr/bin/mount
[PASS] Known SUID binary: /usr/bin/newgrp
[WARN] Unexpected SUID binary: /usr/bin/ntfs-3g — review manually.
[PASS] Known SUID binary: /usr/bin/passwd
[PASS] Known SUID binary: /usr/bin/pkexec
[WARN] Unexpected SUID binary: /usr/bin/rsh-redone-rlogin — review manually.
[WARN] Unexpected SUID binary: /usr/bin/rsh-redone-rsh — review manually.
[PASS] Known SUID binary: /usr/bin/su
[PASS] Known SUID binary: /usr/bin/sudo
[PASS] Known SUID binary: /usr/bin/umount
[WARN] Unexpected SUID binary: /usr/bin/vmware-user-suid-wrapper — review manually.
[WARN] Unexpected SUID binary: /usr/lib/chromium/chrome-sandbox — review manually.
[WARN] Unexpected SUID binary: /usr/lib/dbus-1.0/dbus-daemon-launch-helper — review manually.
[WARN] Unexpected SUID binary: /usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool — review manually.
[WARN] Unexpected SUID binary: /usr/lib/openssh/ssh-keysign — review manually.
[WARN] Unexpected SUID binary: /usr/lib/polkit-1/polkit-agent-helper-1 — review manually.
[WARN] Unexpected SUID binary: /usr/lib/xorg/Xorg.wrap — review manually.
[WARN] Unexpected SUID binary: /usr/sbin/mount.cifs — review manually.
[WARN] Unexpected SUID binary: /usr/sbin/mount.nfs — review manually.
[WARN] Unexpected SUID binary: /usr/sbin/pppd — review manually.
[INFO] Searching for SGID files (may take a moment)...
[PASS] Known SGID binary: /usr/bin/chage
[PASS] Known SGID binary: /usr/bin/crontab
[WARN] Unexpected SGID binary: /usr/bin/dotlockfile — review manually.
[PASS] Known SGID binary: /usr/bin/expiry
[WARN] Unexpected SGID binary: /usr/bin/plocate — review manually.
[PASS] Known SGID binary: /usr/bin/ssh-agent
[WARN] Unexpected SGID binary: /usr/lib/xorg/Xorg.wrap — review manually.
[WARN] Unexpected SGID binary: /usr/sbin/unix_chkpwd — review manually.
[FAIL] 29 unexpected SUID/SGID file(s) found — review the WARN entries above.
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 3 — SSH Configuration Hardening
[HEAD] =================================================================
[INFO] Auditing /etc/ssh/sshd_config ...
[PASS] PermitRootLogin = no — Root login should be disabled
[WARN] PasswordAuthentication not set (system default applies) — Password auth should be disabled (use keys)
[WARN] PermitEmptyPasswords not set (system default applies) — Empty passwords must be denied
[FAIL] X11Forwarding = yes (expected: no) — X11 forwarding should be disabled
[PASS] UsePAM = yes — PAM should be enabled
[WARN] AllowTcpForwarding not set (system default applies) — TCP forwarding should be disabled if unused
[WARN] MaxAuthTries not set (system default applies) — Limit authentication attempts
[WARN] ClientAliveInterval not set (system default applies) — Idle timeout should be set
[WARN] LoginGraceTime not set (system default applies) — Login grace time should be short
[INFO] SSH audit complete. PASS: 2 | FAIL: 1
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 4 — World-Writable Files & Directories
[HEAD] =================================================================
[INFO] Scanning for world-writable paths (excluding /proc /sys /dev /run)...
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice 6/bank info/saving.csv
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice 6/Documents/invoices.md
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice 6/my info/event.yaml
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice 6/my social/social_account.json
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/practice_folder
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/practice_folder/folder1
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file10.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file1.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file2.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file3.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file4.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file5.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file6.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file7.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file8.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder1/file9.txt
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/practice_folder/folder2
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file10.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file1.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file2.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file3.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file4.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file5.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file6.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file7.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file8.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder2/file9.txt
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/practice_folder/folder3
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/commands.sed
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file10.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file1.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file2.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file3.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file4.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file5.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file6.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file7.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file8.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/practice_folder/folder3/file9.txt
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/applications
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/applications/apache.conf
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/applications/database.conf
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/system
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/system/mydbenv
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/system/system.conf
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/system/timezone.conf
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/configs/system/users.conf
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/logs
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/logs/access.log
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/logs/auth.log
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/logs/dev-2021-04.log
[WARN] World-writable directory: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/------------
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/conference.jpg
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/MLasm1.pdf
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/note.txt
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/pass.json
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/resume.docx
[WARN] World-writable file: /home/kali/CYBR352/Module 2/Practice GSUB/mydesktop/Personal/vacation.jpg
[WARN] World-writable file: /home/kali/CYBR352/Module 5/Test
[WARN] World-writable directory: /home/kali/Midterm_prac/mydesktop
[WARN] World-writable directory: /home/kali/Midterm_prac/mydesktop/configs
[WARN] World-writable directory: /home/kali/Midterm_prac/mydesktop/configs/applications
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/configs/applications/apache.conf
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/configs/applications/database.conf
[WARN] World-writable directory: /home/kali/Midterm_prac/mydesktop/configs/system
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/configs/system/mydbenv
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/configs/system/system.conf
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/configs/system/timezone.conf
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/configs/system/users.conf
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/large_file/access.log
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/large_file/auth.log
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/large_file/dev-2021-04.log
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/large_file/MLasm1.pdf
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/large_file/vacation.jpg
[WARN] World-writable directory: /home/kali/Midterm_prac/mydesktop/logs
[WARN] World-writable directory: /home/kali/Midterm_prac/mydesktop/Personal
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/Personal/------------
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/Personal/conference.jpg
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/Personal/note.txt
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/Personal/pass.json
[WARN] World-writable file: /home/kali/Midterm_prac/mydesktop/Personal/resume.docx
[WARN] World-writable directory: /home/kali/Quiz_Prac/Module_2/practice_folder
[WARN] World-writable directory: /home/kali/Quiz_Prac/Module_2/practice_folder/folder1
[WARN] World-writable file: /home/kali/Quiz_Prac/Module_2/practice_folder/folder1/file10.txt
[PASS] Sticky-bit directory (OK): /tmp
[PASS] Sticky-bit directory (OK): /tmp/.font-unix
[PASS] Sticky-bit directory (OK): /tmp/.ICE-unix
[WARN] World-writable file: /tmp/.ICE-unix/1412
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-apache2.service-tiKfNU/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-colord.service-Sl5lbO/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-haveged.service-HrUfJ2/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-ModemManager.service-okYdtd/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-polkit.service-6Yx7ID/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-rsyslog.service-uqZmfs/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-systemd-logind.service-ikclD4/tmp
[PASS] Sticky-bit directory (OK): /tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-upower.service-9S8E5a/tmp
[PASS] Sticky-bit directory (OK): /tmp/VMwareDnD
[PASS] Sticky-bit directory (OK): /tmp/.X11-unix
[WARN] World-writable file: /tmp/.X11-unix/X0
[PASS] Sticky-bit directory (OK): /tmp/.XIM-unix
[PASS] Sticky-bit directory (OK): /var/lib/php/sessions
[PASS] Sticky-bit directory (OK): /var/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-apache2.service-Y6fRhY/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-colord.service-Oun6Zy/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-haveged.service-3UgkmB/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-ModemManager.service-xINGPa/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-polkit.service-GWtjHU/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-rsyslog.service-4rk8tN/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-systemd-logind.service-g2tbcJ/tmp
[PASS] Sticky-bit directory (OK): /var/tmp/systemd-private-81ca8df73338410abeb0ea377624f92b-upower.service-eOzeNp/tmp
[FAIL] 121 world-writable path(s) found — review WARN entries above.
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 5 — Password & Account Policy
[HEAD] =================================================================
[FAIL] PASS_MAX_DAYS = 99999 — should be <= 90 days
[WARN] PASS_MIN_DAYS = 0 — consider setting to >= 1
[PASS] PASS_WARN_AGE = 7 (>= 7 days)
[PASS] No accounts with empty passwords found.
[INFO] Locked accounts (cannot authenticate via password): daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc _apt nobody systemd-network dhcpcd systemd-timesync messagebus tss strongswan tcpdump sshd _rpc statd dnsmasq avahi nm-openvpn speech-dispatcher usbmux nm-openconnect pipewire saned lightdm polkitd rtkit colord pcscd stunnel4 geoclue Debian-snmp sslh cups-pk-helper redsocks _gophish iodine miredo redis postgres mosquitto inetsim mysql _gvm ftp 
[PASS] No unexpected UID 0 accounts.
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 6 — Firewall Status
[HEAD] =================================================================
[INFO] UFW status: Status: active
[PASS] UFW firewall is active.
[INFO] iptables backend: iptables v1.8.11 (nf_tables)
[INFO] iptables rules: 65
[WARN] iptables has rules but INPUT policy is DROP)
[INFO] nftables chains: 69
[PASS] nftables ruleset active.
[WARN] Multiple firewall layers appear active (2). Verify configuration.
[HEAD] 
[HEAD] =================================================================
[HEAD]   MODULE 7 — Sudoers Configuration
[HEAD] =================================================================
[INFO] Checking /etc/sudoers and /etc/sudoers.d/ for risky entries...
[WARN] NOPASSWD entries found (verify these are intentional):
[WARN]   _gvm ALL = NOPASSWD: /usr/sbin/openvas
[WARN]   %kali-trusted   ALL=(ALL:ALL) NOPASSWD: ALL
[WARN] Broad ALL=(ALL) sudo rules found (normal for admin accounts — verify):
[WARN]   root   ALL=(ALL:ALL) ALL
[WARN]   %sudo  ALL=(ALL:ALL) ALL
[WARN]   %kali-trusted   ALL=(ALL:ALL) NOPASSWD: ALL
[PASS] Ownership OK on /etc/sudoers (root:root)
[PASS] Permissions OK on /etc/sudoers (440)
[PASS] Ownership OK on /etc/sudoers.d/ospd-openvas (root:root)
[PASS] Permissions OK on /etc/sudoers.d/ospd-openvas (440)
[PASS] Ownership OK on /etc/sudoers.d/kali-grant-root (root:root)
[PASS] Permissions OK on /etc/sudoers.d/kali-grant-root (440)
[HEAD] 
[HEAD] =================================================================
[HEAD]   AUDIT SUMMARY
[HEAD] =================================================================
[INFO] Host      : kali
[INFO] Interface : eth0
[INFO] Timestamp : 20260708_114000
[INFO] 
[PASS] Checks passed : 51
[WARN] Warnings      : 166
[FAIL] Checks failed : 5
[INFO] 
[INFO] Full report saved to: ./audit_reports/hardening_audit_kali_20260708_114000.txt

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
