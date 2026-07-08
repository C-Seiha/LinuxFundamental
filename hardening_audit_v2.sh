#!/usr/bin/env bash
# =============================================================================
# hardening_audit.sh — System Hardening Auditor
# =============================================================================
# Description : Audits a Linux system for common security misconfigurations:
#               open ports, SUID/SGID files, SSH hardening, world-writable
#               paths, password policy, firewall state, and sudoers risks.
#               Produces a timestamped plain-text report in OUTPUT_DIR.
#
# Usage       : sudo ./hardening_audit.sh [OPTIONS]
# Options     :
#   -o DIR    Output directory for the report (default: ./audit_reports)
#   -i IFACE  Network interface for port scan (default: auto-detected)
#   -s        Silent mode — suppress colour output to terminal
#   -h        Show this help message
#
# Requirements: nmap, ss, find, awk, grep, id, sudo (run as root)
# Tested on   : Kali Linux 2024.x, Ubuntu 22.04 LTS, Debian 12
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONSTANTS & DEFAULTS
# ---------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"

# SC2155 fix: declare readonly vars separately from command substitution
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly TIMESTAMP

HOSTNAME_VAL="$(hostname)"
readonly HOSTNAME_VAL

OUTPUT_DIR="./audit_reports"        # overridden by -o
IFACE=""                            # overridden by -i; auto-detected if empty
SILENT=false                        # overridden by -s

# Report file (set after argument parsing)
REPORT_FILE=""

# ---------------------------------------------------------------------------
# COLOUR CODES  (disabled in silent mode)
# ---------------------------------------------------------------------------
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_RED="\033[0;31m"
CLR_GREEN="\033[0;32m"
CLR_YELLOW="\033[0;33m"
CLR_CYAN="\033[0;36m"
CLR_WHITE="\033[1;37m"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

# Print to terminal (respects silent mode) and always write to report file
log() {
    local level="$1"
    local message="$2"
    local colour=""

    case "$level" in
        INFO)   colour="$CLR_CYAN"   ;;
        PASS)   colour="$CLR_GREEN"  ;;
        WARN)   colour="$CLR_YELLOW" ;;
        FAIL)   colour="$CLR_RED"    ;;
        HEAD)   colour="$CLR_WHITE"  ;;
        *)      colour="$CLR_RESET"  ;;
    esac

    # Write plain text to report (no colour codes in file)
    printf "[%s] %s\n" "$level" "$message" >> "$REPORT_FILE"

    # Print coloured line to terminal unless silent
    if [[ "$SILENT" == false ]]; then
        # SC2059 fix: pass colour code as argument, not in format string
        printf "%b[%s]%b %s\n" "$colour" "$level" "$CLR_RESET" "$message"
    fi
}

# Print a section divider
section() {
    local title="$1"
    local divider="================================================================="
    log "HEAD" ""
    log "HEAD" "$divider"
    log "HEAD" "  $title"
    log "HEAD" "$divider"
}

# Print error to stderr and exit non-zero
die() {
    printf "%b[ERROR]%b %s\n" "$CLR_RED" "$CLR_RESET" "$1" >&2
    exit 1
}

# Print usage information
usage() {
    cat <<EOF
Usage: sudo $SCRIPT_NAME [OPTIONS]

Options:
  -o DIR    Output directory for the report (default: ./audit_reports)
  -i IFACE  Network interface for port scan  (default: auto-detected)
  -s        Silent mode — suppress colour output to terminal
  -h        Show this help message

Examples:
  sudo $SCRIPT_NAME
  sudo $SCRIPT_NAME -o /var/log/audits -i eth0
  sudo $SCRIPT_NAME -s -o /tmp/reports
EOF
}

# ---------------------------------------------------------------------------
# INPUT VALIDATION & DEPENDENCY CHECKS
# ---------------------------------------------------------------------------

# Must be run as root
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root. Try: sudo $SCRIPT_NAME"
    fi
}

# Confirm required tools are installed before any audit runs
check_dependencies() {
    local deps=("nmap" "ss" "ip" "find" "awk" "grep" "cut" "stat" "id" \
    "hostname" "date" "basename" "sort" "head" "tail" "tr" "systemctl")
    
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ "${#missing[@]}" -gt 0 ]]; then
        die "Missing required dependencies: ${missing[*]}
Install with: apt-get install ${missing[*]}"
    fi

    log "INFO" "All required dependencies found."
}

# Ensure the output directory exists and is writable
validate_output_dir() {
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        die "Cannot create output directory: $OUTPUT_DIR"
    fi
    if [[ ! -w "$OUTPUT_DIR" ]]; then
        die "Output directory is not writable: $OUTPUT_DIR"
    fi
}

# Auto-detect the primary non-loopback network interface
detect_interface() {
    IFACE="$(ip route show default 2>/dev/null \
        | awk '/default/ {print $5; exit}')"

    if [[ -z "$IFACE" ]]; then
        # Fallback: first non-loopback interface from ip link
        IFACE="$(ip -o link show \
            | awk -F': ' '$2 !~ /lo/ {print $2; exit}')"
    fi

    if [[ -z "$IFACE" ]]; then
        die "Could not auto-detect a network interface. Specify one with -i IFACE."
    fi

    log "INFO" "Using network interface: $IFACE"
}

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
parse_args() {
    while getopts ":o:i:sh" opt; do
        case "$opt" in
            o) OUTPUT_DIR="$OPTARG"   ;;
            i) IFACE="$OPTARG"        ;;
            s) SILENT=true            ;;
            h) usage; exit 0          ;;
            :) die "Option -$OPTARG requires an argument." ;;
            \?) die "Unknown option: -$OPTARG. Use -h for help." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# AUDIT MODULES
# ---------------------------------------------------------------------------

# MODULE 1: Open port scan using nmap
audit_open_ports() {
    section "MODULE 1 — Open Port Scan (nmap)"

    local iface_ip
    iface_ip="$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1 || true)"

    if [[ -z "$iface_ip" ]]; then
        log "WARN" "Interface $IFACE has no IPv4 address — scanning localhost instead."
        iface_ip="127.0.0.1"
    fi

    log "INFO" "Running SYN scan on $IFACE. This may take a moment..."

    local nmap_out
    # -sS: SYN scan | -O: OS detection | --open: show open ports only
    nmap_out="$(nmap -sS -O --open "$iface_ip" 2>/dev/null || true)"

    local open_count=0

    if [[ -z "$nmap_out" ]] || ! echo "$nmap_out" | grep -q "Nmap scan report"; then
        log "WARN" "nmap produced no usable report."
    else
        open_count="$(echo "$nmap_out" | grep -cE "^[0-9]+/(tcp|udp)" || true)"

        log "INFO" "Open ports detected: $open_count"

        echo "$nmap_out" | grep -E "^(PORT|[0-9]+/(tcp|udp))" | while IFS= read -r line; do
            log "INFO" "  $line"
        done || true
    fi

    log "INFO" ""
    log "INFO" "Listening sockets according to ss:"

    local ss_out
    ss_out="$(ss -tulnH 2>/dev/null || true)"

    if [[ -n "$ss_out" ]]; then
        echo "$ss_out" | while IFS= read -r line; do
            log "INFO" "  $line"
        done
    else
        log "WARN" "ss returned no listening sockets."
    fi

    # Flag commonly risky/unnecessary open ports
    local risky_ports=("21" "23" "25" "111" "135" "139" "445" "512" "513" "514")
    for port in "${risky_ports[@]}"; do
        if echo "$nmap_out" | grep -qE "^${port}/"; then
            log "FAIL" "High-risk port open: $port — consider closing if unused."
        fi
    done

    if [[ "$open_count" -eq 0 ]]; then
        log "PASS" "No open ports detected."
    fi
}

# MODULE 2: SUID and SGID file enumeration
audit_suid_sgid() {
    section "MODULE 2 — SUID / SGID File Enumeration"

    local known_dirs=("/usr/bin/" "/bin/" "/usr/sbin/" "/sbin/" "/usr/libexec/")

    # Whitelist of well-known legitimate SUID binaries
    local suid_whitelist=("sudo" "su" "passwd" "newgrp" "chsh" "chfn" "gpasswd"
                    "pkexec" "mount" "umount" "ping" "ping6" "traceroute6"
                    "ssh-agent" "Xorg" "screen" "crontab" "at" "fusermount")

    local sgid_whitelist=("wall" "write" "ssh-agent" "crontab" "expiry" "chage" 
                    "mlocate" "mlocate.updatedb" "ssh-keysign" "utempter" "postdrop" "postqueue")

    _is_known_binary() {
        local fpath="$1"
        local -n wl="$2"
        local base
        base="$(basename "$fpath")"

        local w d
        for w in "${wl[@]}"; do
            if [[ "$base" == "$w" ]]; then
                for d in "${known_dirs[@]}"; do
                    if [[ "$fpath" == "$d"* ]]; then
                        echo "true" && return
                    fi
                done
            fi
        done
        echo "false"
    }

    log "INFO" "Searching for SUID files (may take a moment)..."

    # --- SUID files ---
    local suid_files
    suid_files="$(find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /dev -prune -o \
        -perm /4000 -type f -print 2>/dev/null | sort || true)"

    local suid_flagged=0
    while IFS= read -r sfile; do
        [[ -z "$sfile" ]] && continue
        if [[ "$(_is_known_binary "$sfile" suid_whitelist)" == "true" ]]; then
            log "PASS" "Known SUID binary: $sfile"
        else
            log "WARN" "Unexpected SUID binary: $sfile — review manually."
            (( suid_flagged++ )) || true
        fi
    done <<< "$suid_files"

    # --- SGID files ---
    log "INFO" "Searching for SGID files (may take a moment)..."
    
    local sgid_files
    sgid_files="$(find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /dev -prune -o \
        -perm /2000 -type f -print 2>/dev/null | sort || true)"

    local sgid_flagged=0
    while IFS= read -r sgfile; do
        [[ -z "$sgfile" ]] && continue

        if [[ "$(_is_known_binary "$sgfile" sgid_whitelist)" == "true" ]]; then
            log "PASS" "Known SGID binary: $sgfile"
        else
            log "WARN" "Unexpected SGID binary: $sgfile — review manually."
            (( sgid_flagged++ )) || true
        fi
    done <<< "$sgid_files"

    unset -f _is_known_binary
    
    # --- Module verdict (covers both SUID and SGID) ---
    local total_flagged=$(( suid_flagged + sgid_flagged ))
    if [[ "$total_flagged" -eq 0 ]]; then
        log "PASS" "No unexpected SUID/SGID files found."
    else
        log "FAIL" "$total_flagged unexpected SUID/SGID file(s) found — review the WARN entries above."
    fi
}

# MODULE 3: SSH configuration hardening check
audit_ssh_config() {
    section "MODULE 3 — SSH Configuration Hardening"

    local ssh_config="/etc/ssh/sshd_config"

    if [[ ! -f "$ssh_config" ]]; then
        log "WARN" "SSH config not found at $ssh_config — skipping module."
        return
    fi

    log "INFO" "Auditing $ssh_config ..."

    # Format: "SettingName ExpectedValue Description of the check"
    local checks=(
        "PermitRootLogin no         Root login should be disabled"
        "PasswordAuthentication no  Password auth should be disabled (use keys)"
        "PermitEmptyPasswords no    Empty passwords must be denied"
        "X11Forwarding no           X11 forwarding should be disabled"
        "UsePAM yes                 PAM should be enabled"
        "AllowTcpForwarding no      TCP forwarding should be disabled if unused"
    )

    local pass=0 fail=0

    for check in "${checks[@]}"; do
        local key expected desc
        key="$(echo "$check"      | awk '{print $1}')"
        expected="$(echo "$check" | awk '{print $2}')"
        desc="$(echo "$check" | tr -s ' ' | cut -d' ' -f3-)"

        local current
        current="$(grep -iE "^[[:space:]]*${key}[[:space:]]" "$ssh_config" | awk '{print $2}' | head -1 || true)"

        if [[ -z "$current" ]]; then
            log "WARN" "$key not set (system default applies) — $desc"
        elif [[ "${current,,}" == "${expected,,}" ]]; then
            log "PASS" "$key = $current — $desc"
            (( pass++ )) || true
        else
            log "FAIL" "$key = $current (expected: $expected) — $desc"
            (( fail++ )) || true
        fi
    done
    # Numeric "at least as strict" checks
    _ssh_numeric_check() {
        local key="$1" max_ok="$2" desc="$3" cmp="$4"   # cmp: "le" or "ge"
        local current
        current="$(grep -iE "^[[:space:]]*${key}[[:space:]]" "$ssh_config" | awk '{print $2}' | head -1 || true)"

        if [[ -z "$current" ]]; then
            log "WARN" "$key not set (system default applies) — $desc"
            return
        fi
        if ! [[ "$current" =~ ^[0-9]+$ ]]; then
            log "WARN" "$key = $current (non-numeric value, e.g. time-unit suffix) — $desc"
            return
        fi
        if [[ "$cmp" == "le" && "$current" -le "$max_ok" ]] || \
           [[ "$cmp" == "ge" && "$current" -ge "$max_ok" ]]; then
            log "PASS" "$key = $current — $desc"
            (( pass++ )) || true
        else
            log "FAIL" "$key = $current (expected ${cmp}: $max_ok) — $desc"
            (( fail++ )) || true
        fi
    }

    _ssh_numeric_check "MaxAuthTries"        3   "Limit authentication attempts"    le
    _ssh_numeric_check "ClientAliveInterval" 300 "Idle timeout should be set"       le
    _ssh_numeric_check "LoginGraceTime"      60  "Login grace time should be short" le

    log "INFO" "SSH audit complete. PASS: $pass | FAIL: $fail"
}

# MODULE 4: World-writable files and directories
audit_world_writable() {
    section "MODULE 4 — World-Writable Files & Directories"

    log "INFO" "Scanning for world-writable paths (excluding /proc /sys /dev /run)..."

    local ww_files
    ww_files="$(find / \
        -path /proc -prune -o \
        -path /sys  -prune -o \
        -path /dev  -prune -o \
        -path /run  -prune -o \
        -perm -0002 -not -type l -print 2>/dev/null | sort || true)"

    local count=0
    while IFS= read -r wfile; do
        [[ -z "$wfile" ]] && continue

        # Sticky-bit directories (e.g. /tmp) are acceptable — skip them
        if [[ -d "$wfile" ]]; then
            local perms
            perms="$(stat -c "%a" "$wfile" 2>/dev/null || true)"
            if [[ -n "$perms" ]] && (( 8#$perms & 01000 )); then
                log "PASS" "Sticky-bit directory (OK): $wfile"
                continue
            fi
        fi

        if [[ -d "$wfile" ]]; then
            log "WARN" "World-writable directory: $wfile"
        else
            log "WARN" "World-writable file: $wfile"
        fi
        (( count++ )) || true

    done <<< "$ww_files"

    if [[ "$count" -eq 0 ]]; then
        log "PASS" "No unexpected world-writable paths found."
    else
        log "FAIL" "$count world-writable path(s) found — review WARN entries above."
    fi
}

# MODULE 5: Password policy and account hygiene
audit_password_policy() {
    section "MODULE 5 — Password & Account Policy"

    local login_defs="/etc/login.defs"
    local shadow="/etc/shadow"

    # --- login.defs aging policy ---
    if [[ -f "$login_defs" ]]; then
        local pass_max_days pass_min_days pass_warn_age
        pass_max_days="$(grep -E "^[[:space:]]*PASS_MAX_DAYS[[:space:]]" "$login_defs" | awk '{print $2}' | tail -1 || true)"
        pass_min_days="$(grep -E "^[[:space:]]*PASS_MIN_DAYS[[:space:]]" "$login_defs" | awk '{print $2}' | tail -1 || true)"
        pass_warn_age="$(grep -E "^[[:space:]]*PASS_WARN_AGE[[:space:]]"  "$login_defs" | awk '{print $2}' | tail -1 || true)"

        # SC2015 fix: use explicit if/else instead of && || chaining
        if [[ "${pass_max_days:-99999}" -le 90 ]]; then
            log "PASS" "PASS_MAX_DAYS = $pass_max_days (<= 90 days)"
        else
            log "FAIL" "PASS_MAX_DAYS = ${pass_max_days:-unset} — should be <= 90 days"
        fi

        if [[ "${pass_min_days:-0}" -ge 1 ]]; then
            log "PASS" "PASS_MIN_DAYS = $pass_min_days (>= 1 day)"
        else
            log "WARN" "PASS_MIN_DAYS = ${pass_min_days:-unset} — consider setting to >= 1"
        fi

        if [[ "${pass_warn_age:-0}" -ge 7 ]]; then
            log "PASS" "PASS_WARN_AGE = $pass_warn_age (>= 7 days)"
        else
            log "WARN" "PASS_WARN_AGE = ${pass_warn_age:-unset} — consider setting to >= 7"
        fi
    else
        log "WARN" "$login_defs not found — skipping password policy checks."
    fi

    # --- Shadow file checks ---
    if [[ -f "$shadow" ]]; then
        # Accounts with empty or locked passwords (excluding root)
        # Truly empty password hash — real risk
        local empty_pw
        empty_pw="$(awk -F: '$2 == "" && $1 != "root" {print $1}' "$shadow" || true)"
        if [[ -n "$empty_pw" ]]; then
            log "FAIL" "Accounts with EMPTY password hash: $empty_pw"
        else
            log "PASS" "No accounts with empty passwords found."
        fi

        # Locked accounts ("!", "!!", or "*") — expected/secure state, informational only
        local locked_pw
        locked_pw="$(awk -F: '($2 ~ /^!/ || $2 == "*") && $1 != "root" {print $1}' \
            "$shadow" || true)"
        if [[ -n "$locked_pw" ]]; then
            log "INFO" "Locked accounts (cannot authenticate via password): $(echo "$locked_pw" | tr '\n' ' ')"
        fi

        # Non-root accounts with UID 0 (privilege escalation risk)
        local uid0_users
        uid0_users="$(awk -F: '($3 == 0) && ($1 != "root") {print $1}' \
            /etc/passwd || true)"
        if [[ -n "$uid0_users" ]]; then
            log "FAIL" "Non-root UID 0 account(s) found: $uid0_users"
        else
            log "PASS" "No unexpected UID 0 accounts."
        fi
    else
        log "WARN" "/etc/shadow not readable — skipping shadow checks."
    fi
}

# MODULE 6: Firewall status across UFW / iptables / nftables
audit_firewall() {
    section "MODULE 6 — Firewall Status"

    local found_any=false
    local active_count=0

    # UFW
    if command -v ufw &>/dev/null; then
        found_any=true

        local ufw_status
        ufw_status="$(ufw status 2>/dev/null | head -1 || true)"

        log "INFO" "UFW status: $ufw_status"

        if [[ "${ufw_status,,}" == *"status: active"* ]]; then
            active_count=$((active_count+1))
            log "PASS" "UFW firewall is active."
        else
            log "WARN" "UFW installed but inactive."
        fi
    fi


    # iptables
    if command -v iptables &>/dev/null; then
        found_any=true

        local backend
        backend="$(iptables -V 2>/dev/null || true)"

        log "INFO" "iptables backend: $backend"

        local rules
        rules="$(iptables -L -n --line-numbers 2>/dev/null \
            | awk '/^[0-9]+/ {c++} END {print c+0}' || true)"

        log "INFO" "iptables rules: $rules"

        local policy
        policy="$(iptables -L INPUT -n 2>/dev/null \
            | head -1 \
            | awk '/policy/ {print $4}' || true)"

        if [[ "$policy" == "DROP" || "$policy" == "REJECT" ]]; then
            active_count=$((active_count+1))
            log "PASS" "iptables INPUT policy: $policy"
        elif [[ "$rules" -gt 0 ]]; then
            log "WARN" "iptables has rules but INPUT policy is $policy"
        else
            log "WARN" "iptables has no filtering rules."
        fi
    fi


    # nftables
    if command -v nft &>/dev/null; then
        found_any=true

        local chains
        chains="$(nft list ruleset 2>/dev/null \
            | awk '/^[[:space:]]*chain / {c++} END {print c+0}' || true)"

        log "INFO" "nftables chains: $chains"

        if [[ "$chains" -gt 0 ]]; then
            active_count=$((active_count+1))
            log "PASS" "nftables ruleset active."
        else
            log "WARN" "nftables installed but empty."
        fi
    fi


    # firewalld
    if command -v firewall-cmd &>/dev/null; then
        found_any=true

        if command -v systemctl &>/dev/null && systemctl is-active --quiet firewalld; then
            active_count=$((active_count+1))
            log "PASS" "firewalld service active."
        else
            log "WARN" "firewalld installed but inactive."
        fi
    fi


    if [[ "$found_any" == false ]]; then
        log "FAIL" "No firewall framework detected."
    elif [[ "$active_count" -eq 0 ]]; then
        log "FAIL" "Firewall tools exist but no active firewall detected."
    elif [[ "$active_count" -gt 1 ]]; then
        log "WARN" "Multiple firewall layers appear active ($active_count). Verify configuration."
    fi
}

# MODULE 7: Sudoers configuration risk analysis
audit_sudoers() {
    section "MODULE 7 — Sudoers Configuration"

    local sudoers_file="/etc/sudoers"

    if [[ ! -f "$sudoers_file" ]]; then
        log "WARN" "/etc/sudoers not found — skipping."
        return
    fi

    log "INFO" "Checking /etc/sudoers and /etc/sudoers.d/ for risky entries..."

    # Aggregate all sudoers content (main file + drop-in directory)
    local all_sudoers
    all_sudoers="$(grep -rh "" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -v "^#" | grep -v "^$" || true)"

    # Check for NOPASSWD — allows sudo without password prompt
    local nopasswd_entries
    nopasswd_entries="$(echo "$all_sudoers" | grep -i "NOPASSWD" || true)"
    if [[ -n "$nopasswd_entries" ]]; then
        log "WARN" "NOPASSWD entries found (verify these are intentional):"
        while IFS= read -r line; do
            log "WARN" "  $line"
        done <<< "$nopasswd_entries"
    else
        log "PASS" "No NOPASSWD entries found."
    fi

    # Check for unrestricted ALL=(ALL) sudo rules
    local all_all
    all_all="$(echo "$all_sudoers" \
        | grep -E "ALL\s*=\s*\(ALL.*\)\s*(ALL|NOPASSWD)" || true)"
    if [[ -n "$all_all" ]]; then
        log "WARN" "Broad ALL=(ALL) sudo rules found (normal for admin accounts — verify):"
        while IFS= read -r line; do
            log "WARN" "  $line"
        done <<< "$all_all"
    else
        log "PASS" "No overly broad sudo rules found."
    fi

    _check_sudoers_perms() {
        local f="$1"
        local owner perms

        owner="$(stat -c "%U:%G" "$f" 2>/dev/null || true)"
        perms="$(stat -c "%a" "$f" 2>/dev/null || true)"

        if [[ -z "$owner" || -z "$perms" ]]; then
            log "WARN" "Could not stat $f"
            return
        fi

        if [[ "$owner" != "root:root" ]]; then
            log "WARN" "Bad ownership on $f: $owner (expected root:root)"
        else
            log "PASS" "Ownership OK on $f (root:root)"
        fi

        case "$perms" in
            440|400)
                log "PASS" "Permissions OK on $f ($perms)"
                ;;
            *)
                log "WARN" "Unexpected permissions on $f: $perms (expected 440 or 400)"
                ;;
        esac
    }

    _check_sudoers_perms "$sudoers_file"

    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r -d '' f; do
            _check_sudoers_perms "$f"
        done < <(find /etc/sudoers.d -maxdepth 1 -type f ! -name "*~" ! -name "*.*" -print0)
    fi

    unset -f _check_sudoers_perms
}

# ---------------------------------------------------------------------------
# REPORT SUMMARY
# ---------------------------------------------------------------------------
generate_summary() {
    section "AUDIT SUMMARY"

    local pass_count fail_count warn_count
    pass_count="$(grep -c "^\[PASS\]" "$REPORT_FILE" || true)"
    fail_count="$(grep -c "^\[FAIL\]" "$REPORT_FILE" || true)"
    warn_count="$(grep -c "^\[WARN\]" "$REPORT_FILE" || true)"

    log "INFO" "Host      : $HOSTNAME_VAL"
    log "INFO" "Interface : $IFACE"
    log "INFO" "Timestamp : $TIMESTAMP"
    log "INFO" ""
    log "PASS" "Checks passed : $pass_count"
    log "WARN" "Warnings      : $warn_count"
    log "FAIL" "Checks failed : $fail_count"
    log "INFO" ""
    log "INFO" "Full report saved to: $REPORT_FILE"
}

# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Validate environment before touching the filesystem or running tools
    check_root
    validate_output_dir

    # Set the report file path now that output dir is confirmed
    REPORT_FILE="${OUTPUT_DIR}/hardening_audit_${HOSTNAME_VAL}_${TIMESTAMP}.txt"

    # Write report header
    {
        echo "============================================================"
        echo "  SYSTEM HARDENING AUDIT REPORT"
        echo "  Host      : $HOSTNAME_VAL"
        echo "  Date/Time : $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "  Script    : $SCRIPT_NAME v$SCRIPT_VERSION"
        echo "============================================================"
    } > "$REPORT_FILE"

    # SC2059 fix: pass colour variables via %b format specifier
    if [[ "$SILENT" == false ]]; then
        printf "%b" "$CLR_BOLD$CLR_CYAN"
        printf "╔══════════════════════════════════════════════╗\n"
        printf "║     SYSTEM HARDENING AUDITOR v%-14s║\n" "$SCRIPT_VERSION"
        printf "║     Host: %-34s║\n" "$HOSTNAME_VAL"
        printf "╚══════════════════════════════════════════════╝\n"
        printf "%b\n" "$CLR_RESET"
    fi

    check_dependencies

    # Auto-detect network interface if not provided via -i
    [[ -z "$IFACE" ]] && detect_interface

    # Run all seven audit modules in sequence
    audit_open_ports
    audit_suid_sgid
    audit_ssh_config
    audit_world_writable
    audit_password_policy
    audit_firewall
    audit_sudoers

    # Print and save the final summary
    generate_summary

    exit 0
}

main "$@"