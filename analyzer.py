#!/usr/bin/env python3
"""
SIEM Log Analyzer
-----------------
Detects suspicious activity in Linux auth logs:
  - Brute force SSH attacks
  - Off-hours logins
  - New user creation (possible backdoor)
  - Privilege escalation via sudo
"""

import re
import sys
import json
from collections import defaultdict
from datetime import datetime, time

# ─────────────────────────────────────────────
#  CONFIG — tweak these thresholds as needed
# ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # failed attempts from same IP in one minute
OFF_HOURS_START = 22            # 10 PM
OFF_HOURS_END   = 6             # 6 AM
REPORT_FILE     = "threat_report.json"
YEAR            = 2024          # auth.log doesn't include year, set manually

# ─────────────────────────────────────────────
#  ANSI COLORS for terminal output
# ─────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}

# ─────────────────────────────────────────────
#  LOG PARSING
# ─────────────────────────────────────────────
LOG_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)"
)

def parse_timestamp(month, day, time_str):
    try:
        return datetime.strptime(f"{YEAR} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def parse_log_file(filepath):
    entries = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = LOG_PATTERN.match(line)
            if m:
                ts = parse_timestamp(m.group("month"), m.group("day"), m.group("time"))
                entries.append({
                    "timestamp": ts,
                    "host":      m.group("host"),
                    "process":   m.group("process"),
                    "message":   m.group("message"),
                    "raw":       line
                })
    return entries

# ─────────────────────────────────────────────
#  DETECTORS
# ─────────────────────────────────────────────

def detect_brute_force(entries):
    """Flag IPs with >= BRUTE_FORCE_THRESHOLD failed logins within 60 seconds."""
    alerts = []
    fail_pattern = re.compile(r"Failed password for (\S+) from (\S+)")
    
    # Group failures by IP
    failures = defaultdict(list)
    for entry in entries:
        m = fail_pattern.search(entry["message"])
        if m and entry["timestamp"]:
            ip = m.group(2)
            failures[ip].append(entry["timestamp"])

    for ip, timestamps in failures.items():
        timestamps.sort()
        # Sliding window: check if THRESHOLD failures happen within 60s
        for i in range(len(timestamps)):
            window = [t for t in timestamps[i:] if (t - timestamps[i]).seconds <= 60]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "type":     "Brute Force Attack",
                    "severity": "HIGH",
                    "ip":       ip,
                    "count":    len(timestamps),
                    "first_seen": str(timestamps[0]),
                    "detail":   f"{len(timestamps)} failed login attempts from {ip}"
                })
                break  # one alert per IP

    return alerts


def detect_off_hours_login(entries):
    """Flag successful logins outside business hours."""
    alerts = []
    success_pattern = re.compile(r"Accepted password for (\S+) from (\S+)")

    for entry in entries:
        m = success_pattern.search(entry["message"])
        if m and entry["timestamp"]:
            hour = entry["timestamp"].hour
            is_off_hours = hour >= OFF_HOURS_START or hour < OFF_HOURS_END
            if is_off_hours:
                user = m.group(1)
                ip   = m.group(2)
                alerts.append({
                    "type":     "Off-Hours Login",
                    "severity": "MEDIUM",
                    "ip":       ip,
                    "user":     user,
                    "time":     str(entry["timestamp"]),
                    "detail":   f"User '{user}' logged in at {entry['timestamp'].strftime('%H:%M')} from {ip}"
                })

    return alerts


def detect_new_user_creation(entries):
    """Flag new user accounts being created (possible backdoor)."""
    alerts = []
    user_pattern = re.compile(r"new user: name=(\S+)")

    for entry in entries:
        m = user_pattern.search(entry["message"])
        if m:
            username = m.group(1).rstrip(",")
            severity = "CRITICAL" if "UID=0" in entry["message"] else "HIGH"
            alerts.append({
                "type":     "New User Created",
                "severity": severity,
                "user":     username,
                "time":     str(entry["timestamp"]),
                "detail":   f"New account '{username}' created — {'ROOT privileges' if 'UID=0' in entry['message'] else 'standard user'}"
            })

    return alerts


def detect_privilege_escalation(entries):
    """Flag sudo commands, especially to root."""
    alerts = []
    sudo_pattern = re.compile(r"(\S+)\s*:.*USER=(\S+)\s*;\s*COMMAND=(.+)")

    for entry in entries:
        if "sudo" not in entry["process"].lower():
            continue
        m = sudo_pattern.search(entry["message"])
        if m:
            user    = m.group(1)
            target  = m.group(2)
            command = m.group(3).strip()
            severity = "HIGH" if target == "root" else "MEDIUM"
            alerts.append({
                "type":     "Privilege Escalation",
                "severity": severity,
                "user":     user,
                "target":   target,
                "command":  command,
                "time":     str(entry["timestamp"]),
                "detail":   f"'{user}' ran '{command}' as {target}"
            })

    return alerts

# ─────────────────────────────────────────────
#  REPORT
# ─────────────────────────────────────────────

def print_banner():
    print(f"""
{BOLD}{CYAN}
╔══════════════════════════════════════════════╗
║         SIEM LOG ANALYZER  v1.0              ║
║    Threat Detection & Incident Reporting     ║
╚══════════════════════════════════════════════╝{RESET}
""")

def severity_order(alert):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get(alert["severity"], 99)

def print_alerts(all_alerts):
    if not all_alerts:
        print(f"{GREEN}✔  No threats detected.{RESET}")
        return

    all_alerts.sort(key=severity_order)

    print(f"{BOLD}{'─'*55}{RESET}")
    print(f"{BOLD}  {'SEV':<10} {'TYPE':<25} DETAIL{RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")

    for a in all_alerts:
        color = SEVERITY_COLOR.get(a["severity"], RESET)
        sev   = f"{color}[{a['severity']}]{RESET}"
        print(f"  {sev:<22} {a['type']:<25}")
        print(f"    {a['detail']}")
        print()

def print_summary(all_alerts, log_path):
    counts = defaultdict(int)
    for a in all_alerts:
        counts[a["severity"]] += 1

    total = len(all_alerts)
    print(f"{BOLD}{'─'*55}")
    print(f"  SUMMARY")
    print(f"{'─'*55}{RESET}")
    print(f"  Log file  : {log_path}")
    print(f"  Total alerts : {BOLD}{total}{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            color = SEVERITY_COLOR[sev]
            print(f"  {color}{sev:<10}{RESET} : {counts[sev]}")
    print()

def save_report(all_alerts, log_path):
    report = {
        "generated_at": datetime.now().isoformat(),
        "log_file":     log_path,
        "total_alerts": len(all_alerts),
        "alerts":       all_alerts
    }
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"{GREEN}  ✔ Report saved → {REPORT_FILE}{RESET}\n")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"

    print_banner()
    print(f"  {CYAN}Analyzing:{RESET} {log_path}\n")

    try:
        entries = parse_log_file(log_path)
    except FileNotFoundError:
        print(f"{RED}Error: File '{log_path}' not found.{RESET}")
        sys.exit(1)

    print(f"  Parsed {len(entries)} log entries\n")

    # Run all detectors
    all_alerts = []
    detectors = [
        ("Brute Force",          detect_brute_force),
        ("Off-Hours Logins",     detect_off_hours_login),
        ("New User Creation",    detect_new_user_creation),
        ("Privilege Escalation", detect_privilege_escalation),
    ]

    for name, fn in detectors:
        results = fn(entries)
        icon = f"{RED}⚠{RESET}" if results else f"{GREEN}✔{RESET}"
        print(f"  {icon}  {name}: {len(results)} alert(s)")
        all_alerts.extend(results)

    print()
    print_alerts(all_alerts)
    print_summary(all_alerts, log_path)
    save_report(all_alerts, log_path)

if __name__ == "__main__":
    main()
