# 🛡️ SIEM Log Analyzer

A Python-based security tool that parses Linux authentication logs and detects suspicious activity — mimicking what real SOC analysts do with enterprise SIEM platforms like Splunk or IBM QRadar.

---

## 🔍 What It Detects

| Threat | Severity | Description |
|---|---|---|
| **Brute Force Attack** | HIGH | 5+ failed SSH logins from same IP within 60 seconds |
| **Off-Hours Login** | MEDIUM | Successful login between 10 PM – 6 AM |
| **New User Creation** | CRITICAL/HIGH | New system account created (UID=0 = root-level backdoor) |
| **Privilege Escalation** | HIGH/MEDIUM | `sudo` command execution, especially to root |

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════╗
║         SIEM LOG ANALYZER  v1.0              ║
║    Threat Detection & Incident Reporting     ║
╚══════════════════════════════════════════════╝

  Analyzing: sample_auth.log
  Parsed 32 log entries

  ⚠  Brute Force: 2 alert(s)
  ⚠  Off-Hours Logins: 3 alert(s)
  ⚠  New User Creation: 2 alert(s)
  ⚠  Privilege Escalation: 2 alert(s)

  [CRITICAL]   New account 'hacker123' created — ROOT privileges
  [CRITICAL]   New account 'backdoor' created — ROOT privileges
  [HIGH]       15 failed login attempts from 203.0.113.42
  [HIGH]       'admin' ran '/bin/bash' as root
  [MEDIUM]     User 'admin' logged in at 02:13 from 203.0.113.42
  ...

  Total alerts : 9  |  CRITICAL: 2  |  HIGH: 4  |  MEDIUM: 3

  ✔ Report saved → threat_report.json
```

---

## 🚀 Getting Started

**Requirements:** Python 3.7+ (no external libraries needed)

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/siem-log-analyzer.git
cd siem-log-analyzer

# Run on the included sample log
python3 analyzer.py sample_auth.log

# Run on your own log (Linux)
python3 analyzer.py /var/log/auth.log
```

---

## 📁 Project Structure

```
siem-log-analyzer/
├── analyzer.py         # Main detection engine
├── sample_auth.log     # Simulated log with attack patterns
├── threat_report.json  # Auto-generated JSON report (created on run)
└── README.md
```

---

## ⚙️ Configuration

Edit these values at the top of `analyzer.py`:

```python
BRUTE_FORCE_THRESHOLD = 5    # failed attempts to trigger alert
OFF_HOURS_START       = 22   # start of off-hours window (10 PM)
OFF_HOURS_END         = 6    # end of off-hours window (6 AM)
```

---

## 📊 JSON Report

Every run saves a structured `threat_report.json`:

```json
{
  "generated_at": "2024-06-15T14:30:00",
  "log_file": "sample_auth.log",
  "total_alerts": 9,
  "alerts": [
    {
      "type": "New User Created",
      "severity": "CRITICAL",
      "user": "hacker123",
      "detail": "New account 'hacker123' created — ROOT privileges"
    }
  ]
}
```

---

## 🧠 How It Works

1. **Parser** — uses regex to extract timestamp, host, process, and message from each log line
2. **Detectors** — four independent modules each scan for a specific threat pattern
3. **Sliding window** — brute force detection uses a 60-second time window per IP
4. **Severity scoring** — alerts ranked CRITICAL → HIGH → MEDIUM → LOW
5. **Reporter** — prints color-coded terminal output and saves JSON report

---

## 🔮 Possible Enhancements

- [ ] Add email/Slack alerting on CRITICAL findings
- [ ] Support Windows Event Log format
- [ ] Add IP geolocation lookup (flag logins from unusual countries)
- [ ] Build a web dashboard with Flask
- [ ] Ingest logs from multiple servers simultaneously

---

## 🎯 Skills Demonstrated

`Python` · `Log Analysis` · `Regex Parsing` · `Threat Detection` · `SIEM Concepts` · `Incident Response` · `Blue Team Security`

---

## 📄 License

MIT License — free to use and modify.
