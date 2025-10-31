SOC Log Monitoring Tool

A simple, single-file Python tool that simulates a Security Operations Center (SOC) log watcher.
Continuously tails a log file, detects suspicious patterns (failed logins, SQL errors, HTTP 5xx, suspicious users/IPs), and raises alerts via desktop notifications (or console fallback). Includes a built-in log simulator for testing.

Features

Real-time log monitoring using watchdog

Regex-based detection (re) for common suspicious events

Sliding-window rate detection (spike detection) with cooldowns to reduce noise

Desktop notifications using plyer (prints to console if unavailable)

Robust tailing that handles truncation/rotation

Optional log simulator to generate sample lines for testing

Configurable patterns and thresholds

Quick demo (recommended)

Create a copy of the script as soc_log_watcher.py (or use the file you already have), then run:

# Create virtualenv (optional but recommended)
python -m venv venv
# Activate: Windows -> venv\Scripts\activate, macOS/Linux -> source venv/bin/activate

pip install watchdog plyer
python soc_log_watcher.py --logfile test.log --simulate


The simulator will append sample log lines to test.log and you should see alerts in your terminal and desktop notifications.

Requirements

Python 3.8+

Packages:

watchdog

plyer (optional; if not present, notifications fall back to console)
Install them with:

pip install watchdog plyer

Usage
usage: soc_log_watcher.py [-h] [--logfile LOGFILE] [--simulate] [--sim-speed SIM_SPEED]

Options:
  --logfile, -f    Path to the log file to monitor (default: soc_test.log)
  --simulate, -s   Enable built-in log simulator (for testing)
  --sim-speed      Simulator speed multiplier (lower = faster; default: 0.7)


Examples:

Run with built-in simulator:

python soc_log_watcher.py --logfile test.log --simulate


Monitor an existing real logfile:

python soc_log_watcher.py --logfile "C:\path\to\your\app.log"

Configuration

Open the script and edit these sections:

PATTERNS — a dict of named re.compile regex patterns. Customize to match your log formats (Apache, syslog, application logs).

RATE_RULES — a dict mapping rule names to (window_seconds, threshold) used for sliding-window spike detection.

RATE_RULES = {
    "failed_login": (60, 5),  # >5 failed logins in 60s -> alert
    "http_5xx": (30, 10),
    "sql_error": (300, 3),
}


ALERT_COOLDOWN_SECONDS — time (seconds) to wait before re-alerting the same rule to avoid spam.

Sample log lines (for simulator / testing)

The included simulator uses permissive sample lines such as:

2025-10-31 22:00:05 WARNING Failed login for user "bob" from 203.0.113.5
2025-10-31 22:00:07 ERROR SQL error: syntax error near "FROM"
2025-10-31 22:00:11 ERROR 500 GET /api/update
2025-10-31 22:00:12 WARNING authentication failure for user "root" from 198.51.100.17


For Apache/Nginx access logs you might tune patterns to capture status codes and request paths:

Example Apache line:

203.0.113.5 - - [31/Oct/2025:22:00:11 +0000] "GET /api/update HTTP/1.1" 500 1234


Adapt PATTERNS to match your exact log format.
