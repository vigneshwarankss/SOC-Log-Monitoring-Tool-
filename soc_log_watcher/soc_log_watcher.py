#!/usr/bin/env python3
"""
SOC Log Monitoring Tool
- Monitors a log file continuously
- Uses regex patterns to classify suspicious events
- Tracks event counts in sliding windows to detect spikes
- Sends desktop notifications via plyer (falls back to console)
- Includes an optional log simulator for testing

Tech: watchdog, re, plyer
"""

import argparse
import os
import re
import time
import threading
import random
from collections import deque, defaultdict
from datetime import datetime, timedelta

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Try to import plyer for desktop notifications (optional)
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except Exception:
    PLYER_AVAILABLE = False

# --------------------
# Configuration
# --------------------
DEFAULT_LOG = "soc_test.log"

# Regex patterns for suspicious events (customize to your log format)
PATTERNS = {
    "failed_login": re.compile(r"(Failed login|authentication failure|invalid password|login failed)", re.IGNORECASE),
    "successful_login": re.compile(r"(Accepted password|authentication success|login succeeded)", re.IGNORECASE),
    "http_5xx": re.compile(r"\b5\d{2}\b"),  # simple: any 5xx status code anywhere
    "sql_error": re.compile(r"(syntax error|SQL error|database error|query failed)", re.IGNORECASE),
    "suspicious_user": re.compile(r"(root|admin|administrator|sysadmin)", re.IGNORECASE),
    # capture IP-looking tokens (very permissive)
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# Sliding window thresholds (window_seconds, threshold count -> alert if exceeded)
RATE_RULES = {
    "failed_login": (60, 5),      # >5 failed logins in 60s -> alert
    "http_5xx": (30, 10),         # >10 HTTP 5xx in 30s -> alert
    "sql_error": (300, 3),        # >3 SQL errors in 5min -> alert
}

ALERT_COOLDOWN_SECONDS = 60  # don't re-alert same rule more often than this

# --------------------
# Utilities
# --------------------
def now_ts():
    return time.time()

def notify(title, message):
    """Desktop notification or fallback to console output"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if PLYER_AVAILABLE:
        try:
            notification.notify(title=title, message=message, timeout=6)
        except Exception:
            print(f"[{ts}] {title} - {message}")
    else:
        print(f"[{ts}] {title} - {message}")

# --------------------
# EventTracker: sliding window counters
# --------------------
class EventTracker:
    def __init__(self):
        # each key -> deque of timestamps (floats)
        self.buckets = defaultdict(deque)
        # last alert timestamp per rule to enforce cooldown
        self.last_alert = {}

    def add_event(self, rule_name):
        t = now_ts()
        self.buckets[rule_name].append(t)

    def count_recent(self, rule_name, window_seconds):
        dq = self.buckets[rule_name]
        cutoff = now_ts() - window_seconds
        # pop older items
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def should_alert_cooldown(self, rule_name):
        last = self.last_alert.get(rule_name, 0)
        if now_ts() - last >= ALERT_COOLDOWN_SECONDS:
            self.last_alert[rule_name] = now_ts()
            return True
        return False

# --------------------
# Log tailing abstraction
# --------------------
class LogTail:
    """
    Tail-like reader that reads appended lines from a file and
    handles truncation/rotation by checking file size and inode.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self._file = None
        self._inode = None
        self._position = 0
        self._open_file()

    def _open_file(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
        # open file in read mode (create if missing)
        self._file = open(self.filepath, "a+", encoding="utf-8")
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.seek(0, os.SEEK_END)
        try:
            self._inode = os.fstat(self._file.fileno()).st_ino
        except Exception:
            self._inode = None
        self._position = self._file.tell()

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def read_new_lines(self):
        """Return list of new lines appended since last read"""
        try:
            # check if file was rotated/truncated
            if self._file is None:
                self._open_file()
            try:
                cur_inode = os.stat(self.filepath).st_ino
            except Exception:
                cur_inode = None

            if self._inode is not None and cur_inode != self._inode:
                # file rotated or replaced; reopen
                self._file.close()
                self._open_file()

            self._file.seek(self._position)
            lines = self._file.read().splitlines()
            self._position = self._file.tell()
            return lines
        except Exception as e:
            print("Error reading log:", e)
            # try to reopen
            try:
                self._open_file()
            except Exception:
                pass
            return []

# --------------------
# Watchdog event handler monitors file changes and triggers processing
# --------------------
class LogFileEventHandler(FileSystemEventHandler):
    def __init__(self, tailer, processor):
        super().__init__()
        self.tailer = tailer
        self.processor = processor

    def on_modified(self, event):
        # Only process the configured file
        if not event.is_directory and os.path.abspath(event.src_path) == os.path.abspath(self.tailer.filepath):
            lines = self.tailer.read_new_lines()
            for line in lines:
                self.processor.process_line(line)

    def on_created(self, event):
        # file created — ensure we read it
        if not event.is_directory and os.path.abspath(event.src_path) == os.path.abspath(self.tailer.filepath):
            lines = self.tailer.read_new_lines()
            for line in lines:
                self.processor.process_line(line)

# --------------------
# Log Processor: pattern matching and alerting logic
# --------------------
class LogProcessor:
    def __init__(self, patterns, rate_rules, tracker):
        self.patterns = patterns
        self.rate_rules = rate_rules
        self.tracker = tracker

    def process_line(self, line):
        line = line.strip()
        if not line:
            return
        # Try matching each pattern
        matched_rules = set()

        # 1) direct named-pattern detection
        for name, pattern in self.patterns.items():
            if name == "ip":
                continue  # handled separately
            if pattern.search(line):
                matched_rules.add(name)
                # general immediate notification for high severity single matches
                if name in ("sql_error", "suspicious_user"):
                    self.alert_immediate(name, line)

        # 2) IP extraction (if any)
        ip_match = self.patterns.get("ip").search(line)
        if ip_match:
            suspect_ip = ip_match.group(0)
            # basic private/public check (very simple): flag non-private as potentially malicious if paired with failed_login
            if "failed_login" in matched_rules and not self._is_private_ip(suspect_ip):
                self.alert_immediate("failed_login_from_public_ip", f"Failed login from public IP {suspect_ip}: {line}")

        # 3) rate rules: record events and check thresholds
        for rule_name, (window_seconds, threshold) in self.rate_rules.items():
            # If the line matched that rule, record it
            if rule_name in matched_rules:
                self.tracker.add_event(rule_name)
                count = self.tracker.count_recent(rule_name, window_seconds)
                if count >= threshold:
                    # cooldown check
                    if self.tracker.should_alert_cooldown(rule_name):
                        self.alert_rate(rule_name, count, window_seconds, line)

    def alert_immediate(self, rule_name, line):
        title = f"[SOC] Immediate Alert: {rule_name}"
        msg = f"{line}"
        notify(title, msg)

    def alert_rate(self, rule_name, count, window_seconds, sample_line=""):
        title = f"[SOC] Rate Alert: {rule_name} ({count} in last {window_seconds}s)"
        msg = f"Detected {count} occurrences of {rule_name} in {window_seconds} seconds. Example: {sample_line}"
        notify(title, msg)

    @staticmethod
    def _is_private_ip(ip):
        # Very simple check: RFC1918 ranges
        try:
            parts = [int(p) for p in ip.split(".")]
            a, b = parts[0], parts[1]
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            return False
        except Exception:
            return False

# --------------------
# Optional: simple log simulator to generate test log lines
# --------------------
class LogSimulator(threading.Thread):
    """Append simulated log lines to a file periodically (for demo/testing)."""
    SAMPLE_LINES = [
        '2025-10-31 22:00:01 INFO User "alice" logged in from 192.168.1.2',
        '2025-10-31 22:00:05 WARNING Failed login for user "bob" from 203.0.113.5',
        '2025-10-31 22:00:07 ERROR SQL error: syntax error near "FROM" in query',
        '2025-10-31 22:00:09 INFO 200 GET /home',
        '2025-10-31 22:00:11 ERROR 500 GET /api/update',  # 5xx
        '2025-10-31 22:00:12 WARNING authentication failure for user "root" from 198.51.100.17',
        '2025-10-31 22:00:14 ERROR 502 POST /api/data',
        '2025-10-31 22:00:16 WARNING invalid password for user "charlie" from 203.0.113.5',
    ]

    def __init__(self, filepath, speed=1.0):
        super().__init__(daemon=True)
        self.filepath = filepath
        self.speed = speed
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        # ensure file exists
        with open(self.filepath, "a", encoding="utf-8") as f:
            pass
        while self.running:
            line = random.choice(self.SAMPLE_LINES)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # add a bit of randomness
            line_to_write = f"{ts} {line}"
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(line_to_write + "\n")
            time.sleep(max(0.1, random.random() * self.speed))

# --------------------
# Main orchestration
# --------------------
def run_monitor(logfile, use_simulator=False, simulator_speed=0.5):
    print(f"Starting SOC Log Monitoring Tool for: {logfile}")
    print("Patterns:", ", ".join(k for k in PATTERNS.keys() if k != "ip"))
    print("Rate rules:", RATE_RULES)
    if not os.path.exists(os.path.dirname(os.path.abspath(logfile))) and os.path.dirname(os.path.abspath(logfile)) != '':
        os.makedirs(os.path.dirname(os.path.abspath(logfile)), exist_ok=True)

    tailer = LogTail(logfile)
    tracker = EventTracker()
    processor = LogProcessor(PATTERNS, RATE_RULES, tracker)
    event_handler = LogFileEventHandler(tailer, processor)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.abspath(logfile), recursive=False)
    # If scheduling path as file fails on some systems, schedule parent directory as fallback
    try:
        observer.start()
    except Exception:
        # fallback to parent directory
        parent = os.path.dirname(os.path.abspath(logfile)) or "."
        observer.schedule(event_handler, path=parent, recursive=False)
        observer.start()

    sim = None
    if use_simulator:
        sim = LogSimulator(logfile, speed=simulator_speed)
        sim.start()
        print("Log simulator started (for testing).")

    # Initial read of existing content (optional)
    existing = tailer.read_new_lines()
    for l in existing:
        processor.process_line(l)

    try:
        while True:
            # Periodically wake up — in case the watcher misses something — do a safe read
            lines = tailer.read_new_lines()
            for l in lines:
                processor.process_line(l)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        if sim:
            sim.stop()
        observer.stop()
        observer.join()
        tailer.close()

# --------------------
# CLI
# --------------------
def parse_args():
    p = argparse.ArgumentParser(description="SOC Log Monitoring Tool (watchdog + re + plyer)")
    p.add_argument("--logfile", "-f", default=DEFAULT_LOG, help="Path to the log file to monitor")
    p.add_argument("--simulate", "-s", action="store_true", help="Enable built-in log simulator (for testing)")
    p.add_argument("--sim-speed", type=float, default=0.7, help="Simulator speed multiplier (lower=faster)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_monitor(args.logfile, use_simulator=args.simulate, simulator_speed=args.sim_speed)
