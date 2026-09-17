"""Tests for the parser and the detection engine.

Run with pytest:      python -m pytest -q
Or without pytest:    python tests/test_detections.py
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detections import Analyzer, Config, find_bursts  # noqa: E402
from src.parser import Event, parse_line  # noqa: E402

YEAR = 2026
BASE = datetime(YEAR, 3, 10, 6, 0, 0)


def make_events(ip, count, spacing_seconds, user="admin", start=BASE, kind="failed"):
    """Build a run of synthetic events for one source address."""
    return [
        Event(
            kind=kind,
            timestamp=start + timedelta(seconds=i * spacing_seconds),
            user=user,
            ip=ip,
            port=40000 + i,
            method="password",
            invalid_user=True,
            line_no=i,
        )
        for i in range(count)
    ]


# --- parser ---------------------------------------------------------------

def test_parses_failed_password_line():
    line = ("Mar 10 06:52:12 web01 sshd[4412]: Failed password for invalid user "
            "admin from 203.0.113.42 port 55314 ssh2")
    event = parse_line(line, YEAR)
    assert event is not None
    assert event.kind == "failed"
    assert event.user == "admin"
    assert event.ip == "203.0.113.42"
    assert event.invalid_user is True
    assert event.timestamp == datetime(YEAR, 3, 10, 6, 52, 12)


def test_parses_accepted_line_and_marks_valid_user():
    line = ("Mar 10 06:52:20 web01 sshd[4418]: Accepted password for deploy "
            "from 198.51.100.7 port 41122 ssh2")
    event = parse_line(line, YEAR)
    assert event.kind == "accepted"
    assert event.succeeded is True
    assert event.invalid_user is False


def test_handles_single_digit_day_padding():
    line = ("Mar  3 01:02:03 web01 sshd[10]: Failed password for root "
            "from 203.0.113.9 port 2222 ssh2")
    event = parse_line(line, YEAR)
    assert event.timestamp == datetime(YEAR, 3, 3, 1, 2, 3)


def test_ignores_unrelated_lines():
    assert parse_line("Mar 10 06:00:00 web01 CRON[2535]: session opened for root", YEAR) is None
    assert parse_line("this is not a log line at all", YEAR) is None
    assert parse_line("", YEAR) is None


# --- brute force ----------------------------------------------------------

def test_detects_burst_of_failures():
    events = make_events("203.0.113.42", count=15, spacing_seconds=2)
    assert "203.0.113.42" in find_bursts(events, threshold=10, window_seconds=60)


def test_ignores_failures_spread_beyond_the_window():
    events = make_events("198.51.100.9", count=15, spacing_seconds=600)
    assert find_bursts(events, threshold=10, window_seconds=60) == {}


def test_threshold_is_respected():
    events = make_events("203.0.113.5", count=9, spacing_seconds=2)
    assert find_bursts(events, threshold=10, window_seconds=60) == {}


# --- password spraying ----------------------------------------------------

def test_detects_spray_that_stays_under_volume_threshold():
    events = []
    for i in range(12):
        events += make_events(
            "198.51.100.23", count=2, spacing_seconds=30,
            user=f"user{i}", start=BASE + timedelta(seconds=i * 300),
        )
    events.sort(key=lambda e: e.timestamp)

    findings = Analyzer(Config(spray_min_users=8, spray_max_per_user=4)).feed_all(events).findings()
    titles = [f.title for f in findings]
    assert "Password spraying" in titles
    assert "Brute-force authentication attempts" not in titles


# --- successful login after failures --------------------------------------

def test_flags_success_after_failures_as_high():
    events = make_events("203.0.113.77", count=20, spacing_seconds=5, user="backup")
    events.append(
        Event(
            kind="accepted",
            timestamp=BASE + timedelta(seconds=110),
            user="backup",
            ip="203.0.113.77",
            port=41000,
            method="password",
            invalid_user=False,
            line_no=99,
        )
    )
    findings = Analyzer().feed_all(events).findings()
    high = [f for f in findings if f.severity == "high"]
    assert len(high) == 1
    assert high[0].technique == "T1110"
    assert "backup" in high[0].detail


def test_normal_login_does_not_raise_a_finding():
    events = [
        Event("accepted", BASE, "deploy", "192.0.2.10", 40000, "publickey", False, 1),
        Event("failed", BASE + timedelta(seconds=5), "deploy", "192.0.2.10", 40001, "password", False, 2),
        Event("accepted", BASE + timedelta(seconds=9), "deploy", "192.0.2.10", 40002, "password", False, 3),
    ]
    assert Analyzer().feed_all(events).findings() == []


if __name__ == "__main__":
    # Lets the suite run without pytest installed.
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
