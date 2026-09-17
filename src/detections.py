"""Detection logic for SSH credential attacks.

Everything here is incremental: events are fed in one at a time and per-IP
state is kept small and bounded, so memory does not grow with file size.

Detections implemented:

  * Brute force (ATT&CK T1110)         - many failures from one IP in a short window
  * Password spraying (T1110.003)      - one IP, many accounts, few tries each
  * Successful login after failures    - the finding that actually matters
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

# Upper bound on the failure timestamps retained per source address. The sliding
# window normally keeps this tiny, but a log with thousands of identical
# timestamps (duplicated or replayed data) would otherwise grow it without
# limit. Capping keeps memory and per-event work constant.
MAX_TRACKED_FAILURES = 2000


@dataclass
class Finding:
    severity: str
    title: str
    technique: str          # MITRE ATT&CK technique ID
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int
    distinct_users: int
    detail: str
    sample_users: List[str] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def as_row(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "technique": self.technique,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(sep=" "),
            "last_seen": self.last_seen.isoformat(sep=" "),
            "attempts": self.attempts,
            "distinct_users": self.distinct_users,
            "sample_users": ", ".join(self.sample_users),
            "detail": self.detail,
        }


@dataclass
class Config:
    """Tunable thresholds. Every one of these is a CLI flag."""

    burst_threshold: int = 10        # failures needed inside the window
    window_seconds: int = 60         # the sliding window itself
    spray_min_users: int = 8         # distinct accounts that makes it a spray
    spray_max_per_user: int = 4      # tries per account, above which it is not a spray
    compromise_window: int = 300     # how far back a success looks for failures
    compromise_min_failures: int = 5 # failures before a success that raise the alarm


@dataclass
class _IPState:
    failures: Deque[datetime] = field(
        default_factory=lambda: deque(maxlen=MAX_TRACKED_FAILURES)
    )
    users: Counter = field(default_factory=Counter)
    total_failures: int = 0
    max_burst: int = 0
    burst_peak_time: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    compromises: List[tuple] = field(default_factory=list)  # (timestamp, user, failures_before)


class Analyzer:
    """Consumes Events in time order and accumulates findings."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._state: Dict[str, _IPState] = defaultdict(_IPState)
        self.total_events = 0

    # -- ingestion ---------------------------------------------------------

    def feed(self, event) -> None:
        self.total_events += 1
        state = self._state[event.ip]
        if state.first_seen is None:
            state.first_seen = event.timestamp
        state.last_seen = event.timestamp

        if event.kind == "failed":
            self._record_failure(state, event)
        elif event.kind == "accepted":
            self._check_compromise(state, event)

    def feed_all(self, events) -> "Analyzer":
        for event in events:
            self.feed(event)
        return self

    # -- per-event logic ---------------------------------------------------

    def _record_failure(self, state: _IPState, event) -> None:
        cfg = self.config
        state.total_failures += 1
        state.users[event.user] += 1
        state.failures.append(event.timestamp)

        # Keep only as much history as the widest detection needs.
        keep = max(cfg.window_seconds, cfg.compromise_window)
        self._trim(state.failures, event.timestamp, keep)

        # Count how many of the retained failures fall inside the burst window.
        burst = 0
        for stamp in reversed(state.failures):
            if (event.timestamp - stamp).total_seconds() <= cfg.window_seconds:
                burst += 1
            else:
                break
            if burst >= MAX_TRACKED_FAILURES:
                break
        if burst > state.max_burst:
            state.max_burst = burst
            state.burst_peak_time = event.timestamp

    def _check_compromise(self, state: _IPState, event) -> None:
        cfg = self.config
        recent = sum(
            1
            for stamp in state.failures
            if 0 <= (event.timestamp - stamp).total_seconds() <= cfg.compromise_window
        )
        if recent >= cfg.compromise_min_failures:
            state.compromises.append((event.timestamp, event.user, recent))

    @staticmethod
    def _trim(queue: Deque[datetime], now: datetime, seconds: int) -> None:
        while queue and (now - queue[0]).total_seconds() > seconds:
            queue.popleft()

    # -- results -----------------------------------------------------------

    def findings(self) -> List[Finding]:
        cfg = self.config
        results: List[Finding] = []

        for ip, state in self._state.items():
            users = state.users
            distinct = len(users)
            sample = [name for name, _ in users.most_common(5)]

            # Highest severity first: someone got in after hammering the host.
            for timestamp, user, before in state.compromises:
                results.append(
                    Finding(
                        severity="high",
                        title="Successful login after repeated failures",
                        technique="T1110",
                        source_ip=ip,
                        first_seen=state.first_seen,
                        last_seen=timestamp,
                        attempts=state.total_failures,
                        distinct_users=distinct,
                        sample_users=[user],
                        detail=(
                            f"Account '{user}' authenticated successfully after {before} failed "
                            f"attempts from this address within {cfg.compromise_window}s. "
                            f"Treat this account as potentially compromised."
                        ),
                    )
                )

            # Password spraying: broad and slow, so volume thresholds miss it.
            spray_users = [u for u, n in users.items() if n <= cfg.spray_max_per_user]
            if len(spray_users) >= cfg.spray_min_users and state.max_burst < cfg.burst_threshold:
                results.append(
                    Finding(
                        severity="medium",
                        title="Password spraying",
                        technique="T1110.003",
                        source_ip=ip,
                        first_seen=state.first_seen,
                        last_seen=state.last_seen,
                        attempts=state.total_failures,
                        distinct_users=distinct,
                        sample_users=sample,
                        detail=(
                            f"{len(spray_users)} distinct accounts tried with no more than "
                            f"{cfg.spray_max_per_user} attempts each - low and slow, designed to "
                            f"stay under lockout thresholds."
                        ),
                    )
                )

            # Classic brute force: a burst of failures in a tight window.
            elif state.max_burst >= cfg.burst_threshold:
                results.append(
                    Finding(
                        severity="medium",
                        title="Brute-force authentication attempts",
                        technique="T1110",
                        source_ip=ip,
                        first_seen=state.first_seen,
                        last_seen=state.last_seen,
                        attempts=state.total_failures,
                        distinct_users=distinct,
                        sample_users=sample,
                        detail=(
                            f"Peak of {state.max_burst} failed logins within "
                            f"{cfg.window_seconds}s (threshold {cfg.burst_threshold}); "
                            f"{state.total_failures} failures in total."
                        ),
                    )
                )

        results.sort(key=lambda f: (-f.rank, -f.attempts, f.source_ip))
        return results


def find_bursts(events, threshold: int = 10, window_seconds: int = 60) -> Dict[str, int]:
    """Convenience helper: {ip: peak failures in window} for IPs over threshold."""
    analyzer = Analyzer(Config(burst_threshold=threshold, window_seconds=window_seconds))
    analyzer.feed_all(events)
    return {
        ip: state.max_burst
        for ip, state in analyzer._state.items()
        if state.max_burst >= threshold
    }
