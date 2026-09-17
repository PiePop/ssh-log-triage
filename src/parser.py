"""Parse OpenSSH authentication events out of a Linux auth.log file.

The parser is a streaming generator: it reads one line at a time and never
holds the whole file in memory, so it handles multi-gigabyte logs.

Two line shapes carry almost all of the signal we care about:

    Mar 10 06:52:12 web01 sshd[4412]: Failed password for invalid user admin from 203.0.113.42 port 55314 ssh2
    Mar 10 06:52:20 web01 sshd[4418]: Accepted password for deploy from 198.51.100.7 port 41122 ssh2
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional, TextIO

# Syslog timestamps carry no year, which is why the caller has to supply one.
_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

FAILED_RE = re.compile(
    rf"^{_TS}\s+\S+\s+sshd\[\d+\]:\s+Failed (?:password|publickey) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

ACCEPTED_RE = re.compile(
    rf"^{_TS}\s+\S+\s+sshd\[\d+\]:\s+Accepted (?P<method>\S+) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


@dataclass(frozen=True)
class Event:
    """A single authentication attempt lifted out of the log."""

    kind: str          # "failed" or "accepted"
    timestamp: datetime
    user: str
    ip: str
    port: int
    method: str        # "password", "publickey", ...
    invalid_user: bool # the account does not exist on the host
    line_no: int

    @property
    def succeeded(self) -> bool:
        return self.kind == "accepted"


@dataclass
class ParseStats:
    """Counters so the CLI can report how much of the file it understood."""

    lines_read: int = 0
    events_parsed: int = 0

    @property
    def lines_ignored(self) -> int:
        return self.lines_read - self.events_parsed


def parse_timestamp(raw: str, year: int) -> datetime:
    """Turn a yearless syslog timestamp into a datetime.

    Normalises the variable run of spaces between month and day, because
    single-digit days are space-padded ("Mar  3" vs "Mar 13").
    """
    normalised = re.sub(r"\s+", " ", raw.strip())
    return datetime.strptime(f"{year} {normalised}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int, line_no: int = 0) -> Optional[Event]:
    """Return an Event for an SSH auth line, or None for anything else."""
    match = FAILED_RE.match(line)
    if match:
        return Event(
            kind="failed",
            timestamp=parse_timestamp(match.group("ts"), year),
            user=match.group("user"),
            ip=match.group("ip"),
            port=int(match.group("port")),
            method="password",
            invalid_user=bool(match.group("invalid")),
            line_no=line_no,
        )

    match = ACCEPTED_RE.match(line)
    if match:
        return Event(
            kind="accepted",
            timestamp=parse_timestamp(match.group("ts"), year),
            user=match.group("user"),
            ip=match.group("ip"),
            port=int(match.group("port")),
            method=match.group("method"),
            invalid_user=False,
            line_no=line_no,
        )

    return None


def iter_events(handle: TextIO, year: int, stats: Optional[ParseStats] = None) -> Iterator[Event]:
    """Yield Events from an open file handle, skipping unparseable lines."""
    for line_no, line in enumerate(handle, start=1):
        if stats is not None:
            stats.lines_read += 1
        try:
            event = parse_line(line, year, line_no)
        except ValueError:
            # A malformed timestamp should skip the line, not kill the run.
            continue
        if event is not None:
            if stats is not None:
                stats.events_parsed += 1
            yield event


def parse_file(path: str, year: int, stats: Optional[ParseStats] = None) -> Iterator[Event]:
    """Stream Events from a log file. Transparently handles .gz archives."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        yield from iter_events(handle, year, stats)
