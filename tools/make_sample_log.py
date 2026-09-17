#!/usr/bin/env python3
"""Generate a synthetic auth.log containing known attack patterns.

Everything this writes is fabricated, which means the repository stays safe to
publish and the test expectations have ground truth to check against.

The generated file contains, deliberately:
  * ordinary successful logins and the occasional fat-fingered password
  * a loud brute-force burst from 203.0.113.42
  * a slow password spray from 198.51.100.23 (under any volume threshold)
  * a compromise chain from 203.0.113.77: failures, then a success
  * unrelated sudo/cron noise that the parser must ignore

Usage:
    python tools/make_sample_log.py --out samples/demo_auth.log
    python tools/make_sample_log.py            # writes to stdout
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta

HOST = "web01"
START = datetime(2026, 3, 10, 6, 0, 0)

REAL_USERS = ["deploy", "ubuntu", "jsmith", "backup"]
COMMON_USERS = [
    "admin", "root", "test", "user", "oracle", "postgres", "git", "ubnt",
    "guest", "ftp", "mysql", "pi", "support", "info", "www-data", "nagios",
]


class LogWriter:
    def __init__(self):
        self.lines: list[tuple[datetime, str]] = []
        self.pid = 1000

    def _next_pid(self) -> int:
        self.pid += random.randint(1, 9)
        return self.pid

    def add(self, when: datetime, message: str) -> None:
        stamp = when.strftime("%b %e %H:%M:%S")
        self.lines.append((when, f"{stamp} {HOST} {message}"))

    def failed(self, when, user, ip, invalid=True):
        who = f"invalid user {user}" if invalid else user
        port = random.randint(30000, 65000)
        self.add(when, f"sshd[{self._next_pid()}]: Failed password for {who} from {ip} port {port} ssh2")

    def accepted(self, when, user, ip, method="password"):
        port = random.randint(30000, 65000)
        self.add(when, f"sshd[{self._next_pid()}]: Accepted {method} for {user} from {ip} port {port} ssh2")

    def noise(self, when, message):
        self.add(when, message)

    def render(self) -> str:
        self.lines.sort(key=lambda pair: pair[0])
        return "\n".join(line for _, line in self.lines) + "\n"


def build(seed: int = 7) -> str:
    random.seed(seed)
    log = LogWriter()

    # --- background: legitimate activity over several hours ----------------
    when = START
    for _ in range(45):
        when += timedelta(seconds=random.randint(120, 900))
        user = random.choice(REAL_USERS)
        ip = f"192.0.2.{random.randint(10, 60)}"
        if random.random() < 0.15:
            # A real person mistyping their password once or twice.
            log.failed(when, user, ip, invalid=False)
            log.accepted(when + timedelta(seconds=random.randint(4, 20)), user, ip)
        else:
            log.accepted(when, user, ip, method=random.choice(["password", "publickey"]))

    # --- unrelated noise the parser must skip ------------------------------
    when = START + timedelta(minutes=5)
    for _ in range(25):
        when += timedelta(seconds=random.randint(200, 1200))
        log.noise(when, f"CRON[{random.randint(2000, 2999)}]: pam_unix(cron:session): session opened for user root")
        log.noise(when + timedelta(seconds=1), "sudo:  jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/apt update")
        log.noise(when + timedelta(seconds=2), f"sshd[{random.randint(3000, 3999)}]: Received disconnect from 192.0.2.15 port 41122:11: disconnected by user")

    # --- loud brute force: 60 failures in about two minutes ----------------
    when = START + timedelta(hours=1, minutes=12)
    for i in range(60):
        log.failed(when + timedelta(seconds=i * 2), random.choice(COMMON_USERS), "203.0.113.42")

    # --- slow password spray: 16 accounts, 2 tries each, 90s apart ---------
    when = START + timedelta(hours=2, minutes=30)
    for i, user in enumerate(COMMON_USERS):
        log.failed(when + timedelta(seconds=i * 90), user, "198.51.100.23")
        log.failed(when + timedelta(seconds=i * 90 + 45), user, "198.51.100.23")

    # --- compromise chain: failures then a success on a real account -------
    when = START + timedelta(hours=3, minutes=5)
    for i in range(22):
        log.failed(when + timedelta(seconds=i * 5), "backup", "203.0.113.77", invalid=False)
    log.accepted(when + timedelta(seconds=115), "backup", "203.0.113.77")
    log.noise(when + timedelta(seconds=140), "sudo:   backup : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")

    return log.render()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic SSH auth.log")
    parser.add_argument("--out", help="write here instead of stdout")
    parser.add_argument("--seed", type=int, default=7, help="random seed (default: 7)")
    args = parser.parse_args()

    content = build(args.seed)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(content)
        print(f"Wrote {content.count(chr(10))} lines to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
