"""Render findings as terminal output, CSV, or a self-contained HTML report."""

from __future__ import annotations

import csv
import html
import os
from datetime import datetime
from typing import List

from .detections import Finding

COLUMNS = [
    "severity", "title", "technique", "source_ip", "first_seen",
    "last_seen", "attempts", "distinct_users", "sample_users", "detail",
]

RECOMMENDATIONS = {
    "Successful login after repeated failures": [
        "Disable or reset the affected account immediately.",
        "Check for attacker persistence: new keys in ~/.ssh/authorized_keys, new cron jobs, new users.",
        "Review command history and any outbound connections made by the session.",
    ],
    "Brute-force authentication attempts": [
        "Block the source address at the firewall or with fail2ban.",
        "Confirm no login from this address succeeded.",
        "Consider disabling password authentication in favour of keys.",
    ],
    "Password spraying": [
        "Check whether the tried usernames correspond to real accounts.",
        "Block the source address and look for the same pattern from related addresses.",
        "Verify account lockout policy is actually enforced.",
    ],
}


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def render_console(findings: List[Finding], stats) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("SSH AUTHENTICATION TRIAGE REPORT")
    lines.append("=" * 72)
    lines.append(
        f"Lines read: {stats.lines_read:,}   "
        f"Auth events parsed: {stats.events_parsed:,}   "
        f"Ignored: {stats.lines_ignored:,}"
    )
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items())) or "none"
    lines.append(f"Findings: {len(findings)} ({summary})")
    lines.append("")

    if not findings:
        lines.append("No credential-attack patterns matched the configured thresholds.")
        return "\n".join(lines)

    for i, finding in enumerate(findings, start=1):
        lines.append(f"[{i}] {finding.severity.upper():6} {finding.title}  ({finding.technique})")
        lines.append(f"    Source IP      : {finding.source_ip}")
        lines.append(f"    Window         : {finding.first_seen} -> {finding.last_seen}")
        lines.append(f"    Failed attempts: {finding.attempts}   Distinct accounts: {finding.distinct_users}")
        if finding.sample_users:
            lines.append(f"    Accounts        : {', '.join(finding.sample_users)}")
        lines.append(f"    Detail         : {finding.detail}")
        for action in RECOMMENDATIONS.get(finding.title, []):
            lines.append(f"      - {action}")
        lines.append("")

    return "\n".join(lines)


def write_csv(findings: List[Finding], path: str) -> None:
    _ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.as_row())


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH authentication triage report</title>
<style>
 body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0;
        background: #f4f6f8; color: #16202b; line-height: 1.55; }}
 .wrap {{ max-width: 60rem; margin: 0 auto; padding: 2rem 1rem 4rem; }}
 h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
 .meta {{ color: #5a6675; font-size: .9rem; margin-bottom: 1.5rem; }}
 .finding {{ background: #fff; border: 1px solid #dde3e9; border-left: 5px solid #8a97a4;
            border-radius: 5px; padding: 1rem 1.2rem; margin-bottom: 1rem; }}
 .high {{ border-left-color: #b03a2e; }}
 .medium {{ border-left-color: #c58a1a; }}
 .low {{ border-left-color: #2f5d7c; }}
 .badge {{ display: inline-block; font-size: .72rem; font-weight: 700; letter-spacing: .04em;
          padding: .15rem .5rem; border-radius: 3px; color: #fff; background: #8a97a4;
          vertical-align: middle; margin-right: .5rem; }}
 .badge.high {{ background: #b03a2e; }}
 .badge.medium {{ background: #c58a1a; }}
 .badge.low {{ background: #2f5d7c; }}
 h2 {{ font-size: 1.02rem; margin: 0 0 .6rem; display: inline; }}
 table {{ border-collapse: collapse; font-size: .88rem; margin: .7rem 0; width: 100%; }}
 td {{ padding: .25rem .5rem .25rem 0; vertical-align: top; }}
 td.k {{ color: #5a6675; white-space: nowrap; width: 11rem; }}
 code {{ font-family: ui-monospace, Menlo, monospace; background: #eef2f5; padding: .1em .3em;
        border-radius: 3px; }}
 ul {{ margin: .4rem 0 0; padding-left: 1.2rem; font-size: .9rem; }}
 .none {{ background: #fff; border: 1px solid #dde3e9; padding: 1.2rem; border-radius: 5px; }}
 .scroll {{ overflow-x: auto; }}
</style></head><body><div class="wrap">
<h1>SSH authentication triage report</h1>
<div class="meta">{meta}</div>
{body}
</div></body></html>
"""


def write_html(findings: List[Finding], stats, path: str, source: str = "") -> None:
    _ensure_parent(path)
    meta = (
        f"Source: <code>{html.escape(source)}</code> &nbsp;|&nbsp; "
        f"Generated {datetime.now():%Y-%m-%d %H:%M} &nbsp;|&nbsp; "
        f"{stats.lines_read:,} lines read, {stats.events_parsed:,} auth events, "
        f"{len(findings)} findings"
    )

    if not findings:
        body = '<div class="none">No credential-attack patterns matched the configured thresholds.</div>'
    else:
        blocks = []
        for finding in findings:
            actions = "".join(
                f"<li>{html.escape(a)}</li>" for a in RECOMMENDATIONS.get(finding.title, [])
            )
            blocks.append(
                f'<div class="finding {finding.severity}">'
                f'<span class="badge {finding.severity}">{finding.severity.upper()}</span>'
                f"<h2>{html.escape(finding.title)}</h2>"
                f'<div class="scroll"><table>'
                f'<tr><td class="k">MITRE ATT&amp;CK</td><td>{finding.technique}</td></tr>'
                f'<tr><td class="k">Source IP</td><td><code>{html.escape(finding.source_ip)}</code></td></tr>'
                f'<tr><td class="k">First seen</td><td>{finding.first_seen}</td></tr>'
                f'<tr><td class="k">Last seen</td><td>{finding.last_seen}</td></tr>'
                f'<tr><td class="k">Failed attempts</td><td>{finding.attempts}</td></tr>'
                f'<tr><td class="k">Distinct accounts</td><td>{finding.distinct_users}</td></tr>'
                f'<tr><td class="k">Accounts targeted</td>'
                f"<td>{html.escape(', '.join(finding.sample_users)) or '-'}</td></tr>"
                f'<tr><td class="k">Detail</td><td>{html.escape(finding.detail)}</td></tr>'
                f"</table></div>"
                f"<ul>{actions}</ul>"
                f"</div>"
            )
        body = "\n".join(blocks)

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_HTML_TEMPLATE.format(meta=meta, body=body))
