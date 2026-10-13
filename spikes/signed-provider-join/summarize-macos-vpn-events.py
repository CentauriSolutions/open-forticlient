#!/usr/bin/env python3
"""Print only fixed, nonsecret NetworkExtension fields from a past time window.

This streams `log show` in memory. It never writes or prints raw log messages.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter
from datetime import datetime


PROCESSES = {"IntegrationHost", "IntegrationProvider", "nesessionmanager"}
STATUSES = {"invalid", "disconnected", "connecting", "connected", "reasserting", "disconnecting"}
PREDICATE = ' OR '.join(f'process == "{name}"' for name in sorted(PROCESSES))


def error_class(value: str) -> str:
    if value.lower() in {"(null)", "null", "none", ""}:
        return "none"
    match = re.search(r"\b(OFTCProvider|NEVPNConnectionErrorDomain)\b.*?\b(?:error|Code=)\s*(-?\d+)", value)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    return "other"


def safe_event(record: dict) -> str | None:
    template = record.get("formatString") or ""
    message = record.get("eventMessage") or ""
    if "Last disconnect error for" in template:
        match = re.search(r'changed from "([^"]*)" to "([^"]*)"', message)
        return (f"last_error {error_class(match.group(1))}->{error_class(match.group(2))}"
                if match else "last_error unparsed")
    if "status changed to %s, last stop reason %s" in template:
        match = re.search(r"status changed to ([A-Za-z]+), last stop reason ([A-Za-z0-9_ -]+)$", message)
        if match:
            status = match.group(1).lower()
            reason = match.group(2).strip().lower().replace(" ", "_")
            if status in STATUSES and re.fullmatch(r"[a-z0-9_-]{1,50}", reason):
                return f"status={status} stop_reason={reason}"
        return "status_and_stop_reason unparsed"
    if "status changed to %s" in template:
        match = re.search(r"status changed to ([A-Za-z]+)", message)
        if match and match.group(1).lower() in STATUSES:
            return f"status={match.group(1).lower()}"
    if "didSetStatus - %d" in template:
        match = re.search(r"didSetStatus - (\d+)", message)
        if match:
            return f"did_set_status={match.group(1)}"
    if "plugin %@ disconnected with reason %s" in template:
        match = re.search(r"disconnected with reason ([A-Za-z0-9_ -]+)$", message)
        if match:
            reason = match.group(1).strip().lower().replace(" ", "_")
            if re.fullmatch(r"[a-z0-9_-]{1,50}", reason):
                return f"plugin_disconnect_reason={reason}"
        return "plugin_disconnect_reason unparsed"
    if "Extension exit timer expired for" in template:
        return "extension_exit_timer_expired"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", required=True, help="Local time: YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end", required=True, help="Local time: YYYY-MM-DD HH:MM:SS")
    args = parser.parse_args()
    start = datetime.strptime(args.start, "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(args.end, "%Y-%m-%d %H:%M:%S")
    if not start < end:
        parser.error("end must follow start")
    command = ["/usr/bin/log", "show", "--style", "ndjson", "--start", args.start,
               "--end", args.end, "--predicate", PREDICATE]
    counts: Counter[str] = Counter()
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True) as process:
        assert process.stdout is not None
        for line in process.stdout:
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = os.path.basename(record.get("processImagePath") or "")
            if name not in PROCESSES:
                continue
            event = safe_event(record)
            if not event:
                continue
            timestamp = (record.get("timestamp") or "")[:19]
            if not re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", timestamp):
                timestamp = "time_unavailable"
            print(timestamp, name, event)
            counts[event.split()[0]] += 1
        if process.wait() != 0:
            raise SystemExit("Could not read unified logs")
    print("event_counts", dict(counts))


if __name__ == "__main__":
    main()
