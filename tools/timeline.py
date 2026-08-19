#!/usr/bin/env python3
"""
timeline.py - correlate identity-collection activity across multiple captures
into a single chronological timeline, and characterise the gaps between
active windows.

The gap structure is what separates a mobile unit from a fixed installation:
a permanent local site produces activity proportional to capture uptime, while
a patrol route produces tight bursts separated by multi-day silence.

Usage:
    ./nas_extract.sh data/captures/*.pcapng > events.csv
    ./timeline.py events.csv
    ./timeline.py events.csv --tz -04:00 --json
    ./timeline.py events.csv --day-zero          # relative days, no calendar dates

--day-zero renders every time as "Day N HH:MM" relative to the first observed
event, and is what the published report uses. Absolute dates narrow a fixed
monitoring point considerably when combined with anything else published under
the same identity; the gap structure that carries the analysis does not depend
on them.
"""
import argparse
import csv
import datetime as dt
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from css_indicators import load  # noqa: E402

IDENT_REQ = 0x55
AUTH_FAIL = 0x5C
ATTACH_REJ, TAU_REJ, SERVICE_REJ = 0x44, 0x4B, 0x4E

CLUSTER_GAP_S = 600.0   # >10 min of quiet ends an activity cluster


def parse_tz(s):
    if not s:
        return dt.timezone.utc
    sign = 1 if s[0] == "+" else -1
    hh, _, mm = s[1:].partition(":")
    return dt.timezone(sign * dt.timedelta(hours=int(hh), minutes=int(mm or 0)))


class Clock:
    """Renders timestamps either as calendar dates or as relative day numbers.

    day_zero is the local-midnight boundary of the first observed event, so
    that Day 1 covers the whole first calendar day of observation rather than
    starting mid-afternoon.
    """

    def __init__(self, tz, relative=False, first_epoch=None):
        self.tz = tz
        self.relative = relative
        self.origin = None
        if relative and first_epoch is not None:
            first = dt.datetime.fromtimestamp(first_epoch, tz)
            self.origin = first.replace(hour=0, minute=0, second=0, microsecond=0)

    def label(self):
        if self.relative:
            return "relative days"
        return "UTC" if self.tz == dt.timezone.utc else "UTC{}".format(
            self.tz.utcoffset(None))

    def _dayno(self, when):
        return (when.date() - self.origin.date()).days + 1

    def long(self, when):
        """Wide form, used in the coverage table."""
        if self.relative:
            return "Day {:<2} {}".format(self._dayno(when), when.strftime("%H:%M"))
        return when.strftime("%Y-%m-%d %H:%M")

    def short(self, when):
        """Narrow form, used in gap lines."""
        if self.relative:
            return "D{} {}".format(self._dayno(when), when.strftime("%H:%M"))
        return when.strftime("%m-%d %H:%M")


def build_clusters(rows, tz):
    """Group identity-collection events into activity clusters."""
    events = [r for r in rows if r["emm_type"] == IDENT_REQ and r["id_type"] in (1, 2, 3)]
    events.sort(key=lambda r: r["epoch"])

    clusters, cur = [], []
    for r in events:
        if cur and r["epoch"] - cur[-1]["epoch"] > CLUSTER_GAP_S:
            clusters.append(cur)
            cur = []
        cur.append(r)
    if cur:
        clusters.append(cur)

    out = []
    for c in clusters:
        start = dt.datetime.fromtimestamp(c[0]["epoch"], tz)
        end = dt.datetime.fromtimestamp(c[-1]["epoch"], tz)
        out.append({
            "capture": c[0]["capture"],
            "start": start,
            "end": end,
            "duration_min": round((c[-1]["epoch"] - c[0]["epoch"]) / 60.0, 1),
            "imsi": sum(1 for r in c if r["id_type"] == 1),
            "imei": sum(1 for r in c if r["id_type"] in (2, 3)),
            "total": len(c),
            "start_epoch": c[0]["epoch"],
            "end_epoch": c[-1]["epoch"],
        })
    return out


def coverage(rows, tz):
    """Per-capture observation windows, so silence can be distinguished from
    'we were not recording'."""
    by_cap = defaultdict(list)
    for r in rows:
        by_cap[r["capture"]].append(r["epoch"])
    out = []
    for cap, ts in by_cap.items():
        out.append({
            "capture": cap,
            "start": dt.datetime.fromtimestamp(min(ts), tz),
            "end": dt.datetime.fromtimestamp(max(ts), tz),
            "hours": round((max(ts) - min(ts)) / 3600.0, 1),
            "events": len(ts),
        })
    out.sort(key=lambda c: c["start"])
    return out


def main():
    p = argparse.ArgumentParser(
        description="Correlate identity-collection activity across captures.")
    p.add_argument("csv", nargs="?", help="events CSV (default: stdin)")
    p.add_argument("--tz", default="", help="display offset, e.g. -04:00 (default UTC)")
    p.add_argument("--day-zero", action="store_true",
                   help="render relative day numbers instead of calendar dates")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    tz = parse_tz(args.tz)
    fh = open(args.csv, newline="", encoding="utf-8") if args.csv else sys.stdin
    try:
        rows = load(fh)
    finally:
        if args.csv:
            fh.close()

    if not rows:
        print("No NAS-EPS events found.", file=sys.stderr)
        return 1

    cov = coverage(rows, tz)
    clusters = build_clusters(rows, tz)
    clock = Clock(tz, relative=args.day_zero,
                  first_epoch=min(r["epoch"] for r in rows))

    if args.json:
        def stamp(c):
            if args.day_zero:
                return dict(c, start=clock.long(c["start"]), end=clock.long(c["end"]))
            return dict(c, start=c["start"].isoformat(), end=c["end"].isoformat())

        payload = {
            "basis": clock.label(),
            "coverage": [stamp(c) for c in cov],
            "clusters": [stamp(c) for c in clusters],
        }
        if args.day_zero:
            # Absolute epochs would defeat the point of --day-zero.
            for group in ("coverage", "clusters"):
                for c in payload[group]:
                    c.pop("start_epoch", None)
                    c.pop("end_epoch", None)
        json.dump(payload, sys.stdout, indent=2)
        print()
        return 0

    label = clock.label()
    print("CAPTURE COVERAGE ({})".format(label))
    print("-" * 72)
    for c in cov:
        print("  {:<16} {} -> {}  ({} h, {} NAS events)".format(
            c["capture"], clock.long(c["start"]),
            clock.long(c["end"]), c["hours"], c["events"]))

    total_h = sum(c["hours"] for c in cov)
    print("\n  Total observation: {} h across {} captures".format(
        round(total_h, 1), len(cov)))

    if not clusters:
        print("\nNo identity-collection activity in any capture.")
        return 0

    print("\n\nACTIVITY CLUSTERS ({})".format(label))
    print("-" * 72)
    print("  {:<18} {:>6}  {:>5} {:>5}  {}".format(
        "START", "DUR/m", "IMSI", "IMEI", "CAPTURE"))
    for c in clusters:
        print("  {:<18} {:>6} {:>6} {:>5}  {}".format(
            clock.long(c["start"]), c["duration_min"],
            c["imsi"], c["imei"], c["capture"]))

    print("\n\nGAP ANALYSIS")
    print("-" * 72)
    if len(clusters) < 2:
        print("  Only one activity cluster - no gap structure to assess.")
    else:
        gaps = []
        for a, b in zip(clusters, clusters[1:]):
            gaps.append((b["start_epoch"] - a["end_epoch"]) / 86400.0)
        for (a, b), g in zip(zip(clusters, clusters[1:]), gaps):
            print("  {} -> {}   {:.1f} days quiet".format(
                clock.short(a["end"]), clock.short(b["start"]), g))
        print("\n  Longest quiet gap: {:.1f} days".format(max(gaps)))
        print("  Median cluster length: {:.1f} min".format(
            sorted(c["duration_min"] for c in clusters)[len(clusters) // 2]))

    hours = [c["start"].hour for c in clusters]
    print("\n  Cluster start hours ({}): {}".format(label, sorted(hours)))
    print("  Window: {:02d}:00 - {:02d}:00".format(min(hours), max(hours) + 1))

    print("\n  Interpretation: tight clusters separated by multi-day silence,")
    print("  inside a consistent time-of-day window, fit a mobile unit on a")
    print("  route. A fixed local installation would instead produce activity")
    print("  roughly proportional to capture uptime. Note this reasoning is")
    print("  only valid where coverage above shows you were actually recording")
    print("  during the quiet gaps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
