#!/usr/bin/env python3
"""
make_fixture.py - generate a SYNTHETIC events CSV for exercising the tooling.

    python data/example/make_fixture.py > data/example/events.csv

THIS IS NOT CAPTURE DATA. It is fabricated input whose *shape* mirrors the
event structure described in docs/TECHNICAL_REPORT.md, so that the analysis
tools can be run and reviewed without access to any real capture. Frame
numbers, sub-second timings, and PLMN interleaving are invented. Do not cite
any number produced from this fixture as a finding.

Timestamps are anchored to SYNTH_DAY1, a deliberately future date, so that no
output of this script can be mistaken for a real observation window. Render it
as relative day numbers with:

    ./tools/timeline.py data/example/events.csv --day-zero

Run the real pipeline against real captures instead:
    ./tools/nas_extract.sh data/captures/*.pcapng > events.csv
"""
import datetime as dt
import sys

# Synthetic anchor for "Day 1, 00:00". Chosen in the future so that fixture
# output is obviously not a real capture window.
SYNTH_DAY1 = dt.datetime(2030, 1, 1, 0, 0, tzinfo=dt.timezone.utc).timestamp()

HEADER = "capture,frame,epoch,emm_type,id_type,emm_cause,mcc,mnc,cipher,integrity"

TMO = ("310", "240")
VZW = ("311", "480")

_frame = [0]


def day(n, h=0, mi=0):
    """Epoch for Day n at h:mi, where Day 1 is the first day of observation."""
    return SYNTH_DAY1 + (n - 1) * 86400 + h * 3600 + mi * 60


def emit(out, cap, t, emm, idt="", cause="", plmn=("", ""), ciph="", integ=""):
    _frame[0] += 1
    out.append("{},{},{:.3f},{},{},{},{},{},{},{}".format(
        cap, _frame[0], t, emm, idt, cause, plmn[0], plmn[1], ciph, integ))


def harvest(out, cap, t, n_imsi, n_imei, spacing=45.0):
    """A CSS-style identity-collection burst: paired IMEI+IMSI, then a
    cause-15 disengagement, then recovery onto a real carrier."""
    for i in range(max(n_imsi, n_imei)):
        tt = t + i * spacing
        if i < n_imei:
            emit(out, cap, tt, "0x55", idt="2")
            emit(out, cap, tt + 1.2, "0x56", plmn=TMO)
        if i < n_imsi:
            emit(out, cap, tt + 2.0, "0x55", idt="1")
            emit(out, cap, tt + 3.1, "0x56", plmn=TMO)
    end = t + max(n_imsi, n_imei) * spacing
    emit(out, cap, end + 5, "0x44", cause="15")
    emit(out, cap, end + 30, "0x5d", plmn=VZW, ciph="2", integ="2")


def normal(out, cap, t, hours, every_min=30):
    """Routine GUTI-based operation on a real carrier."""
    steps = int(hours * 60 / every_min)
    for i in range(steps):
        tt = t + i * every_min * 60
        emit(out, cap, tt, "0x48", plmn=VZW)
        emit(out, cap, tt + 1, "0x5d", plmn=VZW, ciph="2", integ="2")
        emit(out, cap, tt + 2, "0x49")


def main():
    out = []

    # --- C1 : Days 1-3, heaviest activity ----------------------------------
    c = "C1"
    normal(out, c, day(1, 18, 0), hours=18)
    harvest(out, c, day(2, 12, 6), n_imsi=14, n_imei=8)
    harvest(out, c, day(2, 12, 56), n_imsi=14, n_imei=7, spacing=90)
    harvest(out, c, day(2, 15, 51), n_imsi=12, n_imei=5, spacing=120)
    normal(out, c, day(2, 18, 0), hours=12)

    # --- C2 : Days 3-4, follow-up pass -------------------------------------
    c = "C2"
    normal(out, c, day(3, 8, 0), hours=6)
    harvest(out, c, day(3, 14, 49), n_imsi=4, n_imei=2)
    harvest(out, c, day(3, 15, 5), n_imsi=4, n_imei=2)
    normal(out, c, day(3, 17, 0), hours=13)

    # --- C3 : Days 4-10, clean ---------------------------------------------
    normal(out, "C3", day(4, 6, 0), hours=160, every_min=60)

    # --- C4 : Day 13 AM, the auth-failure sequence -------------------------
    c = "C4"
    t = day(13, 10, 8)
    emit(out, c, t, "0x41", plmn=TMO)                 # Attach request
    emit(out, c, t + 2.0, "0x52")                     # Authentication request
    emit(out, c, t + 3.4, "0x5c", cause="20")         # Auth failure, MAC failure
    emit(out, c, t + 4.1, "0x55", idt="1")            # Direct IMSI demand
    emit(out, c, t + 5.3, "0x56", plmn=TMO)           # Identity response
    for i in range(4):                                 # 4x detach, cause 10
        emit(out, c, t + 9 + i, "0x45", cause="10")
    emit(out, c, t + 32.0, "0x55", idt="1")           # Second IMSI request
    emit(out, c, t + 33.2, "0x56", plmn=TMO)
    emit(out, c, t + 41.0, "0x44", cause="15")        # Disengage
    emit(out, c, t + 70.0, "0x5d", plmn=VZW, ciph="2", integ="2")  # Recovery
    emit(out, c, t + 300, "0x55", idt="1")
    emit(out, c, t + 302, "0x56", plmn=TMO)
    emit(out, c, t + 340, "0x4e", cause="15")
    normal(out, c, day(13, 10, 20), hours=0.6, every_min=10)

    # --- C5 : Day 13 PM, light pass ----------------------------------------
    c = "C5"
    normal(out, c, day(13, 11, 0), hours=8)
    harvest(out, c, day(13, 19, 0), n_imsi=2, n_imei=0)
    normal(out, c, day(13, 20, 0), hours=2)

    # --- C6 : Days 14-30, clean until the last day -------------------------
    c = "C6"
    normal(out, c, day(14, 0, 0), hours=395, every_min=120)
    harvest(out, c, day(30, 13, 15), n_imsi=2, n_imei=0)
    harvest(out, c, day(30, 13, 40), n_imsi=2, n_imei=0)
    normal(out, c, day(30, 15, 0), hours=6)

    print(HEADER)
    for line in out:
        print(line)
    print("# synthetic fixture - not capture data", file=sys.stderr)


if __name__ == "__main__":
    main()
