#!/usr/bin/env python3
"""
css_indicators.py - score NAS-EPS events against known cell-site-simulator
indicators.

Consumes the CSV produced by nas_extract.sh:
    capture,frame,epoch,emm_type,id_type,emm_cause,mcc,mnc,cipher,integrity

Usage:
    ./nas_extract.sh cap.pcapng | ./css_indicators.py
    ./css_indicators.py events.csv --json
    ./css_indicators.py events.csv --pair-window 30

Every indicator below is probabilistic. See docs/INDICATORS.md for the benign
explanations that compete with each one. No single indicator is conclusive;
the argument is built on convergence.
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nas_tables import (  # noqa: E402
    EMM_TYPE, EMM_CAUSE, CIPHER, INTEGRITY, MCC_MNC_CARRIER,
)

ATTACH_REQ, ATTACH_REJ = 0x41, 0x44
TAU_REJ, SERVICE_REJ = 0x4B, 0x4E
DETACH_REQ = 0x45
IDENT_REQ, IDENT_RESP = 0x55, 0x56
AUTH_REQ, AUTH_FAIL = 0x52, 0x5C
SEC_MODE_CMD = 0x5D

CLUSTER_GAP_S = 600.0   # a >10 min gap starts a new identity-collection cluster


def _int(v):
    """Parse a tshark field that may be blank, decimal, or 0x-prefixed."""
    v = (v or "").strip()
    if not v:
        return None
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def load(fh):
    rows = []
    for r in csv.DictReader(fh):
        epoch = (r.get("epoch") or "").strip()
        if not epoch:
            continue
        try:
            epoch = float(epoch)
        except ValueError:
            continue
        rows.append({
            "capture": r.get("capture", ""),
            "frame": _int(r.get("frame")),
            "epoch": epoch,
            "emm_type": _int(r.get("emm_type")),
            "id_type": _int(r.get("id_type")),
            "cause": _int(r.get("emm_cause")),
            "mcc": (r.get("mcc") or "").strip(),
            "mnc": (r.get("mnc") or "").strip(),
            "cipher": _int(r.get("cipher")),
            "integrity": _int(r.get("integrity")),
        })
    rows.sort(key=lambda r: (r["capture"], r["epoch"]))
    return rows


def analyze(rows, pair_window=30.0, seq_window=60.0):
    """Return a per-capture indicator dict."""
    out = {}
    by_cap = defaultdict(list)
    for r in rows:
        by_cap[r["capture"]].append(r)

    for cap, ev in by_cap.items():
        ident_reqs = [r for r in ev if r["emm_type"] == IDENT_REQ]
        imsi_reqs = [r for r in ident_reqs if r["id_type"] == 1]
        imei_reqs = [r for r in ident_reqs if r["id_type"] in (2, 3)]

        # Indicator 1: auth MAC failure followed by a bare IMSI demand.
        # The strongest available signature. A simulator has no HSS key
        # material, so its AUTN fails the SIM's MAC check; it then has to ask
        # for the IMSI directly because it cannot resolve a GUTI.
        auth_fail_chains = []
        for i, r in enumerate(ev):
            if r["emm_type"] != AUTH_FAIL or r["cause"] != 20:
                continue
            for nxt in ev[i + 1:]:
                if nxt["epoch"] - r["epoch"] > seq_window:
                    break
                if nxt["emm_type"] == IDENT_REQ and nxt["id_type"] == 1:
                    auth_fail_chains.append({
                        "auth_fail_frame": r["frame"],
                        "imsi_req_frame": nxt["frame"],
                        "epoch": r["epoch"],
                        "gap_s": round(nxt["epoch"] - r["epoch"], 3),
                    })
                    break

        # Indicator 2: IMEI and IMSI requested inside one transaction window.
        paired = []
        used = set()
        for a in imei_reqs:
            for b in imsi_reqs:
                if b["frame"] in used:
                    continue
                if abs(b["epoch"] - a["epoch"]) <= pair_window:
                    used.add(b["frame"])
                    paired.append({
                        "imei_frame": a["frame"],
                        "imsi_frame": b["frame"],
                        "gap_s": round(abs(b["epoch"] - a["epoch"]), 3),
                    })
                    break

        # Indicator 3: null cipher - the content-interception tell.
        smc = [r for r in ev if r["emm_type"] == SEC_MODE_CMD]
        ciphers = defaultdict(int)
        integrities = defaultdict(int)
        for r in smc:
            if r["cipher"] is not None:
                ciphers[r["cipher"]] += 1
            if r["integrity"] is not None:
                integrities[r["integrity"]] += 1

        # Indicator 4: rejection used to hand the UE back to a real network.
        rejects = defaultdict(int)
        for r in ev:
            if r["emm_type"] in (ATTACH_REJ, TAU_REJ, SERVICE_REJ) and r["cause"] is not None:
                rejects[(r["emm_type"], r["cause"])] += 1
        disengage = sum(n for (t, c), n in rejects.items() if c in (13, 15))

        # Indicator 5: identity collection arriving in bursts.
        clusters, cur = [], []
        for r in sorted(ident_reqs, key=lambda x: x["epoch"]):
            if cur and r["epoch"] - cur[-1]["epoch"] > CLUSTER_GAP_S:
                clusters.append(cur)
                cur = []
            cur.append(r)
        if cur:
            clusters.append(cur)

        plmns = defaultdict(int)
        for r in ev:
            if r["mcc"] and r["mnc"]:
                plmns[(r["mcc"], r["mnc"])] += 1

        span = (ev[-1]["epoch"] - ev[0]["epoch"]) if len(ev) > 1 else 0.0
        out[cap] = {
            "nas_events": len(ev),
            "span_hours": round(span / 3600.0, 2),
            "first_epoch": ev[0]["epoch"],
            "last_epoch": ev[-1]["epoch"],
            "imsi_requests": len(imsi_reqs),
            "imei_requests": len(imei_reqs),
            "identity_clusters": len(clusters),
            "auth_mac_failure_to_imsi": auth_fail_chains,
            "imei_imsi_paired": len(paired),
            "security_mode_commands": len(smc),
            "ciphers": {CIPHER.get(k, str(k)): v for k, v in sorted(ciphers.items())},
            "integrity": {INTEGRITY.get(k, str(k)): v for k, v in sorted(integrities.items())},
            "null_cipher_count": ciphers.get(0, 0),
            "rejects": {
                "{} / cause {} ({})".format(
                    EMM_TYPE.get(t, hex(t)), c, EMM_CAUSE.get(c, "unknown")): n
                for (t, c), n in sorted(rejects.items())
            },
            "disengage_rejects": disengage,
            "plmns": {
                "{}/{} {}".format(mcc, mnc, MCC_MNC_CARRIER.get((mcc, mnc), "(unknown)")): n
                for (mcc, mnc), n in sorted(plmns.items(), key=lambda kv: -kv[1])
            },
        }
    return out


def verdict(a):
    """Coarse triage label. Deliberately conservative."""
    score, notes = 0, []
    if a["auth_mac_failure_to_imsi"]:
        score += 3
        notes.append("auth MAC failure followed by direct IMSI request")
    if a["imei_imsi_paired"] >= 3:
        # One IMEI+IMSI pair can be an EIR check landing near a GUTI-resolution
        # fallback. Repeated pairing is coordinated dual-identifier collection.
        score += 3
        notes.append("{} IMEI+IMSI paired transactions (repeated)".format(
            a["imei_imsi_paired"]))
    elif a["imei_imsi_paired"]:
        score += 2
        notes.append("{} IMEI+IMSI paired transactions".format(a["imei_imsi_paired"]))
    elif a["imei_requests"]:
        score += 1
        notes.append("{} standalone IMEI/IMEISV requests".format(a["imei_requests"]))
    if a["null_cipher_count"]:
        score += 3
        notes.append("null cipher negotiated {}x".format(a["null_cipher_count"]))
    if a["disengage_rejects"] >= 2:
        score += 1
        notes.append("{} cause-13/15 disengagements".format(a["disengage_rejects"]))
    if a["imsi_requests"] >= 4 and a["identity_clusters"] >= 2:
        score += 1
        notes.append("clustered IMSI collection")

    if score == 0:
        label = "no indicators"
    elif score <= 1:
        label = "weak"
    elif score <= 3:
        label = "moderate"
    else:
        label = "strong"
    return label, score, notes


def main():
    p = argparse.ArgumentParser(
        description="Score NAS-EPS events against CSS indicators.")
    p.add_argument("csv", nargs="?", help="events CSV (default: stdin)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--pair-window", type=float, default=30.0,
                   help="seconds within which IMEI+IMSI count as one transaction")
    p.add_argument("--seq-window", type=float, default=60.0,
                   help="seconds to look ahead from an auth failure for an IMSI request")
    args = p.parse_args()

    fh = open(args.csv, newline="", encoding="utf-8") if args.csv else sys.stdin
    try:
        rows = load(fh)
    finally:
        if args.csv:
            fh.close()

    if not rows:
        print("No NAS-EPS events found.", file=sys.stderr)
        return 1

    res = analyze(rows, args.pair_window, args.seq_window)

    if args.json:
        for a in res.values():
            a["verdict"], a["score"], a["verdict_notes"] = verdict(a)
        json.dump(res, sys.stdout, indent=2)
        print()
        return 0

    for cap, a in sorted(res.items()):
        label, score, notes = verdict(a)
        print("=" * 68)
        print("CAPTURE: {}".format(cap))
        print("=" * 68)
        print("  NAS-EPS events        {}   span {} h".format(a["nas_events"], a["span_hours"]))
        print("  IMSI requests         {}".format(a["imsi_requests"]))
        print("  IMEI/IMEISV requests  {}".format(a["imei_requests"]))
        print("  Identity clusters     {}".format(a["identity_clusters"]))
        print("  Security Mode Cmds    {}".format(a["security_mode_commands"]))
        if a["ciphers"]:
            print("  Ciphering             {}".format(a["ciphers"]))
        if a["integrity"]:
            print("  Integrity             {}".format(a["integrity"]))
        if a["plmns"]:
            print("  PLMNs seen:")
            for k, v in a["plmns"].items():
                print("      {}: {}".format(k, v))
        if a["rejects"]:
            print("  Rejections:")
            for k, v in a["rejects"].items():
                print("      {}: {}".format(k, v))
        if a["auth_mac_failure_to_imsi"]:
            print("  ** MAC-failure -> IMSI-request chains:")
            for c in a["auth_mac_failure_to_imsi"]:
                print("      frame {} -> {} (+{}s)".format(
                    c["auth_fail_frame"], c["imsi_req_frame"], c["gap_s"]))
        print()
        print("  INDICATOR STRENGTH: {} (score {})".format(label, score))
        for n in notes:
            print("      - {}".format(n))
        print("  Not conclusive on its own - see docs/INDICATORS.md.")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
