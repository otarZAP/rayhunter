#!/usr/bin/env python3
"""
test_indicators.py - self-test for css_indicators.py.

Builds synthetic NAS-EPS event streams (no capture files required) and asserts
the indicator logic fires where it should and stays quiet where it should not.

    python tools/test_indicators.py
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from css_indicators import load, analyze, verdict  # noqa: E402

HEADER = "capture,frame,epoch,emm_type,id_type,emm_cause,mcc,mnc,cipher,integrity"
T0 = 1893456000.0  # synthetic anchor, deliberately not a real capture epoch


def row(cap, frame, t, emm, idt="", cause="", mcc="", mnc="", ciph="", integ=""):
    return "{},{},{:.3f},{},{},{},{},{},{},{}".format(
        cap, frame, t, emm, idt, cause, mcc, mnc, ciph, integ)


def run(rows):
    csv_text = "\n".join([HEADER] + rows) + "\n"
    return analyze(load(io.StringIO(csv_text)))


def check(name, cond):
    print("  {}  {}".format("PASS" if cond else "FAIL", name))
    return bool(cond)


def test_auth_failure_chain():
    """The C4 sequence from the report: MAC failure -> direct IMSI demand."""
    r = [
        row("auth_fail", 1, T0 + 0,   "0x41", mcc="310", mnc="240"),   # Attach req
        row("auth_fail", 2, T0 + 2,   "0x52"),                          # Auth req
        row("auth_fail", 3, T0 + 3,   "0x5c", cause="20"),              # Auth fail, MAC
        row("auth_fail", 4, T0 + 4,   "0x55", idt="1"),                 # Identity req IMSI
        row("auth_fail", 5, T0 + 5,   "0x56", mcc="310", mnc="240"),    # Identity resp
        row("auth_fail", 6, T0 + 10,  "0x45", cause="10"),              # Detach x4
        row("auth_fail", 7, T0 + 11,  "0x45", cause="10"),
        row("auth_fail", 8, T0 + 12,  "0x45", cause="10"),
        row("auth_fail", 9, T0 + 13,  "0x45", cause="10"),
        row("auth_fail", 10, T0 + 32, "0x55", idt="1"),                 # 2nd IMSI req
        row("auth_fail", 11, T0 + 40, "0x44", cause="15"),              # Attach rej c15
        row("auth_fail", 12, T0 + 60, "0x5d", mcc="311", mnc="480",
            ciph="2", integ="2"),                                        # recover, EEA2
    ]
    a = run(r)["auth_fail"]
    label, score, _ = verdict(a)
    ok = True
    ok &= check("MAC-failure chain detected", len(a["auth_mac_failure_to_imsi"]) == 1)
    ok &= check("chain gap is 1.0s", a["auth_mac_failure_to_imsi"][0]["gap_s"] == 1.0)
    ok &= check("2 IMSI requests counted", a["imsi_requests"] == 2)
    ok &= check("no IMEI requests", a["imei_requests"] == 0)
    ok &= check("cause-15 reject recorded", a["disengage_rejects"] == 1)
    ok &= check("no null cipher", a["null_cipher_count"] == 0)
    ok &= check("EEA2 seen", "128-EEA2 (AES)" in a["ciphers"])
    ok &= check("both PLMNs resolved",
                any("T-Mobile" in k for k in a["plmns"]) and
                any("Verizon" in k for k in a["plmns"]))
    ok &= check("verdict is moderate ({}, score {})".format(label, score),
                label == "moderate")
    return ok


def test_imei_imsi_pairing():
    """IMEI and IMSI pulled inside one transaction window."""
    r = []
    f, t = 1, T0
    for i in range(4):
        r.append(row("harvest", f, t, "0x55", idt="2")); f += 1
        r.append(row("harvest", f, t + 1.5, "0x55", idt="1")); f += 1
        t += 700  # >CLUSTER_GAP_S apart, so each is its own cluster
    a = run(r)["harvest"]
    label, score, _ = verdict(a)
    ok = True
    ok &= check("4 IMEI requests", a["imei_requests"] == 4)
    ok &= check("4 IMSI requests", a["imsi_requests"] == 4)
    ok &= check("4 pairs, each IMSI used once", a["imei_imsi_paired"] == 4)
    ok &= check("4 separate clusters", a["identity_clusters"] == 4)
    ok &= check("verdict is strong ({}, score {})".format(label, score),
                label == "strong")
    return ok


def test_null_cipher_flags_hard():
    """EEA0 means a content-interception attempt, and must score heavily."""
    r = [
        row("nullciph", 1, T0, "0x5d", ciph="0", integ="0"),
        row("nullciph", 2, T0 + 1, "0x55", idt="1"),
    ]
    a = run(r)["nullciph"]
    label, score, notes = verdict(a)
    ok = True
    ok &= check("null cipher counted", a["null_cipher_count"] == 1)
    ok &= check("EEA0 labelled", "EEA0 (null)" in a["ciphers"])
    ok &= check("scores >= 3", score >= 3)
    ok &= check("noted in verdict", any("null cipher" in n for n in notes))
    return ok


def test_clean_capture_stays_quiet():
    """Normal LTE: GUTI-based, EEA2, no identity harvesting. Must not fire."""
    r = []
    f, t = 1, T0
    for i in range(40):
        r.append(row("clean", f, t, "0x48", mcc="311", mnc="480")); f += 1   # TAU req
        r.append(row("clean", f, t + 1, "0x5d", ciph="2", integ="2")); f += 1
        r.append(row("clean", f, t + 2, "0x49")); f += 1                      # TAU accept
        t += 1800
    a = run(r)["clean"]
    label, score, _ = verdict(a)
    ok = True
    ok &= check("no identity requests", a["imsi_requests"] == 0 and a["imei_requests"] == 0)
    ok &= check("no null cipher", a["null_cipher_count"] == 0)
    ok &= check("no disengagements", a["disengage_rejects"] == 0)
    ok &= check("verdict is 'no indicators' ({}, score {})".format(label, score),
                label == "no indicators" and score == 0)
    return ok


def test_sync_failure_is_not_mac_failure():
    """EMM cause 21 (SQN desync) is benign and must NOT trigger the chain."""
    r = [
        row("sqn", 1, T0, "0x52"),
        row("sqn", 2, T0 + 1, "0x5c", cause="21"),   # Synch failure, not MAC
        row("sqn", 3, T0 + 2, "0x55", idt="1"),
    ]
    a = run(r)["sqn"]
    return check("cause 21 does not fire the MAC chain",
                 len(a["auth_mac_failure_to_imsi"]) == 0)


def test_window_bounds():
    """An IMSI request far past the window must not be chained to the failure."""
    r = [
        row("far", 1, T0, "0x5c", cause="20"),
        row("far", 2, T0 + 300, "0x55", idt="1"),   # 5 min later, > seq_window
    ]
    a = run(r)["far"]
    return check("IMSI request beyond seq-window is not chained",
                 len(a["auth_mac_failure_to_imsi"]) == 0)


def test_decimal_field_format():
    """tshark builds may emit decimal rather than 0x-prefixed values."""
    r = [
        row("dec", 1, T0, "92", cause="20"),    # 0x5c
        row("dec", 2, T0 + 1, "85", idt="1"),   # 0x55
    ]
    a = run(r)["dec"]
    return check("decimal emm_type values parse identically",
                 len(a["auth_mac_failure_to_imsi"]) == 1)


TESTS = [
    ("auth MAC failure -> IMSI demand", test_auth_failure_chain),
    ("IMEI+IMSI transaction pairing", test_imei_imsi_pairing),
    ("null cipher scores hard", test_null_cipher_flags_hard),
    ("clean capture stays quiet", test_clean_capture_stays_quiet),
    ("synch failure is not MAC failure", test_sync_failure_is_not_mac_failure),
    ("sequence window bounds", test_window_bounds),
    ("decimal field format", test_decimal_field_format),
]

if __name__ == "__main__":
    failed = 0
    for name, fn in TESTS:
        print("\n{}".format(name))
        if not fn():
            failed += 1
    print("\n" + "=" * 50)
    print("{} / {} test groups passed".format(len(TESTS) - failed, len(TESTS)))
    sys.exit(1 if failed else 0)
