"""
NAS-EPS constant tables from 3GPP TS 24.301.

References:
  EMM message types  — TS 24.301 Table 9.8.1
  EMM cause values   — TS 24.301 Section 9.9.3.9
  Identity types     — TS 24.301 Section 9.9.3.3
  Ciphering / integrity algorithms — TS 24.301 Section 9.9.3.23 / 9.9.3.28
"""

EMM_TYPE = {
    0x41: "Attach request",
    0x42: "Attach accept",
    0x43: "Attach complete",
    0x44: "Attach reject",
    0x45: "Detach request",
    0x46: "Detach accept",
    0x48: "Tracking area update request",
    0x49: "Tracking area update accept",
    0x4A: "Tracking area update complete",
    0x4B: "Tracking area update reject",
    0x4C: "Extended service request",
    0x4D: "Control plane service request",
    0x4E: "Service reject",
    0x50: "GUTI reallocation command",
    0x51: "GUTI reallocation complete",
    0x52: "Authentication request",
    0x53: "Authentication response",
    0x54: "Authentication reject",
    0x55: "Identity request",
    0x56: "Identity response",
    0x5C: "Authentication failure",
    0x5D: "Security mode command",
    0x5E: "Security mode complete",
    0x5F: "Security mode reject",
    0x60: "EMM status",
    0x61: "EMM information",
    0x62: "Downlink NAS transport",
    0x63: "Uplink NAS transport",
}

EMM_CAUSE = {
    2:  "IMSI unknown in HSS",
    3:  "Illegal UE",
    6:  "Illegal ME",
    7:  "EPS services not allowed",
    9:  "UE identity cannot be derived by the network",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this tracking area",
    14: "EPS services not allowed in this PLMN",
    15: "No suitable cells in tracking area",
    18: "CS domain not available",
    19: "ESM failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    24: "Security mode rejected, unspecified",
    26: "Non-EPS authentication unacceptable",
}

ID_TYPE = {1: "IMSI", 2: "IMEI", 3: "IMEISV", 4: "TMSI"}

CIPHER = {0: "EEA0 (null)", 1: "128-EEA1", 2: "128-EEA2 (AES)", 3: "128-EEA3"}
INTEGRITY = {0: "EIA0 (null)", 1: "128-EIA1", 2: "128-EIA2 (AES)", 3: "128-EIA3"}

# Message types used as disengagement / rejection signals
REJECT_TYPES = {0x44, 0x4B, 0x4E, 0x54}

MCC_MNC_CARRIER = {
    ("310", "240"): "T-Mobile",
    ("311", "480"): "Verizon",
    ("312", "250"): "Dish Wireless",
    ("310", "410"): "AT&T",
    ("310", "260"): "T-Mobile",
}
