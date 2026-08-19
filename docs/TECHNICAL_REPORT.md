# Cell Site Simulator Indicators in LTE NAS Signaling

**Technical Analysis Report**

| | |
|---|---|
| Observation window | 30 consecutive days (calendar dates withheld) |
| Detection hardware | Rayhunter (EFF) on Orbic RC400L |
| Analysis tooling | tshark 4.2.2, manual NAS-EPS inspection |
| Collection point | Single fixed monitoring point (location withheld) |
| Author | OtarZap |

> **Reading note.** This report argues that a cell site simulator (CSS)
> operated intermittently within range of a single monitoring point over a
> 30-day window. The argument rests on convergence of several independent
> indicators, not on any one of them. Each indicator has benign explanations
> that compete with it; those are catalogued in
> [INDICATORS.md](INDICATORS.md) and should be read alongside this report.

---

## 1. Summary

Six Rayhunter captures collected at one fixed monitoring point over a single
30-day window contain NAS-EPS signaling consistent with CSS interaction on
four separate days. The dataset spans 30 days and roughly 72 hours of active
capture plus one continuous 16.8-day capture.

Five of six captures contain at least one indicator. One capture (C4, Day 13 morning)
contains an authentication MAC failure immediately followed by a direct IMSI
request — the most technically specific sequence in the dataset, and the one
that is hardest to explain benignly.

The gap structure — tight activity bursts separated by 9- and 16-day silences,
consistently inside a daytime window — fits a mobile unit on a recurring route
better than a fixed installation. That inference holds only because the
captures cover the silent intervals; see §4.

| Metric | Value |
|---|---|
| Captures analyzed | 6 |
| Observation window | 30 consecutive days |
| Captures with indicators | 5 of 6 |
| IMSI requests (Identity Request type 1) | 58 |
| IMEI requests (Identity Request type 2) | 24 |
| Days with activity | 2, 3, 13, 30 |
| Longest silence under active capture | 16.8 days |
| Null cipher (EEA0) observed | Never — EEA2/EIA2 throughout |
| PLMN presented during collection | MCC 310 / MNC 240 (T-Mobile) |

---

## 2. Method

### 2.1 Collection

Rayhunter is an open-source CSS detector from the Electronic Frontier
Foundation, running here on an Orbic RC400L hotspot. It records LTE
control-plane signaling — NAS-EPS and LTE-RRC — between the device and nearby
cells. It does not capture voice, SMS content, or user data; the signaling
layer only.

Rayhunter's own heuristic warnings were used **only to decide which captures to
examine**. They are not treated as evidence anywhere in this report, and
warning counts are not used as a severity measure. Rayhunter has a documented
false-positive rate; every finding below was derived independently from the
NAS layer.

### 2.2 Analysis

All findings come from raw pcapng inspection with tshark 4.2.2 using the
NAS-EPS dissector, then correlation across captures. The exact pipeline is
reproducible and scripted — see [METHODOLOGY.md](METHODOLOGY.md) and
[`tools/`](../tools).

### 2.3 Protocol references

- **3GPP TS 24.301** — NAS-EPS protocol
- **3GPP TS 36.331** — LTE-RRC

EMM message types referenced: `0x41` Attach request, `0x44` Attach reject,
`0x45` Detach request, `0x4B` Tracking area update reject, `0x4E` Service
reject, `0x52` Authentication request, `0x55` Identity request, `0x56` Identity
response, `0x5C` Authentication failure, `0x5D` Security mode command.

---

## 3. Findings

### 3.1 Authentication MAC failure followed by a direct IMSI demand

Capture C4 (Day 13, morning) contains the most specific sequence in the
dataset:

```
Attach Request                    -> PLMN 310/240 (T-Mobile)
Authentication Request            <- network
Authentication Failure  0x5C, EMM cause 20 (MAC failure)
Identity Request        0x55, type 1 (IMSI)
Identity Response       0x56      -> IMSI supplied
Detach Request          0x45 x4, cause 10 (re-attach not required)
Identity Request        0x55, type 1 (IMSI)   [+27 s]
Attach Reject           0x44, cause 15 (no suitable cells in tracking area)
  -> device reselects PLMN 311/480 (Verizon), EEA2 + EIA2 restored
```

LTE authentication is mutual. The AUTN token carries a MAC derived from the
subscriber key `K`, which exists only in the SIM and the operator's HSS. A
device that returns cause 20 has cryptographically rejected the network's
challenge as unauthentic.

The failure alone is not conclusive — misprovisioning can cause it. What makes
this sequence specific is the response: a network that has just failed
authentication cannot resolve a GUTI to a subscriber, so an actor wanting an
identifier must ask for the IMSI outright. That is what follows, within
seconds, twice, before the device is released cleanly onto a real carrier.

Note that EMM cause **21** (synch failure) is the *common benign*
authentication failure, caused by SQN desynchronisation. It is a different
cause code and does not appear here.

### 3.2 IMEI collection paired with IMSI collection

Identity Requests of type 2 (IMEI) appear 24 times across two captures — 20 in
C1 (Days 1–3), 4 in C2 (Days 3–4). Every one was paired
with an IMSI request inside the same short transaction window.

**The pairing is the finding, not the IMEI request itself.** Standalone IMEI
requests are atypical but not aberrant: EIR checks against stolen-device
blocklists are a standard 3GPP procedure, and IMEISV is routinely collected via
the IMEISV-request flag in the Security Mode Command. Claims that networks
"never" request equipment identity are wrong.

What does not follow from ordinary EIR behaviour is the pairing. A network
performing an equipment check already knows the subscriber; it has no reason to
demand the IMSI by direct request in the same transaction. Coordinated
collection of both a permanent subscriber identifier and a permanent hardware
identifier, repeated across separate encounters, is the anomaly.

### 3.3 IMSI collection volume and clustering

Identity Requests of type 1 (IMSI) appear 58 times across five captures.

Volume alone carries little weight — first attach, MME restart, GUTI database
loss, SIM re-insertion, and coverage-edge churn all produce legitimate IMSI
requests. The relevant structure is the clustering: requests arrive in tight
bursts of minutes, then nothing for days, with no corresponding change in the
monitoring device's own state (it was stationary, powered, and not
SIM-cycled throughout).

### 3.4 Rejection-based disengagement

Rejections carrying EMM cause 15 ("no suitable cells in tracking area") appear
10 times across affected captures, consistently terminating an
identity-collection burst and returning the device to a legitimate PLMN.

Taken alone this is close to noise — cause 15 and cause 13 occur routinely at
genuine tracking-area boundaries and under normal roaming restrictions. It is
included because of *where* it occurs: at the end of collection bursts, rather
than distributed through the capture.

### 3.5 No content interception attempted

Every Security Mode Command across all six captures specified **EEA2**
(AES-128 ciphering) and **EIA2** (AES-128 integrity). **EEA0, the null cipher,
was never negotiated.**

This is a meaningful negative result. Intercepting call or SMS content requires
downgrading encryption, which would be plainly visible in the Security Mode
Command. Its complete absence constrains the observed activity to identity
collection and argues *against* content interception.

### 3.6 PLMN presented

Every identity exchange in the dataset occurred while the device was attached
to MCC 310 / MNC 240 (T-Mobile). Three PLMNs were visible during normal
operation: 311/480 (Verizon), 312/250 (Dish Wireless), and 310/240 (T-Mobile).

The device's normal service carrier was Verizon; collection events consistently
occurred under a T-Mobile PLMN identity, and normal service resumed on Verizon
afterwards.

---

## 4. Captures and timeline

Captures are labelled C1-C6 in observation order. Rayhunter names capture files
by Unix epoch, so the original filenames encode the collection date and time to
the second; they are replaced here rather than published. Times are local to the
monitoring point, offset withheld -- only the time-of-day *window* matters to
the analysis in §5.1.

| Capture | Days | Duration | IMSI | IMEI | Note |
|---|---|---:|---:|---:|---|
| `C1` | 1-3 | ~31.9 h | 40 | 20 | Heaviest activity |
| `C2` | 3-4 | ~22.1 h | 8 | 4 | Follow-up pass |
| `C3` | 4-10 | ~6.7 d | 0 | 0 | Clean throughout |
| `C4` | 13 (AM) | 57 min | 4 | 0 | Auth-failure sequence |
| `C5` | 13 (PM) | ~10.8 h | 2 | 0 | Light pass |
| `C6` | 14-30 | ~16.8 d | 4 | 0 | Clean until final day |

| Day | Time (local) | Event |
|---|---|---|
| 2 | 12:06 | First paired IMEI+IMSI collection; heaviest day |
| 2 | 12:56-13:19 | Sustained burst, repeating roughly every 10 min |
| 2 | 15:51-16:37 | Second burst, clean disengagement |
| 3 | 14:49 | Follow-up pass, first cluster |
| 3 | 15:05 | Second cluster, then quiet |
| 4-12 | -- | **9 days silent, under continuous capture** |
| 13 | 10:08 | Auth MAC failure → direct IMSI demand (§3.1) |
| 13 | ~19:00 | Light pass, 2 IMSI, no IMEI |
| 14-29 | -- | **16 days silent, under continuous capture** |
| 30 | 13:15, 13:40 | Two clusters, 25 min apart, then quiet |

The silent intervals fall **inside** active captures rather than between them.
This distinction is what allows silence to be read as absence of activity
rather than absence of recording, and it is the load-bearing assumption behind
§5.1.

This table is reproducible from the tooling:

```bash
./tools/timeline.py events.csv --day-zero
```

---

## 5. Assessment

### 5.1 Mobile rather than fixed

The data fits an intermittent mobile source better than a permanent local
installation:

- Multi-week silences (9 and 16 days) occurred while capture was running
- Activity fell consistently in a daytime window (approx. 10:00–19:00 local)
- Bursts started and stopped abruptly within 10–23 minute windows
- Collection intensity decreased across encounters (40 → 8 → 4 → 2 IMSI),
  consistent with initial acquisition followed by lighter confirmatory passes

A fixed installation within range would be expected to produce activity roughly
proportional to capture uptime. It did not.

### 5.2 Confidence

**Moderate-to-high that these captures contain CSS activity.** The convergence
of the authentication failure sequence, repeated IMEI+IMSI pairing, burst
clustering, and consistent disengagement across four separate days is
difficult to account for with any single benign explanation.

Confidence is held below "high" for reasons worth stating:

- **No baseline.** This is a single-site dataset. Captures from other
  locations with the same hardware and firmware would establish what these
  rates look like normally. That comparison was not performed, and it is the
  most significant gap in the analysis.
- **A nearby private LTE, CBRS, or test deployment** would produce overlapping
  signatures and cannot be excluded from NAS data alone.
- **Carrier-side faults** — an MME migration or provisioning error during the
  observation window — were not ruled out with the carrier.

### 5.3 What was and was not exposed

Exposed to whatever operated the equipment:

- IMSI — permanent subscriber identifier
- IMEI — permanent hardware identifier
- Presence within radio range at specific times
- Serving carrier identity

Not exposed, per §3.5:

- Voice, SMS, or data content — EEA2 maintained throughout, EEA0 never
  negotiated
- Credentials or application data
- Precise location

### 5.4 On attribution

**No attribution is offered, because NAS data does not support one.**

It is sometimes argued that CSS hardware capable of clean disengagement and
coordinated collection is expensive and therefore implies a particular class of
operator. That reasoning is weaker than it looks: it rests on assumptions about
equipment cost and availability that are not observable in the captures, and
the capability gap has narrowed considerably with SDR-based implementations.

The captures show identity collection. They do not show who performed it, why,
or under what authority. Readers should treat any operator attribution — in
this dataset or others — as speculation unless it comes with evidence outside
the signaling layer.

---

## 6. Follow-up

Technical work that would strengthen or falsify the analysis, roughly in order
of value:

1. **Collect baseline captures at other locations** with the same hardware and
   firmware. This is the single highest-value next step and its absence is the
   main limitation of the current dataset.
2. **Analyze the QMDL files** with SCAT or SignalCat to recover physical-layer
   cell parameters — PCI, EARFCN, TAC, and RRC measurement reports — which
   would constrain whether collection events came from a cell distinguishable
   from known local infrastructure.
3. **Query the carrier** about infrastructure changes, MME migrations, or
   provisioning faults during the observation window.
4. **Survey for private LTE and CBRS deployments** in range.

### Reporting status

The findings in this report have **not** been submitted to the EFF at time of
writing. Submission via the [Rayhunter
repository](https://github.com/EFForg/rayhunter) is planned. Earlier drafts of
this document described submission as complete; that was inaccurate and is
corrected here.

---

## 7. Corrections from earlier drafts

Recorded openly, since earlier versions circulated privately:

| Earlier claim | Correction |
|---|---|
| "IMEI requests are absent from normal LTE operation" | Overstated. EIR checks are standard; IMEISV is routinely collected via the Security Mode Command. The IMSI *pairing* is the anomaly, not the IMEI request. |
| `0x4B` labelled "Service Reject" | `0x4B` is Tracking area update reject. Service reject is `0x4E`. |
| Cause 15 as "no suitable cells in location area" | In EPS the field is *tracking* area. |
| Rayhunter warning counts cited as a severity metric | Rayhunter is a heuristic trigger with a known false-positive rate. Warning counts are not used as evidence in this version. |
| Operator attributed to law enforcement on a cost-of-hardware argument | Removed. NAS data does not support attribution. See §5.4. |
| Findings described as submitted to the EFF | Not yet submitted. See §6. |
| Activity described as occurring on "five separate dates" while four were listed | Four separate days. Two captures cover the same day (C4 and C5), which is likely where the miscount came from. |
| Captures identified by their Rayhunter filenames | Those filenames are Unix epochs and decode to the collection date and time to the second. Relabelled C1-C6. |
