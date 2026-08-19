# Methodology

How to reproduce this analysis against your own Rayhunter captures.

## Requirements

- **tshark** 4.x with the NAS-EPS dissector (ships with Wireshark)
- **Python** 3.8+ — standard library only, no dependencies
- Rayhunter `.pcapng` captures

Verify the dissector fields your Wireshark build exposes before doing anything
else, since field names occasionally shift between major versions:

```bash
./tools/nas_extract.sh --check-fields
```

On Windows, point the script at the Wireshark install:

```bash
TSHARK="/c/Program Files/Wireshark/tshark.exe" ./tools/nas_extract.sh --check-fields
```

---

## Pipeline

### 1. Retrieve captures

Pull the `.pcapng` files off the Rayhunter device. Put them in
`data/captures/` — that path is gitignored, and it must stay that way. **Raw
captures contain your own IMSI and IMEI in cleartext** inside Identity Response
frames. Do not commit them, and do not attach them to a public issue without
scrubbing.

### 2. Extract NAS-EPS events

```bash
./tools/nas_extract.sh data/captures/*.pcapng > events.csv
```

This runs tshark with `-Y nas_eps` and emits one normalized CSV row per NAS
frame:

```
capture,frame,epoch,emm_type,id_type,emm_cause,mcc,mnc,cipher,integrity
```

Rayhunter writes GSMTAP-encapsulated traffic, which tshark dissects
automatically on UDP/4729 — no `decode-as` needed.

The CSV carries no IMSI or IMEI *values*, only the fact that a request or
response of a given type occurred. That is deliberate: it makes the derived
data safe to publish while remaining sufficient for every indicator here.

### 3. Score indicators

```bash
./tools/css_indicators.py events.csv
./tools/css_indicators.py events.csv --json     # machine-readable
```

Per capture, this reports identity-request counts, IMEI/IMSI transaction
pairing, ciphering and integrity algorithms negotiated, rejection causes,
PLMNs seen, and any authentication-MAC-failure-to-IMSI-request chains.

Tunable windows:

| Flag | Default | Meaning |
|---|---:|---|
| `--pair-window` | 30 s | Window within which an IMEI and IMSI request count as one transaction |
| `--seq-window` | 60 s | How far past an authentication failure to look for a direct IMSI request |

The `INDICATOR STRENGTH` label is coarse triage for deciding which captures
deserve manual inspection. **It is not a finding.** Every hit needs the
competing benign explanations in [INDICATORS.md](INDICATORS.md) worked through
by hand.

### 4. Correlate across captures

```bash
./tools/timeline.py events.csv --tz -04:00     # calendar dates
./tools/timeline.py events.csv --day-zero      # relative days
```

`--day-zero` numbers days from the first observed event and prints no calendar
dates. The published report uses this form: a timestamped 30-day presence
record for a fixed monitoring point is location-correlating on its own, and the
gap structure that carries the analysis does not depend on the calendar.

Groups identity-collection events into activity clusters (a gap over 10 minutes
starts a new cluster), then reports capture coverage, cluster times, gaps
between clusters, and the time-of-day distribution.

Coverage is printed first and deliberately so. **Silence only means "no
activity" where the coverage table shows you were actually recording.** A gap
between captures proves nothing; a gap inside one is evidence.

### 5. Inspect the interesting frames by hand

Automated scoring narrows the search. It does not replace reading the
signaling. For any capture that scored, go back to the packets:

```bash
# The full NAS exchange around an authentication failure
tshark -r data/captures/CAPTURE.pcapng -Y nas_eps -V | less

# Identity requests only, with type
tshark -r data/captures/CAPTURE.pcapng \
  -Y 'nas_eps.nas_msg_emm_type == 0x55' \
  -T fields -e frame.number -e frame.time -e nas_eps.emm.id_type2

# Everything in a window around a frame of interest
tshark -r data/captures/CAPTURE.pcapng \
  -Y 'frame.number >= 400 && frame.number <= 520' -V
```

---

## Verifying the tooling

The indicator logic has a self-test that needs no capture files:

```bash
python tools/test_indicators.py
```

It asserts that the MAC-failure chain fires on cause 20 and **not** on cause 21
(synch failure, the benign SQN-desync case), that the sequence window bounds
hold, that a clean GUTI-based capture produces no indicators, that null-cipher
negotiation scores heavily, and that both hex and decimal tshark field formats
parse identically.

A synthetic fixture is also included so the full pipeline can be run without
any capture data:

```bash
python data/example/make_fixture.py > data/example/events.csv
./tools/css_indicators.py data/example/events.csv
./tools/timeline.py data/example/events.csv --day-zero
```

**The fixture is fabricated input, not capture data.** Its event *shape*
mirrors the structure described in the report so the tools can be exercised and
reviewed; frame numbers and sub-second timings are invented. Nothing produced
from it should be cited as a finding.

---

## Handling captures safely

- **Never commit `.pcapng`, `.pcap`, or `.qmdl` files.** They contain your IMSI
  and IMEI in cleartext. The `.gitignore` blocks them; do not override it.
- Derived CSV from step 2 contains no identifier *values* and is safe to share.
- Before sending captures to anyone — including a research submission —
  understand that you are sending your permanent subscriber and device
  identifiers, plus a timestamped record of where your device was.
- Timestamps are location-correlating even without an address attached.
  Consider what a 30-day timeline reveals when combined with anything else
  published under the same identity. Use `--day-zero` when publishing.
- **Rayhunter names capture files by Unix epoch**, so a filename like
  `1234567890.pcapng` decodes to the collection date and time to the second.
  Relabel captures before publishing anything that cites them; redacting dates
  in prose while leaving the filenames in a table accomplishes nothing.
