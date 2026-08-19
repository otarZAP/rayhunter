# LTE NAS Analysis for Cell Site Simulator Indicators

Tooling and a written analysis for identifying cell site simulator (CSS)
activity in LTE control-plane signaling, built from a six-capture
[Rayhunter](https://github.com/EFForg/rayhunter) dataset spanning a 30-day
observation window.

The dataset contains an authentication MAC failure followed within seconds by a
direct IMSI demand — the sequence a network produces when it wants a subscriber
identifier and has no operator key material — plus 24 IMEI requests each paired
with an IMSI request in the same transaction, across four separate days, with
encryption never downgraded.

**[Read the technical report →](docs/TECHNICAL_REPORT.md)**

---

## What's here

| | |
|---|---|
| [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md) | The findings, the timeline, and the assessment with its limits |
| [docs/INDICATORS.md](docs/INDICATORS.md) | Each indicator, why a simulator produces it, and the benign behaviour that produces the same signal |
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Reproduce the analysis against your own captures |
| [tools/](tools/) | tshark extraction, indicator scoring, multi-capture correlation |
| [data/example/](data/example/) | Synthetic fixture so the pipeline runs without capture data |

## Quick start

No dependencies beyond Wireshark's CLI and Python 3.8+.

```bash
# Run the whole pipeline on the synthetic fixture — no captures needed
python data/example/make_fixture.py > data/example/events.csv
./tools/css_indicators.py data/example/events.csv
./tools/timeline.py data/example/events.csv --day-zero

# Verify the indicator logic
python tools/test_indicators.py

# Against real captures
./tools/nas_extract.sh --check-fields
./tools/nas_extract.sh data/captures/*.pcapng > events.csv
./tools/css_indicators.py events.csv
./tools/timeline.py events.csv --day-zero
```

## What the tools detect

| Indicator | Strength | Notes |
|---|---|---|
| Auth failure (EMM cause 20) → direct IMSI request | Strongest | A simulator has no HSS key material, so its AUTN fails the SIM's MAC check; unable to resolve a GUTI, it must then ask outright |
| Repeated IMEI+IMSI pairing in one transaction | Strong | The *pairing* is the anomaly — standalone IMEI requests occur legitimately via EIR checks |
| Null cipher (EEA0) negotiated | Strong | The content-interception tell. Its **absence** is itself informative |
| Clustered IMSI collection | Moderate | Volume proves little; burst structure is what matters |
| Cause 13/15 disengagement | Weak alone | Meaningful only when it consistently terminates a collection burst |

Cause **21** (synch failure) is the *benign* authentication failure — SQN
desynchronisation — and is deliberately excluded from the chain detector, with
a regression test asserting it stays excluded.

## Reading this honestly

CSS detection is mostly a discipline of ruling things out, and analysis that
skips that step deserves to be dismissed. So, plainly:

- **No single indicator here is conclusive.** The argument rests on
  convergence. [INDICATORS.md](docs/INDICATORS.md) gives every indicator's
  competing benign explanation.
- **NAS data does not support attribution.** These captures show identity
  collection. They do not show who did it, why, or under what authority. The
  report offers no operator attribution and explains why the common
  cost-of-hardware argument is weaker than it appears.
- **This dataset has no baseline.** It is a single site. Comparison captures
  from other locations with the same hardware would establish what these rates
  look like normally — that work has not been done, and it is the analysis's
  main limitation.
- **Rayhunter's warnings are a trigger, not evidence.** It is a heuristic
  detector with a documented false-positive rate. Every finding here was
  derived independently from the NAS layer.
- **Dates are relative and the location is withheld.** Days are numbered from
  the start of observation. A timestamped 30-day presence record for a fixed
  monitoring point is location-correlating on its own, and none of the analysis
  depends on the calendar. `timeline.py --day-zero` reproduces the report's
  tables in this form.

The report's [corrections table](docs/TECHNICAL_REPORT.md#7-corrections-from-earlier-drafts)
records what earlier drafts got wrong, including an overstated claim about IMEI
requests and a misidentified message type.

## Note on the tooling

The scripts here reproduce the documented methodology; they are not the
original ad-hoc analysis session. They were written to make the pipeline
reproducible and reviewable, and are verified against a synthetic fixture and a
unit-test suite rather than against the original captures, which are not
published (see below). Field names are checked against your Wireshark build via
`--check-fields`.

## Captures are not published

Raw `.pcapng` files contain the collecting device's IMSI and IMEI **in
cleartext** in Identity Response frames, alongside a timestamped record of the
device's presence. They are gitignored and will not be published.

The derived CSV the tools produce records only that a request of a given type
occurred — no identifier values — which is sufficient for every indicator here
and safe to share.

## Protocol references

- 3GPP TS 24.301 — NAS-EPS
- 3GPP TS 36.331 — LTE-RRC
- [EFF Rayhunter](https://github.com/EFForg/rayhunter)

## License

MIT for the tooling. See [LICENSE](LICENSE).
