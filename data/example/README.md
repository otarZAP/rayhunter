# Synthetic fixture

`make_fixture.py` generates a fabricated `events.csv` whose event *shape*
mirrors the structure described in [the technical report](../../docs/TECHNICAL_REPORT.md),
so the analysis tools can be run and reviewed without any capture data.

    python data/example/make_fixture.py > data/example/events.csv
    ./tools/css_indicators.py data/example/events.csv
    ./tools/timeline.py data/example/events.csv --tz -04:00

**This is not capture data.** Frame numbers, sub-second timings, and PLMN
interleaving are invented. Nothing produced from this fixture is a finding.
