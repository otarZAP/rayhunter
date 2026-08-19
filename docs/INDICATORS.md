# CSS Indicators and Their Benign Competitors

Every indicator this repository uses is probabilistic. None is conclusive
alone. This document exists because the honest version of CSS detection is
mostly a discipline of ruling things out, and a writeup that skips that step
deserves to be dismissed.

For each indicator: what it is, why a simulator produces it, and what
legitimate network behaviour produces the same signal.

---

## 1. Authentication failure (EMM cause 20, MAC failure) followed by a bare IMSI request

**Strength: strongest single indicator in this dataset.**

LTE authentication is mutual. The network sends `RAND` + `AUTN`; the AUTN
carries a MAC computed with the subscriber key `K`, which lives in the SIM and
in the operator's HSS and nowhere else. A simulator has no access to `K`, so it
cannot construct a valid AUTN. The SIM checks the MAC, fails it, and returns
`Authentication Failure` with cause 20.

What makes the sequence meaningful is not the failure but what follows it. A
simulator that cannot authenticate also cannot resolve a GUTI into a
subscriber, so its only remaining move to identify the device is to ask
directly: `Identity Request`, type 1, IMSI. Failure immediately followed by a
bare IMSI demand is the shape of a network that wants an identifier and has no
key material.

**Benign explanations to rule out:**

- **EMM cause 21 (synch failure), not 20.** SQN desynchronisation is the
  common benign authentication failure — it happens after SIM cloning to a
  test device, restoring an old profile, or an HSS rollback. It is a different
  cause code. `css_indicators.py` deliberately does not chain on cause 21, and
  there is a regression test asserting that.
- **Operator misconfiguration.** A wrong OPc after a profile provisioning
  error can produce genuine MAC failures on a real network. These normally
  affect the device persistently and across all cells, rather than appearing in
  isolated bursts with a clean recovery onto another carrier.
- **Test networks and lab equipment.** A nearby private LTE deployment,
  CBRS installation, or engineering setup can present the same failure. This is
  a real ambiguity and cannot be excluded from NAS data alone.

**What raises confidence:** the failure is isolated in time, the IMSI request
follows within seconds, the device is released cleanly, and normal service
resumes on a legitimate PLMN immediately afterwards.

---

## 2. Standalone `Identity Request` type 2 (IMEI)

**Strength: moderate. Frequently overstated.**

The IMEI is a permanent hardware identifier that survives a SIM swap, which
makes it valuable to anyone building a persistent device record.

**This is where most writeups overreach.** The claim "networks never request
the IMEI" is false:

- **EIR checks are a standard 3GPP procedure.** Networks legitimately query
  equipment identity against an Equipment Identity Register to enforce
  stolen-device blocklists.
- **IMEISV is routinely collected via the Security Mode Command**, using the
  IMEISV-request flag, rather than a standalone Identity Request. This is
  ordinary and happens constantly.
- Some networks request IMEI during emergency-call registration and certain
  VoLTE feature negotiations.

So a standalone Identity Request type 2 is **atypical, not impossible**. The
anomalous part is not the request; it is the *pairing* — an IMEI request and
an IMSI request inside the same short transaction window, repeated across
separate encounters. An EIR check does not need the IMSI fetched alongside it
by direct demand, because the network already knows the subscriber.

`css_indicators.py` therefore scores repeated pairing (3+ transactions) higher
than isolated IMEI requests, and reports the two separately.

---

## 3. `Identity Request` type 1 (IMSI)

**Strength: weak alone, meaningful in volume and clustering.**

Normal LTE minimises IMSI exposure by design: the network issues temporary
identifiers (GUTI/TMSI) and reallocates them. A cleartext IMSI request is a
fallback for when GUTI resolution fails.

**Benign explanations to rule out:**

- First attach after power-on with no valid stored GUTI
- MME failure, restart, or GUTI database loss
- Roaming onto a network that cannot resolve the visiting GUTI
- SIM re-insertion or airplane-mode cycling
- Coverage-edge attach churn, which can produce genuine repeats

Volume alone proves little. What matters is clustering — many requests in a
tight window, then nothing for days, with no corresponding change in the
device's own state.

---

## 4. Rejection with EMM cause 15 or 13

**Strength: weak alone. Meaningful as a disengagement pattern.**

Cause 15 is "no suitable cells in tracking area"; cause 13 is "roaming not
allowed in this tracking area". A simulator that has collected what it wants
has an incentive to release the device cleanly, because a device stuck without
service is a device whose user notices. A rejection pushes the device to
reselect a real network.

**Benign explanations to rule out:** genuine tracking-area boundaries,
legitimate roaming restrictions, and ordinary network configuration all
produce these causes routinely. On its own this indicator is close to noise.
It matters only when it consistently terminates an identity-collection burst.

> **Note on message types.** Cause 15 can arrive on `Attach reject` (0x44),
> `Tracking area update reject` (0x4B), or `Service reject` (0x4E). These are
> distinct message types — 0x4B is TAU reject, *not* Service reject. The tools
> here report the message type alongside the cause so the distinction survives.

---

## 5. Null cipher (EEA0) negotiated in the Security Mode Command

**Strength: strong, and it is the content-interception tell.**

A simulator that wants call or SMS *content* rather than identifiers must
downgrade encryption, because it cannot decrypt EEA2 traffic it did not key.
Forcing EEA0 is visible in the Security Mode Command.

**Its absence is itself a finding.** If every Security Mode Command in a
dataset specifies EEA2/EIA2 and EEA0 never appears, that is positive evidence
*against* content interception — it constrains the activity to identity
collection. This is the one place where a negative result is genuinely
informative, and it is worth stating plainly rather than burying.

---

## 6. Rayhunter's own warning flags

**Strength: use as a trigger, not as evidence.**

Rayhunter is a heuristic detector and the EFF is explicit that it produces
false positives. Its warnings are an excellent reason to go look at a capture.
They are not a finding, and warning *counts* are not a severity metric —
citing "34 warnings" as though it quantifies threat conflates the detector's
sensitivity with the phenomenon.

Treat Rayhunter as the thing that told you where to look, then make the
argument from the NAS layer yourself.

---

## What NAS-layer analysis cannot tell you

Stating these limits up front is not hedging; it is the difference between
analysis and speculation.

- **Who operates the equipment.** Cost and capability arguments about
  simulator hardware are inference, not evidence. NAS data contains no
  attribution.
- **Physical location, distance, or direction** of the transmitter. RRC
  measurement reports and cell parameters constrain this somewhat; NAS alone
  does not.
- **Whether you specifically were targeted.** A simulator sweeps every device
  in range indiscriminately. Appearing in a capture does not imply selection.
- **Whether collected identifiers were retained, queried, or discarded.**
- **Intent.** The technical signature of identity collection is the same
  regardless of purpose.

---

## Falsification

The claims in this repository would be substantially weakened by any of:

- Finding the same NAS patterns in captures from a location with no plausible
  simulator activity, at comparable rates
- A carrier confirming an infrastructure change, MME migration, or
  provisioning fault covering the observation window
- A private LTE, CBRS, or test deployment identified nearby
- Baseline captures from other locations showing that the "anomalous" rates
  are ordinary for this device model and firmware

The last item is the most important and the least often done. A single-site
dataset with no baseline is a description, not a controlled comparison.
