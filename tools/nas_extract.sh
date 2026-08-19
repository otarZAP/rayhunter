#!/usr/bin/env bash
#
# nas_extract.sh — extract NAS-EPS signaling events from Rayhunter pcapng
#                  captures into a normalized CSV for downstream analysis.
#
# Rayhunter writes GSMTAP-encapsulated LTE control-plane traffic. tshark
# dissects GSMTAP on UDP/4729 automatically, so no decode-as is needed for
# standard captures.
#
# Usage:
#   ./nas_extract.sh capture.pcapng            > events.csv
#   ./nas_extract.sh data/captures/*.pcapng    > events.csv
#   ./nas_extract.sh --check-fields                     # verify dissector fields
#
# Output columns:
#   capture,frame,epoch,emm_type,emm_type_name,id_type,emm_cause,mcc,mnc,cipher,integrity
#
set -euo pipefail

TSHARK="${TSHARK:-tshark}"

# NAS-EPS fields. Names are stable across Wireshark 3.x/4.x but --check-fields
# will tell you if your build differs.
FIELDS=(
  frame.number
  frame.time_epoch
  nas_eps.nas_msg_emm_type
  nas_eps.emm.id_type2
  nas_eps.emm.cause
  e212.mcc
  e212.mnc
  nas_eps.emm.toc
  nas_eps.emm.toi
)

check_fields() {
  echo "Checking NAS-EPS dissector fields against: $($TSHARK --version | head -1)"
  local missing=0
  for f in "${FIELDS[@]}"; do
    if $TSHARK -G fields 2>/dev/null | cut -f3 | grep -qx "$f"; then
      printf '  ok      %s\n' "$f"
    else
      printf '  MISSING %s\n' "$f"; missing=1
    fi
  done
  [ "$missing" -eq 0 ] && echo "All fields present." || \
    echo "Some fields missing — check 'tshark -G fields | grep nas_eps' for your build."
  exit "$missing"
}

[ "${1:-}" = "--check-fields" ] && check_fields

if [ $# -eq 0 ]; then
  echo "usage: $0 <capture.pcapng> [more.pcapng ...]" >&2
  exit 2
fi

command -v "$TSHARK" >/dev/null 2>&1 || {
  echo "error: tshark not found. Set TSHARK=/path/to/tshark or install Wireshark CLI." >&2
  exit 1
}

# Header
echo "capture,frame,epoch,emm_type,id_type,emm_cause,mcc,mnc,cipher,integrity"

for cap in "$@"; do
  [ -f "$cap" ] || { echo "warn: skipping missing file $cap" >&2; continue; }
  name=$(basename "$cap" .pcapng)

  args=()
  for f in "${FIELDS[@]}"; do args+=(-e "$f"); done

  # -Y nas_eps limits output to frames the NAS-EPS dissector claimed.
  # occurrence=f takes the first value when a field repeats in one frame.
  "$TSHARK" -r "$cap" -Y nas_eps -T fields "${args[@]}" \
      -E separator=, -E occurrence=f 2>/dev/null \
    | awk -v cap="$name" 'BEGIN{FS=OFS=","} {print cap, $0}'
done
