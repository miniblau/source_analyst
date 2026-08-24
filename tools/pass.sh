#!/usr/bin/env bash
# One chunked agent pass: brief -> run_agent -> admit, batch by batch.
#
# Nothing clever lives here — it is the four-stage pipe from the design, wrapped
# in the loop that chunking makes necessary. Written out rather than hidden in a
# tool because the composition IS the interface: run the stages by hand, from a
# Makefile, from Zed, from an opencode agent, whatever you like.
#
#   tools/pass.sh hypothesize sqli java 4
#   tools/pass.sh report sqli java 6
#
# Environment: SOURCE_ANALYST_RUNNER picks the model (see config/runners.yaml).
set -euo pipefail

agent="${1:?agent (hypothesize|report)}"
class="${2:?vuln class}"
lang="${3:?language}"
size="${4:-4}"
case "$agent" in
  hypothesize) type=hypothesis; extra=() ;;
  report)      type=finding;    extra=(--status needs_proof) ;;
  *) echo "pass.sh: unknown agent $agent" >&2; exit 2 ;;
esac

runner="${SOURCE_ANALYST_RUNNER:-$(python3 -c 'import yaml,sys;print(yaml.safe_load(open("config/runners.yaml"))["default"])')}"

remaining() {
  brief --agent "$agent" --class "$class" --lang "$lang" "${extra[@]}" \
        --chunk-size "$size" --chunks
}

todo=$(remaining)
if [ "$todo" -eq 0 ]; then
  # Nothing to judge is not success. Either the leg before this one never ran, or
  # everything here was already done — and those are different situations a caller
  # must be able to tell apart, so say so and exit non-zero.
  echo "pass: nothing to do — no row is waiting for $agent (already judged, or the" \
       "previous leg has not run)" >&2
  exit 3
fi
echo "pass: $agent x $class/$lang — $todo batch(es) of $size via runner '$runner'" >&2

# DRAIN, rather than counting batches up front. Every leg is self-consuming now — a
# hypothesis removes its case, a finding removes its hypothesis — so a count taken at
# the start is stale by the second batch, and the last `--chunk N` runs off the end.
# Draining also makes the pass resumable: interrupt it, run it again, and it picks up
# exactly what is left instead of rewriting what it already did.
n=0
while [ "$(remaining)" -gt 0 ]; do
  n=$((n + 1))
  echo "pass: batch $n (of $todo at the start)" >&2
  # No `|| true`: a batch that fails stops the pass. Half a pass silently
  # admitted is worse than none, because the log then looks complete.
  brief --agent "$agent" --class "$class" --lang "$lang" "${extra[@]}" \
        --chunk-size "$size" --chunk 0 \
    | run_agent --agent "$agent" \
    | admit --type "$type" --class "$class" --lang "$lang" --src "agent:$agent" >/dev/null
done

echo "pass: done — $n batch(es) admitted" >&2
