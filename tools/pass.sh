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
chunks=$(brief --agent "$agent" --class "$class" --lang "$lang" "${extra[@]}" \
                --chunk-size "$size" --chunks)
echo "pass: $agent x $class/$lang — $chunks batch(es) of $size via runner '$runner'" >&2

for i in $(seq 0 $((chunks - 1))); do
  echo "pass: batch $((i + 1))/$chunks" >&2
  # No `|| true`: a batch that fails stops the pass. Half a pass silently
  # admitted is worse than none, because the log then looks complete.
  brief --agent "$agent" --class "$class" --lang "$lang" "${extra[@]}" \
        --chunk-size "$size" --chunk "$i" \
    | run_agent --agent "$agent" \
    | admit --type "$type" --class "$class" --lang "$lang" --src "agent:$agent" >/dev/null
done

echo "pass: done — $chunks batch(es) admitted" >&2
