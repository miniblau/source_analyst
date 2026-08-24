#!/usr/bin/env bash
# The trace loop: read the code, re-judge, descend (design §4.1, §4.2).
#
#   tools/trace.sh <src> <class> <lang> [batch] [status]
#   tools/trace.sh corpus/webgoat sqli java
#   tools/trace.sh corpus/webgoat sqli java 1 refuted   # re-examine the exclusions
#
# This is the only loop in the system. Everything else is single-shot, which is what
# keeps iteration in one auditable place.
#
# Each turn has two stages, in this order and never the other:
#
#   1. SUBSTRATE. `brief --callees` decides mechanically which methods are worth
#      reading — the sink, the sanitizer candidates, and every method the flow passes
#      through — and `callee_body` reads them into the log as facts. The agent is not
#      consulted about what to read. A model that chose its own reading list would be
#      steering the deterministic layer, and a name it invented would come back
#      `not_in_cpg` looking like a fact about the code. Re-reading is free: facts are
#      content-hashed, so `belief append` dedupes a body already in the log.
#
#   2. REASONING. `brief --agent trace` hands over one batch of hypotheses plus the
#      bodies they touch; the revision comes back through `admit`, which is still the
#      only door and which expands each revision into a child hypothesis plus one
#      belief per verdict.
#
# It DRAINS rather than counting batches up front, because admitting a child removes
# its parent from the eligible set — a batch count computed at the start is stale by
# the second batch. The loop ends when `brief --callees` reports nothing eligible,
# which happens when every leaf has hit `depth.max`, been stopped by the spend gate,
# or reached a status this run is not tracing.
#
# Environment: SOURCE_ANALYST_RUNNER picks the model (see config/runners.yaml).
set -euo pipefail

src="${1:?source tree, e.g. corpus/webgoat}"
class="${2:?vuln class}"
lang="${3:?language}"
# 1, not 4 as the flat pass uses: a trace briefing carries method source and runs
# ~10k tokens per case. Three cases put it at ~15k against a 16384 context, which is
# how the first live run died mid-record.
size="${4:-1}"
status="${5:-needs_proof}"

# A loop that cannot terminate is worse than a slow one. Every turn must admit at
# least one child and so shrink the eligible set; this cap catches the day that
# stops being true instead of running until someone notices.
max_turns="${TRACE_MAX_TURNS:-200}"

runner="${SOURCE_ANALYST_RUNNER:-$(python3 -c 'import yaml;print(yaml.safe_load(open("config/runners.yaml"))["default"])')}"
params=$(mktemp); trap 'rm -f "$params"' EXIT

echo "trace: $class/$lang at status '$status', batches of $size via runner '$runner'" >&2

turn=0
while true; do
  # Non-zero here means "nothing left to descend into" — the loop's normal end, and
  # the message on stderr says which of the reasons applies.
  if ! brief --agent trace --class "$class" --lang "$lang" --status "$status" \
              --callees > "$params"; then
    break
  fi
  turn=$((turn + 1))
  if [ "$turn" -gt "$max_turns" ]; then
    echo "trace: stopped after $max_turns turns without draining — the eligible set is" \
         "not shrinking, which is a bug, not a deep tree" >&2
    exit 4
  fi
  echo "trace: turn $turn — reading callee bodies" >&2
  cpg query --src "$src" --query callee_body --params-from - < "$params" \
    | belief append >/dev/null

  # Always batch 0: each admitted child removes its parent from the eligible set,
  # so the queue drains from the front. No `|| true` — a batch that fails stops the
  # run, because a tree that looks deeper than it is, is worse than a shallow one.
  brief --agent trace --class "$class" --lang "$lang" --status "$status" \
        --chunk-size "$size" --chunk 0 \
    | run_agent --agent trace \
    | admit --type trace --class "$class" --lang "$lang" --src "agent:trace" >/dev/null
done

echo "trace: done — $turn turn(s)" >&2
