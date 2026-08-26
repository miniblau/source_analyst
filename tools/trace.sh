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

# Cases whose revision `admit` refused this run. They are SKIPPED, not forgiven:
# the record was rejected outright and nothing about them entered the log. Without
# this the loop re-briefs the same case every turn and, at temperature 0, gets the
# identical rejection back — so one unusable answer costs the class. Measured on
# WebGoat 2026-08-25: sqli died on turn 21 of ~26 having already admitted 20
# children and 13 beliefs, path_traversal on turn 4 of ~5. A per-turn refusal rate
# of about 5% makes completing a 26-turn class a coin-flip at best (0.95^26).
skip=""
refused=0
max_refusals="${TRACE_MAX_REFUSALS:-5}"

turn=0
while true; do
  # Non-zero here means "nothing left to descend into" — the loop's normal end, and
  # the message on stderr says which of the reasons applies.
  if ! brief --agent trace --class "$class" --lang "$lang" --status "$status" \
              --exclude "$skip" --callees > "$params"; then
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
  # so the queue drains from the front. The batch is written to a file first so the
  # ids in it are known if it has to be skipped — a pipe cannot be read twice.
  batch=$(mktemp)
  brief --agent trace --class "$class" --lang "$lang" --status "$status" \
        --exclude "$skip" --chunk-size "$size" --chunk 0 > "$batch"

  # Still no `|| true`: a refused batch admits NOTHING, and half a revision is worse
  # than none. What changed is the blast radius — the case is dropped from this run
  # instead of the class being abandoned. It keeps whatever status it already had,
  # so `report` still writes it up from the pre-trace judgement and nothing is
  # silently lost; the count of skipped cases is printed at the end.
  if ! run_agent --agent trace < "$batch" \
       | admit --type trace --class "$class" --lang "$lang" --src "agent:trace" >/dev/null; then
    ids=$(python3 -c "
import json,sys
out=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line.startswith('{'): continue
    d=json.loads(line)
    if d.get('kind')=='trace_case':
        h=d.get('hypothesis') or {}
        i=h.get('id') or d.get('id')
        if i: out.append(i)
print(','.join(out))" "$batch")
    rm -f "$batch"
    if [ -z "$ids" ]; then
      echo "trace: a batch was refused and its case ids could not be read — stopping," \
           "because skipping a case this loop cannot name would re-brief it forever" >&2
      exit 6
    fi
    skip="${skip:+$skip,}$ids"
    refused=$((refused + 1))
    echo "trace: batch refused by admit — skipping case(s) $ids ($refused of at most" \
         "$max_refusals; nothing was admitted for them)" >&2
    if [ "$refused" -gt "$max_refusals" ]; then
      echo "trace: stopped after $max_refusals refusals — this is a model or contract" \
           "problem, not a deep tree, and grinding through the rest would hide it" >&2
      exit 5
    fi
    continue
  fi
  rm -f "$batch"
done

if [ "$refused" -gt 0 ]; then
  echo "trace: $refused case(s) were skipped after admit refused their revision —" \
       "they keep their pre-trace status and are still reported" >&2
fi

echo "trace: done — $turn turn(s)" >&2
