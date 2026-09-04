#!/usr/bin/env bash
# Repeated-run evaluation — the harness that makes a change measurable at all.
#
#   tools/eval.sh <runs> [tag]
#
# WHY THIS EXISTS. Temperature 0 is not reproducible on this stack: three runs of
# a BYTE-IDENTICAL briefing agreed on the clear-cut cases and flipped on the
# marginal one. So a single run is not a measurement, and every A/B taken on one
# sample here has been unfalsifiable — including one whose result was published
# and later withdrawn ("precision 0.5 -> 1.0" turned out to be 1 of 3 samples).
#
# What this does instead: run the same small set N times and report the
# DISTRIBUTION. A change is only visible if it moves a metric outside the band the
# same code produces against itself.
#
# The set is deliberately small and hypothesize-only — that is the leg where
# judgement lives, and the whole point is to be cheap enough to repeat:
#
#   webgoat/open_redirect   3 cases — THE ONLY SET WHERE PRECISION CAN FAIL TODAY
#                                     (2 labelled not_this_class); everything else
#                                     is all-vulnerable, so its precision is 1.0
#                                     whatever the model does
#   juiceshop/xss           7 cases — Angular, framework sinks
#   juiceshop/sqli (routes) 3 cases — Express, member-read sources (the oracle
#                                     names 2 sink sites; login.ts is reached from
#                                     two request fields and scores as one)
#
# Facts are built ONCE and reused across runs, so what varies between runs is the
# model and nothing else.

set -uo pipefail
cd "$(dirname "$0")/.."
runs="${1:-3}"
tag="${2:-eval}"
out="var/eval.$(date -u +%Y%m%dT%H%M%SZ).$tag"
mkdir -p "$out"; chmod 700 "$out" 2>/dev/null || true

targets=(
  "open_redirect:java:corpus/webgoat:webgoat"
  "xss:js:corpus/juice-shop/frontend/src/app:juiceshop"
  "sqli:js:corpus/juice-shop/routes:juiceshop"
)

echo "eval: $runs run(s) -> $out" >&2

# ---- facts once, shared by every run --------------------------------------
for spec in "${targets[@]}"; do
  IFS=: read -r c l src target <<< "$spec"
  base="$out/facts.$c.$l.jsonl"
  export SOURCE_ANALYST_LOG="$base"
  : > "$base"
  for q in sql_sinks request_sources reachable sanitizer_on_path; do
    manifest params --class "$c" --lang "$l" --query "$q" 2>/dev/null \
      | cpg query --src "$src" --query "$q" --params-from - 2>>"$out/facts.err" \
      | belief append >/dev/null 2>>"$out/facts.err"
  done
  for rs in $(manifest show --class "$c" --lang "$l" 2>/dev/null \
              | python3 -c 'import json,sys
try: print(" ".join(json.load(sys.stdin).get("rules") or []))
except Exception: pass'); do
    struct_grep scan --src "$src" --rules "$rs" 2>>"$out/facts.err" \
      | belief append >/dev/null 2>>"$out/facts.err"
  done
  echo "eval: facts $c/$l -> $(grep -c . "$base") records" >&2
done

# ---- N independent judgement runs off the same facts -----------------------
# A runner that is misconfigured fails identically every time, so grinding through
# every run to discover that wastes the window and buries the cause under N copies
# of the same line. Measured the hard way: LLM_MODEL unset against a llama-server
# in router mode gives `model 'local' not found`, and nine runs failed in under a
# second each. A per-run flake must still be tolerated — that is what the band is
# for — so the abort is specific: if EVERY target of run 1 failed, this is setup,
# not variance.
failed_run1=0
for i in $(seq 1 "$runs"); do
  for spec in "${targets[@]}"; do
    IFS=: read -r c l src target <<< "$spec"
    log="$out/run$i.$c.$l.jsonl"
    cp "$out/facts.$c.$l.jsonl" "$log"
    export SOURCE_ANALYST_LOG="$log"
    echo "eval: run $i — $c/$l" >&2
    # Through pass.sh, NOT a reimplementation of its pipeline. The first version of
    # this loop piped `brief --chunk-size 4` straight at the runner with no --chunk,
    # which defaults to 0 — so it judged the FIRST FOUR cases of each set and scored
    # that as the whole. xss has seven. A harness whose job is to measure must not
    # be the thing that silently measures a subset, and pass.sh already drains.
    if tools/pass.sh hypothesize "$c" "$l" 4 >>"$out/run$i.err" 2>&1; then
      score --class "$c" --target "$target" --src agent:hypothesize \
        > "$out/run$i.$c.$l.score.json" 2>/dev/null || true
    else
      echo "eval: run $i $c/$l FAILED — recorded, not retried" >&2
      [ "$i" -eq 1 ] && failed_run1=$((failed_run1 + 1))
    fi
  done
  if [ "$i" -eq 1 ] && [ "$failed_run1" -eq "${#targets[@]}" ]; then
    echo "eval: every target of run 1 failed — this is a setup problem, not model" \
         "variance, and repeating it $runs times would only hide the cause." \
         "See $out/run1.err" >&2
    python3 tools/eval_report.py "$out"
    exit 2
  fi
done

python3 tools/eval_report.py "$out"
