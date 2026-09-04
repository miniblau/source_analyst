#!/usr/bin/env bash
# The unattended run: every class, every leg, one source tree, one log.
#
#   tools/night.sh <src> [class ...]
#   tools/night.sh corpus/webgoat                    # every class the manifest knows
#   tools/night.sh corpus/webgoat sqli open_redirect
#
# WHY THIS EXISTS, given pass.sh already works. `pass.sh` drives one class and one
# leg, and a batch that fails stops it — correct there, and wrong for a queue: sqli
# failing at 02:00 would otherwise cost you path_traversal's report as well, and you
# would find that out at breakfast. Here every leg is attempted, every failure is
# recorded, and the run always ends with a summary saying what ran, what failed and
# what is still owed. The strictness stays where it belongs, inside pass.sh; what
# this adds is that a failure is isolated and *named* rather than silent.
#
# LEG ORDER is hypothesize -> trace -> report, per README and design §4.1: trace
# reads the code and re-judges, and report writes up whatever trace left. Trace is
# the leg most likely to fail, so it is explicitly NOT allowed to block report — a
# run that traced nothing still owes you a document from the hypotheses it has.
#
# ONE LOG PER CLASS, and this is not a stylistic choice. CPG facts carry no
# `vuln_class` — a `flow` is a flow, and only opengrep facts are class-tagged — and
# `brief` does not filter facts by class. Point three classes at one log and the
# first one briefed consumes EVERY flow in it: measured here with the stub runner,
# open_redirect was briefed 34 cases instead of 2, filed them all under its own
# class, and the remaining two classes reported "nothing waiting" while the summary
# said no legs had failed. That is the exact shape of failure this script exists to
# prevent, so the run gives each class its own log and joins them nowhere.
# Tagging CPG facts with a class and filtering in `brief` is the real fix; it is a
# record-schema change (§10.4, a deliberate `v` bump) and is not done here.
#
# Environment:
#   NIGHT_LOG_DIR           where the per-class logs go (default <outdir>/logs)
#   SOURCE_ANALYST_RUNNER   which model (config/runners.yaml)
#   NIGHT_SKIP_TRACE=1      hypothesize + report only
#   NIGHT_LANG              default java
#   NIGHT_HYP_SIZE / NIGHT_REPORT_SIZE / NIGHT_TRACE_SIZE   batch sizes
#
# Batch sizes default to what fits the measured slot context, not to what is fast.
# See the note in README; a briefing that overruns the slot dies mid-record and the
# leg is lost, which is the single most expensive thing that can happen overnight.
#
# AND BATCHING IS NOT A SPEED LEVER — measured on the 2026-08-31 run, so do not
# reach for it again. Median seconds PER CASE, by agent and batch size:
#
#   hypothesize   1 case 130s | 2 cases 109s | 3 cases 201s | 4 cases 139s
#   report        1 case 312s | 2 cases 305s
#
# Flat. Generation dominates on a local model and generation is per-case work, so
# a bigger batch moves the same tokens in fewer HTTP requests and saves nothing.
# The shared prompt that batching amortises is the small half of the cost.
#
# What a bigger batch does change is the downside: one refusal now costs N cases
# instead of 1, and the briefing grows faster than the case count. Tried on trace
# at 4 (2026-09-04): the briefing was 53,892 bytes / ~23.4k tokens against a 32k
# slot, the call blew the 1800s timeout, and four cases were dropped having
# admitted nothing. Trace stays at 1.

set -uo pipefail   # deliberately NOT -e: a failing leg must not kill the queue

# The run's Joern server must not outlive the run. The CPG cache is keyed on a
# source hash, so each new tree mints a new workspace and its own server, and
# nothing used to stop them: measured 2026-09-04, fifteen had accumulated over
# fifteen days holding 13.1GB. A FRESH server for WebGoat is 599MB — the 7.4GB
# the oldest had reached is JVM heap growth over days of queries, not the cost of
# the CPG. Either way the model loses its residency and generation drops ~17x,
# and nothing fails while it happens.
#
# `ensure_server` now reaps other workspaces on the way up; this trap closes the
# other half, so an overnight run leaves the box as it found it.
trap 'cpg stop --all >/dev/null 2>&1 || true' EXIT

src="${1:?source tree, e.g. corpus/webgoat}"; shift
lang="${NIGHT_LANG:-java}"
# The name the ground truth is filed under, which is NOT always the directory's.
# `corpus/juice-shop/frontend/src/app` is one target's frontend and
# `corpus/juice-shop/routes` its server, and both are scored against `juiceshop.*`
# — deriving it from basename asked for `app.xss.yaml` and `routes.sqli.yaml`,
# found neither, and recorded `score skipped` as though there were no oracle.
target="${NIGHT_TARGET:-$(basename "$src")}"
hyp_size="${NIGHT_HYP_SIZE:-4}"
report_size="${NIGHT_REPORT_SIZE:-2}"
trace_size="${NIGHT_TRACE_SIZE:-1}"


if [ "$#" -gt 0 ]; then
  classes=("$@")
else
  # `manifest classes` reports on STDERR — it is metadata, not facts (§10.4, and the
  # rule every tool here follows). Reading stdout got an empty list, and an empty
  # list ran zero legs and printed "no failed legs": a broken install reporting a
  # clean night. Hence both halves of this — the right stream, and the guard.
  mapfile -t classes < <(python3 -c "
import json,subprocess,sys
out=subprocess.run([sys.executable,'-m','source_analyst.manifest.cli','classes'],
                   capture_output=True,text=True)
line=[l for l in out.stderr.splitlines() if l.startswith('{')]
if not line: sys.exit('night: could not read the class vocabulary: '+out.stderr[-300:])
print('\n'.join(json.loads(line[-1])['classes']))")
fi

if [ "${#classes[@]}" -eq 0 ]; then
  # A manifest tree with no classes is a broken install, not a clean result.
  echo "night: no vuln classes to run — refusing to report a clean night over an" \
       "empty vocabulary. Check manifests/classes/ and SOURCE_ANALYST_MANIFESTS." >&2
  exit 2
fi

runner="${SOURCE_ANALYST_RUNNER:-$(python3 -c 'import yaml;print(yaml.safe_load(open("config/runners.yaml"))["default"])')}"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
outdir="var/night.$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$outdir"
# Owner-only, for the same reason belief/store and run_agent do it: this directory
# ends up holding the reports, which quote the client's source, and the per-class
# logs, which contain it wholesale. `var/` is already 0700 so this is defence in
# depth rather than a fix — but the run writes wherever it is pointed, and the
# report is the single most sensitive artifact the system produces.
chmod 700 "$outdir" 2>/dev/null || true

# One line per (class, leg, outcome). Written as it happens, so an interrupted run
# still explains itself — the summary at the end is a rendering of this, not a
# separate account that could disagree with it.
ledger="$outdir/ledger.tsv"
: > "$ledger"
note() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" >> "$ledger"; }

logdir="${NIGHT_LOG_DIR:-$outdir/logs}"
mkdir -p "$logdir"
chmod 700 "$logdir" 2>/dev/null || true
echo "night: $runner | classes: ${classes[*]}" >&2
echo "night: output -> $outdir | logs -> $logdir (one per class)" >&2

# ---- facts first, for every class, before any model runs -------------------
# Queries are seconds and deterministic; the hypothesizer can only judge what the
# substrate already put in front of it, so nothing model-shaped starts until every
# class's facts are in the log.
for c in "${classes[@]}"; do
  export SOURCE_ANALYST_LOG="$logdir/$c.log.jsonl"
  for q in sql_sinks request_sources reachable sanitizer_on_path; do
    if manifest params --class "$c" --lang "$lang" --query "$q" 2>/dev/null \
       | cpg query --src "$src" --query "$q" --params-from - 2>>"$outdir/$c.facts.err" \
       | belief append >/dev/null 2>>"$outdir/$c.facts.err"; then
      note "$c" "facts:$q" ok
    else
      note "$c" "facts:$q" FAILED "see $outdir/$c.facts.err"
    fi
  done

  # THE PATTERN SUBSTRATE, which this stage did not run at all until now. Four of
  # five pattern files declare `rules:` and nothing consumed them: measured across
  # both directories of the first full run, ZERO opengrep facts in any class, ever.
  # So every report ever produced here was CPG-only while the manifests claimed two
  # substrates, and the LEADS section — sinks no query can reach, the whole reason
  # the stitching exists — never had a fact to render. Its absence read as "there
  # were none". Juice Shop's twelve `[innerHTML]` bindings are the standing example.
  for rs in $(manifest show --class "$c" --lang "$lang" 2>/dev/null \
              | python3 -c 'import json,sys
try: print(" ".join(json.load(sys.stdin).get("rules") or []))
except Exception: pass'); do
    if struct_grep scan --src "$src" --rules "$rs" 2>>"$outdir/$c.facts.err" \
       | belief append >/dev/null 2>>"$outdir/$c.facts.err"; then
      note "$c" "rules:$rs" ok
    else
      note "$c" "rules:$rs" FAILED "see $outdir/$c.facts.err"
    fi
  done
done

# ---- then the model legs, class by class ----------------------------------
leg() {  # leg <class> <name> <command...>
  local c="$1" name="$2"; shift 2
  local log="$outdir/$c.$name.log"
  echo "night: $c / $name" >&2
  if "$@" >"$log" 2>&1; then
    note "$c" "$name" ok
  else
    local rc=$?
    # exit 3 from pass.sh is "nothing to do", which is not a failure of this run:
    # an earlier leg may legitimately have left this one empty. It is still worth
    # distinguishing from success, because a report leg with nothing to write is
    # how an empty deliverable looks.
    if [ "$rc" -eq 3 ]; then note "$c" "$name" empty "nothing waiting"
    else note "$c" "$name" FAILED "rc=$rc see $log"; fi
  fi
}

for c in "${classes[@]}"; do
  export SOURCE_ANALYST_LOG="$logdir/$c.log.jsonl"
  leg "$c" hypothesize tools/pass.sh hypothesize "$c" "$lang" "$hyp_size"
  if [ -z "${NIGHT_SKIP_TRACE:-}" ]; then
    # Allowed to fail without taking report with it — see the leg-order note above.
    leg "$c" trace tools/trace.sh "$src" "$c" "$lang" "$trace_size"
  fi
  leg "$c" report tools/pass.sh report "$c" "$lang" "$report_size"

  # Deterministic tails: no model, so they run whatever the legs above did.
  if render --class "$c" --target "$target" > "$outdir/$c.report.md" 2>"$outdir/$c.render.err"; then
    note "$c" render ok "$outdir/$c.report.md"
  else
    note "$c" render FAILED "see $outdir/$c.render.err"
  fi
  if score --class "$c" --target "$target" --src agent:hypothesize \
       > "$outdir/$c.scorecard.json" 2>"$outdir/$c.score.err"; then
    note "$c" score ok
  else
    note "$c" score skipped "no ground truth, or nothing scored"
  fi
done

# ---- the index a human opens first ----------------------------------------
# Deterministic, no model, and it reads the logs rather than the ledger — so it
# reports what the run actually produced, including classes a failed leg left
# empty. summary.txt below is the operator's account of the RUN; this is the
# reader's account of the FINDINGS, and they answer different questions.
if overview --logs "$logdir" --target "$target" --reports . \
     > "$outdir/overview.md" 2>"$outdir/overview.err"; then
  note "-" overview ok "$outdir/overview.md"
else
  note "-" overview FAILED "see $outdir/overview.err"
fi

# ---- the summary, which is the whole point --------------------------------
{
  echo "# night run"
  echo
  echo "started $started, finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "runner $runner, logs $logdir (one per class)"
  echo
  printf '%-16s %-16s %-9s %s\n' CLASS LEG OUTCOME DETAIL
  awk -F'\t' '{printf "%-16s %-16s %-9s %s\n",$1,$2,$3,$4}' "$ledger"
  echo
  if grep -q FAILED "$ledger"; then
    echo "FAILURES — the log is incomplete for these, and short reads as complete:"
    awk -F'\t' '$3=="FAILED"{printf "  %s %s (%s)\n",$1,$2,$4}' "$ledger"
  else
    echo "no failed legs."
  fi
  echo
  echo "## scorecards"
  for c in "${classes[@]}"; do
    [ -s "$outdir/$c.scorecard.json" ] || continue
    python3 - "$c" "$outdir/$c.scorecard.json" <<'PY'
import json,sys
c,p=sys.argv[1],sys.argv[2]
try: d=json.load(open(p))
except Exception: sys.exit()
cs=d.get("cases",{})
print(f"  {c}: scored={d.get('scored')} precision={d.get('precision')} recall={d.get('recall')} "
      f"tp={cs.get('true_positive')} fn={cs.get('false_negative')} fp={cs.get('false_positive')} "
      f"sep={d.get('confidence',{}).get('separation')}")
PY
  done
} | tee "$outdir/summary.txt" >&2

grep -q FAILED "$ledger" && exit 1
exit 0
