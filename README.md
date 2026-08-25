# source_analyst

A source-code review system that works the way an assessor does — read, understand,
hypothesize, branch, prove — on a deterministic substrate, with an LLM as glue.

Static-only in v1. The deliverable is **many well-described hypotheses with manual
recreation flows**, not a scanner verdict. Nothing here ever reports `confirmed`.

- `design_and_roadmap.md` — what is being built, and why (§10 is the frozen spec)
- `CLAUDE.md` — how code is written here (hard invariants, working agreement)

## The one idea

An LLM never asserts ground truth. Every claim about reachability, dataflow or call
edges comes from a substrate tool and carries its `src`; anything else is labelled a
hypothesis. Two deterministic tools enforce it: **`brief`** fixes what an agent may
see, **`admit`** fixes what it may assert. A hallucinated fact reference is rejected
at the door rather than believed, which is what makes an unfamiliar or weaker model
*safe* to run here.

## Install

```bash
uv pip install -e .
```

Needs `joern` on PATH for reachability, `opengrep` for pattern search. Each test
suite skips cleanly when its binary is absent, so neither blocks work on the other.

## Reviewing a Java repo for SQL injection

That pair — SQLi × Java — is the only one currently built and corpus-validated.

```bash
cpg build --src /path/to/project          # once per tree, cached on a content hash
manifest detect --src /path/to/project    # read the coverage gaps it prints

for q in sql_sinks request_sources reachable sanitizer_on_path; do
  manifest params --class sqli --lang java --query $q \
    | cpg query --query $q --params-from - --src /path/to/project \
    | belief append
done

# a model server, kept warm — reloading one per batch costs more than the inference
llama-server -m <model>.gguf -c 16384 --host 127.0.0.1 --port 8080 &
export LLM_BASE_URL=http://127.0.0.1:8080/v1 SOURCE_ANALYST_RUNNER=openai_compat

tools/pass.sh hypothesize sqli java 4
tools/trace.sh /path/to/project sqli java 1      # optional: read the code, re-judge
tools/pass.sh report      sqli java 5
render --class sqli --target "Client Project" > report.md
```

`openai_compat` speaks to anything with an OpenAI-compatible `/chat/completions` —
llama.cpp, Ollama's `/v1`, LM Studio, vLLM, a hosted API. Which one is
`LLM_BASE_URL`, never a line in this repo.

## Digging deeper

`trace` is the only loop. Each turn the *substrate* decides which methods a
hypothesis needs read — the sink, the sanitizer candidates, and every method the
flow passes through — `callee_body` reads them into the log, and the agent re-judges
with the source in front of it. Each revision becomes a child hypothesis plus one
belief per trust verdict, so the log grows a tree and the belief store stops the next
run re-litigating a sanitizer someone already audited.

```bash
tools/trace.sh /path/to/project sqli java 1
tools/trace.sh /path/to/project sqli java 1 refuted   # re-examine the exclusions
```

**Batch size 1**, not 4 — a trace briefing carries method source and runs ~10k tokens
per case against a hypothesize batch's ~4k. `brief` prints `bytes` in its run meta;
budget against **~2.3 chars per token**, not 4, because source and fully-qualified
identifiers tokenize far worse than prose. Getting this wrong is a batch that dies
mid-record on the context limit.

**Re-examining exclusions, and when to.** Everything `trace` drops lands in the
report's "Refuted — verify these" section. Entries flagged **Check this one** are
refutations on a sanitizer-carrying path — the shape that does not correlate with
confidence — and those are the ones to send back through:

```bash
tools/trace.sh /path/to/project sqli java 1 refuted
```

Do this **selectively, not wholesale.** Measured on WebGoat: the first traced pass
refuted seven real vulnerabilities (recall 1.0 -> 0.696); re-examining every exclusion
restored all seven (recall 1.0) but also dissolved the three *correct* exclusions into
`inconclusive`, landing precision at 0.885 — exactly the null baseline's. Run to
exhaustion this converges on "keep everything". The flag selects the six that were
wrong without touching the three that were right.

Depth is bounded by `config/depth.yaml`: a hard `max`, and a `spend_gate` that
descends only where the last level made the case *stronger*. The null baseline keeps
confidence flat and so cannot buy itself another level, which is the property that
makes the gate worth having.

The loop **drains and resumes**: admitting a child removes its parent from the
eligible set, so a run interrupted halfway leaves a consistent log and re-running
picks up where it stopped.

## Measuring a model

Against a labelled corpus set only — your own code has no ground truth:

```bash
score --class sqli --target webgoat --src agent:hypothesize
```

The floor to beat is `tests/stub_runner.py`, which judges nothing: **precision 0.885,
confidence separation 0.0**. Read `calibration` rather than `separation` for a good
model — separation is undefined when a model keeps no noise.

## What it cannot do

- **One class, one language.** Adding a class is `manifests/classes/*.yaml`; adding a
  language for it is `manifests/patterns/<lang>/*.yaml`. Zero code change — but the
  queries must be able to *see* the sink shape.
- **Call nodes and annotated parameters only.** A JSX attribute, a template
  expression or a config key is reachable by no manifest, only by a new query.
- **Representative paths, not all routes.** "No clean path was reported" is never
  "every route is sanitized".
- **A callee outside the tree stays unread.** `trace` reads the methods a flow
  passes through, but a library or a dependency comes back `external_stub` — the
  signature is known, the body is not. That is a gap in coverage, never evidence
  that a call is harmless, and `admit` refuses a trust verdict based on one.
- **No exploitation.** The v1 ceiling is `needs_proof` plus a writeup a human can
  follow in minutes.

Zero findings is never a clean bill of health, and `render` says so explicitly with
the numbers that distinguish the cases.

## Tests

```bash
python -m unittest discover -s tests
```

The deterministic core runs with **zero model calls**. Agents are measured with
`score`, never asserted by a test.

## Layout

```
manifests/   vuln knowledge as data — classes × per-language patterns
queries/     named Joern .sc scripts (fixed vocabulary; agents never send Scala)
rules/       named opengrep rule sets
config/      tiers, statuses, verdicts, triage bands, calibration signals, runners
agents/      agent prompts — markdown in, JSONL out
corpus/      fixtures, golden outputs, labelled ground truth
tools/       runner shims and the chunked-pass loop (not the substrate)
var/         runtime: CPG cache, log.jsonl, agent transcripts (gitignored, 0700)
```
