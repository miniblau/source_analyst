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
tools/pass.sh report      sqli java 5
render --class sqli --target "Client Project" > report.md
```

`openai_compat` speaks to anything with an OpenAI-compatible `/chat/completions` —
llama.cpp, Ollama's `/v1`, LM Studio, vLLM, a hosted API. Which one is
`LLM_BASE_URL`, never a line in this repo.

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
- **Nobody reads a called method's body.** Agents judge the briefing they are given;
  asking follow-up questions is the Phase 2 `trace` loop.
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
