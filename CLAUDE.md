# CLAUDE.md — Operating Contract

This file governs **how** code is written in this repo. `design_and_roadmap.md` is
**what** we're building; read its §0 orientation and §10 frozen spec before touching
anything. When the two conflict, the design doc's §10 wins on *contracts*; this file
wins on *conduct*.

**Mission.** Build a source-code review system that reasons like a human assessor —
read, understand, hypothesize, branch, prove — on a deterministic substrate, with the
LLM as glue. Static-only v1: the deliverable is many well-described hypotheses with
manual recreation flows, not a scanner.

---

## Hard invariants (never violate without an explicit, logged decision)

1. **The LLM never asserts ground truth.** Any claim about reachability, dataflow,
   call edges, or xref MUST originate from a substrate tool and carry its `src`. If it
   didn't come from a tool, it is a *hypothesis* and is labeled as one. No exceptions,
   no "it's obviously reachable."

2. **Deterministic and reasoning layers never mix in one process.** Substrate tools
   reason about nothing — they answer factual queries. Agents query and interpret —
   they compute no dataflow themselves. A tool that "decides" or an agent that
   hand-derives a taint path is a bug.

3. **Vuln knowledge is data.** No vuln class, sink, source, or sanitizer is hardcoded
   in tool or agent code. New class = new `manifests/classes/*.yaml`; new language for
   a class = new `manifests/patterns/<lang>/*.yaml`. Zero code change. If you're editing
   code to add a sink, stop — it belongs in a manifest.

4. **The JSONL contract is law** (§10.4). Single append-only `log.jsonl`; bare records,
   one per line; every record carries `v`, `ts`, `id`, `src`. Facts are content-hashed
   (idempotent); hypotheses/beliefs/findings are ULID. Schema changes bump `v` and are
   deliberate — never incidental. Belief store is a latest-wins projection, always
   rebuildable from the log.

5. **UNIX composition.** Every tool is single-purpose, reads stdin, writes JSONL to
   stdout, and has no side effect beyond appending to the log. Provenance rides on the
   record; human/metadata chatter goes to stderr. If it can't sit in a pipe, redesign it.

6. **Joern: server mode, warm queries, fixed vocabulary.** The CPG is built once per
   source tree, cached, and warm-queried. Agents select from named `.sc` queries only —
   no raw Joern from the reasoning layer in v1. New query = new reviewed `.sc` file.

7. **Nothing is trusted until validated against corpus ground truth.** Every query is
   proven against known-vuln fixtures (WebGoat / Juice Shop / DVIA) before it runs on
   client code. Findings carry their verification tier honestly — static-only is a
   hypothesis, never `confirmed`.

8. **Depth is budgeted and gated** (§4.2). Branching respects `spend_gate` and the
   `checkpoint` human-in-loop. No unbounded recursion, no silent rabbit holes.

---

## Working agreement (how you, Claude, behave here)

- **Plan before code.** For anything non-trivial, state the approach in 2–4 lines and
  which invariants/contracts it touches, then implement. No essays.
- **Respect the frozen spec.** If a task seems to require changing §10, *stop and flag
  it* with the tradeoff — don't quietly refactor a contract. Schema/interface changes
  are deliberate acts.
- **Small, verifiable increments.** One tool or one query at a time, validated against
  the corpus before moving on. Prefer a working `sql_sinks.sc` over a half-built five-tool
  skeleton.
- **Boring beats clever.** No speculative abstraction, no framework, no premature
  generality. Build the concrete thing the current phase needs. YAGNI is in force.
- **Determinism first.** Isolate all non-deterministic (LLM) logic behind a seam. The
  deterministic core must be testable with zero model calls.
- **Match the operator.** Immediate-to-expert audience: no hand-holding, no tutorials
  unless asked. Concise. Clean, performant code. `underscore_separated` filenames.
- **Own mistakes plainly.** If a query returns garbage or a design smells wrong, say so
  and propose the fix — no varnish.

---

## Joern playbook

The substrate spine. Get this right and most of the system follows.

- **Lifecycle.** `build (cache-miss) → load → warm-query*`. Key the CPG cache on a hash
  of the source tree; a source change invalidates the cache, nothing else does. Never
  rebuild inside a query burst.
- **Dataflow needs the overlay.** `reachableByFlows` requires the OSS dataflow overlay
  applied to the CPG. Confirm it's present before trusting any reachability result.
- **An empty result is ambiguous — always disambiguate.** No path can mean (a) genuinely
  no flow, or (b) the frontend never built the edge (unresolved call, dynamic dispatch,
  reflection, missing dependency), or (c) *no query can see this sink shape at all*.
  Before reporting "no vuln," verify the source and sink nodes actually exist in the CPG.
  A query that can't tell these apart is not done. This extends past queries: a tool that
  scanned nothing must not exit 0, and a manifest tree with no classes is a broken install,
  not a clean bill of health.
- **`reachableByFlows` returns representative paths, not all routes.** Proven on WebGoat
  Lesson8: the clean 61→62 route is never enumerated, only a detour through a `replace()`.
  So "no clean path was reported" is NOT "every route is sanitized" — that error makes a
  live vulnerability look safer. Scope any such count to what the engine returned and name
  the field accordingly (`reported_*`).
- **Node vocabulary is a hard boundary.** Every query today matches call nodes or annotated
  parameters. A sink that is neither — a JSX attribute, a template expression, a config key
  — cannot be reached by *any* manifest, only by a new query. Verified: `jssrc2cpg` builds a
  `.jsx` file happily and produces no node for `dangerouslySetInnerHTML` at all.
- **Portable-first matching** (§10.3). Match on method `.name` + a resolution step, not
  frontend-specific `methodFullName` regex. Java resolves cleanly; JS/Swift frontends are
  partial — expect gaps and validate empirically, tightening per-language only where the
  corpus proves it noisy.
- **Frontend maturity varies.** `javasrc2cpg` is solid; `jssrc2cpg` and `swiftsrc2cpg`
  are weaker. When a corpus fixture yields nothing, suspect the frontend before the query.
  Prove each frontend builds a usable CPG on its corpus repo early.
- **Queries are parameterized and generic.** The `.sc` script matches "call nodes with
  sink pattern P, non-constant arg N"; P comes from the pattern file, never inlined.
- **Performance.** Don't materialize huge node sets (`.l` on everything); constrain, then
  expand. Set query timeouts. Large CPGs are slow to load — that's why the server stays warm.
- **Every query is validated against ground truth before use.** Known-vuln fixture must
  light up; a clean control must stay dark. That pair is the query's test.

---

## Architecture guidance

- **Three layers, hard boundaries** (design §2): cognition (LLM) ↔ substrate
  (deterministic) ↔ memory (log). Dependencies point inward toward the log; nothing
  reaches across a layer except through the JSONL contract.
- **Tools own no state** beyond the log. Rerunnable, idempotent where facts are produced.
- **The manifest is the seam** between deterministic and reasoning layers: its
  `sources/sinks/sanitizers` drive queries, its `narrative/seed_hypotheses` drive the model.
- **Brief in batches, and say so.** The full WebGoat briefing is ~38k tokens; most
  models cannot hold it and none reasons well across it. `brief --chunk-size` batches it,
  and the header tells the agent it is holding a chunk — an agent given four cases must
  not conclude four is all there is. A batch that fails stops the pass: half a pass
  silently admitted is worse than none, because the log then looks complete.
- **Keep the model server warm**, for the same reason the Joern server stays warm.
  Reloading a 20GB model per batch costs more than the inference does.
- **`run_agent` is the seam, and the only one.** It spawns a command from
  `config/runners.yaml` and moves bytes; it makes no API call, holds no key, and names no
  vendor — a test fails if a provider or model name appears anywhere in `source_analyst/`.
  So "a tool wants to make an LLM call" is still a smell: the answer is to go *through*
  the seam, never to open a second one. `admit` remains the only door into the log, and
  it re-validates whatever comes back.
- **Only `trace` loops.** Keep iteration in one place; other agents are single-shot.
- **New capability decision tree:** is it factual ground truth? → substrate tool. Is it
  vuln knowledge? → manifest. Is it interpretation/selection? → agent prompt. Nothing
  else gets to be code.

---

## Testing discipline

- **Corpus is the test oracle.** Golden JSONL outputs per query per fixture. A query
  change that alters golden output is reviewed, not rubber-stamped.
- **Two-sided query tests.** Positive: the planted vuln appears. Negative: a sanitized
  control does not. Both required before a query is trusted. Build the two sides from the
  *same sink names*, so a query that passes by name-matching alone fails the test.
- **Invariant #3 is enforced mechanically**, not by review: `test_manifest.py` greps
  `source_analyst/**.py` and every query body for sink/source tokens. If you need one in
  code, you are about to break the manifest seam.
- **Determinism tests.** Same input → byte-identical facts. Re-running a query produces
  no duplicate facts (content-hash idempotence holds).
- **Projection tests.** Belief store rebuilt from the log equals the live projection;
  latest-wins keying on `subject+predicate+object` is exercised with a supersede case.
- **The deterministic core is tested with zero LLM calls.** Agent prompts are evaluated
  separately and empirically, never blocking the substrate's test suite.
- **Agents are measured, not tested.** `score` grades a run against a labelled corpus set
  (`corpus/ground_truth/<target>.<class>.yaml`). Three things it must never conflate, and
  neither may you: a case the agent *dropped* that was real (false negative), a labelled
  site the *substrate* never offered (a substrate gap, not a model miss), and a hypothesis
  about an *unlabelled* site (unscored, not correct). Grade on evidence facts, never on
  the `case` string the agent wrote about itself.
- **A prompt and a grammar that disagree fail silently.** Constrained decoding cannot
  emit a field the schema does not declare, so an instruction to produce one is
  unobeyable and *nothing errors*. Anything the agent prompt asks for must exist in
  `config/schemas/<agent>.json`, and a test parses the prompt's JSON example to enforce
  it. What the report must not omit belongs in `admit`'s required fields too: prompts
  request, the gate enforces.
- **A metric that cannot fail is decoration.** `score`'s `calibration` asks whether an
  agent's confidence tracks the evidence, and `agrees: false` must be reachable. It also
  keeps three nothings apart: constant confidence (the model expressed no opinion), a
  signal absent from the evidence (a substrate gap), and a signal present but never
  varying. Collapsing any of them into `0.0` reads as a measurement that was never made.
- **Keep the null baseline runnable.** `tests/stub_runner.py` judges nothing and scores
  0.885 precision with 0.0 confidence separation. A model that cannot beat it has added
  nothing, and that is only visible because the floor is a thing you can execute.

---

## Definition of done (a Phase 0/1 tool)

- Single responsibility; reads stdin, writes bare JSONL; provenance on each record.
- Validated on the corpus — positive and negative fixture both pass.
- Deterministic and idempotent where it emits facts; `v` present on every record.
- No hardcoded vuln knowledge; no cross-layer reach; no raw Joern from an agent path.
- Composes in a pipe with the tools before and after it.

---

## Stop-and-flag smells

Any of these means pause and raise it, don't code through it:

- You're about to hardcode a sink/source/sanitizer in code → manifest.
- You're about to let an agent emit raw Joern → named query instead (v1).
- You're about to change a record schema or the log format → deliberate `v` bump + note.
- A tool wants to make an LLM call → that belongs in an agent; keep tools deterministic.
- A query returns empty and you're about to call it "no vuln" → disambiguate first.
- You're about to emit a field that asserts something the substrate cannot prove
  (`sanitized`, `exploitable`, `unsanitized_path_exists`) → it's a belief, not a fact.
- An agent prompt names a vuln class ("SQL", "XSS") → it belongs in the manifest
  `narrative`; the prompt must work unchanged for the next class.
- You're adding an abstraction "for later" → YAGNI; build the concrete phase need.
- A fact is being asserted without a `src` → it's a hypothesis; label it.
