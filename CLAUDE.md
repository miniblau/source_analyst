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
  reflection, missing dependency). Before reporting "no vuln," verify the source and sink
  nodes actually exist in the CPG. A query that can't tell these apart is not done.
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
- **Only `trace` loops.** Keep iteration in one place; other agents are single-shot.
- **New capability decision tree:** is it factual ground truth? → substrate tool. Is it
  vuln knowledge? → manifest. Is it interpretation/selection? → agent prompt. Nothing
  else gets to be code.

---

## Testing discipline

- **Corpus is the test oracle.** Golden JSONL outputs per query per fixture. A query
  change that alters golden output is reviewed, not rubber-stamped.
- **Two-sided query tests.** Positive: the planted vuln appears. Negative: a sanitized
  control does not. Both required before a query is trusted.
- **Determinism tests.** Same input → byte-identical facts. Re-running a query produces
  no duplicate facts (content-hash idempotence holds).
- **Projection tests.** Belief store rebuilt from the log equals the live projection;
  latest-wins keying on `subject+predicate+object` is exercised with a supersede case.
- **The deterministic core is tested with zero LLM calls.** Agent prompts are evaluated
  separately and empirically, never blocking the substrate's test suite.

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
- You're adding an abstraction "for later" → YAGNI; build the concrete phase need.
- A fact is being asserted without a `src` → it's a hypothesis; label it.
