# Source Code Review System — Design & Roadmap

An LLM-orchestrated, deterministic-backed system that reviews source code the way
a human assessor does: read → understand → pattern-match → hypothesize → branch →
prove. Static-only in v1; the goal is **N well-described hypotheses with manual
recreation flows**, not a black-box scanner.

---

## 0. Orientation (read this first)

**What this is.** A source-code review system that works like a human assessor:
read → understand → hypothesize → branch → prove. LLM agents orchestrate; a
deterministic substrate (Joern-centric) supplies ground truth; an append-only memory
accretes facts, hypotheses, trust decisions, and findings.

**Status.** Design frozen (§10). No code written yet. Next action = Phase 0 substrate.

**Operating contract.** `CLAUDE.md` governs *how* code gets written here (invariants,
Joern playbook, testing, architecture). Read it before writing anything. This doc is
*what* we're building; `CLAUDE.md` is *how*.

**Build order for the code session:**
1. `cpg` wrapper — Joern server lifecycle (build → cache → warm-query), plus one named
   query `sql_sinks.sc`, validated against WebGoat ground truth.
2. `belief` CLI — append to `log.jsonl` + latest-wins projection.
3. `manifest` + `detect` — class×language join (§10.1) driven by language detection (§10.2).

Then Phase 1 wires SQLi end-to-end (§8). Everything in §10 is locked — change it
deliberately, per `CLAUDE.md`.

**Design reading order:** §1 principles → §2 layers → **§10 frozen spec** (the contracts
you implement) → §3–5 for manifest / lifecycle / memory detail.

### 0.1 Repository layout (proposed)

```
repo/
  CLAUDE.md                # operating contract — read before writing code
  design_and_roadmap.md    # this file (the design)
  config/
    languages.yaml         # extension → language map (§10.2)
    depth.yaml             # branching budget + gates (§4.2)
  manifests/
    classes/               # language-agnostic vuln concepts (§10.1)
    patterns/<lang>/        # per-language sink/source/sanitizer patterns
  queries/                 # named Joern .sc scripts (§10.3) — fixed vocabulary
  tools/                   # single-purpose CLIs: cpg, belief, manifest, detect, …
  agents/                  # OpenCode subagent defs: orchestrator, hypothesize, trace, …
  corpus/                  # fixtures (WebGoat, Juice Shop, DVIA) + golden outputs
  var/                     # runtime: CPG cache, log.jsonl — XDG-style, gitignored
```

**Implementation language — decided 2026-08-14: Python + uv.** Follows `cve_hunter`'s
shape (uv + Python + XDG + subprocess orchestration + manual LLM gating). Applies to
everything under `tools/`; agents may differ later. Doesn't touch the design.

---

## 1. Principles

- **LLM is glue, tools do the work.** Reasoning, orientation, and query selection
  are the model's job. Ground truth (reachability, xref, call graphs) is the
  substrate's job. Never let the model *assert* a data-flow fact it didn't get
  from a tool.
- **Vuln knowledge is data, not code.** New vuln class = new manifest. No code change.
- **Everything accretes.** Append-only log + projected belief store. Iteration 2 is
  smarter than iteration 1 because trust decisions and facts persist.
- **UNIX composition.** Single-purpose CLIs, JSONL over stdin/stdout, deterministic
  logic strictly separated from the reasoning layer.
- **Expensive steps are manually gateable.** Same discipline as `cve_hunter`.

---

## 2. Three layers

```
┌─────────────────────────────────────────────────────────────┐
│ COGNITION (LLM, single-responsibility subagents)             │
│   orchestrator · hypothesize · trace · checkpoint · report   │
│   — reasons, selects queries, refines confidence, branches   │
└─────────────────────────────────────────────────────────────┘
                 │ tool calls (MCP or shell)   ▲ facts/beliefs
                 ▼                             │
┌─────────────────────────────────────────────────────────────┐
│ SUBSTRATE (deterministic ground truth)                       │
│   cpg (Joern) · struct_grep (ast-grep/opengrep) · lsp ·      │
│   entrypoints · git_risk · sbom · gjorda(MCP, iOS) · …       │
│   — answers factual queries, reasons about nothing           │
└─────────────────────────────────────────────────────────────┘
                 │ writes                       ▲ reads
                 ▼                             │
┌─────────────────────────────────────────────────────────────┐
│ MEMORY (append-only JSONL log + belief store projection)     │
│   facts · hypotheses · beliefs(trust) · findings             │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Substrate (hybrid: adopt mature, build the gaps)

| Tool            | Role                                              | Source        |
|-----------------|---------------------------------------------------|---------------|
| `cpg`           | Joern CPG: AST+CFG+data-flow+call-graph, reachability | wrap Joern |
| `struct_grep`   | structural sink/pattern search where Joern is blind (templates, HTML/CSS, config, Swift) | wrap ast-grep/opengrep |
| `lsp`           | precise xref / go-to-def / implementors           | per-language LSP |
| `entrypoints`   | enumerate routes, consumers, deserialization, IPC/CLI, per-framework | first-party |
| `git_risk`      | churn / recency / authorship risk scoring         | **first-party** |
| `sbom`          | dependency sinks                                  | wrap syft/etc |
| `gjorda`        | iOS/Swift where Joern doesn't reach               | MCP           |

**Joern gap policy:** Joern is the spine (covers JVM/Android + most API backends).
Where it's blind, `struct_grep` gives structural sink-finding (no data-flow), and
the **trace** agent stitches across the blind edge using the CPG on one side and
grep on the other (e.g. controller taints var → passed to template → grep confirms
unescaped render). Solve gaps only when a live engagement needs them.

Every substrate tool: `--query NAME --param k=v` in, JSONL out, no reasoning.

### 2.2 Cognition (see §5 topology)

Subagents, each one responsibility. Only **trace** loops.

### 2.3 Memory

Append-only JSONL is the audit trail (reproducibility). The **belief store** is a
latest-wins projection over the log, serving as working memory across iterations.

---

## 3. Vuln classes as data

The substrate does not know what SSRF *is*. A manifest is the contract between the
deterministic layer (drives queries) and the reasoning layer (drives narrative).

```yaml
# manifests/ssrf.yaml
id: ssrf
sources:            # cpg/struct_grep patterns for attacker-controlled input
  - request params, headers, body fields (per-framework)
sinks:              # dangerous operations
  - http client calls with non-constant URL/host
sanitizers:         # things that break the chain (candidates to audit, not trust)
  - allowlist checks, URL parsers with host validation
narrative: >        # fed to hypothesize/trace agents — the "why" and "how to think"
  SSRF requires attacker control over the destination of a server-side request.
  Watch for redirect following, DNS rebinding gaps, allowlist bypass via parser
  confusion, IMDS/metadata reachability once a request path is confirmed.
seed_hypotheses:    # optional priors that kick off branching (see §4 example)
  - "feature makes outbound requests to third-party systems"
```

- `sources` / `sinks` / `sanitizers` → **deterministic** substrate queries.
- `narrative` / `seed_hypotheses` → **LLM** reasoning.
- Existing 32-class prompt library is the seed corpus for these manifests.

---

## 4. Hypothesis lifecycle (the core loop)

```
proposed → investigating → needs_proof → { confirmed | refuted | inconclusive }
```

v1 static ceiling is `needs_proof` + a great writeup. `confirmed` is reserved for
later dynamic tiers (§6).

### 4.1 Branching — the deep-dig engine

Hypotheses form a **tree**. A verification step writes new *facts*; new facts spawn
*child* hypotheses. That branching is what produces depth beyond a 3-day black-box test.

Worked example (your SSRF chain):

```
H0  d0  "feature needs to call a third-party system"        (behavioral prior)
└─ H1 d1  "if it sends requests, the URL is not validated"   (spawned once H0 supported)
   └─ H2 d2  "if validated, allowlist bypassable via <parser-confusion>"
      └─ H3 d3  "confirmed request path reaches internal metadata endpoint"
```

Each node:

```jsonc
{
  "type": "hypothesis",
  "id": "h_...", "parent": "h_..." | null, "depth": 2,
  "statement": "...", "vuln_class": "ssrf",
  "status": "needs_proof",
  "confidence": 0.62,
  "evidence": ["f_...", "f_..."],      // fact refs from substrate
  "spawned_queries": ["cpg:callers", "cpg:implementors"],
  "ts": 0
}
```

### 4.2 Depth control (configurable + human-gated)

```yaml
# config: depth.yaml
depth:
  max: 4
  checkpoint_every: 2          # checkpoint agent interrupts at these depths
  spend_gate: rising_confidence # spawn child only if parent confidence >= threshold
budget:
  llm_calls_per_hypothesis: 6
  cpg_queries_per_trace: 20
```

- **spend_gate** — a level costs budget; you only descend when confidence rose,
  which starves rabbit holes and feeds promising chains.
- **checkpoint** — at `depth % checkpoint_every == 0`, the checkpoint agent emits a
  tree summary and asks `continue? [y / adjust-depth / prune-branch / stop]`.
  This is the "I'm this deep, continue?" behavior — manual gate on the expensive
  descent, same philosophy as manual LLM invocation elsewhere.

---

## 5. Memory: record types (append-only JSONL)

```jsonl
{"type":"fact","id":"f_1","kind":"calls","subject":"Ctrl.fetch","object":"HttpClient.get","src":"cpg:reachable","ts":0}
{"type":"hypothesis","id":"h_1","parent":null,"depth":0,"statement":"...","vuln_class":"ssrf","status":"proposed","confidence":0.4,"evidence":["f_1"],"ts":0}
{"type":"belief","id":"b_1","subject":"isAllowedUrl","predicate":"sanitizes","object":"ssrf","verdict":"sound","rationale":"host allowlist, no redirect follow","audited_by":"trace","ts":0}
{"type":"finding","id":"v_1","hypothesis":"h_1","tier":"static_trace","severity":"high","recreation":"...","refs":["path/file:line"],"ts":0}
```

- **fact** — deterministic, always traceable to a substrate query (`src`).
- **hypothesis** — LLM, tree-structured (§4).
- **belief (trust decision)** — the learning system. First time trace hits a
  sanitizer it audits it *once* and records a verdict; every later path through it
  is pruned automatically. `belief` is keyed on `subject+predicate+object`,
  latest-wins on projection. This is what stops false-positive drowning and makes
  later iterations smarter.
- **finding** — a `needs_proof` hypothesis rendered as recreation flow + code refs +
  verification `tier`.

The `belief` store projection is rebuildable from the log at any time → full
reproducibility and audit.

---

## 6. Verification tiers (report honesty)

Every finding carries its tier. Static-only is honest about being a hypothesis.

1. **static_reachability** — clean CPG path, no known sanitizer → *hypothesis*.
2. **static_trace** — LLM+xref confirms path under dynamic dispatch/reflection the
   raw CPG missed → *strong hypothesis*. **v1 ceiling.**
3. **dynamic_poc** — build target, drive source with payload, assert sink misbehavior
   → *confirmed*. Deferred.
4. **fuzz** — harness for parsers/format handlers. Deferred.

Mobile/web/API dynamic targets (your 9/10 case) make tier 3 attractive *later*, but
v1 stops at tier 2 by design.

---

## 7. OpenCode agent topology

```
orchestrator  (primary — "understands me")
  │  parses the question ("any SSRF here?"), picks manifest(s),
  │  drives the loop, owns budget/depth config, delegates
  ├── hypothesize   proposes hypotheses from manifest + substrate facts
  ├── trace  ◄─loops the deep-digger: requests specific substrate queries,
  │                checks beliefs, refines confidence, spawns children
  ├── checkpoint    depth-gate human-in-loop (§4.2)
  └── report        needs_proof → recreation flow + refs
```

`orchestrator` is the assistant you talk to. Only `trace` iterates. All of them
reach the substrate through the same JSONL tool contract (MCP or shell wrappers).

### Decomposition of "are there any SSRF here?"

```
orient       cpg built? entrypoints/framework enumerated? (cached)
load         manifests/ssrf.yaml
find         cpg: sink candidates (non-constant-URL http calls)
             cpg: source candidates (request-tainted)
             cpg: reachability source→sink
hypothesize  one record per surviving pair {status: proposed}
             + seed_hypotheses from manifest → tree roots
trace(loop)  per node: expand callers, resolve dispatch, audit sanitizers
             against belief store, refine confidence, spawn children,
             checkpoint at configured depth
report       per needs_proof: recreation flow + why + code refs + tier
```

---

## 8. Roadmap

**Phase 0 — Substrate foundations (no LLM).**
`cpg` wrapper (build+cache+named queries), `belief` CLI (append + projection),
`manifest` loader/validator. Everything JSONL. Prove the queries by hand.

**Phase 1 — One class, end-to-end, flat, static.**
SSRF manifest. orchestrator + hypothesize + report. No branching yet. Manual LLM
gating. Output: findings with recreation flows. *This is the first useful deliverable.*

**Phase 2 — Branching + learning.**
`trace` subagent, hypothesis tree, `spend_gate`, `checkpoint` subagent, belief-store
trust decisions. This is where it starts feeling like you.

**Phase 3 — Breadth.**
More manifests. `struct_grep` fallback for Joern-blind files. `git_risk` first-party
tool to prioritize churned/recent code. `gjorda` MCP for iOS.

**Phase 4 — Dynamic (deferred).**
Verification tier 3 against a defined target: harness generation, PoC execution,
`confirmed` findings.

---

## 9. Open questions (next iteration)

- Belief store scope: per-repo, or a shared cross-engagement corpus of sanitizer
  verdicts? (Cross-engagement = faster ramp, but soundness is framework/version-bound.)
- `trace` query vocabulary — **v1 resolved: fixed named `.sc` queries only** (cacheable,
  agent can't wander). Raw-Joern escape hatch deferred to a later phase.
- Confidence model: single scalar, or separate reachability-confidence vs
  exploitability-confidence? (The latter maps better to your manual triage.)

---

## 10. Phase 0 pre-build decisions (FROZEN SPEC)

Locked before the code session. Change these deliberately, not incidentally.

### 10.1 Vuln class × language matrix

Two orthogonal axes. A **class** is the language-agnostic concept; a **pattern file**
is its concrete realization in one frontend. Never conflate them — buffer-overflow
has no Node realization and must not carry a dead stub.

```
manifests/
  classes/
    sqli.yaml         # narrative, seed_hypotheses, applies_to: [java, js, swift, c]
    bof.yaml          # applies_to: [c, cpp]   ← never loads for a Node repo
  patterns/
    java/sqli.yaml    # Statement.execute*, PreparedStatement misuse, ...
    js/sqli.yaml      # db.query, knex.raw, sequelize literal, ...
    swift/sqli.yaml   # sqlite3_exec, ...
    c/bof.yaml        # strcpy, memcpy, sprintf, gets, ...
```

**Loader:** detect repo languages → for each class where
`class.applies_to ∩ repo_languages ≠ ∅`, load `classes/<class>.yaml` joined with
`patterns/<lang>/<class>.yaml` for the intersecting langs only.

- Add a language to a class → one new pattern file. Class untouched.
- Add a class → one concept file + patterns for the langs you care about.
- Both axes evolve independently; both stay data-not-code.

### 10.2 Language detection (explicit and boring)

Static extension map + a count. No linguist, no shell-out, no vendoring heuristics.
Output is **read and confirmed** before a run.

```yaml
# config/languages.yaml
java:  [.java]
js:    [.js, .jsx, .ts, .tsx]
swift: [.swift]
c:     [.c, .h]
```

`detect`: walk repo → count by extension via the map → emit
`{language, file_count}` JSONL, sorted desc. Wrong output is a one-line fix to the
map. Auto-detect-and-run is Phase 3+.

### 10.3 CPG query catalog (SQLi seed)

Named `.sc` files, one per query, parameterized. The query is generic; the sink/source
**pattern set comes from the pattern file** (§10.1). Fixed vocabulary — no raw Joern in v1.

```
queries/
  sql_sinks.sc          # Call nodes matching sink pattern P
  request_sources.sc    # request-tainted entry values
  reachable.sc          # dataflow source → sink
  callers.sc            # expand callers of a method
  implementors.sc       # resolve dynamic dispatch / interface impls
  arg_is_constant.sc    # prune: is arg N a compile-time constant?
  sanitizer_on_path.sc  # does a candidate sanitizer sit on the flow?
```

- **Matching posture: portable-first.** Prefer short-name + resolution over
  frontend-specific `methodFullName` regex; tighten per-language only where the corpus
  proves it noisy. (Java resolves cleanly; JS/Swift are partial — validate empirically.)
- Writing these against the corpus **is** the "get familiar with Joern" task.

### 10.4 JSONL contract

Single append-only `log.jsonl`. Bare records, one per line (`jq`/`awk`/`grep`-friendly).
Provenance on each record, not wrapped. Query/param metadata → stderr or `--meta`.

Every record carries:

| field | rule |
|-------|------|
| `v`   | schema version int — present on every record from day one |
| `ts`  | RFC3339, unified across all tooling (redundant with ULID time, kept for convenience) |
| `id`  | **facts = content-hash** (idempotent — identical facts dedupe) · **hypotheses / beliefs / findings = ULID** (time-sortable, unique) |
| `src` | provenance, e.g. `cpg:reachable` (facts always trace to a substrate query) |

Belief projection: latest-wins keyed on `subject + predicate + object`; rebuildable
from the log at any time.

### 10.5 Joern lifecycle

**Server mode.** CPG built once per repo, cached on disk, warm-queried by the `cpg`
wrapper. Lifecycle: `build (cache-miss) → load → warm-query*`. The `trace` agent's
20-query bursts hit a warm server, never a cold rebuild.

### 10.6 Corpus (fixtures + ground truth)

| repo        | stack          | validates            |
|-------------|----------------|----------------------|
| WebGoat     | Java / Spring  | SQLi dataflow (clean CPG) |
| Juice Shop  | Node / Express | SQLi, cross-language portability |
| DVIA        | iOS Obj-C/Swift| SQLi via sqlite, frontend edge cases |

Known-vuln repos double as regression fixtures: validate every query against ground
truth before trusting it on client code.

### 10.7 Class #1

**SQLi** — source and sink both live inside the CPG, so it validates the dataflow
spine cleanly across three languages without touching the template blind-spot. XSS is
class #2, deferred until `struct_grep` stitching exists (GraphQL/template work),
proving the "Joern-blind but JSONL-unified" path.
