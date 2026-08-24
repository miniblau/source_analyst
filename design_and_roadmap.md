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

**Status.** Design frozen (§10). **Phase 0 complete; Phase 1 complete and proven on a
local model.** `cpg` (Joern) and `struct_grep`
(opengrep) both emit facts; SQLi is validated on WebGoat from both substrates and their
sink inventories agree exactly. The dataflow spine is in: `request_sources` → `reachable`
→ `sanitizer_on_path` narrow 39 WebGoat sink candidates to 16 sites with a proven flow,
inter-procedural to 4 method hops. `manifest` + `detect` drive all four queries from
`manifests/patterns/java/sqli.yaml`, so no sink list is typed by hand. `belief` closes
Phase 0: one append-only `var/log.jsonl`, facts idempotent on content hash, trust
decisions latest-wins by log position.

**Phase 1 first pass is running end to end on WebGoat.** `brief` → agent → `admit` →
`render`: 26 cases briefed, 23 judged `needs_proof` and 3 refuted (the ProfileUpload
`execute` name collisions), one belief recorded against the Lesson8 `replace`, 23
findings rendered with recreation flows. `run_agent` now closes the loop: the model is
reached through a command named in `config/runners.yaml`, so the whole chain runs
unattended and — with the stub runner — under test with zero model calls. `score` closes
the other half: 16 labelled WebGoat sites, and the null-baseline stub measurably loses to
a real model (precision 0.885 vs 1.0, confidence separation 0.0).

**First local-model pass — 2026-08-23.** Qwen3-Coder-30B-A3B Q5_K_XL on the laptop,
7 batches of 4, zero malformed records across the run. Judgement was **26 for 26**,
including every discriminator the oracle was built around: `Assignment5:44` kept at 0.9
despite the sink being named `prepareStatement`, `Servers:50` (ORDER BY under
`mitigation/`), the second-order `log()` helper, and all three ProfileUpload name
collisions refuted at 1.0. So the substrate-plus-manifest briefing is enough for a 30B
local model to do this job — no source access, no retrieval, and no knowledge of the
class beyond the manifest `narrative`.

Final scorecard after the fixes below, 19.3 min (23.8 before the briefing trim):

```
scored 26/26   TP 23  TN 3  FP 0  FN 0
precision 1.0  recall 1.0  site_recall 1.0
skipped_other_class []   unlabelled 0   substrate gaps []
```

**Two confidence metrics, and why there are two.** `confidence.separation` compares the
mean confidence on kept-true against kept-noise. It is `null` on this run because the
model kept no noise — undefined exactly when a model is perfect, so it can rank two
mediocre models and cannot certify a good one. Do not read `null` there as a failure, and
do not read it as a pass either.

`calibration` is the one that stays defined: it reads the **kept set only** and asks
whether confidence moves with the evidence signals the agent was told to weigh, by rank
correlation. Signals and their expected direction live in `config/calibration.yaml` —
data, like everything else, and `direction` is the only judgement in the file. Measured:

```
              spread   sanitizer_candidates   path_length   methods_crossed
stub            0.00   (confidence constant — nothing to correlate)
Qwen3-Coder     0.35   rho -0.747  agrees     -0.719 agrees  -0.817 agrees
```

Three distinctions it refuses to blur: a **constant confidence** returns `null` with a
note rather than `0.0`, because "the model expressed no opinion" is not "measured, no
relationship"; a signal **absent from the evidence** is reported separately from a signal
**present but constant**, since the first is a substrate gap wearing a model result's
clothes; and `agrees: false` is reachable — a metric that cannot fail is decoration.

**What that pass caught in our own code — 2026-08-23.** It scored 22 of 26 and looked
flawless. Four judgements carried `vuln_class: "SQL injection"` — the class's human
*title* where its identifier belongs — and three separate layers let it through:
`admit` never checked the record agreed with the `--class` it was admitted under, so
correct judgements entered the log filed under a class that does not exist and vanished
from every query keyed on class; `score` filtered them out in silence; and because
`score` derived *reached-ness* from scored rows rather than from facts, it then reported
two sites as substrate gaps — blaming the tool for a data defect, the exact conflation it
was written to refuse. All three are fixed and pinned by tests. The lesson is the one the
architecture is built on: a partial result that validates is more dangerous than a loud
failure, so every filter must say what it removed.

**And what the report leg caught — 2026-08-23.** 23 findings, all correctly capped at
`static_reachability`, 713 lines of markdown with recreation flows. Every one of them was
missing `caveats`, the field that states what the tier does *not* establish — because
`config/schemas/report.json` set `additionalProperties: false` and never declared the
field the agent prompt demanded. Constrained decoding made an instruction impossible to
obey, and nothing failed: `render` printed a bare `**Caveats.**` heading and moved on.
`caveats` is now in the schema, required by `admit`, and a test parses the JSON example
out of every agent prompt and asserts the schema permits every field it names. (That test
immediately found a second instance: `seed` in `agents/hypothesize.md`.) The general
lesson: **a prompt and a grammar that disagree fail silently**, so the agreement has to be
checked mechanically rather than by reading both.

**Report opens with triage, and closes with what it dropped — 2026-08-24.** `render`
now leads with an *At a glance* table: findings bucketed by confidence band against
severity, plus the count of distinct sites (more findings than sites means several
tainted parameters reach one sink). Bands live in `config/triage.yaml` like every other
vocabulary; the last band must have `min: 0.0` or `render` refuses, because a finding
that falls through the summary is a finding the reader never learns exists. A missing
confidence is its own `unscored` bucket rather than being filed under the weakest band,
which would invent a judgement.

The refuted section is written for verification, not for the record. Exclusions are
listed **weakest refutation first** — the confidence shown is the agent's confidence *in
the refutation*, so the top of the list is where it was least sure it was right to drop a
path the substrate had already proven. Each carries its reasoning and its evidence ids,
and the site comes from the evidence facts rather than the `case` string the agent wrote
about itself (the same discipline `score` uses). A refutation is a model judgement; the
path underneath it is a fact, and the two must not be allowed to blur.

**Where a limit gets stated is a design decision — 2026-08-24.** The second report run
produced caveats on all 23 findings, and **none of them** mentioned that the engine
enumerates representative paths rather than all routes — the single most load-bearing
caveat in the system. That was the wrong layer, not a weak model: the limit is a property
of the engine, known deterministically, so `render` now states it in the report preamble
and attaches a per-finding **Sanitizer note** wherever the evidence carries sanitizer
candidates, naming them and saying plainly that a route with no sanitizer at all may exist
unreported. The note appears only where candidates exist — boilerplate on every finding
trains the reader to skip it. General rule: **if a caveat is derivable from the facts,
the renderer owes it; only case-specific judgement belongs to the agent.**

**Refutations must not rest on names — 2026-08-24.** The three ProfileUpload exclusions
were correct (`ProfileUploadBase.execute` is pure file I/O; no JDBC anywhere in the
package) but the agent reached that by arguing from the *package name*, having never been
shown the callee's body. Structurally the log could not tell "refuted because the code
does no SQL" from "refuted because the package is called pathtraversal" — and the second
is a guess about code nobody looked at. Two fixes:

* `reachable` now emits **`sink_arg_type`** and `sink_arg_type_resolved`. Sinks match on a
  short name, so the tainted argument's static type is what settles "is this the right
  kind of call at all" without appealing to naming. On WebGoat it separates cleanly: 23
  `java.lang.String` against 3 `MultipartFile`, and the three are exactly the known false
  positives. An unresolved type is explicitly *not* evidence — `ANY` from a frontend gap
  must never refute a live case.
* `render` states each refutation's **basis**: a resolved argument type, or "call site
  only — the callee's implementation was never examined… treat this exclusion as
  unverified". Derivable from the facts, so the renderer owes it.

`agents/hypothesize.md` now ranks the evidence — type, then code, then resolved callee —
and says plainly that a file or package name is not an argument, and that a refutation
which cannot be supported from the evidence is `inconclusive`, not `refuted`.

Reading a *called method's body* remains impossible for any agent: that needs a new query
and the `trace` loop, and is deliberately Phase 2. Until then nothing in the system can
find a sink inside a method the briefing did not quote.

**Known limit, load-bearing.** `reachableByFlows` enumerates *representative* paths, not
all routes (proven on WebGoat Lesson8: the clean 61→62 route is never returned). No tool
may therefore claim a flow is sanitized, and none does — `sanitizer_on_path` reports
candidates and scopes every count to `reported_*`.

**Substrate posture — decided 2026-08-20.** Two substrates, kept wired, with different
jobs. `struct_grep` leads: no build step, every language on day one, sub-3s on WebGoat.
`cpg` is what answers reachability, and nothing else can — opengrep has no call graph and
no inter-procedural dataflow, so §4.1 branching and the §7 `trace` loop stay Joern-bound.
Leading with patterns is a sequencing decision, not a replacement.

**Operating contract.** `CLAUDE.md` governs *how* code gets written here (invariants,
Joern playbook, testing, architecture). Read it before writing anything. This doc is
*what* we're building; `CLAUDE.md` is *how*.

**Build order for the code session:**
1. ~~`cpg` wrapper — Joern server lifecycle (build → cache → warm-query), plus one named
   query `sql_sinks.sc`, validated against WebGoat ground truth.~~ **done**
2. ~~`struct_grep` wrapper — opengrep, plus `rules/java/sqli.yaml`, validated against the
   same WebGoat ground truth.~~ **done**
3. ~~Dataflow spine — `request_sources.sc`, `reachable.sc`, `sanitizer_on_path.sc`, with a
   two-sided flow fixture (`corpus/fixtures/java_sqli_flow`).~~ **done**
4. ~~`manifest` + `detect` — class×language join (§10.1) driven by language detection
   (§10.2). `manifest params … | cpg query --params-from -` is the composition seam.~~ **done**
5. ~~`belief` CLI — append to `log.jsonl` + latest-wins projection, verdict vocabulary
   in `config/verdicts.yaml`.~~ **done — Phase 0 complete**

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
    tiers.yaml             # verification tiers + the queries each requires (§6)
    verdicts.yaml          # belief verdict vocabulary (§5)
    depth.yaml             # branching budget + gates (§4.2)
  manifests/
    classes/               # language-agnostic vuln concepts (§10.1)
    patterns/<lang>/        # per-language sink/source/sanitizer patterns
  queries/                 # named Joern .sc scripts (§10.3) — fixed vocabulary
  rules/<lang>/            # named opengrep rule sets (§10.3) — fixed vocabulary
  config/                  # vocabulary as data — nothing here is code:
                           #   tiers.yaml       verification tiers (§6)
                           #   hypothesis.yaml  lifecycle statuses (§4)
                           #   verdicts.yaml    belief verdicts (§5)
                           #   languages.yaml   extension → language (§10.2)
                           #   triage.yaml      report confidence bands
                           #   calibration.yaml signals `score` correlates confidence with
                           #   runners.yaml     the ONLY file that may name a model/provider
                           #   schemas/         per-agent constrained-decoding schemas
  source_analyst/          # single-purpose CLIs: cpg, struct_grep, manifest, belief,
                           #   brief, run_agent, admit, render, score — all deterministic
  agents/                  # agent prompts: hypothesize, report (orchestrator, trace, … later)
  corpus/                  # fixtures (WebGoat, Juice Shop, DVIA) + golden outputs
    ground_truth/          # labelled case sets — the oracle `score` measures agents on
  config/schemas/          # per-agent JSON schemas for constrained decoding
  tools/                   # runner shims and the chunked-pass loop — NOT the substrate
  var/                     # runtime: CPG cache, log.jsonl, agent_runs/ — gitignored
```

**Substrate prerequisites.** `joern` (4.0.604 validated) and `opengrep` (1.27.1
validated, `OPENGREP_BIN` to override) on PATH. Each substrate's test suite skips
cleanly when its binary is absent, so neither is required to work on the other.

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
| `struct_grep`   | breadth-first structural sink/pattern search — every language, no build step; also covers what Joern is blind to (templates, HTML/CSS, config, Swift) | wrap opengrep |
| `lsp`           | precise xref / go-to-def / implementors           | per-language LSP |
| `entrypoints`   | enumerate routes, consumers, deserialization, IPC/CLI, per-framework | first-party |
| `git_risk`      | churn / recency / authorship risk scoring         | **first-party** |
| `sbom`          | dependency sinks                                  | wrap syft/etc |
| `gjorda`        | iOS/Swift where Joern doesn't reach               | MCP           |

**Division of labour (measured, not assumed).** On WebGoat both substrates find the
*same 39 SQL sinks* at the same 39 `file:line` pairs — pattern search loses nothing on
sink inventory, at 2.6s and no CPG. They diverge on the *verdict*: opengrep's constant
propagation folds `String q = "SELECT …"; execute(q)` and `"a" + " ?"` down to literals,
cutting 24 candidates to 18 with no true positive lost. So `struct_grep` is the better
front door, and `cpg` earns its keep on the one thing patterns cannot do at all —
reachability. Neither is a substitute for the other.

### 2.1.1 Measured substrate coverage (2026-08-21)

Against the actual target profile — web apps (Python, .NET, PHP, React, Vue, Angular,
JS/TS, HTML/CSS) and mobile (Android Java/Kotlin, iOS Swift/Obj-C). Measured on this
install, not read off a docs page.

| Target | `struct_grep` (tier 0 leads) | `cpg` (tier 1 reachability) |
|---|---|---|
| Python — Django/Flask/FastAPI | ✅ | ✅ **verified**: `request.args.get` → `execute`/`os.system`, inter-procedural, zero code change |
| Java / Kotlin (incl. Android) | ✅ | ✅ `javasrc2cpg` proven on WebGoat; `kotlin2cpg`, `jimple2cpg` (APK bytecode) installed, unproven |
| PHP — Laravel/Symfony | ✅ | ⚠️ `php2cpg` installed, unproven. `$_GET` is a superglobal, not a call — likely needs a new source model |
| JS/TS — node/express | ✅ | ✅ non-JSX only |
| **React JSX** | ✅ | ❌ **JSX is not modelled at all** — verified: the CPG of a `.jsx` file contains no node for `dangerouslySetInnerHTML`, only `<operator>.assignment`, `fieldAccess`, `get`, `require`, `useSearchParams` |
| Vue SFC / Angular templates | ✅ (`vue`, `html`) | ❌ template not modelled (component TS/JS logic is) |
| **.NET / C#** | ✅ | ❌ **no frontend installed** |
| **iOS Swift** | ✅ | ❌ **no frontend installed** |
| Objective-C | ❌ | ❌ |
| HTML | ✅ | ❌ |
| CSS | ❌ | ❌ |

Plain-DOM JS sits between the extremes: `eval` and `document.write` are call nodes and
work with the existing queries today; `innerHTML =` exists as a `fieldAccess` node, so
it is reachable but needs a field-access sink query that does not exist yet.

**Consequence — this inverts the emphasis.** For this profile Joern covers roughly half
the surface, and the half it misses (React, Vue, Angular, .NET, iOS) is where a large
share of real review time goes. `struct_grep` is therefore the *breadth engine* and
`cpg` the *depth engine for a subset*. The "Joern-blind but JSONL-unified" path (§10.7)
is not a Phase 3 nicety here — it is the main path for most of the profile.

**Spec-vs-reality gaps to resolve:** §10.1 names `patterns/swift/sqli.yaml` and §10.6
puts DVIA in the corpus, but no Swift frontend is installed; same for C#. Both exist
upstream in Joern and were simply not packaged in this install. Establish whether they
can be added before the design leans on them further.

**C/C++ (checked, deprioritised):** `c2cpg` builds and sinks match (`strcpy` args come
back as `1:dst, 2:src`), but `reachable` returns nothing, because C taint arrives via
*out-parameters* — `fgets(buf, …)` fills arg 1 rather than returning — and `argv` is an
unannotated named parameter. Both need new source models (`argument N tainted after
call`, `parameter named X of function Y`), which is query work, not manifest work. Out
of scope for the current profile.

**Joern gap policy:** Joern is the reachability spine (covers JVM/Android + most API
backends).
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

The substrate does not know what SQLi *is*, and neither does any agent. A manifest is
the contract between the deterministic layer (drives queries) and the reasoning layer
(drives narrative).

Split on two axes (§10.1): the **class** is the language-agnostic concept, the
**pattern file** is its realization in one frontend. As built:

```yaml
# manifests/classes/sqli.yaml — no patterns live here
class: sqli
applies_to: [java, js, swift, c]
max_static_tier: static_reachability   # ceiling across languages (§6)
narrative: >                           # the "why" and "how to think" — LLM only
  A value the caller controls reaches a database engine as statement *text* rather
  than as a bound parameter...
seed_hypotheses:                       # priors that kick off branching (§4)
  - The tainted value lands in an identifier position (table, column, ORDER BY)
    where bound parameters are not usable...
```

```yaml
# manifests/patterns/java/sqli.yaml — named blocks whose INNER KEYS ARE QUERY
# PARAM NAMES, plus a binding of each named query to the blocks it takes.
sources:      {annotations: [RequestParam, ...], calls: [getParameter, ...]}
sinks:        {sinks: [executeQuery, ...], full_name_filter: [], arg_index: "1"}
sanitizers:   {sanitizers: [replace, escape.*, ...]}
queries:
  sql_sinks:         [sinks]
  reachable:         [sources, sinks]
  sanitizer_on_path: [sources, sinks, sanitizers]
rules: [java/sqli]                     # struct_grep rule sets
max_static_tier: static_reachability   # guarded: rejected unless the queries are bound
```

- `sources` / `sinks` / `sanitizers` → **deterministic** substrate queries. The loader
  merges the referenced blocks into a params object and never learns what a parameter
  *means*, so a new query is a line of YAML rather than a code change.
- `narrative` / `seed_hypotheses` → **LLM** reasoning. This is the only seam through
  which an agent learns what a class is; agents never name a class themselves.
- Composition seam: `manifest params … | cpg query --params-from -`.
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

**As built.** One append-only `var/log.jsonl`; the projection is recomputed on read, so
no cache exists that could drift from the log. Ids: facts are content hashes (so
re-running a query does not grow the log — `belief append` skips facts already present),
while beliefs/hypotheses/findings get ULIDs, because asserting the same belief twice is
two decisions and the second supersedes the first. **Latest-wins is decided by position
in the log**, never by `ts` or `id`: a clock that jumps backwards must not be able to
resurrect a superseded verdict. Superseding is reported, not silent, and the projection
carries `superseded_count`. Verdict vocabulary is data (`config/verdicts.yaml`):
`sound` / `unsound` / `partial` / `unknown`, each with a `prunes` flag.

---

## 6. Verification tiers (report honesty)

Every finding carries its tier. Static-only is honest about being a hypothesis.

0. **static_pattern** — a sink exists at a location, and that is the entire claim.
   Pattern search has no call graph, so *nothing* about reachability may be asserted
   from it → *lead, not yet a hypothesis*. Most `struct_grep` output starts here.
   **A tier-0 ceiling is not a weak finding.** React's `dangerouslySetInnerHTML` is
   an explicit opt-out of the framework's escaping — a strong lead — yet a JSX
   attribute is not a call node, so no current query can reach it. Such a class must
   report "never assessed for a path", never "no path found"; the second downgrades
   the lead by implying we looked.
1. **static_reachability** — clean CPG path, no known sanitizer → *hypothesis*.
2. **static_trace** — LLM+xref confirms path under dynamic dispatch/reflection the
   raw CPG missed → *strong hypothesis*. **v1 ceiling.**
3. **dynamic_poc** — build target, drive source with payload, assert sink misbehavior
   → *confirmed*. Deferred.
4. **fuzz** — harness for parsers/format handlers. Deferred.

Mobile/web/API dynamic targets (your 9/10 case) make tier 3 attractive *later*, but
v1 stops at tier 2 by design.

**The table is data** (`config/tiers.yaml`), and each tier declares the queries it
requires. A class×language may only claim a tier whose queries it binds, so a pattern
file for a sink shape no query can reach *cannot* declare `static_reachability` — the
loader rejects it. `manifest plan` reports the per-language ceiling and, when
reachability is not assessable, says so before anything runs.

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

**`agents/trace.md` — built 2026-08-24.** The loop. Each turn: the substrate reads
the methods a hypothesis touches (`callee_body`), the agent re-judges with the source
in front of it, and `admit --type trace` expands each revision into a child hypothesis
plus one belief per verdict. Three things make it safe to iterate:

  * **The reading list is not the agent's.** `brief --callees` derives it from the
    hypothesis's own facts. A model choosing what to read would be steering the
    deterministic layer, and a method name it invented would come back `not_in_cpg`
    looking like a fact about the code.
  * **A gap is not an acquittal.** `callee_body` distinguishes "the body says X" from
    "the body is outside the tree", and `admit` refuses a trust verdict whose subject
    was not actually *read* — citing an `external_stub` is not the same as reading it.
    That distinction is the whole reason the query has a `status` field.
  * **Depth costs something.** `config/depth.yaml` caps depth outright and, under
    `rising_confidence`, funds another level only where the last one made the case
    stronger. The stub runner keeps confidence flat and therefore cannot descend at
    all — a floor that could buy depth for free would not be a floor.

Adding a second level also changed what "the hypotheses" *means* to everything
downstream: a traced log holds one hypothesis per level per site, all at the same
status. `brief --agent report` and `score` now read **leaves**; `score --src` still
grades what a named producer said, superseded or not, because those are two different
questions and collapsing them would score the hypothesize leg at zero on any log that
had been traced.

**`agents/orchestrator.md` — written 2026-08-23.** Unlike the others it is a *driver*,
not a producer: it runs CLIs and emits no records, so it has no `config/schemas/` entry
and never passes through `admit`. Its prompt is mostly about the four ways a zero result
can arise (§10.5) and the duty to say which one applies, because "no findings" without
that sentence is the most expensive thing an orchestrator can output. It also has to
report `detect`'s coverage gaps *up front* — an operator must never infer an unrealized
language from a suspiciously short report at the end.

**Model-agnostic by construction — decided 2026-08-21.** No provider, model name,
API key or SDK appears anywhere in `source_analyst/`; an agent is a markdown prompt
plus JSONL in and JSONL out. So each agent can be pointed at whatever model suits it
— a local model at the desk, a hosted one for the harder judgement — and swapping
one changes no code. `brief` fixes what an agent may see and `admit` fixes what it
may assert, which is what makes a weaker or unfamiliar model *safe* to use here: a
hallucinated fact reference is rejected at the door rather than trusted. Intended
runner is OpenCode; nothing in the design depends on it.

**The seam is `run_agent` — built 2026-08-22.** It spawns a command from
`config/runners.yaml`, writes the agent prompt plus the briefing to its stdin, and reads
JSON objects off its stdout; that file is the only place in the repo where a provider or
model name may appear, and `tests/test_run_agent.py` fails if one leaks into code. Prose
around the JSON is discarded and *counted* (`discarded_lines` in the run meta) rather
than quietly cleaned up — how much slop a model produces is a fact about that model.
Every run writes a transcript to `var/agent_runs/<ulid>.<agent>.txt` holding the exact
bytes in and out, because a nondeterministic step needs provenance a surprising
hypothesis can be traced back to. Two outcomes are non-zero exits, deliberately: a runner
that failed, and a runner that produced no records at all — the second would otherwise
reach `admit` looking like a model that judged there was nothing to say.

**The null baseline.** `tests/stub_runner.py` is a runner that emits one undifferentiated
`needs_proof` per case and judges nothing. It exists so the chain is testable without a
model, and so model comparison has a floor: a model that produces the same rows as the
stub has added nothing, which is only visible if the stub is something you can run.

**Runner catalog.** `openai_compat` is the one that matters: `tools/openai_chat.py` is a
stdlib shim onto any OpenAI-compatible `/chat/completions`, so llama.cpp's `llama-server`,
Ollama's `/v1`, LM Studio, vLLM, an internal gateway and a hosted API are all the same
runner with a different `LLM_BASE_URL`. Which server answers is **environment, not a line
in the repo** — that is what lets the same setup follow you from the desk to work. There
is a `_free` variant with no constrained decoding, `ollama` for its own CLI, and
`opencode` for §7's intended host.

**Constrained decoding — `config/schemas/<agent>.json`.** With `--schema` the request
asks the endpoint to constrain output and the shim flattens `{"records": [...]}` into
JSONL. This takes "did the model remember the output format" out of the measurement, so a
scorecard reports judgement rather than formatting. It is **never** retried unconstrained
on rejection: a silent downgrade would mean scoring a setup you did not think you ran.
A test asserts each schema's required fields are a superset of what `admit` demands and
that its enums match the config vocabulary, so schema and gate cannot drift apart.

**Chunking — `brief --chunk-size N --chunk I`, added 2026-08-22.** The full WebGoat
briefing is ~38k tokens (115KB; path `steps` carry code), which most models cannot hold
and none reasons well across. Seven batches of four are ~9k tokens each. Batching is
lossless — the chunked stub pass scores identically to the unchunked one — and the header
carries `chunk: {index, of, rows, rows_total}` so an agent handed four cases does not read
that as the whole set. `brief --chunks` prints the batch count as a bare integer so a
shell driver can loop without parsing JSON; `tools/pass.sh` is that loop.

```
llama-server -m <model>.gguf -c 32768 --host 127.0.0.1 --port 8080   # keep it WARM
export LLM_BASE_URL=http://127.0.0.1:8080/v1 SOURCE_ANALYST_RUNNER=openai_compat
tools/pass.sh hypothesize sqli java 4
tools/pass.sh report      sqli java 6
score --class sqli --target webgoat --src agent:hypothesize
```

The model server stays warm across batches for the same reason the Joern server does:
reloading a 20GB model per batch costs more than the inference.

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

**Phase 0 — Substrate foundations (no LLM). ✅ COMPLETE.**
`struct_grep` (opengrep + named rule sets), `cpg` (build+cache+named queries, four
queries: `sql_sinks`, `request_sources`, `reachable`, `sanitizer_on_path`), `manifest`
loader/validator + `detect`, `belief` (append + latest-wins projection). Everything
JSONL, every query proven two-sided against the corpus.

**Phase 1 — One class, end-to-end, flat, static.**
**SQLi**, not SSRF: §10.7 freezes SQLi as class #1, and it is the class that is built
and corpus-validated. (An earlier draft of this line said SSRF; §10 wins on contracts.)
orchestrator + hypothesize + report. No branching yet. Manual LLM gating. Output:
findings with recreation flows. *This is the first useful deliverable.* Built:
`brief` → `run_agent` → `admit` → `render` → `score`, proven end to end on WebGoat and
in test against the stub runner. `agents/orchestrator.md` written 2026-08-23.
**Phase 1 is complete.**

A second model was run against the same 348-fact substrate on 2026-08-24, and the
apparatus discriminated — which is the whole reason for having it. See §8.1.

Phase 1 deliberately runs against **one class in one language**. The agent layer is the
only nondeterministic component in the system; introducing it against a substrate whose
every output is byte-reproducible means anomalies are attributable to the model rather
than to a frontend gap, a bad rule, and a hallucination at once. WebGoat SQLi is also a
*labelled* set — 16 flows, 3 known false positives from the generic `execute` name, one
known-ineffective sanitizer, one second-order case — so the hypothesizer can be scored,
not just eyeballed. Breadth waits (decided 2026-08-21).

**Guard against over-fitting:** agents read `narrative` / `seed_hypotheses` from the
manifest and must never name a vuln class themselves. If a prompt contains the word
"SQL", that is a bug. The running check is "would this prompt work unchanged for SSRF?"

**Phase 2 — Branching + learning. IN PROGRESS (started 2026-08-24).**
`trace` subagent, hypothesis tree, `spend_gate`, `checkpoint` subagent, belief-store
trust decisions. This is where it starts feeling like you.

Built: `queries/callee_body.sc` (a method's real source, its parameters' resolved
types, and the calls it makes — with a `status` separating `resolved` from
`external_stub` / `source_unavailable` / `not_in_cpg`, because an empty answer is
four different answers); `agents/trace.md` + `config/schemas/trace.json`;
`brief --agent trace` and its `--callees` reading-list emitter; `admit --type trace`,
which expands one revision into a child hypothesis plus one belief per verdict;
`config/depth.yaml`; `tools/trace.sh`, the draining loop.

The reading list is chosen by the substrate, never by the agent — the sink, the
sanitizer candidates, and every method the flow passes through. That last part was
not the obvious design and the corpus corrected it: on WebGoat SQLi every sink and
every sanitizer candidate resolves into `java.sql` or `java.lang` and has no body in
the tree, so a list of those alone returns eight stubs and teaches the agent nothing.
27 of 35 in-tree methods resolve, including `SqlInjectionLesson8.log()`.

Not yet built: the `checkpoint` agent (the human-in-loop depth gate, §4.2 — the value
is in `config/depth.yaml` and read by nothing; a run today is bounded by `max` and the
spend gate alone), and re-tracing at `--status refuted` has the machinery but has not
been run against a real model.

**Phase 3 — Breadth.**
More manifests and rule sets (js, swift). Cross-substrate stitching for Joern-blind
files. `git_risk` first-party tool to prioritize churned/recent code. `gjorda` MCP
for iOS.

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
- Calibration signal selection — **deferred by decision (2026-08-24).**
  `config/calibration.yaml` is data and `score` already reports rho per signal, so a
  sweep costs no code. But WebGoat is a teaching corpus: one class, one language, sinks
  shaped to be found, and no negatives among the kept set — which is exactly why
  `mean_on_noise` and `separation` come back null. Selecting a metric there optimises
  against a set that has nothing to discriminate. Revisit once >=2 classes and >=2
  languages are live on a target that resembles an application rather than a lesson
  plan, and hold targets out of the sweep: best-of-N over 23 points selects noise.

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
  sql_sinks.sc          # ✅ built — call nodes matching sink pattern P
  request_sources.sc    # ✅ built — request-tainted entry values (annotations + calls)
  reachable.sc          # ✅ built — dataflow source → sink
  sanitizer_on_path.sc  # ✅ built — does a candidate sanitizer sit on the flow?
  callers.sc            # not built — expand callers of a method (needed for tier 2)
  implementors.sc       # not built — dynamic dispatch / interface impls (tier 2)
  arg_is_constant.sc    # not built — prune: is arg N a compile-time constant?
                        #   (partly redundant: sql_sinks already emits arg_is_literal)
```

**Known engine limit, load-bearing.** `reachableByFlows` enumerates *representative*
paths, not every route. Proven on WebGoat: for (`SqlInjectionLesson8` `name@43` →
`executeQuery@62`) the engine returns only a path detouring through `log()`'s
`replace()` and back out to the call site — the direct route 61→62, which touches no
sanitizer, is never enumerated. Therefore **no tool may claim a flow is sanitized, and
none does**: `sanitizer_on_path` reports candidates and scopes every count to
`reported_*`, with `meta.paths_are_representative` stating the limit machine-visibly.
An earlier draft emitted `unsanitized_path_exists`, which would have reported `false`
there — making a live vulnerability look safer.

- **Matching posture: portable-first.** Prefer short-name + resolution over
  frontend-specific `methodFullName` regex; tighten per-language only where the corpus
  proves it noisy. (Java resolves cleanly; JS/Swift are partial — validate empirically.)
- Writing these against the corpus **is** the "get familiar with Joern" task.

#### Rule catalog (`struct_grep`)

The opengrep half of the fixed vocabulary. Named YAML rule sets at
`rules/<lang>/<class>.yaml`, selected by name — agents never hand the tool rule text,
exactly as they never hand `cpg` raw Joern.

```
rules/
  java/sqli.yaml        # java_sql_sink (inventory) + java_sql_sink_dynamic (candidates)
```

- **The rule *is* the pattern file.** All vuln knowledge lives here; `struct_grep`
  contains none (invariant #3). Rule `metadata.kind` / `metadata.vuln_class` are
  promoted onto the fact, the rest rides along in `rule_meta` unread.
- **Deliberately two rules per class:** a full inventory, and the subset that survives
  a constant-folding filter. The inventory is what makes an empty candidate set legible
  — you can see the sinks were found and then excluded, rather than never seen.
- **Bind the first argument at any arity** (`$R.m($SQL, ...)`, not `$R.m($SQL)`). The
  arity-1 form silently drops overloads like
  `prepareStatement(sql, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)` — a real WebGoat
  SQLi. The corpus caught this; a rule review would not have.
- Kept separate from `manifests/patterns/` for now: opengrep validates rule files
  strictly, so a dual-consumer file (Joern sink lists + opengrep rules in one YAML) is
  a decision for when the manifest loader is real (§10.1), not before.

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

**Status.** WebGoat is cloned at the pinned commit and is the live oracle for all four
queries. Juice Shop is **not yet cloned**; DVIA is **blocked** — no Swift frontend is
installed (§2.1.1). Two in-repo fixtures carry the two-sided controls that WebGoat
cannot: `corpus/fixtures/java_sqli_min` (sink inventory, literal vs runtime-built) and
`corpus/fixtures/java_sqli_flow` (dataflow — a tainted path, a sanitized-but-still-
flowing path, plus bound-parameter, constant-only and sink-less negatives, all sharing
the same sink names so only dataflow separates them).

Golden files hold facts with `ts` stripped; `UPDATE_GOLDEN=1` regenerates, and drift is
reviewed rather than rubber-stamped.

**Labelled case set — added 2026-08-22.** `corpus/ground_truth/webgoat.sqli.yaml` labels
all 16 sink sites the substrate reports on the pinned commit: 13 `vulnerable`, 3
`not_this_class` (the ProfileUpload file-upload `execute`). Every label was settled by
reading the method at the cited line and carries a `why`, so it can be argued with rather
than trusted; five carry a `discriminator` naming what a careless reasoner gets wrong
there — `prepareStatement` with the parameters already concatenated (Assignment5:44), a
sanitizer candidate that only *detects* a UNION (6a:72), a half-bound statement (5b:48),
the second-order `log()` helper (8:142), and an ORDER BY under `mitigation/` (Servers:50).
This is what `score` reads; agents are **measured** against it, not tested.

### 10.7 Class #1

**SQLi** — source and sink both live inside the CPG, so it validates the dataflow
spine cleanly across three languages without touching the template blind-spot. XSS is
class #2, deferred until `struct_grep` stitching exists (GraphQL/template work),
proving the "Joern-blind but JSONL-unified" path.
