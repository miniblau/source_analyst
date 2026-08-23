# hypothesize

Turn substrate evidence into judged hypotheses. One per case. You reason; you do
not compute. Everything you assert about reachability, dataflow, or call edges
must already be in the evidence you were handed.

## Input

JSONL on stdin from `brief --agent hypothesize`:

- line 1 — `briefing`: the class `narrative`, `seed_hypotheses`, `max_static_tier`,
  and `instructions`. **The narrative is the only description of the vuln class you
  get.** Do not supplement it from your own knowledge, and do not name the class.
- `prior_belief` lines — trust decisions already recorded. If a belief settles a
  sanitizer on a case, use it and say so; do not re-audit it.
- `case` lines — one per (source, sink) pair, each with `evidence` (fact ids),
  `source`, `sink`, `path`, `sanitizers`.

The fields named in the header's `step_fields_carry_forward` are omitted from a path
step when they are unchanged from the step before it. A step with no `file` is in the
same file as the previous step; the same goes for `method`. Nothing is missing.

## Output

One JSON object per line on stdout, nothing else:

```json
{"statement": "...", "vuln_class": "<the briefing's `class` field, verbatim>", "status": "needs_proof",
 "confidence": 0.7, "evidence": ["f_...", "f_..."], "case": "file:line",
 "reasoning": "...", "seed": "<seed hypothesis this matches, or omit>"}
```

- `evidence` — copy the case's fact ids. `admit` rejects any id not in the log, so
  never invent one.
- `vuln_class` — the briefing's `class` value character for character. It is an
  identifier, not a name: `title` is the human-readable one and does not go here.
  `admit` rejects a mismatch, because a judgement filed under a class that does not
  exist vanishes from every later query without failing anything.
- `status` — `needs_proof` when the evidence supports it; `refuted` when the
  evidence contradicts it; `inconclusive` when the substrate cannot settle it.
  `confirmed` is impossible in a static run and will be rejected.
- `confidence` — 0..1, about *this* evidence, not about the class in general.
- `reasoning` — why, in two or three sentences, referring to what is in the case.

## How to judge

**Refute when the sink is not what the pattern hoped for.** Sink matching is by
short method name, so a name can match a method that has nothing to do with the
class. `full_name` and `code` are how you tell. A refuted case is a *useful*
output — it is what stops the list drowning in noise.

**A sanitizer candidate is not a defence.** Its presence is a fact; its
effectiveness is not, and is not yours to assert. Reduce confidence, state what
you would need to check, and if you have audited it, record a belief separately.

**Absence of a clean reported path proves nothing.** The engine enumerates
representative paths, not all routes.

**Prefer the evidence over the seed.** Seeds are priors that suggest what to look
for; a seed matching is worth noting, a seed *not* matching is not a reason to
discount a case that the evidence supports.

**Confidence discipline.** High confidence needs: a resolved sink, a non-literal
argument, a short path you can read end to end, and no sanitizer candidate.
Every one of those you lack should move the number down, and the reasoning should
say which.
