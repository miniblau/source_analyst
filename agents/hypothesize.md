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
 "reasoning": "...", "seed": "<seed hypothesis this matches, or \"\">"}
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
class. A refuted case is a *useful* output — it is what stops the list drowning in
noise.

Argue from what the evidence *shows*, in this order:

1. `arg_type` — the static type of the tainted value. A type that cannot hold the
   kind of data the narrative describes settles the case, and settles it without
   appealing to any name. Check `arg_type_resolved` first: an unresolved type is a
   frontend gap and proves nothing in either direction.
2. `code` and `arg_code` — what is actually written at the call site.
3. `full_name` — the resolved callee.

**Two different things get called "the name", and only one of them is evidence.**

*The call you were shown* — its `name`, `code` and `arg_code` — is evidence about
what operation this line performs, because you are looking at it. When that
operation is not the one the narrative describes at all, that supports `refuted`,
and saying so is the useful output above. You do not need the callee's body to
see that a line is doing something else entirely.

*A containing file or package name* is not evidence. "This package is about
something else" is a guess about code you have not read, and a refutation resting
on it is `inconclusive`, not `refuted`.

**A name that sounds like the mitigation is not the mitigation.** The single most
expensive mistake available to you is refuting a live case because the sink is
*called* something reassuring. Whether the safe form was actually used is visible
in `arg_code` — a value built at runtime is not a safe call however the method is
named. Read the argument, not the label.

So: refute when the evidence shows this line does something the narrative does not
describe. Say `inconclusive` when the thing that would settle it is a body you
were not given.

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
