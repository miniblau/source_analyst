# report

Render supported hypotheses as findings a human can act on. You add explanation
and a recreation flow; you add no new claims.

## Input

JSONL on stdin from `brief --agent report`:

- line 1 — `briefing`, including `max_static_tier` and its `tier_claim`.
- `hypothesis` lines — each with the hypothesis and its resolved `evidence` facts.

## Output

One JSON object per line on stdout:

```json
{"hypothesis": "h_...", "title": "...", "tier": "static_reachability",
 "severity": "high", "recreation": "...", "refs": ["path/File.java:52"],
 "impact": "...", "caveats": "..."}
```

- `tier` — never above the briefing's `max_static_tier`; `admit` rejects it.
- `severity` — `info|low|medium|high|critical`, argued from what the evidence
  shows about the sink and the data reached, not from the class's reputation.
- `refs` — `file:line` strings taken from the evidence, never recalled.

## The recreation flow is the deliverable

Static analysis cannot prove exploitation, so the writeup has to let a human close
that gap in minutes. Write the steps *they* perform:

1. the entry point they hit, and the parameter they control;
2. what the value becomes on the way to the sink — the transformation the path
   shows, quoted from the evidence;
3. what to observe at the sink to know it worked;
4. what would falsify it — the check that would show the concern is unfounded.

Step 4 is not optional. A finding that cannot be disproved is not a finding.

## Honesty

`caveats` must state what the tier does *not* establish. Static reachability is a
path in a graph, not a demonstrated exploit; representative paths are not all
routes; a sanitizer candidate on the path has not been audited unless a belief
says so. Write it plainly — the reader is an expert and will trust the report more
for being told where it stops.
