# js_juiceshop_codefixes — negatives somebody else wrote

Ten files copied verbatim from OWASP Juice Shop's `data/static/codefixes/`
(commit `1618a611b173b4bf114028e6e02549950606e29d`, MIT). Each challenge ships
several variants of the same function, exactly one marked `_correct`: the fix its
own maintainers consider right.

## Why these and not more of mine

Every other negative control in `corpus/fixtures/` was written by the same person
who wrote the query it is testing, on the same afternoon. That proves a query
matches the code its author was picturing. It cannot prove the query stays dark
on a fix somebody else thought of, and a negative you authored to pass is close
to no negative at all.

These were written by people who had never seen this tool.

## The two sides, and how strong each one is

**sqli — the strong form.** The pairs differ only in dataflow:

    dbSchemaChallenge_1.ts:5          "... LIKE '%"+criteria+"%' ..."   vulnerable
    dbSchemaChallenge_2_correct.ts:5  ":criteria" + { replacements }    fixed
    unionSqlInjectionChallenge_1.ts:6 `... ${criteria} ...`             vulnerable
    unionSqlInjectionChallenge_2_correct.ts:5  ":criteria" + replacements  fixed

Same sink (`models.sequelize.query`), same source (`req.query.q`), same file
shape. A query that matched on the sink name alone would fire on all four, so
only the dataflow result separates them — which is the property CLAUDE.md asks a
two-sided test to have.

**xss — the near-miss form, and it is weaker.** Here the fix REMOVES the sink:

    restfulXssChallenge_3.ts:46  this.sanitizer.bypassSecurityTrustHtml(product.description)
    restfulXssChallenge_1_correct.ts  — the call and its method are gone

The two files are otherwise ~95% identical, so this does test that the query is
firing on the sink rather than on the surrounding shape. It does NOT test
whether the query can tell a guarded sink from an unguarded one, because there is
no sink on the clean side to get wrong. Do not read an xss pass here as evidence
of the same quality as an sqli pass.

## What the substrate does with them (measured 2026-09-04, jssrc2cpg 4.0.604)

    sql_sinks  3 sink candidates — the 3 vulnerable xss files, none of the 3 fixed
    reachable  2 flows           — the 2 vulnerable sqli files, neither fixed one

And the measurement that shows the sqli side is not passing by luck. Run
`sql_sinks` with the sqli sink names — name matching, no dataflow — and all FOUR
sqli files come back:

    src/dbSchemaChallenge_1.ts:5                    query
    src/dbSchemaChallenge_2_correct.ts:5            query
    src/unionSqlInjectionChallenge_1.ts:6           query
    src/unionSqlInjectionChallenge_2_correct.ts:5   query

The sink is present on both sides and only `reachable` separates them. That is
the property CLAUDE.md asks a two-sided test to have, and here it is measured
rather than asserted.

## Not included: the three login challenges

`loginAdminChallenge`, `loginBenderChallenge` and `loginJimChallenge` are the
most interesting SQLi pairs in the set and all three are unusable. Their variants
are spliced fragments carrying one unclosed brace, so they do not parse
standalone: jssrc2cpg emits a CPG with zero files and exits 0. That is what
`cpg build`'s empty-CPG guard now refuses. If a future frontend parses them,
they belong here.
