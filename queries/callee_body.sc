// callee_body — what does this method actually do? (design §4.1, Phase 2)
//
// Every query before this one answers a question about *edges*: is there a sink,
// a source, a path, a sanitizer on it. This one answers a question about *code*,
// and it exists because of a failure the first WebGoat run made visible: an agent
// that can only see a call site refutes on what things are named. Three exclusions
// in that report rested on the callee's package looking unrelated to databases —
// a guess about code nobody had read. A name is the weakest argument there is.
//
// **This query decides nothing.** It reports a method's own source, its parameters
// and their types, and the calls it makes. Whether `escape()` neutralises an
// injection is still a *belief*, argued from what is returned here and recorded
// with a rationale. A field like `sanitizes` would be exactly the overclaiming the
// rest of the substrate refuses.
//
// **An empty answer is four different answers** (§10.5), so every requested method
// comes back with a `status` that says which:
//
//   resolved            the method is in this source tree; `body` is its real text
//   external_stub       the frontend knows the signature but has no body — a
//                       library or a dependency outside the analysed tree. We know
//                       WHAT is called and nothing about what it does.
//   source_unavailable  in-tree with line numbers, but the file could not be read
//                       (a CPG built from a path that has since moved). Different
//                       from "no body" and must not read as one.
//   not_in_cpg          no method node carries this full name at all
//
// A caller that treats `external_stub` as "nothing there" has re-created the bug
// this query was written to fix — it is a gap in coverage, not evidence of safety.
//
// params:
//   methods    [string] required — exact method full names to look up
//   max_lines  string   optional — body lines per method (default "200")
//   max_calls  string   optional — calls listed per method (default "60")
//
// emits kind=callee_body, exactly one row per requested name, in the order asked.

import io.shiftleft.codepropertygraph.generated.nodes

val methods = strList("methods")
val maxLines = str("max_lines", "200").toInt
val maxCalls = str("max_calls", "60").toInt

if (methods.isEmpty)
  throw new IllegalArgumentException("callee_body: param `methods` is required")

def clip(s: String, n: Int = 500): String = if (s.length > n) s.take(n) + "…" else s

/** Same test the other queries use: a frontend that could not resolve a type says
  * so in the string, and `ANY` is not evidence in either direction. */
def typeResolved(t: String): Boolean =
  t.nonEmpty && t != "ANY" && !t.toLowerCase.contains("unresolved")

val root = cpg.metaData.root.headOption.getOrElse("")

/** The method's verbatim source. The CPG stores only the signature in `code`, so
  * the body has to come off disk — which is also why `source_unavailable` is a
  * status a caller can see rather than an empty string it has to guess about. */
def readBody(file: String, a: Int, b: Int): Option[(String, Int, Boolean)] = {
  if (root.isEmpty || file.isEmpty || a <= 0) return None
  val p = java.nio.file.Path.of(root, file)
  if (!java.nio.file.Files.isReadable(p)) return None
  try {
    val all = java.nio.file.Files.readAllLines(p)
    if (a > all.size) return None
    val end = math.min(math.max(b, a), all.size)
    val want = end - a + 1
    val take = math.min(want, maxLines)
    val text = all.subList(a - 1, a - 1 + take).toArray.map(_.toString).mkString("\n")
    Some((text, want, want > take))
  } catch { case _: Throwable => None }
}

def callsIn(m: nodes.Method): (List[ujson.Obj], Int) = {
  val all = m.ast.isCall.l.sortBy(c => (c.lineNumber.map(_.toInt).getOrElse(-1), c.order))
  val rows = all.take(maxCalls).map(c =>
    ujson.Obj(
      "name"        -> c.name,
      "full_name"   -> c.methodFullName,
      "line"        -> c.lineNumber.map(_.toInt).getOrElse(-1),
      "code"        -> clip(c.code, 200),
      // Operators are not noise for this class: `<operator>.addition` on strings
      // IS the concatenation that makes a statement injectable. Flagged, not dropped.
      "is_operator" -> c.name.startsWith("<operator>"),
      "resolved"    -> typeResolved(c.methodFullName)
    ))
  (rows, all.size)
}

def paramsOf(m: nodes.Method): List[ujson.Obj] =
  m.parameter.l.sortBy(_.index).map(p =>
    ujson.Obj(
      "index"         -> p.index,
      "name"          -> p.name,
      "type"          -> p.typeFullName,
      "type_resolved" -> typeResolved(p.typeFullName)
    ))

def row(fullName: String): ujson.Obj = {
  val hits = cpg.method.fullNameExact(fullName).l
  if (hits.isEmpty)
    return ujson.Obj(
      "kind" -> "callee_body", "full_name" -> fullName, "status" -> "not_in_cpg",
      "name" -> "", "signature" -> "", "file" -> "", "line_start" -> -1, "line_end" -> -1,
      "is_external" -> false, "return_type" -> "", "return_type_resolved" -> false,
      "body" -> "", "body_lines" -> 0, "body_truncated" -> false,
      "parameters" -> ujson.Arr(), "statements" -> ujson.Arr(),
      "calls" -> ujson.Arr(), "call_count" -> 0)

  val m = hits.head
  val file = m.file.name.headOption.getOrElse("")
  val a = m.lineNumber.map(_.toInt).getOrElse(-1)
  val b = m.lineNumberEnd.map(_.toInt).getOrElse(a)
  // A frontend stub: the signature is known, the implementation is not in this
  // tree. `<unknown>` is javasrc2cpg's filename for one.
  val isStub = m.isExternal || a <= 0 || file.isEmpty || file == "<unknown>"
  val (callRows, callTotal) = if (isStub) (Nil, 0) else callsIn(m)
  val body = if (isStub) None else readBody(file, a, b)
  val status =
    if (isStub) "external_stub"
    else body.map(_ => "resolved").getOrElse("source_unavailable")
  val stmts =
    if (isStub) Nil
    else m.body.astChildren.l.sortBy(_.order).map(n =>
      ujson.Obj("line" -> n.lineNumber.map(_.toInt).getOrElse(-1), "code" -> clip(n.code, 300)))

  ujson.Obj(
    "kind"                 -> "callee_body",
    "full_name"            -> m.fullName,
    "status"               -> status,
    "name"                 -> m.name,
    "signature"            -> m.signature,
    "file"                 -> (if (file == "<unknown>") "" else file),
    "line_start"           -> a,
    "line_end"             -> b,
    "is_external"          -> m.isExternal,
    "return_type"          -> m.methodReturn.typeFullName,
    "return_type_resolved" -> typeResolved(m.methodReturn.typeFullName),
    "body"                 -> body.map(_._1).getOrElse(""),
    "body_lines"           -> body.map(_._2).getOrElse(0),
    "body_truncated"       -> body.exists(_._3),
    "parameters"           -> ujson.Arr(paramsOf(m)*),
    // The CPG's own view of the body, which survives a source tree that moved.
    "statements"           -> ujson.Arr(stmts*),
    "calls"                -> ujson.Arr(callRows*),
    "call_count"           -> callTotal
  )
}

// One row per request, in the order asked: a name that matched nothing is stated,
// never omitted. A short answer would leave the caller inferring which of its
// questions went unanswered — the same silence the status field exists to break.
val rows = methods.map(row)

def countOf(s: String): Int = rows.count(_("status").str == s)

emit(
  rows,
  ujson.Obj(
    "requested"          -> methods.size,
    "resolved"           -> countOf("resolved"),
    "external_stub"      -> countOf("external_stub"),
    "source_unavailable" -> countOf("source_unavailable"),
    "not_in_cpg"         -> countOf("not_in_cpg"),
    "source_root"        -> root,
    "source_root_readable" -> (root.nonEmpty &&
      java.nio.file.Files.isReadable(java.nio.file.Path.of(root))),
    "max_lines"          -> maxLines,
    "max_calls"          -> maxCalls,
    "cpg_methods"        -> cpg.method.size,
    "cpg_files"          -> cpg.file.size
  )
)
