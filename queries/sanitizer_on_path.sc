// sanitizer_on_path — do candidate sanitizers sit on a source→sink flow? (design §10.3)
//
// **This query does not decide that anything is safe.** It reports which
// candidate sanitizers a tainted value passes through, and whether a route to
// the sink exists that passes through none. Whether `replace('\'', '"')`
// actually neutralises an injection is a *belief*, decided against the belief
// store (§4) with a src — never asserted here. WebGoat's SqlInjectionLesson8
// is the standing counter-example: a real escaping call on a still-vulnerable
// path. A query that emitted `sanitized: true` would launder that into a lie.
//
// **Nor does it prove a clean route is absent.** `reachableByFlows` enumerates
// *representative* paths, not every route. Verified on WebGoat: for the pair
// (SqlInjectionLesson8 name@43 -> executeQuery@62) the engine reports only a
// path that detours through log()'s replace() and back out to the call site;
// the direct route 61->62, which touches no sanitizer, is never enumerated.
// So "no clean path was reported" must never be read as "every route is
// sanitized" — that error makes a live vulnerability look safer. Every count
// below is therefore named `reported_*` and scoped to the engine's output.
//
// Endpoint selection is deliberately identical to reachable.sc so the two
// queries' facts join on the same (source, sink) pairs. If a third query needs
// this block, that is the signal to add an include mechanism — not before.
//
// params (sources — at least one of the two required):
//   annotations [string] regexes over parameter annotation short names
//   calls       [string] regexes over source-call short names
//   receivers   [string] optional — narrow `calls` by receiver type regex
// params (sinks):
//   sinks            [string] required — sink short-name regexes
//   full_name_filter [string] optional — regexes over methodFullName
//   arg_index        string   optional — sink argument to taint-check (default "1")
// params (sanitizers):
//   sanitizers       [string] required — regexes over call short names on the path
//   sanitizer_full_name_filter [string] optional — regexes over methodFullName
//   max_paths        string   optional — cap on emitted facts (default "500")
//
// emits kind=sanitizer_check, one fact per (source, sink) pair — including
// pairs where nothing matched, so the fact set joins 1:1 with reachable's and
// "no sanitizer here" is stated rather than inferred from absence.

import io.shiftleft.codepropertygraph.generated.nodes

val annotations = strList("annotations")
val calls = strList("calls")
val receivers = strList("receivers")
val sinks = strList("sinks")
val fullNameFilter = strList("full_name_filter")
val sanitizers = strList("sanitizers")
val sanitizerFilter = strList("sanitizer_full_name_filter")
val argIndex = str("arg_index", "1").toInt
val maxPaths = str("max_paths", "500").toInt

if (annotations.isEmpty && calls.isEmpty)
  throw new IllegalArgumentException(
    "sanitizer_on_path: at least one of `annotations` or `calls` is required")
if (sinks.isEmpty) throw new IllegalArgumentException("sanitizer_on_path: param `sinks` is required")
if (sanitizers.isEmpty)
  throw new IllegalArgumentException("sanitizer_on_path: param `sanitizers` is required")

def clip(s: String, n: Int = 300): String = if (s.length > n) s.take(n) + "…" else s

def receiverType(c: nodes.Call): String = c.receiver.headOption match {
  case Some(x: nodes.Identifier)        => x.typeFullName
  case Some(x: nodes.Call)              => x.typeFullName
  case Some(x: nodes.MethodParameterIn) => x.typeFullName
  case _                                => ""
}

def inCallOf(n: nodes.AstNode): Option[nodes.Call] = n match {
  case e: nodes.Expression => e.inCall.headOption
  case _                   => None
}

// ------------------------------------------------------------------ endpoints

val annotatedParams: List[nodes.CfgNode] =
  if (annotations.isEmpty) Nil
  else cpg.parameter.where(_.annotation.name(annotations*)).collectAll[nodes.CfgNode].l

val matchedCalls: List[nodes.Call] = if (calls.isEmpty) Nil else cpg.call.name(calls*).l
val sourceCalls: List[nodes.CfgNode] =
  (if (receivers.isEmpty) matchedCalls
   else matchedCalls.filter(c => receivers.exists(r => receiverType(c).matches(r))))
    .collectAll[nodes.CfgNode].l

val sourceNodes = annotatedParams ++ sourceCalls

val sinkCalls = cpg.call.name(sinks*).l
val selectedSinks =
  if (fullNameFilter.isEmpty) sinkCalls
  else sinkCalls.filter(c => fullNameFilter.exists(p => c.methodFullName.matches(p)))
val sinkArgs: List[nodes.CfgNode] =
  selectedSinks.flatMap(_.argument.find(_.argumentIndex == argIndex)).collectAll[nodes.CfgNode].l

val overlays = cpg.metaData.overlays.l
val hasDataflow = overlays.contains("dataflowOss")

val paths = if (sourceNodes.isEmpty || sinkArgs.isEmpty) Nil
            else sinkArgs.reachableByFlows(sourceNodes.iterator).l

// ------------------------------------------------------------------ sanitizers

val sanitizerRe = sanitizers.map(_.r)

/** Candidate sanitizer calls the value passes through on ONE path.
  *
  * A path element is a node the value flows through; the sanitizer is the call
  * that element sits inside (`action.replace(..)` appears as its argument), so
  * both the element and its enclosing call are considered.
  */
def sanitizersOn(els: List[nodes.AstNode]): List[ujson.Obj] = {
  val hits = els.zipWithIndex.flatMap { case (n, i) =>
    val candidates: List[nodes.Call] = (n match {
      case c: nodes.Call => List(c)
      case _             => Nil
    }) ++ inCallOf(n).toList
    candidates
      .filter(c => sanitizerRe.exists(_.matches(c.name)))
      .filter(c => sanitizerFilter.isEmpty || sanitizerFilter.exists(p => c.methodFullName.matches(p)))
      .map(c => (i, c))
  }
  hits
    .groupBy { case (_, c) => c.id }
    .toList
    .map { case (_, group) =>
      val (idx, c) = group.minBy(_._1)
      ujson.Obj(
        "name"       -> c.name,
        "full_name"  -> c.methodFullName,
        "file"       -> c.location.filename,
        "line"       -> c.lineNumber.map(_.toInt).getOrElse(-1),
        "step_index" -> idx,
        "code"       -> clip(c.code, 200),
        "resolved"   -> !c.methodFullName.toLowerCase.contains("unresolved")
      )
    }
    .sortBy(o => (o("step_index").num, o("file").str, o("line").num, o("name").str))
}

val grouped = paths
  .flatMap { p =>
    val els = p.elements
    for { s <- els.headOption; k <- els.lastOption } yield ((s.id, k.id), (s, k, els))
  }
  .groupBy(_._1)

val rows = grouped.toList.map { case (_, entries) =>
  val (srcNode, sinkNode, _) = entries.head._2
  val perPath = entries.map { case (_, (_, _, els)) => sanitizersOn(els) }
  // Union across every path for the pair, deduped on (file, line, name).
  val union = perPath.flatten
    .groupBy(o => (o("file").str, o("line").num, o("name").str))
    .toList
    .map { case (_, g) => g.minBy(_("step_index").num) }
    .sortBy(o => (o("step_index").num, o("file").str, o("line").num, o("name").str))
  val clean = perPath.count(_.isEmpty)

  ujson.Obj(
    "kind"                    -> "sanitizer_check",
    "subject"                 -> srcNode.location.methodFullName,
    "object"                  -> sinkNode.location.methodFullName,
    "source_name"             -> (srcNode match {
                                    case p: nodes.MethodParameterIn => p.name
                                    case c: nodes.Call              => c.name
                                    case _                          => "" }),
    "source_file"             -> srcNode.location.filename,
    "source_line"             -> srcNode.lineNumber.map(_.toInt).getOrElse(-1),
    "sink_name"               -> inCallOf(sinkNode).map(_.name).getOrElse(""),
    // Anchored on the call, matching sql_sinks and reachable, so facts join.
    "sink_file"               -> inCallOf(sinkNode).map(_.location.filename)
                                   .getOrElse(sinkNode.location.filename),
    "sink_line"               -> inCallOf(sinkNode).flatMap(_.lineNumber.map(_.toInt))
                                   .getOrElse(sinkNode.lineNumber.map(_.toInt).getOrElse(-1)),
    "sink_arg_index"          -> argIndex,
    // Counts over the paths the ENGINE REPORTED, not over all routes in the
    // program — see the header. A reader must be able to tell these apart, so
    // the field names say `reported_`.
    "reported_paths"                 -> entries.size,
    "reported_paths_with_sanitizer"  -> (entries.size - clean),
    "reported_paths_without_sanitizer" -> clean,
    "candidate_count"         -> union.size,
    "candidate_sanitizers"    -> ujson.Arr(union*)
  )
}

val ordered = rows.sortBy(r =>
  (r("sink_file").str, r("sink_line").num, r("source_file").str,
   r("source_line").num, r("source_name").str, r.render()))
val emitted = ordered.take(maxPaths)

emit(
  emitted,
  ujson.Obj(
    "sinks"             -> ujson.Arr(sinks.map(ujson.Str(_))*),
    "sanitizers"        -> ujson.Arr(sanitizers.map(ujson.Str(_))*),
    "arg_index"         -> argIndex,
    "dataflow_overlay"  -> hasDataflow,
    "source_nodes"      -> sourceNodes.size,
    "sink_arg_nodes"    -> sinkArgs.size,
    "paths_found"       -> paths.size,
    "pairs"             -> rows.size,
    // Disambiguation: zero sanitizer hits over zero flows says nothing about
    // sanitizers. Zero hits over N flows, with the sanitizer names present in
    // the CPG at all, is the informative case.
    "pairs_with_candidate"   -> rows.count(_("candidate_count").num > 0),
    "pairs_without_candidate"-> rows.count(_("candidate_count").num == 0),
    "sanitizer_calls_in_cpg" -> cpg.call.name(sanitizers*).size,
    // Machine-visible statement of the limitation above: consumers must not
    // infer route coverage from these counts.
    "paths_are_representative" -> true,
    "emitted"           -> emitted.size,
    "truncated"         -> (ordered.size > emitted.size),
    "cpg_calls"         -> cpg.call.size,
    "cpg_methods"       -> cpg.method.size,
    "cpg_files"         -> cpg.file.size
  )
)
