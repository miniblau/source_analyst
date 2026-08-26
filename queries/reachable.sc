// reachable — dataflow from a request source to a sink argument (design §10.3).
//
// The dataflow spine. Everything else in the SQLi path produces *candidates*;
// this is the only query that produces evidence a value actually travels. It
// knows nothing about SQL or about Spring — both pattern sets are params.
//
// Requires the `dataflowOss` overlay on the CPG (`cpg status --overlays`).
// Without it `reachableByFlows` yields nothing and the emptiness is a lie;
// meta.dataflow_overlay carries the answer so a caller can never miss it.
//
// params (sources — at least one of the two required):
//   annotations [string] regexes over parameter annotation short names
//   calls       [string] regexes over source-call short names
//   receivers   [string] optional — narrow `calls` by receiver type regex
// params (sinks):
//   sinks            [string] required — sink short-name regexes
//   full_name_filter [string] optional — regexes over methodFullName
//   arg_index        string   optional — sink argument position(s) to taint-check,
//                             comma-separated for several ("0,1,2"); default "1"
//   max_paths        string   optional — cap on emitted facts (default "500")
//
// emits kind=flow, one fact per distinct (source, sink) pair carrying the
// SHORTEST path between them. Multiple paths to the same pair are one finding
// for a reviewer, not N; `path_count` says how many the engine found.

import io.shiftleft.codepropertygraph.generated.nodes

val annotations = strList("annotations")
val calls = strList("calls")
val receivers = strList("receivers")
val sinks = strList("sinks")
val fullNameFilter = strList("full_name_filter")
// SINK GROUPS. Different sink shapes carry their taint in different places, and a
// single position per class means the class matches only the shape its corpus
// happens to use — path_traversal was pinned to the receiver because that is
// WebGoat's lesson, which made every static path API invisible. One list of
// positions for the whole class fixed the blindness but probed every sink at every
// position, so a static call got asked about its receiver and a constructor about
// the object being built: harmless, and noise.
//
// A group is {sinks, full_name_filter, arg_index} and each is matched only where
// its taint actually lands. `sinks`/`full_name_filter`/`arg_index` at the top level
// still work and mean exactly what they did — they are read as a single group — so
// a manifest that never needed groups changes nothing.
case class SinkGroup(sinks: List[String], filter: List[String], indices: List[Int])

def parseIndices(s: String): List[Int] =
  s.split(",").map(_.trim).filter(_.nonEmpty).map(_.toInt).toList

val sinkGroups: List[SinkGroup] = objList("sink_groups") match {
  case Nil => List(SinkGroup(sinks, fullNameFilter, parseIndices(str("arg_index", "1"))))
  case gs  => gs.map { g =>
    SinkGroup(
      g.obj.get("sinks").map(_.arr.map(_.str).toList).getOrElse(Nil),
      g.obj.get("full_name_filter").map(_.arr.map(_.str).toList).getOrElse(Nil),
      parseIndices(g.obj.get("arg_index").map(_.str).getOrElse("1")))
  }
}
val argIndices: List[Int] = sinkGroups.flatMap(_.indices).distinct.sorted
val maxPaths = str("max_paths", "500").toInt

if (annotations.isEmpty && calls.isEmpty)
  throw new IllegalArgumentException(
    "reachable: at least one of `annotations` or `calls` is required")
if (sinkGroups.forall(_.sinks.isEmpty))
  throw new IllegalArgumentException(
    "reachable: `sinks` (or a non-empty `sink_groups`) is required")

def clip(s: String, n: Int = 300): String = if (s.length > n) s.take(n) + "…" else s

def receiverType(c: nodes.Call): String = c.receiver.headOption match {
  case Some(x: nodes.Identifier)        => x.typeFullName
  case Some(x: nodes.Call)              => x.typeFullName
  case Some(x: nodes.MethodParameterIn) => x.typeFullName
  case _                                => ""
}

// Static type of the value that lands in the sink argument. Reported because a
// sink is matched on a SHORT NAME, so a name can match a method that has nothing
// to do with the class — and the argument's type settles that without appealing
// to what anything is called. Proven on WebGoat: the three ProfileUpload
// `execute` collisions take a MultipartFile, which cannot be statement text,
// while the package name that was used to dismiss them proves nothing at all.
def typeOf(n: nodes.AstNode): String = n match {
  case x: nodes.Identifier        => x.typeFullName
  case x: nodes.Call              => x.typeFullName
  case x: nodes.Literal           => x.typeFullName
  case x: nodes.MethodParameterIn => x.typeFullName
  case x: nodes.MethodRef         => x.typeFullName
  case x: nodes.TypeRef           => x.typeFullName
  case _                          => ""
}

// An unresolved type is NOT evidence of anything. `javasrc2cpg` yields ANY for a
// value it could not resolve, and reading that as "not a string" would refute a
// live case on a frontend gap. Callers must check this before arguing from type.
def typeResolved(t: String): Boolean =
  t.nonEmpty && t != "ANY" && !t.toLowerCase.contains("unresolved")

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

// Selection is per group, so a group's filter narrows only its own sinks.
def selectFor(g: SinkGroup) = {
  val calls = if (g.sinks.isEmpty) Nil else cpg.call.name(g.sinks*).l
  if (g.filter.isEmpty) calls
  else calls.filter(c => g.filter.exists(p => c.methodFullName.matches(p)))
}
val selectedSinks = sinkGroups.flatMap(selectFor).distinctBy(_.id)
val sinkCalls = selectedSinks
// The sink node for dataflow is the ARGUMENT, not the call: we are asking
// whether tainted data lands in the statement text, not whether the call runs.
// Each (call, position) pair is its own sink: taint into argument 1 and taint into
// argument 2 of the same call are different facts about different values. The index
// is carried alongside so each flow can report the position it actually landed in,
// which keeps `sink_arg_index` a single number and the record schema untouched.
val sinkArgPairs =
  sinkGroups.flatMap { g =>
    selectFor(g).flatMap(c => g.indices.flatMap(i =>
      c.argument.find(_.argumentIndex == i).map(a => (a, i))))
  }.distinctBy { case (a, _) => a.id }
val argIndexOf: Map[Long, Int] = sinkArgPairs.map { case (a, i) => (a.id, i) }.toMap
val sinkArgs: List[nodes.CfgNode] =
  sinkArgPairs.map(_._1).collectAll[nodes.CfgNode].l

// ------------------------------------------------------------------ dataflow

val overlays = cpg.metaData.overlays.l
val hasDataflow = overlays.contains("dataflowOss")

val paths = if (sourceNodes.isEmpty || sinkArgs.isEmpty) Nil
            else sinkArgs.reachableByFlows(sourceNodes.iterator).l

// A path endpoint arrives typed as AstNode; only an Expression sits inside a
// call, so the enclosing sink call is recovered by narrowing, not assumed.
def inCallOf(n: nodes.AstNode): Option[nodes.Call] = n match {
  case e: nodes.Expression => e.inCall.headOption
  case _                   => None
}

def step(n: nodes.AstNode): ujson.Obj = ujson.Obj(
  "label"  -> n.label,
  "file"   -> n.location.filename,
  "line"   -> n.lineNumber.map(_.toInt).getOrElse(-1),
  "method" -> n.location.methodFullName,
  "code"   -> clip(n.code, 200)
)

// Key on (source, sink) node ids: the engine reports every distinct path, but a
// reviewer opens one file:line pair. Keep the shortest path as the exhibit and
// count the rest — tie broken on the serialized steps so the choice is stable.
case class Cand(steps: List[ujson.Obj], len: Int, key: String)

val grouped = paths
  .flatMap { p =>
    val els = p.elements
    for {
      s <- els.headOption
      k <- els.lastOption
    } yield ((s.id, k.id), (s, k, els))
  }
  .groupBy(_._1)

val rows = grouped.toList.flatMap { case (_, entries) =>
  val (srcNode, sinkNode, _) = entries.head._2
  val cands = entries.map { case (_, (_, _, els)) =>
    val steps = els.map(step)
    Cand(steps, els.size, steps.map(_.render()).mkString("|"))
  }
  val best = cands.sortBy(c => (c.len, c.key)).head
  val srcAnnotations = srcNode match {
    case p: nodes.MethodParameterIn => p.annotation.name.l.sorted.mkString(",")
    case _                          => ""
  }
  Some(ujson.Obj(
    "kind"            -> "flow",
    // subject/object are the two ends a reviewer navigates between.
    "subject"         -> srcNode.location.methodFullName,
    "object"          -> sinkNode.location.methodFullName,
    "source_origin"   -> (srcNode match {
                            case _: nodes.MethodParameterIn => "annotation"
                            case _                          => "call" }),
    "source_name"     -> (srcNode match {
                            case p: nodes.MethodParameterIn => p.name
                            case c: nodes.Call              => c.name
                            case _                          => "" }),
    "source_marker"   -> srcAnnotations,
    "source_code"     -> clip(srcNode.code, 200),
    "source_file"     -> srcNode.location.filename,
    "source_line"     -> srcNode.lineNumber.map(_.toInt).getOrElse(-1),
    "sink_name"       -> inCallOf(sinkNode).map(_.name).getOrElse(""),
    "sink_full_name"  -> inCallOf(sinkNode).map(_.methodFullName).getOrElse(""),
    "sink_code"       -> clip(inCallOf(sinkNode).map(_.code).getOrElse(sinkNode.code), 200),
    "sink_arg_code"   -> clip(sinkNode.code, 200),
    "sink_arg_type"          -> typeOf(sinkNode),
    "sink_arg_type_resolved" -> typeResolved(typeOf(sinkNode)),
    "sink_arg_index"  -> argIndexOf.getOrElse(sinkNode.id, -1),
    // Anchor on the CALL, not the tainted argument. On a multi-line call the
    // two differ (WebGoat Servers.java: call at 50, argument at 51), and
    // sql_sinks anchors on the call — facts from the two queries have to join
    // on (file, line) or a hypothesis cannot cite both. The argument's own
    // position is kept alongside rather than lost.
    "sink_file"       -> inCallOf(sinkNode).map(_.location.filename)
                           .getOrElse(sinkNode.location.filename),
    "sink_line"       -> inCallOf(sinkNode).flatMap(_.lineNumber.map(_.toInt))
                           .getOrElse(sinkNode.lineNumber.map(_.toInt).getOrElse(-1)),
    "sink_arg_line"   -> sinkNode.lineNumber.map(_.toInt).getOrElse(-1),
    "path_length"     -> best.len,
    "path_count"      -> entries.size,
    "crosses_methods" -> best.steps.map(_("method").str).distinct.size,
    "steps"           -> ujson.Arr(best.steps*)
  ))
}

// `grouped` iterates a Map (order not defined) and sortBy is stable, so any two
// rows sharing a key would keep whatever order the Map happened to yield. The
// serialized row is the final tiebreak: the ordering is total, and identical
// input gives byte-identical JSONL.
val ordered = rows.sortBy(r =>
  (r("sink_file").str, r("sink_line").num, r("source_file").str,
   r("source_line").num, r("source_name").str, r.render()))
val emitted = ordered.take(maxPaths)

emit(
  emitted,
  ujson.Obj(
    "annotations"      -> ujson.Arr(annotations.map(ujson.Str(_))*),
    "calls"            -> ujson.Arr(calls.map(ujson.Str(_))*),
    "sinks"            -> ujson.Arr(sinks.map(ujson.Str(_))*),
    "arg_index"        -> argIndices.mkString(","),
    // Disambiguation (playbook: an empty result is ambiguous). Zero flows with
    // zero sources, or zero sinks, or no overlay, are four different claims.
    "dataflow_overlay" -> hasDataflow,
    "overlays"         -> ujson.Arr(overlays.map(ujson.Str(_))*),
    "source_nodes"     -> sourceNodes.size,
    "sink_calls"       -> selectedSinks.size,
    "sink_arg_nodes"   -> sinkArgs.size,
    "sink_args_missing"-> (selectedSinks.size - sinkArgs.size),
    "paths_found"      -> paths.size,
    "pairs"            -> rows.size,
    "emitted"          -> emitted.size,
    "truncated"        -> (ordered.size > emitted.size),
    "cpg_calls"        -> cpg.call.size,
    "cpg_methods"      -> cpg.method.size,
    "cpg_files"        -> cpg.file.size
  )
)
