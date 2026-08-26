// sql_sinks — call sites matching a SQL sink pattern set (design §10.3).
//
// Knows nothing about SQL: the pattern set arrives in `sinks` from the
// language's pattern file (§10.1). Portable-first matching — the primary match
// is the method short name (regex), with resolution reported, not required.
// Constant-argument pruning is arg_is_constant.sc's job, not this query's.
//
// params:
//   sinks            [string] required — short-name regexes, e.g. ["executeQuery", "execute"]
//   full_name_filter [string] optional — regexes over methodFullName; opt-in narrowing
//   arg_index        string   optional — argument to report (default "1")
//
// emits kind=sink_candidate; meta carries CPG-wide counts so an empty result
// can be told apart from a frontend that built nothing.
//
// known frontend property: for a chained call the CPG anchors line/column at
// the start of the receiver chain, not at the sink token — `code` carries the
// whole expression, so a reviewer can still land on the site.

import io.shiftleft.codepropertygraph.generated.nodes

val sinks = strList("sinks")
if (sinks.isEmpty) throw new IllegalArgumentException("sql_sinks: param `sinks` is required")
val fullNameFilter = strList("full_name_filter")
// Comma-separated positions, as in reachable.sc. The inventory emits one record per
// (call, position) so a class that taints several arguments can still say which of
// them is a runtime value — with a single value, one record per call as before.
val argIndices: List[Int] =
  str("arg_index", "1").split(",").map(_.trim).filter(_.nonEmpty).map(_.toInt).toList

def typeOf(n: nodes.AstNode): String = n match {
  case x: nodes.Identifier      => x.typeFullName
  case x: nodes.Call            => x.typeFullName
  case x: nodes.Literal         => x.typeFullName
  case x: nodes.MethodParameterIn => x.typeFullName
  case _                        => ""
}

def clip(s: String, n: Int = 300): String = if (s.length > n) s.take(n) + "…" else s

val allMatches = cpg.call.name(sinks*).l
val selected =
  if (fullNameFilter.isEmpty) allMatches
  else allMatches.filter(c => fullNameFilter.exists(p => c.methodFullName.matches(p)))

val rows = selected.flatMap { c => argIndices.map { argIndex =>
  val arg = c.argument.find(_.argumentIndex == argIndex)
  val recv = c.receiver.headOption
  ujson.Obj(
    "kind"             -> "sink_candidate",
    "subject"          -> c.method.fullName,
    "object"           -> c.methodFullName,
    "name"             -> c.name,
    "code"             -> clip(c.code),
    "file"             -> c.location.filename,
    "line"             -> c.lineNumber.map(_.toInt).getOrElse(-1),
    "column"           -> c.columnNumber.map(_.toInt).getOrElse(-1),
    "resolved"         -> !c.methodFullName.toLowerCase.contains("unresolved"),
    "receiver_type"    -> recv.map(typeOf).getOrElse(""),
    "arg_index"        -> argIndex,
    "arg_code"         -> arg.map(a => clip(a.code)).getOrElse(""),
    "arg_is_literal"   -> arg.exists(_.isInstanceOf[nodes.Literal]),
    "arg_present"      -> arg.isDefined
  )
}}

emit(
  rows,
  ujson.Obj(
    "patterns"        -> ujson.Arr(sinks.map(ujson.Str(_))*),
    "full_name_filter"-> ujson.Arr(fullNameFilter.map(ujson.Str(_))*),
    "cpg_calls"       -> cpg.call.size,
    "cpg_methods"     -> cpg.method.size,
    "cpg_files"       -> cpg.file.size,
    "matched"         -> allMatches.size,
    "selected"        -> rows.size,
    "matched_names"   -> ujson.Arr(allMatches.map(_.name).distinct.sorted.map(ujson.Str(_))*),
    "unresolved"      -> selected.count(_.methodFullName.toLowerCase.contains("unresolved"))
  )
)
