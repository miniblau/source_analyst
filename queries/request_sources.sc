// request_sources — values entering the program from an untrusted request (design §10.3).
//
// Knows nothing about any framework: both pattern sets arrive as params from the
// language's pattern file (§10.1). Two origins, because Java web input arrives
// two ways and a reviewer needs to tell them apart:
//
//   annotation  a method parameter carrying e.g. @RequestParam — the value is
//               bound by the framework, so the *parameter node* is the source
//   call        an explicit read, e.g. request.getParameter("q") — the *call
//               node* is the source
//
// params:
//   annotations [string] regexes over parameter annotation short names
//   calls       [string] regexes over source-call short names
//   (at least one of the two is required)
//   receivers   [string] optional — regexes over the call receiver's type, to
//                        narrow `calls` when a short name is generic
//
// emits kind=source_candidate; meta carries CPG-wide counts and the annotation
// names actually present, so an empty result can be told apart from a frontend
// that resolved no annotations at all.

import io.shiftleft.codepropertygraph.generated.nodes

val annotations = strList("annotations")
val calls = strList("calls")
val receivers = strList("receivers")
if (annotations.isEmpty && calls.isEmpty)
  throw new IllegalArgumentException(
    "request_sources: at least one of `annotations` or `calls` is required")

def clip(s: String, n: Int = 300): String = if (s.length > n) s.take(n) + "…" else s

// ------------------------------------------------------------------ annotation sources

val annotated: List[nodes.MethodParameterIn] =
  if (annotations.isEmpty) Nil
  else cpg.parameter.where(_.annotation.name(annotations*)).l

val annotationRows = annotated.map { p =>
  val names = p.annotation.name.l.sorted
  ujson.Obj(
    "kind"          -> "source_candidate",
    "origin"        -> "annotation",
    "subject"       -> p.method.fullName,
    "object"        -> names.mkString(","),
    "name"          -> p.name,
    "code"          -> clip(p.code),
    "file"          -> p.method.location.filename,
    "line"          -> p.lineNumber.map(_.toInt).getOrElse(-1),
    "column"        -> p.columnNumber.map(_.toInt).getOrElse(-1),
    "param_index"   -> p.index,
    "param_type"    -> p.typeFullName,
    // A source is only interesting if something can call it. An annotated
    // parameter on a method with no CPG callers is either a framework entry
    // point (the normal case for a controller) or an unresolved edge — the
    // reviewer needs to know which, so report the count rather than filter.
    "callers"       -> p.method.caller.size,
    "resolved"      -> !p.typeFullName.toLowerCase.contains("unresolved")
  )
}

// ------------------------------------------------------------------ call sources

val matchedCalls: List[nodes.Call] =
  if (calls.isEmpty) Nil else cpg.call.name(calls*).l

def receiverType(c: nodes.Call): String = c.receiver.headOption match {
  case Some(x: nodes.Identifier)        => x.typeFullName
  case Some(x: nodes.Call)              => x.typeFullName
  case Some(x: nodes.MethodParameterIn) => x.typeFullName
  case _                                => ""
}

val selectedCalls =
  if (receivers.isEmpty) matchedCalls
  else matchedCalls.filter(c => receivers.exists(r => receiverType(c).matches(r)))

val callRows = selectedCalls.map { c =>
  ujson.Obj(
    "kind"          -> "source_candidate",
    "origin"        -> "call",
    "subject"       -> c.method.fullName,
    "object"        -> c.methodFullName,
    "name"          -> c.name,
    "code"          -> clip(c.code),
    "file"          -> c.location.filename,
    "line"          -> c.lineNumber.map(_.toInt).getOrElse(-1),
    "column"        -> c.columnNumber.map(_.toInt).getOrElse(-1),
    "param_index"   -> -1,
    "param_type"    -> c.typeFullName,
    "callers"       -> c.method.caller.size,
    "resolved"      -> !c.methodFullName.toLowerCase.contains("unresolved")
  )
}

// Node order out of the CPG is not a contract; the JSONL sequence must be.
val rows = (annotationRows ++ callRows).sortBy(r =>
  (r("file").str, r("line").num, r("column").num, r("name").str, r("origin").str))

emit(
  rows,
  ujson.Obj(
    "annotations"        -> ujson.Arr(annotations.map(ujson.Str(_))*),
    "calls"              -> ujson.Arr(calls.map(ujson.Str(_))*),
    "receivers"          -> ujson.Arr(receivers.map(ujson.Str(_))*),
    "cpg_calls"          -> cpg.call.size,
    "cpg_methods"        -> cpg.method.size,
    "cpg_parameters"     -> cpg.parameter.size,
    "cpg_files"          -> cpg.file.size,
    // Disambiguation: zero annotation sources over a CPG that resolved *no*
    // parameter annotations at all is a frontend gap, not a clean codebase.
    "cpg_annotated_params" -> cpg.parameter.where(_.annotation).size,
    "annotation_names_present" -> ujson.Arr(
      annotated.flatMap(_.annotation.name.l).distinct.sorted.map(ujson.Str(_))*),
    "matched_annotation" -> annotationRows.size,
    "matched_calls"      -> matchedCalls.size,
    "selected_calls"     -> callRows.size,
    "unresolved"         -> rows.count(!_("resolved").bool)
  )
)
