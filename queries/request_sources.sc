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
//   member_reads [string] optional — regexes over the CODE of a field access, for
//                        input that arrives as a property (`req.query.name`)
//
// emits kind=source_candidate; meta carries CPG-wide counts and the annotation
// names actually present, so an empty result can be told apart from a frontend
// that resolved no annotations at all.

import io.shiftleft.codepropertygraph.generated.nodes

val annotations = strList("annotations")
val calls = strList("calls")
val receivers = strList("receivers")
// A THIRD ORIGIN, because the first two are Java-shaped. Java web input arrives as
// an annotated parameter or a named call; JavaScript input arrives as a MEMBER READ
// off a request object — `req.query.name` — which is neither. In the CPG that is an
// `<operator>.fieldAccess` call, and matching those by NAME is useless: on a
// four-route fixture it selects all 19 field accesses, `res.json` and `db.query`
// among them. So these are regexes over the access's CODE, which is the only thing
// that distinguishes `req.query` from `res.json`.
//
// This is not a JavaScript special case. Any language whose framework hands input
// through a property rather than a parameter needs it, and a class that binds none
// of these behaves exactly as before.
val memberReads = strList("member_reads")
if (annotations.isEmpty && calls.isEmpty && memberReads.isEmpty)
  throw new IllegalArgumentException(
    "request_sources: at least one of `annotations`, `calls` or `member_reads` is required")

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
    // For an annotation source this reports whether the ANNOTATION resolved to
    // a full name, not whether the parameter's type did. The parameter type is
    // java.lang.String on virtually every Spring controller, so deriving it
    // from typeFullName was true everywhere and told a reviewer nothing.
    "resolved"      -> p.annotation.fullName.l.exists(fn =>
                         fn.nonEmpty && !fn.toLowerCase.contains("unresolved"))
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

// Member reads, e.g. `req.query.name`. A THIRD origin, because the first two are
// Java-shaped: Java hands over an annotated parameter or a named call, Express and
// Angular hand over a property. Adding the parameter here without the matching was
// its own small lesson — the inventory reported ZERO sources for a class whose
// sources are all member reads, while `reachable` found flows from them, so the one
// query whose job is telling "no sources" apart from "sources unparsed" said the
// first when the truth was neither.
val memberCalls: List[nodes.Call] =
  if (memberReads.isEmpty) Nil
  else cpg.call.name("<operator>.fieldAccess")
         .filter(c => memberReads.exists(r => c.code.matches(r))).l

val selectedCalls =
  (if (receivers.isEmpty) matchedCalls
   else matchedCalls.filter(c => receivers.exists(r => receiverType(c).matches(r)))
  ) ++ memberCalls

val callRows = selectedCalls.map { c =>
  ujson.Obj(
    "kind"          -> "source_candidate",
    "origin"        -> "call",
    "subject"       -> c.method.fullName,
    "object"        -> c.methodFullName,
    // Same reason as reachable.sc: every member read is called
    // `<operator>.fieldAccess`, so the name distinguishes nothing and the sorted
    // output cannot even be read as an inventory. Name a field access by its code.
    "name"          -> (if (c.name == "<operator>.fieldAccess") clip(c.code, 120)
                        else c.name),
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
    // CPG-WIDE, not drawn from the matched set: `annotated` is already filtered
    // by the `annotations` param, so deriving this from it made the list empty
    // in exactly the case it exists to disambiguate — zero matches. An operator
    // seeing matched_annotation:0 needs to know which annotation names the
    // frontend resolved *at all*, to tell "none of ours" from "none, period".
    "annotation_names_in_cpg" -> ujson.Arr(
      cpg.parameter.annotation.name.l.distinct.sorted.map(ujson.Str(_))*),
    "matched_annotation" -> annotationRows.size,
    "matched_calls"      -> matchedCalls.size,
    "selected_calls"     -> callRows.size,
    "unresolved"         -> rows.count(!_("resolved").bool)
  )
)
