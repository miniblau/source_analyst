"""Named query vocabulary (design §10.3).

Agents select a query by name; they never send Scala. A query file is a Scala
fragment that reads its sink/source patterns from `params` and hands its result
to `emit` — it hardcodes no vuln knowledge and prints nothing.

Injected contract, available to every query:

    outFile : String        where the result goes (handled by `emit`)
    params  : ujson.Value   the --param / --param-json map
    strList(key, dflt)      list-of-strings param accessor
    str(key, dflt)          string param accessor
    emit(rows, meta)        write {"rows": [...], "meta": {...}} to outFile

`rows` are fact payloads (each must carry a `kind`); `meta` is disambiguation
context — counts that tell "no result" apart from "frontend built nothing".
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

from .workspace import repo_root

NAME_RE = re.compile(r"^[a-z0-9_]+$")


def queries_dir() -> Path:
    env = os.environ.get("SOURCE_ANALYST_QUERIES")
    return Path(env).expanduser().resolve() if env else repo_root() / "queries"


def available() -> list[str]:
    d = queries_dir()
    return sorted(p.stem for p in d.glob("*.sc")) if d.is_dir() else []


def resolve(name: str) -> Path:
    if not NAME_RE.match(name):
        raise SystemExit(f"cpg: invalid query name {name!r} (expected [a-z0-9_]+)")
    path = queries_dir() / f"{name}.sc"
    if not path.is_file():
        raise SystemExit(f"cpg: unknown query {name!r}; available: {', '.join(available())}")
    return path


def prelude(out_file: Path, params: dict) -> str:
    """Bind the injected contract. Params ride in base64 so no pattern string —
    quotes, backslashes, triple-quotes — can break out into the Scala source."""
    blob = base64.b64encode(json.dumps(params).encode()).decode()
    return f'''// --- injected by tools/cpg (do not edit in query files) ---
val outFile: String = {json.dumps(str(out_file))}
val paramsJson: String = new String(
  java.util.Base64.getDecoder.decode("{blob}"), java.nio.charset.StandardCharsets.UTF_8)
val params: ujson.Value = ujson.read(paramsJson)
def strList(key: String, dflt: List[String] = Nil): List[String] =
  params.obj.get(key).map(_.arr.map(_.str).toList).getOrElse(dflt)
def str(key: String, dflt: String = ""): String =
  params.obj.get(key).map(_.str).getOrElse(dflt)
def emit(rows: Seq[ujson.Value], meta: ujson.Value = ujson.Obj()): Unit =
  java.nio.file.Files.writeString(
    java.nio.file.Path.of(outFile), ujson.Obj("rows" -> ujson.Arr(rows*), "meta" -> meta).toString)
// --- query: {out_file.name} ---
'''


def source(name: str, out_file: Path, params: dict) -> str:
    return prelude(out_file, params) + resolve(name).read_text()


def read_result(out_file: Path) -> tuple[list[dict], dict]:
    doc = json.loads(out_file.read_text())
    rows = doc.get("rows", [])
    meta = doc.get("meta", {})
    if not isinstance(rows, list) or not isinstance(meta, dict):
        raise SystemExit(f"cpg: malformed query result in {out_file}")
    return rows, meta
