#!/usr/bin/env python3
"""Runner shim: stdin -> any OpenAI-compatible /chat/completions -> stdout.

Deliberately generic. The same script serves llama.cpp's `llama-server`, Ollama's
/v1 endpoint, LM Studio, vLLM, an internal gateway, or a hosted API — the only
difference is LLM_BASE_URL and LLM_MODEL. It is stdlib-only, holds no vendor SDK,
and is not part of `source_analyst`: it lives out here because it is one possible
runner among many, and `run_agent` must not care which one you use.

    LLM_BASE_URL   default http://127.0.0.1:8080/v1
    LLM_MODEL      default "local" (llama-server ignores it; most others need it)
    LLM_API_KEY    optional; sent as `Authorization: Bearer ...` when set
    LLM_TEMPERATURE / LLM_MAX_TOKENS / LLM_TIMEOUT

With `--schema FILE`, the request asks the server to constrain output to that JSON
schema and the shim flattens the resulting `{"records": [...]}` into one object per
line. That turns "did the model remember the output format" from a variable into a
constant, so a scorecard measures judgement instead of formatting. If the endpoint
does not support constrained decoding the request fails loudly — it is not retried
unconstrained, because then you would not know which mode produced your numbers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def _dump(text: str) -> None:
    """Put the model's raw output where the transcript will catch it.

    Learned the hard way: on a failure the shim printed only a diagnosis and threw
    the text away, so `run_agent` recorded an empty stdout and the one artifact that
    would have explained the run did not exist. Provenance is worth least when
    everything worked.
    """
    print("openai_chat: raw output follows ---8<---", file=sys.stderr)
    print(text, file=sys.stderr)
    print("---8<--- end raw output", file=sys.stderr)


def main() -> int:
    p = argparse.ArgumentParser(prog="openai_chat")
    p.add_argument("--schema", help="JSON schema file to constrain the response")
    p.add_argument("--system", help="optional system message")
    args = p.parse_args()

    prompt = sys.stdin.read()
    if not prompt.strip():
        print("openai_chat: nothing on stdin", file=sys.stderr)
        return 2

    base = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:8080/v1").rstrip("/")
    body = {
        "model": os.environ.get("LLM_MODEL", "local"),
        "messages": ([{"role": "system", "content": args.system}] if args.system else [])
                    + [{"role": "user", "content": prompt}],
        "temperature": float(os.environ.get("LLM_TEMPERATURE", "0")),
        "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "4096")),
        "stream": False,
    }

    schema = None
    if args.schema:
        if not os.path.isfile(args.schema):
            # A schema that silently isn't there is the worst case: you believe
            # output was constrained and it was not.
            print(f"openai_chat: no such schema file: {args.schema}", file=sys.stderr)
            return 2
        schema = json.loads(open(args.schema).read())
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "records", "strict": True, "schema": schema},
        }

    headers = {"Content-Type": "application/json"}
    if os.environ.get("LLM_API_KEY"):
        headers["Authorization"] = f"Bearer {os.environ['LLM_API_KEY']}"

    req = urllib.request.Request(f"{base}/chat/completions", headers=headers,
                                 data=json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=float(os.environ.get("LLM_TIMEOUT", "1800"))) as r:
            doc = json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:2000]
        print(f"openai_chat: {base} returned {e.code}: {detail}", file=sys.stderr)
        if schema:
            print("openai_chat: the request used --schema; if this endpoint has no "
                  "constrained decoding, drop --schema from the runner cmd rather than "
                  "assuming it was applied", file=sys.stderr)
        return 2
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"openai_chat: cannot reach {base}: {e}", file=sys.stderr)
        return 2

    try:
        choice = doc["choices"][0]
        text = choice["message"]["content"]
    except (KeyError, IndexError, TypeError):
        print(f"openai_chat: unexpected response shape: {json.dumps(doc)[:800]}", file=sys.stderr)
        return 2

    usage = doc.get("usage") or {}
    finish = choice.get("finish_reason")
    print(json.dumps({"cmd": "openai_chat", "base_url": base, "model": body["model"],
                      "schema": bool(schema), "finish_reason": finish, "usage": usage},
                     separators=(",", ":")), file=sys.stderr)

    if finish == "length":
        # Diagnose this HERE. Truncated JSON reaches the parser below as a syntax
        # error, and "did not parse" sends you looking at the model's formatting
        # when the real answer is that it was cut off mid-sentence.
        print(f"openai_chat: the model hit max_tokens "
              f"({body['max_tokens']}) and its output is truncated — raise "
              f"LLM_MAX_TOKENS, or shrink the batch (`brief --chunk-size`)", file=sys.stderr)
        _dump(text)
        return 2

    if schema:
        # Constrained mode returns one document; the pipeline speaks JSONL.
        try:
            parsed = json.loads(text)
        except ValueError as e:
            print(f"openai_chat: constrained output did not parse as JSON ({e})", file=sys.stderr)
            _dump(text)
            return 2
        records = parsed.get("records") if isinstance(parsed, dict) else parsed
        if not isinstance(records, list):
            print("openai_chat: schema output has no `records` list", file=sys.stderr)
            _dump(text)
            return 2
        for rec in records:
            print(json.dumps(rec, ensure_ascii=False, separators=(",", ":")))
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
