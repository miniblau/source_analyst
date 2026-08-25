---
description: Transport shell for a source_analyst agent run. Single-shot, no tools, no autonomy.
mode: primary
temperature: 0
tools:
  bash: false
  edit: false
  write: false
  read: false
  grep: false
  glob: false
  list: false
  patch: false
  webfetch: false
  todowrite: false
  todoread: false
  task: false
---
Answer the request exactly as instructed by the message you are given.

The message carries its own complete instructions and its own output contract.
Follow those and nothing else. Emit only what they ask for — no preamble, no
commentary, no code fences around the whole answer.
