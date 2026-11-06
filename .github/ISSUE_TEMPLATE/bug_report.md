---
name: Bug report
about: Report a problem with an ffdec MCP tool or the server itself
title: "[bug] "
labels:
  - bug
---

**Tool / component**
Which of the tools (see the README tool tables) or which part of the server?
e.g. `encrypt_swf`, `extract_assets`, `set_header`, `run_ffdec` — or "server startup",
"FFDec detection/download", "documentation".

**Describe the bug**
A clear and concise description of what happened.

**To reproduce**
1. How the server was started (e.g. `python -m ffdecmcp`, `--ffdec-path ...`) and which
   MCP client you used (OpenCode, Claude Desktop, other).
2. The tool call with its exact arguments (redact personal paths if you like).
3. The input file: attach a minimal reproducer SWF if possible, or describe it
   (size, AS2/AS3, compression, obfuscated/encrypted, where it came from).
   Don't attach files you can't share publicly.
4. What actually happened: paste the returned result (the tools return JSON-style
   dicts) and any relevant stderr/log lines. Server logs go to stderr.

**Expected behavior**
What the tool should have returned or done instead.

**Environment (please complete):**
- ffdecmcp-ext version: [e.g. 0.2.1, or commit SHA]
- OS: [e.g. Windows 11, macOS 14, Ubuntu 24.04]
- Python: [e.g. 3.12.3 — output of `python --version`]
- Java: [e.g. OpenJDK 25 — output of `java -version`]
- FFDec version: [e.g. 26.4.0 — shown in the CLI banner / GUI About; required for
  anything involving FFDec output]
- FFDec mode: [jar / native / wsl — auto-detected unless `FFDEC_PATH`/`FFDEC_MODE` set]

**Additional context**
- Does the same operation work in the FFDec GUI or directly on the FFDec command
  line? (helps isolate wrapper bugs from FFDec behavior)
- Check the README's "FFDec quirks found (and how this fork handles them)" table
  first — some upstream CLI quirks are already handled or documented
  (e.g. FFDec 26.4's `-encrypt` CLI is broken, which is why encryption is
  Python-implemented here).
- Bugs in FFDec itself belong upstream at
  https://github.com/jindrapetrik/jpexs-decompiler/issues — wrapper bugs in the
  non-extended base belong at https://github.com/sublimnl/ffdecmcp.
