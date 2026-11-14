# ffdecmcp (extended fork)

MCP (Model Context Protocol) wrapper for **JPEXS Free Flash Decompiler (FFDec)** — exposes the full FFDec CLI to AI assistants: decompilation, inspection, SWF **editing**, format conversion, and HARMAN Air encryption.

> **Fork notice:** maintained at [an4strawhat/ffdecmcp-ext](https://github.com/an4strawhat/ffdecmcp-ext), based on [sublimnl/ffdecmcp](https://github.com/sublimnl/ffdecmcp) v0.1.2 (MIT). **Not published on PyPI** — install from git (see [Quick Start](#quick-start)). This fork (v0.3.0) adds the 33 missing FFDec commands as tools, fixes several upstream bugs, implements Air encryption natively in Python, and adds a library-backed read-only AVM2 inspection layer.

**42 tools** — all verified against real SWFs (see [Verification](#verification)).

## Tools

### Decompile / analyse

| Tool | Description |
|---|---|
| `decompile_swf` | Decompile all ActionScript (AS2/AS3) to a directory tree |
| `extract_actionscript` | Extract specific AS3 classes by name |
| `list_symbols` | List classes/packages without decompiling |
| `extract_assets` | Export assets with format/range/zoom control (see [details](#extract_assets-extensions)) |
| `get_swf_metadata` | Read header: dimensions, version, frame rate, compression |
| `deobfuscate` | Strip AS3 obfuscation (`traps` / `deadcode` / `max`) |
| `dump_swf` | Dump all SWF tags (index, name, tagId, length) |
| `dump_as2` / `dump_as3` | Raw script listings (`-exportNames` supported for AS2) |
| `link_report` | Generate a linker/dependency XML report |
| `generate_documentation` | AVM1/AVM2 P-code instruction reference |

### AVM2 inspection (read-only, library-backed)

These three tools call the **FFDec Java library directly** — no CLI, no export
files, no SWF modification:

| Tool | Description |
|---|---|
| `list_avm2_classes` | Class identities, superclasses, interfaces, instance/static initializer IDs |
| `inspect_avm2_method` | Method signature, direct/enclosing owners, exception table, decoded instructions |
| `find_avm2_property_accesses` | Property reads/writes (`get/setproperty`, `get/setsuper`, `initproperty`, `get/setslot`, `get/setglobalslot`) with containing methods, lexical contexts and bytecode offsets |

**Requirements:** Java 17+ **JDK** (the bridge uses the Java source-file
launcher), FFDec **26.4.0** JAR via `FFDEC_PATH`, FWS/CWS input ≤64 MiB.
Other signatures are rejected with an explicit error.

**Bounded responses:** every response is limited by `max_bytes` (default 64 KiB)
with cursor pagination — continue with `next_offset` as `offset` and the
returned `sha256` as `expected_sha256`, keeping other parameters unchanged.
Pagination is rejected if the file changes. Errors return structured
`success:false` results without disconnecting.

**Explicit uncertainties (never guessed):** `receiver_type` is always `null`
(containing class ≠ receiver type); runtime-computed property names and
unresolved slot IDs are reported as such; `enclosing_contexts` follow
`newfunction` lexical chains and are not proof of unique ownership or runtime
execution; container validation is not full ABC verification.

### Instance metadata (AMF)

| Tool | Description |
|---|---|
| `get_instance_metadata` | Read instance metadata (`jslike`/`raw`) |
| `set_instance_metadata` | Add/replace instance metadata |
| `remove_instance_metadata` | Remove instance metadata (all or one key) |

### Header, compression, encryption

| Tool | Description |
|---|---|
| `set_header` | Print header, or set `version`/`width`/`height`/`framerate`/`framecount`/`displayrect`/`gfx` |
| `compress_swf` | `compress` (zlib/lzma) or `decompress` |
| `encrypt_swf` / `decrypt_swf` | HARMAN Air encryption — pure Python, no AIR SDK needed |

### SWF editing (write access)

| Tool | Description |
|---|---|
| `replace_asset` | Replace binaryData/image/shape/text/font/sound tag or AS3 script |
| `replace_alpha` | Replace JPEG3/JPEG4 alpha channel (image must match dimensions) |
| `replace_character` | Swap character tags for other characters in the same SWF |
| `replace_character_ids` | Bulk id replacement, or `pack` / `sort` |
| `remove_tags` | Remove tags by main-timeline index |
| `remove_characters` | Remove characters, optionally with dependencies |
| `import_assets` | Bulk re-import previously exported assets (script/images/sounds/movies/shapes/sprites/text/symbolclass) |
| `enable_debugging` | Inject debug info / generate SWD |
| `rename_invalid_identifiers` | Rename invalid identifiers (`typeNumber`/`randomWord`) |

### Conversion

| Tool | Description |
|---|---|
| `swf_to_xml` / `xml_to_swf` | Full tag-level XML round-trip (lossless editing path) |
| `swf_to_exe` | `wrapper`, `projector_win`, `projector_mac`, `projector_linux` |
| `swf_to_iggy` / `iggy_to_swf` | Scaleform Iggy conversion |
| `flashpaper_to_pdf` | FlashPaper SWF → PDF |
| `swf_to_swc` | Generate SWC library |
| `merge_abc` / `clean_abc` | Merge ABC tags / remove unused ABC items |

### Utilities

| Tool | Description |
|---|---|
| `extract_swf_files` | Extract SWFs from ZIP/binary files (`all`/`biggest`/`smallest`/`first`/`last`) |
| `search_memory` | Find SWFs in process memory (names or PIDs) |
| `run_ffdec` | Generic FFDec CLI passthrough — any command not covered above |

### `extract_assets` extensions

Besides the original `image`, `sound`, `font`, `shape`, `movie`, `binaryData`, `all`, the tool now accepts `text`, `frame`, `sprite`, `button`, `morphshape`, `font4`, `symbolClass`, `fla`, `xfl`, and supports:

- `formats` — e.g. `["script:pcode", "shape:svg", "frame:png", "image:webp"]`
- `select` / `select_ids` — frame ranges / character ranges
- `zoom`, `ignore_background`, `onerror` (+ retries), `export_timeout`

## FFDec quirks found (and how this fork handles them)

| Quirk | Handling |
|---|---|
| **`-encrypt` CLI is broken in FFDec 26.4.0** (and current master): the dispatcher calls `parseDecrypt` for both `encrypt` and `decrypt`, so `-encrypt` always decrypts and returns `FAIL` | `encrypt_swf`/`decrypt_swf` are implemented in Python (`aircrypto.py`, exact port of FFDec's `HarmanSwfEncrypt`). Encrypt self-verifies by decrypting in memory before writing |
| `-compress` requires the **method before the paths** (`-compress zlib in out`) although its help says the opposite; without a method it misparses silently | `compress_swf` always passes the method (default `zlib`) |
| FFDec can exit **0 while writing a 0-byte output** | File-producing commands verify existence **and** non-empty size |
| `-importSymbolClass` appends `symbols.csv` to the argument | `import_assets(symbolclass)` takes the **folder** containing `symbols.csv` |
| `-replaceAlpha` fails with `I/O error` unless the alpha image exactly matches the JPEG dimensions | Documented; tests generate a dimension-matched RGBA PNG |
| `-dumpAS3` prints `ClassName index` — upstream `list_symbols` parser expected `class X` and returned 0 classes | Parser rewritten for the real formats (AS3 + legacy AS2) |
| Multiple `-export` flags don't accumulate | Asset types are sent as one comma-separated list |
| `projector_*` export needs a Flash Player projector in `%APPDATA%\JPEXS\FFDec\projector` | Download `flashplayer_32_sa.exe` there, or use `wrapper` mode (no projector needed) |
| `flashpaper_to_pdf` refuses non-FlashPaper SWFs | Expected; error is surfaced clearly |
| Large text outputs can exceed MCP transport limits (OpenCode caps a single stdio message at 16 MiB — a multi-MB tag dump kills the connection) | Text tools (`dump_swf`, `dump_as2`/`dump_as3`, `link_report`, `generate_documentation`, `run_ffdec`) clip responses to `max_chars` (default 250,000) and accept `outfile=` to save the complete output to disk |

## Verification

Tested against real files with FFDec 26.4.0 on Windows 11, Java 25, plus **43 unit tests** (`pytest`; Java-bridge tests opt in via `FFDEC_TEST_JAR`).

### Suite 1 — single-player game SWF (2.89 MB, AS3, 305 classes, 20,130 tags)

**47/47 passed, 0 skipped, 0 failed**, run twice from scratch. Covered: all analysis tools (10,131 assets exported, 76.9 MB XML round-trip), every conversion (Iggy, SWC, exe wrapper + 18 MB projector build, HARMAN Air round-trip), every edit op (image/alpha/character replace, tag/character removal, image + SymbolClass import), instance-metadata calls, memory search, and MCP-layer delegation.

### Suite 2 — multiplayer AIR bundle (4,740 SWFs + AIR SDK 51.1.3)

**66 passed / 1 skipped (no JPEG3/4 in target) / 0 failed.**
Primary target: a 453 KB base-actions module (70 classes): full battery including 1,207 asset exports, XML round-trip, both exe modes, shape + SymbolClass re-import.
Section scans passed on the core multiplayer client files: the main asset library (937 classes), the code library (223), the networking library (139), the menu (195), a popup framework (119), a map asset (48) and a social-connector module (25). Decompiling the networking library surfaced the live endpoints.

### Air crypto interoperability (three-way)

1. Our encrypted output → **FFDec native decryptor** → byte-identical to original
2. Our encrypt → our decrypt → identical, including all padding edge cases (0–70+ byte bodies)
3. **AIR SDK `swfencrypt`** output → our `decrypt_swf` → byte-identical
4. Re-encrypt and decrypt-plain cases are rejected with clear errors

### AVM2 inspection layer evidence

Validated with synthetic ABC fixtures (exact property-write → method ID, class
trait, multiname and bytecode offset; initializer IDs; runtime-name and slot
cases; controlled single-method comparisons) and three representative real
assets: **14,272 of 14,296 property writes** resolved to direct method owners,
the remainder reported as unresolved lexical contexts. In-memory SymbolClass
linkage matched CSV exports, including document-class character ID 0. Input
SHA-256s stayed unchanged and inspection created no export files. An opt-in
strict SWF preflight rejects malformed containers (including a truncated file
that FFDec itself accepted). Details and reproducible scripts:
`tests/prototypes/README.md`.

Notes from testing: all 4,740 bundled SWFs were plain `CWS`/`ZWS2` (none pre-encrypted); shape-based SWFs export PNGs under `shapes/`, so `import_assets(shapes)` is the correct round-trip there; instance-metadata tools are wiring-tested via unknown-instance calls because the samples contain no named `PlaceObject` instances.

## Quick Start

**Prerequisites:** Python 3.10+, Java (for FFDec). No AIR SDK required.
The AVM2 inspection tools additionally require a **Java 17+ JDK** and are
verified against FFDec **26.4.0** JARs only.

This fork is **not on PyPI** — install from git:

```bash
pip install "ffdecmcp @ git+https://github.com/an4strawhat/ffdecmcp-ext.git"
# or, for development:
git clone https://github.com/an4strawhat/ffdecmcp-ext.git
pip install -e "./ffdecmcp[dev]"
```

### Run the server

```bash
python -m ffdecmcp
# against a specific FFDec installation:
python -m ffdecmcp --ffdec-path C:\path\to\ffdec.jar
```

### OpenCode

```jsonc
{
  "mcp": {
    "servers": {
      "ffdec": {
        "type": "local",
        "command": ["python", "-m", "ffdecmcp"],
        "environment": { "FFDEC_PATH": "C:\\path\\to\\ffdec.jar" }
      }
    }
  }
}
```

### Claude Desktop / generic stdio clients

```json
{
  "mcpServers": {
    "ffdec": {
      "command": "python",
      "args": ["-m", "ffdecmcp"],
      "env": { "FFDEC_PATH": "C:\\path\\to\\ffdec.jar" }
    }
  }
}
```

## Installation

```bash
# this fork (not on PyPI):
pip install "ffdecmcp @ git+https://github.com/an4strawhat/ffdecmcp-ext.git"
# development install:
pip install -e ".[dev]"
# upstream (without the extended tools):
pip install ffdecmcp
```

### FFDec detection order

1. `--ffdec-path` / `FFDEC_PATH`
2. Previously auto-downloaded JAR (`~/.ffdecmcp/ffdec.jar`)
3. Common install locations / `PATH`
4. Auto-download from GitHub releases

### CLI options

| Option | Env Var | Description |
|---|---|---|
| `--ffdec-path` | `FFDEC_PATH` | FFDec JAR, native binary, or WSL path |
| `--timeout` | `FFDEC_TIMEOUT` | Default timeout in seconds (60) |
| — | `FFDEC_JAR_PATH` | Legacy: checked first when searching for a JAR (`FFDEC_PATH` supersedes it) |

CLI arguments take precedence over environment variables.

## Development

```bash
git clone https://github.com/an4strawhat/ffdecmcp-ext.git
cd ffdecmcp-ext
pip install -e ".[dev]"
python -m pytest tests/          # 43 tests; set FFDEC_TEST_JAR to include Java bridge tests
```

Verification against real SWFs (two full suites plus negative cases) was
performed with dedicated scripts that are kept out of the repository.

## Performance notes

Timings scale with asset count, not file size alone: a 2.9 MB SWF with 10k+ assets took ~5.7 min for `extract_assets(all)`; a 453 KB shape-heavy SWF with 1.2k assets took ~1.8 min. Everything else (decompile, conversions, edits, encryption) is seconds. Use `select`/`select_ids` and per-call `timeout` to bound large jobs.

## References

- **Upstream project**: [sublimnl/ffdecmcp](https://github.com/sublimnl/ffdecmcp) — the MCP wrapper this fork extends (MIT)
- **FFDec**: https://github.com/jindrapetrik/jpexs-decompiler
- **FFDec CLI docs**: https://github.com/jindrapetrik/jpexs-decompiler/wiki/Commandline-arguments
- **Air crypto reference**: FFDec `HarmanSwfEncrypt` (LGPL), based on `swfdecrypt.py` by NathaanTFM
- **HARMAN / Adobe AIR SDK**: origin of the SWF encryption format; the SDK's `swfencrypt` tool was used for interop verification
- **MCP**: https://modelcontextprotocol.io

## License

MIT — see the `LICENSE` file. This project is based on sublimnl's MIT-licensed
`ffdecmcp`; fork modifications © an4strawhat. Note that
`src/ffdecmcp/aircrypto.py` is a Python port of FFDec's LGPL-licensed
`HarmanSwfEncrypt` and is therefore distributed under the GNU LGPL v3; all
other code is MIT.
