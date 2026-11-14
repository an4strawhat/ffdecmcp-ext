# AVM2 inspection feasibility verification

These are opt-in experiments, **not six new MCP tools**. They do not change the
installed server, its catalog, or the public API.

## Run

Requires a Java 17+ JDK (`java` and `javac`) and FFDec 26.4.0:

```text
python tests/prototypes/verify_avm2.py --ffdec-jar "<FFDec installation>/ffdec.jar" --assets "<local SWF asset directory>"
```

The harness compiles the small bridge into temporary storage and constructs
synthetic SWFs. Representative assets are located by filename in the supplied
directory. No game files are bundled. Results and intermediate fixtures stay in
temporary storage; the script prints the report location.

The bridge reads SWFs using FFDec's library API, walks ABC objects, and prints
JSON records. It never invokes export, save, or source decompilation APIs.
The harness separately invokes existing CLI inventory/report tools and exports
SymbolClass CSVs **only as an independent baseline oracle**.

## Observed results

Tested with FFDec 26.4.0 and Java 25 on Windows:

- Feasibility checks: **33/33 passed**.
- Existing project tests: **30/30 passed** (using this checkout's `src`).
- Every inspected SWF retained its SHA-256 hash.
- Each bridge invocation ran in an empty working directory and left it empty.
- Synthetic property writes resolved to their exact method ID, class trait,
  multiname, opcode, and bytecode offset.
- Method bytes and initializer IDs matched the synthetic fixture.
- Runtime-computed property names were marked unresolved, not guessed.
- An FWS fixture and its CWS equivalent produced identical write evidence.
- Changing one fixture instruction changed precisely one method in comparison.
- In-memory SymbolClass mappings matched CSV exports, including document-class
  character ID 0. The initial prototype missed ID 0; the baseline caught this
  and the bridge was corrected.
- Every reported property-write opcode in the three real assets was checked
  against its method's raw bytecode at the reported offset.

| Anonymous sample | Classes | Method bodies | Property writes | Directly mapped owners | Unmapped owners |
|---|---:|---:|---:|---:|---:|
| 1 | 103 | 980 | 3,097 | 3,096 | 1 |
| 2 | 133 | 1,311 | 4,547 | 4,546 | 1 |
| 3 | 235 | 5,467 | 6,652 | 6,630 | 22 |

Direct owner means a method attached to a class/script trait or initializer,
not the inferred runtime type of the object receiving the property write.
Script-level functions are explicitly labelled as script-owned.

## What this proves for proposed tools

| Proposed tool | Verified capability | Still missing |
|---|---|---|
| `find_avm2_property_accesses` | Property instructions with method IDs, direct owners, multinames and offsets | MCP schema/filtering/pagination, closure ownership, slot resolution |
| `inspect_avm2_method` | Raw method bytes, decoded instructions, stack/local limits, owners | Full signatures, exception-handler presentation, bounded instruction windows |
| `list_avm2_classes` | Class/superclass identities, constructor/static initializer IDs, trait counts | Interface/detail presentation and pagination |
| `find_avm2_references` | Multiname-bearing instruction references with owner context | Complete constant/trait/string references and semantic usages |
| `inspect_swf_linkage` | Class/character mappings, export names and character dependencies in memory | Timeline placement references and complete nested-tag coverage |
| `compare_avm2` | Detecting one changed method in a controlled fixture | Stable matching across reordered method/ABC indices, real patched-pair validation |

The first two provide bytecode-location evidence not present in `dump_as3`
or `link_report`. Class listing and linkage largely improve structure and the
no-export workflow rather than introducing entirely new information.

## Limitations and production requirements

- This prototype emits a large internal record stream to a subprocess pipe.
  It must **not** be exposed wholesale as an MCP response. Serialized records
  from the real samples were approximately 17, 30 and 109 million bytes.
  Filtering, byte-budgeted pagination and early limits belong in the bridge.
  A ten-result subset was measured below 100 KB; that is not a production
  transport regression test.
- Direct trait mapping leaves nested/anonymous functions unmapped. Report
  unresolved owners explicitly; do not claim complete enclosing-class coverage.
- An opcode's containing class is not necessarily its receiver's class.
  Dynamic namespaces/names, slots and control-flow reachability need more work.
- No general call graph or sound receiver-type inference is established here.
- The fixture comparison uses method IDs, which may shift between builds.
- Do not infer that XML lacks bytecode because it contains no literal opcode
  names. The earlier string-only XML investigation was inconclusive; this
  experiment instead reads decoded method bodies directly.
- Parsing still uses the installed FFDec library and materializes each SWF.
  Memory/time limits, malformed-input tests, API-version checks and MCP-level
  integration tests are required before shipping.

No commits, tags, pushes, package version changes or server registrations are
performed by these scripts.

## Follow-up: limitation-mitigation experiments

Run independently:

```text
python tests/prototypes/verify_limitations.py --ffdec-jar "<FFDec installation>/ffdec.jar"
```

Initially **23/24 checks passed**: a truncated SWF was accepted by the
underlying parser with process exit code 0. After adding the independent
`strict_swf.py` preflight to this harness, **26/26 checks pass**, including
rejection of that input before launching FFDec. The raw Java bridge and
production server do not yet enforce this preflight.

Evidence from the follow-up:

- A generated nested-function fixture starts with an ownerless method. Following
  `newfunction` references recovers the known enclosing method context.
- Graph unit tests preserve two possible contexts and terminate with a cycle.
  These graph tests do not establish complete ownership recovery on real games.
- Runtime names/namespaces stay unresolved. A receiver type is not invented.
  No actual receiver-type inference has been implemented.
- A generated `setslot` fixture exposes slot ID 1 without incorrectly labelling
  it a constant-pool property. Mapping slot IDs to traits is still unimplemented.
- A fixture with a write after `returnvoid` demonstrates why bytecode presence
  is not proof of execution. It does not validate a general CFG algorithm.
- Reindexing the fixture's multiname pool changes raw bytecode but leaves the
  normalized instruction sequence equal. General cross-build method matching,
  branch normalization and call-target matching remain unverified.
- A reference pagination algorithm measures the serialized JSON envelope,
  handles escaped supplementary Unicode, returns all records once, detects an
  oversized single result, and detects a stale artifact fingerprint. This runs
  in the Python test harness; bridge-side pagination and MCP integration remain
  to be built. Oversized records need an explicit production error response.
- Fixtures parse under a Java `-Xmx128m` heap cap, and a short subprocess
  deadline interrupts an invocation. This does not establish real-asset memory
  sufficiency, resource-exhaustion resilience or descendant-process cleanup.
- Short headers are rejected, but a truncated tag stream is not reliably
  rejected by FFDec alone. The follow-up preflight addresses this envelope
  failure. Source hashes stayed unchanged and bridge working directories
  remained empty throughout.

Still not verified: exception-aware reachability, timeline placement traversal,
slot-trait inference, receiver/constant data flow, complete reference indexing,
cross-version compatibility and actual bounded MCP responses. These are
proposed engineering tasks, not implemented features.

## Strict validation and additional verification

```text
python tests/prototypes/verify_hardening.py --ffdec-jar "<FFDec installation>/ffdec.jar" --assets "<local SWF asset directory>"
```

Observed **23/23 additional checks passed**:

- `strict_swf.py` rejects short headers, wrong lengths, truncated tag payloads
  even when the header length matches, incomplete zlib streams, trailing
  compressed data, unsupported signatures, missing End tags, oversized decoded
  sizes and missing nested sprite End tags.
- Valid synthetic FWS/CWS and all three representative real assets pass.
- Ownership propagation on the real samples reduces unmapped write contexts
  from **1/1/22 to 0/0/0**. These are enclosing contexts through `newfunction`,
  not proven receiver types or guaranteed unique owners.
- Real input hashes remain unchanged and inspection directories stay empty.
- A **test-only stdio MCP server** pages 100 Unicode-heavy records without
  missing/repeated records; the largest reconstructed protocol result body
  measured **2,796 bytes**. The connection survives an intentional tool error.
  This is not the six proposed tools, not the OpenCode-specific transport, and
  not production Java-side pagination.

The preflight deliberately supports **FWS/CWS only** and rejects other
signatures rather than guessing. It checks SWF container/tag boundaries, not
the complete ABC grammar, operand validity or verifier semantics. ZWS/encrypted
input handling needs a separately validated path. Its strict trailing-data
policy may reject noncanonical files that FFDec tolerates.

Remaining open work: full ABC malformed-input validation/fuzzing, ZWS preflight,
receiver/constant data-flow analysis, trait-resolved slots, exception-aware CFG,
complete timeline traversal, cross-build method matching, FFDec version
compatibility, Java-side filtering and hostile-resource/process-tree cleanup.
These remain **unverified**, not implicitly covered by the passing fixtures.
