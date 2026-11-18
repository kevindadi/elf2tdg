# Program CFG format

The analyzer has one primary analysis model:

```text
ELF
  -> Image (sections, symbols, imports, DWARF)
  -> ProgramCfg (one StableDiGraph per function plus program metadata)
```

## Why a function CFG layer

The CFG is the lossless intermediate representation. It keeps:

- every decoded instruction, including raw bytes;
- basic-block boundaries and typed control-flow edges;
- direct and indirect call expressions;
- call sites inside the block that performs them;
- timing cost, source file/line, function metadata and diagnostics.

`ProgramCfg` is the primary analysis IR. It owns execution roots, the
interprocedural call graph, concurrency annotations, locks, diagnostics, image
and timing metadata.

## CLI

The CFG is the primary analysis and default view:

```sh
elf2tdg firmware.elf --format json
```

```sh
# Complete CFG JSON for one function
elf2tdg firmware.elf --view cfg --format json \
    --function main --output main.cfg.json

# Default system export: main + startup + ISR vectors + tasks + callbacks +
# pointer roots + symbol/DWARF function roots
elf2tdg firmware.elf --view cfg --format json --output system.cfg.json

# Single-root slice for focused analysis
elf2tdg firmware.elf --view cfg --format json \
    --reachable-from main --output main.cfg.json
elf2tdg firmware.elf --view cfg --format json \
    --reachable-from sensor_task --output sensor-task.cfg.json

# Complete image export (can be very large)
elf2tdg firmware.elf --view cfg --format json \
    --all-functions --output program.cfg.json

# Graphviz and Mermaid
elf2tdg firmware.elf --view cfg --format dot --function main --output main.dot
elf2tdg firmware.elf --view cfg --format mermaid --function main --output main.mmd

# Block/call skeleton without instruction arrays
elf2tdg firmware.elf --view cfg --format json --function main \
    --no-cfg-instructions --output main-blocks.json
```

`--function` accepts an exact function name or symbol, a unique substring, a
task alias, or a `0x` address. Task names map to the task entry function, so `--function sensor_task` or
`--function app::sensor_task` selects the real `TaskStorage<...>::poll` body
instead of an initialization helper whose symbol happens to contain the task
name. `--reachable-from` accepts the same selectors. Without a selector, CFG
output uses a multi-root system scope:
functions reachable from main/startup, all valid vector-table ISRs, task/async
roots, callback registrations, function pointers recovered from global data, every named code symbol or DWARF subprogram entry, and code addresses
recovered from literal/function-pointer escapes. `--reachable-from ROOT`
narrows this to one root, and `--all-functions` exports the complete image.

Plain function symbols and DWARF `DW_TAG_subprogram` entries are roots even
when no call, callback registration or data pointer reaches them. This keeps
uncalled static functions, cold fragments and local library helpers visible,
and lets a debug build recover function entries whose ELF symbols were stripped
but whose DWARF subprogram DIE and concrete range remain. A symbol name takes
precedence over a DWARF name; DWARF supplies the display name only when the
symbol was removed. PLT stubs, external imports and default-handler stubs are
not added through this rule.

These symbol/DWARF entries are **discovery roots**, not **execution roots**.
`ProgramCfg::system_roots` combines both for the lossless default export;
`ProgramCfg::execution_roots` and `reachable_from_execution_roots` omit
discovery-only functions and are the appropriate base for reachability or
dead-code decisions. Graph passes must also preserve unresolved call sites:
`ProgramCfg.calls` retains them with `unresolved: true` and
`confidence: unknown`, rather than pretending the caller has no outbound call.

Vector-table roots are read from `.vector_table`/`.isr_vector`-style sections.
The initial stack word is skipped, Thumb bits are cleared and unused vectors
that all point at a default handler symbol are excluded. The reset vector and
real ISRs remain roots.

Pointer roots are recovered from pointer-aligned words in allocated data:
`.init_array`/`.fini_array`/`.preinit_array`/`.ctors`/`.dtors`, writable data
and GOT sections, and read-only `.rodata`/`.srodata`/`.data.rel.ro` tables. A
value is accepted when it already names a discovered function or when the slot
is strong evidence (a resolved relocation, an init/fini array, a Thumb function
pointer, or a plausible function prologue). They are listed as
`pointer_roots` in CFG JSON and seed the default system export, so a callback
table or global function-pointer variable can keep a function visible without
a call edge. The analyzer emits an informational `pointer-roots` diagnostic.

Reachability follows CFG call edges and spawn/callback/join/await annotations,
plus CFG code-reference edges. It also resolves pointer-sized dynamic relocations (for
example `R_X86_64_RELATIVE` GOT slots), so function pointers stored in
`.got`/`.data.rel.ro` can become call or escape edges instead of remaining
unresolved. When a function references a data address, the analyzer follows a
bounded run of pointer-aligned executable values (stopping at null, data or a
section end), so callback/dispatch tables reachable from a single root remain
in that root's CFG slice.

By default, recursion stops at known runtime noise boundaries
(`core::panicking`, `std::panicking`, `core::fmt`, `alloc::fmt`,
`compiler_builtins`, `drop_glue`/`drop_in_place`). Boundary functions remain
visible but their callees are not expanded. `--no-prune-runtime` disables this
stop-at-boundary rule; use it when investigating panic formatting, allocation
or destructor behavior.

Filtering happens after analysis, so it reduces export size and layout time but
does not change ELF decoding or analysis time.

ARM Cortex-M vector tables are the primary static-root source. Detection is
not limited to one section name: the loader also recognizes the characteristic
initial-SP word followed by Thumb handler addresses when a table is embedded in
another allocated section. ARM/AArch64 exception-vector sections and RISC-V
`.trap`/vector sections contribute their base address and direct branch targets
(`b`/`jal`), so vector/trap dispatch becomes reachable without a call edge.
Executable symbols with recognizable `vector`, `trap` or `exception` names
(such as `vectors`, `__vector_table`, `trap_entry` or `exception_handler`) are
also retained. `_init`/`_fini` and libc startup symbols are architecture-level
roots as well. Every remaining named code symbol and DWARF subprogram entry is
a general function root rather than an architecture-specific one.
Computed trap dispatch through `auipc`+`jalr` or a value written to `mtvec`/
`VBAR` still needs `--reachable-from` or `--all-functions`.

CFG output includes concrete instructions by default: JSON carries the full
`instructions` arrays with raw bytes, and DOT/Mermaid block labels print the
first eight decoded instructions. `--no-cfg-instructions` omits the arrays and
the label text while retaining addresses, sizes, cycle costs, terminators and
call sites.

## Graph analysis and normalization

`FunctionCfg::analyze_graph()` (also available as
`cfg_graph::analyze`) is a non-destructive structural pass:

- `reachable`/`unreachable` classify blocks from the function entry;
- `sccs` contains strongly connected components and marks cyclic components;
- `loops` contains natural loops derived from dominator backedges, with the
  header, latches and backedges;
- `dominators` and `post_dominators` contain full block sets, and
  `immediate_dominators`/`immediate_post_dominators` contain the unique real
  immediate block where one exists;
- `blocked_by_unresolved` is true when a reachable block has an unresolved
  control transfer.

Results use stable `BlockId` values, so they can be correlated with CFG JSON
and DOT/Mermaid output. Post-dominators use a virtual exit; when no real exit
exists, the post-dominator maps are empty.

`FunctionCfg::normalize()` (also `cfg_graph::normalize`) mutates a function CFG
and returns a `CfgNormalization` report:

- blocks unreachable from the entry are removed when the function has an entry
  and no reachable unresolved control transfer;
- contiguous blocks connected by a single fallthrough edge are merged,
  including instructions, calls, block cost and outgoing edges;
- `skip_reason` records `NoEntry` or `UnresolvedControlFlow` when unreachable
  removal was intentionally skipped.

Normalization is conservative: unresolved jumps are unknown frontiers, so
unreachable blocks are retained when they could be a target. It is not applied
automatically to the lossless default CFG export; callers opt in when building
an optimized view.

## Unresolved call and jump sites

A block has exactly one call record per call instruction. When a bounded
indirect target set is known, that record has `target: null`, `unresolved:
false` and a non-empty `candidates` array. Each candidate has its own `target`,
`target_function` and `target_name`; the block's call count therefore stays one.
This is used for Embassy's task-poll dispatch, where stores to a task-header
field identify the concrete `TaskStorage<...>::poll` functions plus
`poll_exited`.

A `null_target: true` call record has a statically null function pointer and no
call edge. It is not unresolved: the diagnostic `null-indirect-call-target`
records the dead call site, and DOT/Mermaid render a `null target` note. When
the instruction is unconditional it also cannot return, so its path has no
`call-return` continuation; the call record carries `"noreturn": true`.

A multi-target call record looks like:

```json
{
  "site": "0x80005da",
  "target": null,
  "target_function": null,
  "direct": false,
  "tail": false,
  "heuristic": true,
  "unresolved": false,
  "candidates": [
    { "target": "0x800082a", "target_function": "fn:0x800082a", "target_name": "..." },
    { "target": "0x800085c", "target_function": "fn:0x800085c", "target_name": "..." }
  ]
}
```

`unresolved: true` in a block's `calls` entry means an indirect call or an
indirect tail jump had no static target. A `tail: true` entry records a jump
that leaves the function; unresolved tail jumps are retained as candidates so
the information is not lost. Common causes in Rust images are:

- calls through a register (`call rax`) where the value came from a closure,
  vtable or other runtime computation;
- calls through a GOT/`.data.rel.ro` slot whose dynamic relocation could not be
  applied;
- imported libc functions reached through an unresolved GOT slot;
- calls through opaque async state machines or trait objects that cannot be
  associated with a plausible vtable candidate.

Relative relocations for the supported architectures are applied when reading
pointer-sized slots, which resolves many `R_*_RELATIVE` GOT entries. Import
GOT slots (`GLOB_DAT`/`JUMP_SLOT`) resolve to synthesized PLT stubs when the
binary has one; imports without a local stub remain unresolved.

Indirect calls and jumps are also resolved through:

- static pointer chains ending in a vtable or function-pointer slot;
- direct memory slots and vtable entries whose bases are statically known;
- ABI arguments of the containing function, evaluated at direct caller sites
  (for example a function-pointer dispatch helper or a C++ virtual call on a
  static object);
- indexed function-pointer call tables, both direct operands such as
  `call [table + index*scale]` and a register loaded from an indexed table
  immediately before the call. The scan is bounded by a recovered comparison
  and by the allocated data symbol or DWARF variable at the table base when
  one exists; matches produce `resolved-call-table` candidate sets. RISC-V
  table-relative
  `slli`/`add`/`load`/`jalr` sequences are included;
- return values of direct callees. A getter or factory such as
  `get_handler()()` is summarized by walking back from each reachable return
  to the ABI return-register definition, including copies, AArch64 `csel` and
  branch-selected returns. A unique target becomes a direct-target call
  record; multiple targets become a bounded candidate set with a
  `resolved-returned-indirect-call` diagnostic;
- local stack slots containing function pointers, including immediate stores
  and branchy assignments. Frame-relative loads are resolved from every
  modeled store to the same slot, so `void (*fn)(void) = handler; fn()` works
  even when the compiler materializes the value through a stack slot;
- DWARF-typed function-pointer fields. A dynamic load such as `ops->run()` is
  checked against aggregate member types; concrete values are read from typed
  global objects and from global pointers to typed objects. The result is a
  bounded `resolved-typed-field-candidates` call set. The field type and the
  object's declared size keep the candidate scan conservative;
- Rust trait-object method slots. Candidate vtable bases come first from
  validated vtable-shaped read-only tables referenced by pointer constants in
  the caller/callee neighborhood. When that produces no method candidate,
  DWARF fat-pointer layouts (`&dyn Trait`, `Box<dyn Trait>`) supply vtable
  pointers from static fat-pointer variables, arrays/registries and nested
  aggregate fields. These produce low-confidence candidate call or tail-call
  edges and a `resolved-trait-object-candidates` diagnostic; a DWARF vtable
  method name is included when available.

A resolved jump whose target lies inside the same function becomes a `branch`
or `jump` CFG edge. A resolved jump to another function is emitted as a call
site with `tail: true`. Unresolved indirect jumps produce
`unresolved-indirect-jump` diagnostics and, when they leave the function, an
unresolved tail-call candidate in `calls`.

### Jump tables

Switch tables are recognized in these layouts:

- x86-64 direct indexed memory: `jmp qword ptr [table + index*8]`;
- x86-64 PIE-relative:
  `lea table(%rip), %rdx; movslq (%rdx,%rdi,4), %rax; add %rdx,%rax; jmp *%rax`;
- x86-64 absolute pointer and offset tables whose indexed load has no base
  register, such as `mov table(,%rdi,8), %rax; jmp *%rax`, or
  `lea table(%rip), %rdx; movslq table(,%rdi,4), %rax;
  add %rdx,%rax; jmp *%rax`;
- ARM Thumb `tbb [pc, rN]` and `tbh [pc, rN, lsl #1]`, including
  register-based table bases;
- AArch64 relative byte and halfword tables such as
  `adr base; ldrb wN, [table, xM]; add base, base, wN, lsl #2; br base`;
- AArch64 signed word-offset tables such as
  `adr base; adr table; ldrsw xN, [table, xM, sxtw #2];
  add base, base, xN; br base`;
- AArch64 absolute-pointer tables such as
  `adrp/add table; ldr xN, [table, xM, lsl #3]; br xN`;
- ARM A32 conditional PC loads such as
  `cmp rN, N; ldrls pc, [pc, rN, lsl #2]` with absolute-address table entries;
- ARM A32 branch tables such as `addls pc, pc, rN, lsl #2` followed by
  branch instructions, expanded through their table-entry blocks;
- RISC-V absolute-pointer tables such as
  `slli index, index, 2; ...; add index, index, table; lw target, 0(index); jr target`;
- RISC-V table-relative offset tables used by PIC/PIE code, such as
  `slli index, index, 2; auipc/addi table; add index, index, table;
  lw target, 0(index); add target, target, table; jr target`, where each
  signed 32-bit entry is an offset from the table base.

Entries are read until the first non-executable target, the end of the
containing section, or the bound implied by a preceding guard: `cmp index, N`
or a materialized bound such as `movw; cmp index, bound` on ARM/AArch64/x86,
or `li bound, N` followed by `bltu`/`bgeu` on RISC-V. Guarded tables may span
up to 4096 entries, including inverted guards where the conditional branch
targets the table path and an unconditional jump reaches the default block.
Without a recoverable guard the scan falls back to a 256-entry safety limit.
Each valid entry becomes a CFG successor; entries outside the function become
tail-call candidates. x86 indexed instructions report `indirect` as
`indexed-memory` with `base`, `index`, `scale` and `disp`; Thumb table branches
report `table-branch` with `halfword`, `index` and an optional base; A32 PC
tables report `table-load` with `index`, `base` and `disp`; A32 branch tables
report `branch-table` with an optional base and index.

Caller-argument propagation accepts only a unique executable target across the
known callers and marks the resulting call as indirect/medium confidence. If
any known caller cannot be evaluated, the call stays unresolved.
A target that depends on a heap object outside the bounded vtable/field
analysis, on a field with no DWARF function-pointer type, on an unresolved
function return, or on disagreeing callers stays `unresolved` with an
`unresolved-indirect-call` diagnostic rather than being guessed. The CFG JSON
still records the raw instruction, call site and indirect target expression for
each of them.

### DWARF types and variables

The DWARF reader derives a compact type/variable database alongside
subprograms and line ranges:

- `DwarfInfo::aggregates` contains structure/class/union layouts with member
  names, byte offsets, sizes and resolved type names;
- `DwarfInfo::variables` contains globals with `DW_OP_addr`/`DW_OP_addrx`
  locations and frame-relative locals/parameters from `DW_OP_fbreg` or the
  CFA expression, plus their type size and function-pointer classification;
- pointer, reference, typedef, qualifier, subroutine and array types are
  followed through bounded type chains; arrays expose their element count and
  aggregate element type;
- aggregate layouts named `&dyn ...`/`Box<dyn ...>` with `pointer` and
  `vtable` members become trait-object layouts with data/vtable offsets;
- Rust vtable variables and vtable-shaped aggregate types expose vtable
  addresses, header entries and method names;
- `function_pointer_field_at(offset)`, `variable_at(address)`,
  `object_end_at(address)`, `local_variable_at`, `trait_object_layout`,
  `vtable_at` and `vtable_method_at` query the derived data.

Points-to uses this metadata in three places. Function-pointer field offsets
validate dynamic field calls and gather values from typed global objects or
global pointers to those objects. The field-offset search is object-insensitive:
several aggregate types may share an offset, so the result is a bounded set of
low-confidence alternatives rather than a proof of the object's dynamic type.
Trait-object layouts are walked from global fat pointers, including arrays and
nested aggregate fields, to collect vtable bases; these are a fallback after
code-referenced vtable bases, so existing precise candidates keep precedence.
Allocated data-symbol sizes and DWARF variable extents bound indexed call/jump
table scans, including images where a data symbol was stripped but its debug
information survived. Bitfields, anonymous member flattening, location lists
and cross-unit split-DWARF type references are intentionally not reconstructed;
missing metadata falls back to the existing bounded heuristics.

## JSON document

`cfg_schema_version` is `2.4`.
Every document contains image metadata, diagnostics, and the selected
functions. Version 2.4 adds per-function and per-root WCET metadata. Version
2.3 adds region-based data-memory latency metadata. Version 2.2 adds
branch-prediction analysis metadata. Version 2.1 adds data-cache analysis and
decoded memory-access metadata. Version 2.0 adds instruction-cache analysis
metadata. Version 1.9 added runtime/API provenance to callback annotations.
Version 1.8 made the CFG document self-contained: it adds top-level
`timing`, `roots`, `calls`, `concurrency` and `locks`, all sourced from
`ProgramCfg`. `roots` records startup/main/ISR/task/callback/
pointer entries, `calls` is the interprocedural call graph derived from block
call sites, and `concurrency` annotates spawn/join/await/callback/scope call
sites. These arrays are omitted when empty. `pointer_roots` (version 1.7) lists
executable addresses recovered from global pointer-sized data and is omitted
when empty. Version 1.1 adds an optional per-function `inline_frames` list
recovered from DWARF. Version 1.2 scopes diagnostics to the selected functions
and adds `diagnostics_omitted` when other image diagnostics were filtered out.
Version 1.3 adds an optional `no_code` descriptor for functions that have no
machine code in the image. Version 1.4 adds `null_target` to CFG call records
whose target expression is a statically null function pointer. Version 1.5
represents a bounded indirect target set as one call site with a `candidates`
array instead of duplicate call records. Version 1.6 adds function and call
`noreturn` classification and the `noreturn-call` terminator. Version 1.7 adds
a top-level `pointer_roots` array with executable addresses recovered from
global data.

```json
{
  "cfg_schema_version": "2.4",
  "image": { "arch": "thumb", "...": "..." },
  "timing": { "models": [], "frequency_domains": [] },
  "wcet": {
    "model": "cfg-longest-path", "default_loop_bound": 4,
    "max_states": 20000, "frequency_hz": 168000000,
    "functions_analyzed": 8, "functions_partial": 8,
    "functions_unbounded": 4, "functions_unknown": 0,
    "roots": [
      { "function": "fn:0x800085c", "kind": "task", "name": "sensor_task",
        "status": "partial", "cycles": 87.0, "time_ns": 517.86,
        "path": ["bb:0x800085c", "bb:0x800086a"] }
    ],
    "caveats": []
  },
  "data_memory": {
    "model": "region-data-wait-states", "functions_analyzed": 20,
    "blocks_analyzed": 72, "accesses": 129, "resolved_accesses": 57,
    "unresolved_accesses": 72, "mapped_accesses": 47,
    "unmapped_accesses": 10, "read_wait_cycles": 21,
    "write_wait_cycles": 34, "wait_cycles": 55, "caveats": []
  },
  "branch_prediction": {
    "model": "btfn", "mispredict_penalty": 3, "max_states": 128,
    "functions_analyzed": 7, "functions_fallback": 0,
    "branches_analyzed": 59, "branches_fallback": 0, "caveats": []
  },
  "data_cache": {
    "model": "data-lru", "size": 32768, "line_bytes": 32, "ways": 4, "sets": 256,
    "miss_penalty": 20, "write_allocate": true,
    "entry_state": "cold-per-function", "invalidate_on_call": true,
    "max_states": 128, "memory_accesses": 97, "resolved_memory_accesses": 57,
    "unresolved_memory_accesses": 40, "line_accesses": 57,
    "functions_analyzed": 20, "functions_fallback": 0,
    "blocks_analyzed": 158, "blocks_fallback": 0, "caveats": []
  },
  "pointer_roots": ["0x8000120", "0x800013c"],
  "roots": [
    { "function": "fn:0x8000138", "kind": "main", "name": "main", "confidence": "high" }
  ],
  "calls": [
    { "caller": "fn:0x8000138", "callee": "fn:0x800014c", "site": "0x800013a",
      "direct": true, "tail": false, "conditional": false, "heuristic": false,
      "unresolved": false, "confidence": "high" }
  ],
  "functions": [
    {
      "id": "fn:0x8000138",
      "primary_name": "main",
      "address": "0x8000138",
      "size": 16,
      "entry": "bb:0x8000138",
      "blocks": [
        {
          "id": "bb:0x8000138",
          "address": "0x8000138",
          "size": 4,
          "terminator": "call",
          "instructions": [
            {
              "address": "0x8000138",
              "size": 2,
              "bytes": "10b5",
              "mnemonic": "push",
              "operands": "{r4, lr}",
              "text": "push {r4, lr}",
              "is_call": false,
              "is_jump": false,
              "is_return": false,
              "is_conditional": false,
              "direct_target": null,
              "indirect": null,
              "memory_accesses": [
                {
                  "kind": "write",
                  "width": 4,
                  "resolution": "unresolved",
                  "base": "sp",
                  "disp": 0
                }
              ],
              "source": { "file": "main.c", "line": 38 }
            },
            {
              "address": "0x800013a",
              "size": 2,
              "bytes": "fff7f1ff",
              "mnemonic": "bl",
              "operands": "#0x8000120",
              "text": "bl #0x8000120",
              "is_call": true,
              "is_jump": false,
              "is_return": false,
              "is_conditional": false,
              "direct_target": "0x8000120",
              "indirect": null,
              "memory_accesses": [],
              "source": { "file": "main.c", "line": 39 }
            }
          ],
          "calls": [
            {
              "site": "0x800013a",
              "target": "0x8000120",
              "target_function": "fn:0x8000120",
              "target_name": "sensor_task",
              "direct": true,
              "tail": false,
              "conditional": false,
              "heuristic": false,
              "unresolved": false
            }
          ],
          "cycles": { "min": 2.0, "max": 4.0 }
        }
      ],
      "edges": [
        {
          "from": "bb:0x8000138",
          "to": "bb:0x800013c",
          "kind": "call-return",
          "site": "0x800013a",
          "conditional": false
        }
      ],
      "recovered_calls": []
    }
  ],
  "diagnostics": [],
  "diagnostics_omitted": 0
}
```

Function selection is also applied to diagnostics: a diagnostic whose related
`function` is outside the selected CFG set is omitted, while global diagnostics
without a function remain. The omitted count is reported as
`diagnostics_omitted` (absent when zero). This keeps a `--reachable-from`
slice from being dominated by unrelated runtime diagnostics.

When full debug information is present, each function can also carry the unique
inlined subroutine ranges found inside it:

```json
"inline_frames": [
  {
    "name": "<embassy_executor::spawner::Spawner>::spawn::<rust_concurrency::sensor_task::{closure#0}>",
    "linkage_name": "_ZN...",
    "call_site": { "file": "main.rs", "line": 43, "column": 17 },
    "low": "0x800061c",
    "high": "0x80006c2",
    "depth": 4
  }
]
```

Frames are ordered by address and depth; lower `depth` values are outer inline
calls. `low`/`high` are the concrete addresses of that inline instance.
`call_site` is recovered from `DW_AT_call_file`/`DW_AT_call_line` and points at
the source call that was inlined. An instruction belongs to a frame when its
address lies in `[low, high)`, so the list stays compact even for heavily
inlined Rust functions. It is independent of `--no-cfg-instructions`. See
[analysis-profile.md](analysis-profile.md) for the recommended build flags.

### Program metadata

| Field | Meaning |
|---|---|
| `image` | architecture, entry, ELF type and available metadata |
| `timing` | timing models and frequency domains used by block costs |
| `cache` | instruction-cache model parameters, analysis counts and caveats |
| `data_cache` | data-cache model parameters, access coverage, analysis counts and caveats |
| `branch_prediction` | branch-prediction model parameters, branch counts and caveats |
| `data_memory` | region-based data-memory latency model, access coverage, wait cycles and caveats |
| `wcet` | CFG longest-path WCET model, per-root results and caveats |
| `pointer_roots` | function-pointer addresses recovered from data |
| `roots` | startup/main/ISR/task/callback/pointer roots with ISR vector and IRQ |
| `calls` | program call graph: caller, resolved callee or `candidates`, call-site flags and confidence |
| `concurrency` | spawn/join/await/callback-bind/scope annotations attached to call sites |
| `locks` | lock acquire/try-acquire/release events with runtime API and primitive kind |

When an instruction-cache profile is active, each block can carry a `cache`
object with the number of fetch-line accesses, minimum/maximum modeled misses,
the number of cache states reaching the block, and per-line hit/miss ranges.
Each line also has a `classification`: `always-hit`, `always-miss` or `may-hit`
across the modeled entry states. The model assumes a cold cache at each
function entry and can conservatively invalidate state across call-return
edges.

When a data-cache profile is active, each block can carry a `data_cache`
object with decoded, resolved and unresolved memory-access counts, modeled
line accesses, minimum/maximum misses, the number of cache states reaching the
block, and per-line read/write and hit/miss ranges. Every line has the same
`always-hit`, `always-miss` or `may-hit` classification used by the
instruction cache. The model assumes a cold cache at each function entry and
can conservatively clear state across call-return edges.

Every instruction with a decoded data-memory access carries a
`memory_accesses` array, including implicit `push`/`pop` stack traffic. Each
entry has a `kind` (`read`, `write` or
`read-write`), an optional resolved `address`, a byte `width`, a `resolution`
(`direct`, `register` or `unresolved`), and the original `base`, `index` and
`disp`. Stack, indexed and register-dependent addresses remain
`unresolved`; they are counted but excluded from data-cache miss penalties and
state propagation, so modeled hits are optimistic. All resolved addresses are
treated as cacheable; per-region cacheability attributes are not modeled.

When a branch-prediction profile is active, each modeled conditional-branch
block carries a `branch_prediction` object with the branch `site`, minimum and
maximum mispredictions, the number of predictor states reaching the block, a
fallback flag, and one outcome per successor. Each outcome records its actual
direction (`taken` or `not-taken`), the branch-level predicted direction
(`taken`, `not-taken` or `mixed`), and its own misprediction range. An outcome's
`predicted` value is the direction the predictor chose, not whether that
particular successor was selected.

When per-region data-memory timing is active, each block with data accesses
can carry a `data_memory` object. It records resolved, unresolved, mapped and
unmapped access counts, read and write wait cycles, and a per-region breakdown
with region name, kind, access count, bytes, and read/write wait cycles. An
access spanning multiple regions is split at boundaries and can appear in more
than one region. Wait cycles are included in block `cycles`.

When a WCET profile is active, every analyzed function carries a `wcet`
object with a `status` (`bounded`, `partial`, `unbounded` or `unknown`),
optional `cycles` and `time_ns`, the worst-case local block `path`, an
optional reason, and unresolved/external call counts. The top-level `wcet`
object records the model configuration, aggregate function counts and one
result per execution root. A partial result has a finite estimate but
incomplete inputs; an unbounded result has no finite estimate. Paths contain
local block IDs, including repeated blocks for loop iterations.

These fields are CFG-native. They are populated from function CFGs and runtime
analysis facts; serializing the CFG JSON is self-contained. `calls`,
`concurrency` and `locks` are scoped to the selected functions; `roots`,
`image`, `timing` and `pointer_roots` describe the program.

### Node semantics

| Field | Meaning |
|---|---|
| `id` | stable `bb:0x...` block ID; CFG node indices are internal |
| `address`, `size` | linked virtual address and byte size |
| `instructions` | full instruction list with raw bytes and control-flow flags |
| `calls` | call sites owned by this block |
| `cycles` | static instruction-cost sum, or local resource/dependency pipeline schedule when the Cortex-M4 pipeline profile is active; includes profile fetch wait states, instruction-/data-cache miss penalties, data-memory wait cycles and branch misprediction penalties |
| `terminator` | `fallthrough`, `call`, `noreturn-call`, `return`, `branch`, `jump`, `unresolved` |
| `noreturn` | `api` or `control-flow` when the function cannot return; absent otherwise |
| `instructions[].source` | per-instruction file/line/column when DWARF provides it |
| `inline_frames` | unique `DW_TAG_inlined_subroutine` ranges inside the function |
| `wcet` | per-function status, cycles, time, worst-case local path and call coverage |
| `cache` | per-block fetch-line accesses, hit/miss ranges and classification, entry-state count and fallback flag |
| `data_cache` | per-block resolved/unresolved access counts, data-line hit/miss ranges, entry-state count and fallback flag |
| `branch_prediction` | conditional-branch site, per-successor prediction outcomes, misprediction range, entry-state count and fallback flag |
| `data_memory` | per-block access coverage, read/write wait cycles and per-region breakdown |
| `instructions[].memory_accesses` | explicit data-memory operands with kind, address resolution, width and addressing fields |

Functions that have no machine code in the image are still selectable and
renderable. Their `blocks` array is empty and the function carries:

```json
"no_code": {
  "reason": "external",
  "message": "declared external symbol; no machine code in this image"
}
```

`reason` is `external` for PLT/GOT imports and other undefined symbols,
`logical` for zero-size logical task entries created by a runtime spawn rule,
and `unavailable` when no basic blocks could be recovered for another reason.
DOT and Mermaid render a dashed note inside the function cluster instead of an
empty graph. External GOT pseudo-addresses and logical spawn-site addresses are
metadata addresses, not instruction addresses.

`indirect` is retained when known: `register`, `register-memory`, `memory`,
`register-offset`, `indexed-memory`, `table-branch`, `table-load`, or
`branch-table`, with register names, displacement, address, index, scale and
halfword mode. Unresolved indirect
calls and jumps remain explicit rather than being guessed. GOT-only dynamic
imports are represented as zero-size `external` functions; a call `target` may
therefore be the GOT slot pseudo-address of that external node rather than an
executable code address.

### Edge semantics

| `kind` | Meaning |
|---|---|
| `fallthrough` | sequential control flow, including the not-taken side of a conditional |
| `call-return` | continuation after a call that can return; noreturn calls do not create this edge |
| `branch` | taken conditional branch within the function |
| `jump` | direct or statically resolved indirect unconditional jump, including a self-loop |

Calls are not control-flow edges. They are retained on blocks and are rendered
as dashed call-target edges in DOT/Mermaid.

### Noreturn calls and continuation semantics

A call record with `"noreturn": true` cannot return to the instruction after
the call. Its block terminates with `noreturn-call`, has no `call-return`
successor, and is labelled `noreturn` in DOT/Mermaid. Conditional calls are
never marked noreturn because the not-taken path still reaches the
continuation. A call is marked only when every possible target is classified
noreturn; mixed candidate sets retain the continuation. A statically null
target is treated as terminating because executing the call cannot return.

Functions are classified in two ways:

- `api` — a recognized noreturn symbol or ABI entry point, including C
  `abort`/`_exit`/`exit`, `pthread_exit`, `longjmp`, assertion and stack-check
  failures, C++ `std::terminate`/`__cxa_throw`/`_Unwind_Resume`, Rust
  `core::panicking::*` entry points, allocation failure handlers, and embedded
  system-reset/fatal APIs;
- `control-flow` — the recovered CFG has no path back to the caller. This
  covers halt loops such as `DefaultHandler`, fault stubs, panic handlers, and
  callers that only reach other noreturn functions.

Control-flow classification is a monotone fixed point over the call graph.
Tentative functions are reconsidered after their callees are classified, so a
caller of a user panic handler or a `loop {}` helper becomes noreturn without
an explicit annotation. Unresolved calls and unresolved jumps are treated as
possibly returning; the classifier never guesses noreturn from incomplete
control flow. Once a call site is noreturn, blocks that were reachable only
through its continuation are removed. A shared block that is also reachable
from another branch remains.

The classification is exposed as `CfgFunction.noreturn`
(`api` or `control-flow`). The program call edge is retained in
`ProgramCfg.calls`; only the intra-function continuation and its `call-return`
edge are removed. This preserves call-graph reachability and
call-site cost attribution while preventing impossible post-call paths from
being counted as executable.

`calls` may contain tail calls recovered from indirect jumps (`tail: true`,
usually `direct: false`). `recovered_calls` carries call sites found by the
bounded gap scan after an unresolved indirect jump. They have no proven
containing basic block, so they are kept at function level with
`heuristic: true`; they are not silently dropped from `ProgramCfg.calls`.

## CFG validation

Every analysis validates the complete `ProgramCfg` before returning. The same
checker is available directly:

- `ProgramCfg::validate()`, `validate_with_limit(n)` and `ensure_valid()`;
- `CfgFunction::validate()` and `ensure_valid()`;
- `FunctionCfg::validate()` and `ensure_valid()`.

Validation checks entry and address-map/node consistency, block and
instruction ranges, one call record per call instruction, call-site ownership,
target/candidate/unresolved/null flag combinations, terminator semantics,
edge kinds and sites, duplicate edges, pointer-root duplicates and
cross-function target references. It returns structured
`CfgValidationIssue { code, path, message }` values and a
`CfgValidationError` from `ensure_valid()`.

Reachability is deliberately not required: retained orphan blocks and
intra-function call targets are valid. An invalid CFG produced during analysis
is reported as a fatal validation error rather than being exported.

Deterministic malformed-ELF and CFG-invariant tests run in the normal test
suite. A libFuzzer harness is provided under [`fuzz/`](../fuzz/); it loads
arbitrary bytes through `loader::load_from_bytes`, runs a bounded analysis and
asserts that the CFG validates.

## Current limits

- Calls end their basic block; returning calls continue in a new block, while
  noreturn calls have no continuation. Call targets remain metadata, not
  intra-function CFG edges.
- Recognized jump-table forms on x86-64 (including base-less absolute pointer
  and offset tables), ARM Thumb/A32, common AArch64 relative
  byte/halfword/word and absolute-pointer layouts, and RISC-V absolute-pointer
  and table-relative offset layouts are expanded. Guarded tables larger than
  256 entries are supported; unguarded scans stay conservative.
  Computed/indirect tables remain unresolved; heap/stack trait-object vtable
  calls use bounded candidate resolution, not full field-sensitive points-to.
- Cortex-M vector tables are found by section name or by the initial-SP and
  Thumb-handler pattern. ARM/AArch64 exception vectors and RISC-V trap vectors
  need a recognizable vector/trap/exception section or symbol; a bare table
  installed at run time through `VBAR`/`mtvec` is not recovered.
- Pointer roots require a direct pointer-shaped function address in an
  allocated data section. Nested pointer tables, computed function pointers,
  encoded jump tables and pointers built at run time are not chased.
- CFG node IDs are stable within an analysis but are not persisted across
  relinking or address changes.
- Function selection by name requires symbols, unless DWARF provided the name;
  stripped images can still be selected by address.
