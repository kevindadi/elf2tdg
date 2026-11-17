# Function CFG format

The analyzer now has two layers:

```text
ELF
  -> Image (sections, symbols, imports, DWARF)
  -> ProgramCfg (one petgraph StableDiGraph per function)
  -> TDG (contexts and spawn/join/scope edges)
```

## Why a function CFG layer

The CFG is the lossless intermediate representation. It keeps:

- every decoded instruction, including raw bytes;
- basic-block boundaries and typed control-flow edges;
- direct and indirect call expressions;
- call sites inside the block that performs them;
- timing cost, source file/line, function metadata and diagnostics.

The TDG is derived from this CFG; it is not a second, independently built
control-flow graph. The same representation is intended for a later IDA-style
UI and other downstream consumers.

## CLI

The default view remains the TDG:

```sh
elf2tdg firmware.elf --format json
```

Use `--view cfg` for the intermediate CFG:

```sh
# Complete CFG JSON for one function
elf2tdg firmware.elf --view cfg --format json \
    --function main --output main.cfg.json

# Default system export: main + startup + ISR vectors + tasks + callbacks + pointer roots
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
task/execution-context name, or a `0x` address. Task names map to the context
entry function, so `--function sensor_task` or
`--function app::sensor_task` selects the real `TaskStorage<...>::poll` body
instead of an initialization helper whose symbol happens to contain the task
name. `--reachable-from` accepts the same selectors. Without a selector, CFG
output uses a multi-root system scope:
functions reachable from main/startup, all valid vector-table ISRs, task/async
contexts, callback registrations, function pointers recovered from global
data, and code addresses recovered from literal/function-pointer escapes.
`--reachable-from ROOT` narrows this to one root, and `--all-functions` exports
the complete image.

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
a call edge. The TDG receives an informational `pointer-roots` diagnostic.

Reachability follows TDG call, spawn, callback, join and await edges, plus CFG
code-reference edges. It also resolves pointer-sized dynamic relocations (for
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
does not change ELF decoding or TDG construction time.

ARM Cortex-M vector tables are the primary static-root source. Detection is
not limited to one section name: the loader also recognizes the characteristic
initial-SP word followed by Thumb handler addresses when a table is embedded in
another allocated section. ARM/AArch64 exception-vector sections and RISC-V
`.trap`/vector sections contribute their base address and direct branch targets
(`b`/`jal`), so vector/trap dispatch becomes reachable without a call edge.
Executable symbols with recognizable `vector`, `trap` or `exception` names
(such as `vectors`, `__vector_table`, `trap_entry` or `exception_handler`) are
also retained. `_init`/`_fini` and libc startup symbols are architecture-level
roots as well.
Computed trap dispatch through `auipc`+`jalr` or a value written to `mtvec`/
`VBAR` still needs `--reachable-from` or `--all-functions`.

CFG output includes concrete instructions by default: JSON carries the full
`instructions` arrays with raw bytes, and DOT/Mermaid block labels print the
first eight decoded instructions. `--no-cfg-instructions` omits the arrays and
the label text while retaining addresses, sizes, cycle costs, terminators and
call sites. The TDG-only flags `--instructions`, `--projection` and `--legend`
do not change CFG output.

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
- Rust trait-object method slots, using validated vtable-shaped read-only
  tables referenced by pointer constants in the caller/callee neighborhood.
  These produce low-confidence candidate call or tail-call edges and a
  `resolved-trait-object-candidates` diagnostic.

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
A target that depends on a heap/stack object outside the bounded vtable
candidate analysis, or on disagreeing callers, stays `unresolved` with an
`unresolved-indirect-call` diagnostic rather than being guessed. The CFG JSON
still records the raw instruction, call site and indirect target expression for
each of them.

## JSON document

`cfg_schema_version` is `1.7` and is independent of the TDG schema version.
Every document contains image metadata, diagnostics, and the selected
functions. `pointer_roots` (version 1.7) lists executable addresses recovered
from global pointer-sized data and is omitted when empty. Version 1.1 adds an optional per-function `inline_frames` list
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
  "cfg_schema_version": "1.7",
  "image": { "arch": "thumb", "...": "..." },
  "pointer_roots": ["0x8000120", "0x800013c"],
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

### Node semantics

| Field | Meaning |
|---|---|
| `id` | stable `bb:0x...` block ID; CFG node indices are internal |
| `address`, `size` | linked virtual address and byte size |
| `instructions` | full instruction list with raw bytes and control-flow flags |
| `calls` | call sites owned by this block |
| `cycles` | static instruction-cost sum for the block |
| `terminator` | `fallthrough`, `call`, `noreturn-call`, `return`, `branch`, `jump`, `unresolved` |
| `noreturn` | `api` or `control-flow` when the function cannot return; absent otherwise |
| `instructions[].source` | per-instruction file/line/column when DWARF provides it |
| `inline_frames` | unique `DW_TAG_inlined_subroutine` ranges inside the function |

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

The TDG mirrors the classification in function extensions:

```json
"ext": {
  "elf2tdg.noreturn": true,
  "elf2tdg.noreturn_source": "control-flow"
}
```

The TDG call edge itself is retained; only the intra-function continuation and
its `call-return` edge are removed. This preserves call-graph reachability and
call-site cost attribution while preventing impossible post-call paths from
being counted as executable.

`calls` may contain tail calls recovered from indirect jumps (`tail: true`,
usually `direct: false`). `recovered_calls` carries call sites found by the
bounded gap scan after an unresolved indirect jump. They have no proven
containing basic block, so they are kept at function level with
`heuristic: true`; they are not silently dropped from the TDG.

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
asserts that both the TDG and CFG validate.

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
  calls are handled only through bounded candidate resolution, not full
  field-sensitive points-to.
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
