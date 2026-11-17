# TDG schema v1.2

This document defines the Task Dependency Graph (TDG) produced by `elf2tdg`.
The Rust types in `crates/elf2tdg-schema` are the normative definition; the
generated [JSON Schema](../schema/tdg.schema.json) is the machine-readable
contract.

## 1. Why a typed graph, not only a call graph

A call graph has function nodes and call edges. That is not enough for a
real-time system: a thread's lifetime starts at a spawn site, a join waits for
an *execution context* rather than a function, and an ISR is activated by a
vector table rather than by a caller. The TDG therefore has two node kinds:

- **Function**: code, basic blocks, call sites, per-block timing.
- **Context**: startup, main, thread, async task, executor, ISR, timer callback,
  system workqueue, kernel thread.

Two projections are always available:

- **Call-graph projection**: keep `Function` nodes and `Call` edges.
- **Concurrency projection**: keep `Context` nodes and `Spawn`, `Join`,
  `Await`, `IsrActivate`, `CallbackBind` and `Preempts` edges.

A function can be reachable from several contexts. The schema does not
duplicate a function per context; consumers compute the may-run sets by
reachability from each context entry.

The TDG is not built directly from a loose block list. The analyzer first
builds a per-function `FunctionCfg` using `petgraph::StableDiGraph`, preserving
typed edges, raw instruction bytes, call sites, indirect-target expressions,
timing and source locations. TDG function blocks and call edges are derived
from these CFGs; concurrency-control edges are added on top. The intermediate
format is documented in [cfg-format.md](cfg-format.md).

## 2. IDs and addresses

IDs are strings with a fixed prefix:

| Node/edge | Prefix | Example |
|---|---|---|
| Function | `fn:` | `fn:0x08000400` |
| Basic block | `bb:` | `bb:0x08000400` |
| Context | `ctx:` | `ctx:thread:sensor` |
| Edge | `e:` | `e:spawn:0x08000320` |
| Lock event | `lock:` | `lock:0x08000240:acquire:pthread_mutex_lock` |
| Scope | `scope:` | `scope:0x08001300` |
| Frequency domain | `clk:` | `clk:core` |

IDs are stable within one analysis and meaningful across JSON diffing. They are
not array indices.

Addresses are serialized as lowercase `0x`-prefixed hex strings. This avoids
JSON number precision problems for 64-bit addresses and makes fixtures
readable. Deserialization is deliberately lenient (hex string, decimal string
or integer); serialization is canonical. Thumb interworking bits may appear in
the ELF entry point and in symbol values; function addresses are canonicalized
by the loader, and that policy is reported through diagnostics when relevant.

## 3. Functions and basic blocks

A `Function` carries:

- raw symbols (several for ICF aliases or linker aliases) and a display name;
- inferred language (`rust`, `c`, `cpp`, `assembly`, `mixed`, `unknown`);
- address, size, section and role (`normal`, `entry`, `isr`, `task-entry`,
  `future-poll`, `thunk`, `plt`, `trampoline`, `kernel`, `external`);
- basic blocks with intra-function successors;
- optional source location and inline sites;
- optional aggregate block timing, explicitly named
  `static_block_sum_cycles` to prevent it being mistaken for a path time.

Dynamic imports without a local PLT stub are represented as zero-size
`external` functions. Their address is the GOT slot pseudo-address, not code.
The TDG edge from a caller resolves the GOT-indirect call/jump to that external
node, so imports such as `malloc`, `free` and `syscall` are not reported as
unresolved indirect branches.

A spawn site recovered only from DWARF inlining may have no separately compiled
entry function. Such a **logical task entry** is a zero-size `task-entry`
function whose address is the inline call site, carrying
`ext["elf2tdg.logical_task"] = true`. It is a node for context identity and
reachability, not an executable symbol; consumers must not treat its address as
a function entry point.

A `BasicBlock` carries an address, size, successor block IDs, optional
per-instruction timing detail, and optional `BlockTiming`. Calls are **not**
basic-block successors; every call/thread-control relation is an `Edge` at the
top level. A call whose every possible target is noreturn contributes no CFG
continuation block, so its caller's `BasicBlock.successors` is empty at that
site.

Function discovery is seeded by symbols, the ELF entry point, Cortex-M vector
entries, ARM/AArch64 exception vectors, RISC-V trap vectors, init/fini symbols,
global pointer roots and direct call targets. When no local code symbols exist, common
prologue patterns add conservative seeds and a `stripped-heuristic-seeds`
diagnostic. `Function.source` is filled from the DWARF line program when
available; it is informational and does not affect graph identity.

The CFG layer records block terminators (`fallthrough`, `call`,
`noreturn-call`, `return`, `branch`, `jump`, `unresolved`), typed edges
(`fallthrough`, `call-return`, `branch`, `jump`), per-block calls, raw
instruction bytes and static instruction costs. Calls are block-owned metadata,
not intra-function edges. Every call ends its basic block; returning calls
continue in a new block, while calls to noreturn functions have no
`call-return` continuation. Functions classified noreturn carry
`ext["elf2tdg.noreturn"] = true` and
`ext["elf2tdg.noreturn_source"] = "api" | "control-flow"`. `--view cfg` exports
this format.

## 4. Contexts

| `kind` | Meaning | Typical evidence |
|---|---|---|
| `startup` | reset/startup code | ELF entry, vector table |
| `main` | main thread/task | runtime API, symbol |
| `thread` | OS thread/task | `pthread_create`, `xTaskCreate`, `k_thread_create` |
| `scoped-thread` | thread inside a structured scope | schema legacy; no default Rust rules |
| `async-task` | task on an async executor | Embassy `Spawner::spawn`, RTIC |
| `executor` | executor/driver context | runtime symbols |
| `isr` | interrupt/exception handler | vector table |
| `timer-callback` | timer callback context | runtime timer rules when a service context is recoverable |
| `system-workqueue` | deferred work context | runtime workqueue rules when a service context is recoverable |
| `kernel-thread` | RTOS kernel thread | runtime symbols |
| `unknown` | context exists but kind is unresolved | partial evidence |

Each context has an entry function, optional parent, scheduling discipline,
optional priority (raw value plus ordering convention), optional core and
frequency domain, and an optional `spawn_edge` reference. A context backed by a
logical task entry carries the same `ext["elf2tdg.logical_task"]` marker as its
entry function. Contexts created from a spawn API symbol with no recoverable
call site are marked `ext["elf2tdg.orphan_spawn_api"]` instead and have no
`spawn_edge`.

Priorities are not normalized: FreeRTOS uses larger-is-higher, Zephyr/ThreadX
use lower-is-higher, pthread depends on the scheduling policy. The
`Priority.scheme` field carries the convention so downstream analysis does not
guess.

## 5. Edges

Every edge has an ID, a source/site when applicable, and a `confidence` value.
There are no silent guesses.

| `kind` | From → To | Purpose |
|---|---|---|
| `call` | function → function | direct, indirect, tail or inlined call |
| `spawn` | function → context (or opaque target) | creation of a thread/task/executor task; a resolved entry must match the context entry |
| `join` | function → context (or opaque target) | join/detach/abort/scope-end barrier |
| `await` | context → context/function/opaque | `.await`, `select!`, join-handle await |
| `callback-bind` | function → function (+ target context) | timer/workqueue/ISR callback registration |
| `isr-activate` | vector → context | hardware activation of an ISR |
| `preempts` | context → context | derived priority-based preemption; `derived: true` |

A bounded indirect target set may produce multiple `Call` edges with the same
`site`, one per candidate callee. Edge IDs include the target address. This is
used for Embassy's executor task-poll dispatch, where the task pointer is
dynamic but the poll-field stores identify the candidate poll functions.

Call edges distinguish:

- `direct`: target resolved statically;
- `tail`: unconditional branch into another function;
- `inlined`: logical edge recovered from DWARF call-site/inlining info.

Spawn edges record the runtime (`freertos`, `zephyr`, `pthread`, `rust-embassy`,
`rust-rtic`, `openmp`, ...), the API
symbol, the execution-unit kind, an optional constant priority, and an optional
`name` for a recovered closure/future/task label. Their target is either a
resolved `context` + `entry` pair or `opaque` with candidate entry functions.
The call site is retained even when the target is opaque; inventing a context
would be worse than reporting uncertainty.

Join edges use `join_kind` (`join`, `detach`, `abort`, `scope-end`, `barrier`)
and may reference the scope that provides an implicit join. Like spawn, the
target is resolved or opaque with candidate contexts. Thread handles are often
unresolvable at `-O2` even when symbols are available, so this is a normal
outcome, not an error.

`callback-bind` edges are emitted for recognized registration APIs when the
callback argument resolves to a concrete function. The current rules cover
POSIX/libc `atexit`, `__cxa_atexit`, `on_exit`, `signal`, `bsd_signal`,
`qsort`, `bsearch`, `pthread_once`, `pthread_key_create`, `pthread_atfork`,
`ftw`, `nftw`, `scandir`, FreeRTOS timer registration, Zephyr timer/work
initialization and ThreadX timer creation. `target_context` remains unset when
the callback does not have a separately identified execution context. The
callback function is also treated as a system root, so ambiguity in the
registration site does not hide the callback body from the default CFG scope.
A registration alone does not synthesize a new context: timer/workqueue
context kinds are reserved for runtimes that can identify the concrete service
context, while `target_context` stays unset for synchronous callbacks.

Global function-pointer roots are not separate TDG edges. They are used when
selecting the default CFG system scope and are listed in CFG JSON as
`pointer_roots`; the TDG carries an informational `pointer-roots` diagnostic
with the recovered count.

### Lock and semaphore events

`locks` is a top-level list of acquire/try-acquire/release events rather than a
graph edge: without points-to analysis the analyzer cannot prove which object
instance is protected. Each event records:

- the containing function and execution context (when reachable);
- the direct-call site, or the concrete inline `[site, extent)` range;
- the source-level inline call site from `DW_AT_call_file`/`DW_AT_call_line`;
- runtime and API (`pthread_mutex_lock`, `xSemaphoreTake`, ...);
- `lock_kind` (`mutex`, `rwlock`, `rwlock-read`, `rwlock-write`, `spinlock`,
  `semaphore`, `other`) and `operation` (`acquire`, `try-acquire`, `release`);
- `inlined`/`inline_depth` and confidence.

Supported rules cover pthread mutex/RW-lock/semaphores,
FreeRTOS/Zephyr/ThreadX semaphores and mutexes, and C++
`std::mutex`/`shared_mutex`. The default Rust `no_std` profile does not define
std or `parking_lot` lock rules. Inlined events are found by matching the DWARF
inline stack, not by requiring a machine call instruction. Lock ordering and
deadlock claims are intentionally out of scope.

Await targets use the same `resolution` tag with three states: a known context,
a known function/future, or `opaque` with candidate functions. Rust async await
targets are frequently unresolvable without whole-program data flow; the schema
marks that honestly instead of inventing an edge.

### Structured concurrency

A `Scope` groups spawn edges created inside a structured region. The schema
retains variants for structured thread scopes, but the supported default rules
currently emit only OpenMP parallel-region scopes; Rust `std::thread`, Rayon,
Crossbeam and Tokio are outside the no-std support profile. TBB task groups are
schema vocabulary only. Scopes record enter/exit sites, the entering context,
membership (spawn edge IDs), whether the scope implies a join, and confidence.
Nested scopes are separate `Scope` entries.

## 6. Timing and frequency

### 6.1 Cycles and time

`BlockTiming` carries:

```text
model           -> timing model ID (must exist in timing.models)
cycles.min/max  -> modeled cycle range
time_ns.min/max -> cycles * 1e9 / hz, when a frequency is known
frequency_domain-> which clock domain produced time_ns
confidence      -> high / medium / low / unknown
caveats         -> assumptions that matter for this block
```

`time_ns = cycles * 1_000_000_000 / hz`. If the frequency is unknown, `time_ns`
is omitted rather than guessed. If a block can execute in contexts with
different clock domains, producers may omit `time_ns` and leave cycle counts
only; consumers can apply the context's frequency themselves.

`InstructionTiming` is optional detail. Block-level timing is always sufficient
for aggregation; instruction detail is enabled per invocation for human
inspection or fine-grained downstream analysis.

### 6.2 Determinism

Every timing model declares `Determinism`:

- `deterministic`: exact for the modeled core/memory configuration (simple
  in-order MCU, documented pipeline rules).
- `bounded`: sound min/max for the modeled configuration, but not a WCET proof
  (flash wait states, pipeline refills, partial cache modeling).
- `statistical`: throughput estimate for an out-of-order or otherwise
  unpredictable core; **not a bound**.
- `unknown`: no reliable model.

The tool must never label a statistical estimate as WCET. `FunctionTiming`
contains a block *sum*, not an execution path; loops make that sum meaningless
as a time. Path analysis and WCET need loop bounds/execution counts, which are
out of scope for schema v1.

### 6.3 Timing model families

| Tier | Examples | Model class | Notes |
|---|---|---|---|
| 1 | Cortex-M0/M0+/M3/M4/M33, simple RV32 | deterministic/bounded | per-instruction cycle table, flash wait states, branch penalties |
| 2 | Cortex-M7, Cortex-A53/A55, dual-issue RV64 | bounded/statistical | pipeline, branch prediction, cache configuration |
| 3 | x86-64, Cortex-A7x | statistical | throughput estimate only; never a bound |

Instruction tables are data-driven (mnemonic + operand-class patterns) and
versioned. Per-core/per-board overrides are first-class so a vendor errata or a
different flash configuration does not require a code change.

The current implementation ships Cortex-M, generic RV32/RV64, and generic
AArch64/x86-64 tables. The latter two are statistical throughput tables and are
selected only by an explicit `--cpu aarch64` or `--cpu x86-64`; auto-detection
does not silently attach a generic out-of-order estimate to every image.

### 6.4 Frequency domains

A `FrequencyDomain` is a named clock (`clk:core`, `clk:timer2`, ...) with a
provenance and confidence:

| Source | Meaning |
|---|---|
| `cli` | explicitly supplied |
| `board-profile` | supplied by a board/clock profile |
| `elf-symbol` | recovered from a known symbol (for example `SystemCoreClock`) |
| `code-pattern` | recovered from clock/PLL configuration code |
| `default` | built-in fallback (tests only) |
| `unknown` | no provenance |

Discovery order is: CLI/board profile, then image-level evidence, then
defaults. Code-pattern extraction is best-effort and must be marked as such.
Multi-core/multi-domain images are supported by assigning a domain per context;
per-block `time_ns` is omitted when a block is shared by contexts with different
domains.

## 7. Confidence and diagnostics

Every inferred relation carries `Confidence`:

- `high`: symbol/relocation/DWARF evidence;
- `medium`: strong pattern with assumptions (for example a wrapper summary);
- `low`: heuristic or partially resolved, for example a call recovered by
  scanning undecoded bytes after an unresolved indirect jump;
- `unknown`: not assessed.

`Diagnostic` entries use stable `code` strings, a severity (`info`, `warning`,
`error`), an optional function/context/address, and structured details. A
document can be structurally valid while containing warnings. Consumers should
surface diagnostics rather than silently dropping uncertain edges.

## 8. Validation

`Tdg::validate()` checks, among other things:

- schema major version;
- ID prefixes and uniqueness;
- all references (functions, blocks, contexts, edges, lock events, scopes,
  timing models, frequency domains);
- block ownership and address ranges;
- call/spawn/join/lock sites inside their containing functions;
- spawn entry equals target-context entry;
- ISR activation targets an `isr` context;
- scope members are spawn edges and exit ≥ entry;
- parent-chain cycles;
- cycle/time ranges are finite, non-negative and ordered;
- frequencies are greater than zero.

`validate_with_limit(n)` bounds the number of issues for hostile input, and
`ensure_valid()` returns a structured error. Producers must call
`ensure_valid()` before publishing a document; consumers should call
`validate()` defensively.

The intermediate CFG has a separate validator exposed by `ProgramCfg`,
`CfgFunction` and `FunctionCfg`. It checks graph/map consistency, basic-block
and instruction ranges, call-site and terminator semantics, edge consistency,
pointer-root duplicates and cross-function references. Analysis validates the
CFG automatically before returning. See [cfg-format.md](cfg-format.md#cfg-validation).

## 9. Output views

JSON is canonical. DOT and Mermaid are projections intended for humans. The
renderers use these styles:

| Relation / node | DOT style |
|---|---|
| direct / tail call | solid gray / dashed gray |
| spawn | bold red; dashed with `?` when low/unknown confidence |
| join | bold blue; dashed with `?` when low/unknown confidence |
| await | bold purple; dashed with `?` when low/unknown confidence |
| callback bind | dashed teal |
| ISR activation | dashed orange from an orange vector diamond |
| preempts | dotted orange |
| context entry | dotted blue |
| scope | dashed green ellipse, with dotted green `in`/`member` edges |
| opaque target | gray note with candidate count |
| logical/orphan task context | dashed purple border |

Function nodes are labelled with their name, address and static block-sum cycle
range when available. Contexts are filled boxes labeled with their kind. The
complete visual vocabulary is in [tdg-legend.md](tdg-legend.md).

DOT and Mermaid accept two projections:

- `full` (default): every function and call edge plus concurrency relations;
- `concurrency`: contexts, scopes, lock events,
  spawn/join/await/callback/ISR/preemption relations, and only the functions
  participating in them. Ordinary call edges are omitted so large optimized
  Rust binaries remain readable.

`--legend` appends a legend describing node kinds, relation styles and the
confidence encoding. It is supported for DOT and Mermaid only; JSON is
unaffected.

`--view cfg` switches the output from the TDG to the intermediate function
CFG. CFG JSON uses its own `cfg_schema_version` (`1.7`), includes full
instruction/raw-byte information by default, carries optional per-function
inline-frame ranges from DWARF, scopes diagnostics to the selected functions
with a `diagnostics_omitted` count, records a `no_code` reason for external or
logical functions without machine code, and can omit instruction arrays with
`--no-cfg-instructions`. Without a selector, the CFG is limited to
functions reachable from a multi-root system scope (main/startup, Cortex-M
vector-table ISRs, ARM/AArch64 exception vectors, RISC-V trap vectors, ELF
init/fini entry points, tasks, callback registrations and global
function-pointer roots). `--reachable-from ROOT` selects one root and
`--all-functions` exports the complete image. Default handler stubs for unused
vectors are excluded; code-address escapes and pointer relocations extend the
worklist. DOT and Mermaid CFG views render function clusters, typed block edges
and dashed call-target edges.

## 10. Runtime coverage

Rust embedded no-std concurrency is the first priority:

| Runtime | Spawn | Join/Await | Scope |
|---|---|---|---|
| Embassy | `Spawner::spawn`, task pool | task-handle poll (best effort) | — |
| RTIC | generated task dispatchers | — | — |
| C++ `std::thread`/`jthread` | constructors | `join`, `detach` | — |
| C++ `std::async` | async template | future wait not modeled | — |
| OpenMP | `GOMP_parallel`, `GOMP_parallel_start`, `__kmpc_fork_call`, `__kmpc_fork_teams` | region end not modeled | parallel region |

Rust `std::thread`, Rayon, Crossbeam, Tokio, async-std and smol are not part of
the supported Rust profile. Keeping them out avoids pulling large runtime and
formatting trees into real-time images. No thread/task contexts are synthesized
for those APIs.

Detection order is high-level API first, low-level runtime API fallback. This
avoids reporting a Rust/C++ runtime trampoline (`thread_start`, `_M_run`) as the
user task when the actual spawn site and closure/callable type are visible.

C/C++ and OpenMP are second priority: pthread, `std::thread`/`jthread`/`async`,
OpenMP regions, FreeRTOS, Zephyr and ThreadX. Dynamic PLT imports are synthesized
as named function nodes before rule matching, so a call to an imported
`GOMP_parallel`, `pthread_create` or `std::thread::join` is not folded into an
anonymous neighboring stub. OpenMP outlined entries are recovered from the
runtime argument register (`GOMP_parallel` argument 0, libomp fork-call
argument 2), and each resolved parallel region gets an
`openmp-parallel` scope with an implicit join. C++ callable entries are
recovered conservatively by matching the constructor's Itanium callable marker
against generated `_M_run` symbols; the lambda body itself is not demangled or
reconstructed.

## 11. Architecture coverage

Decoding is table/trait-driven. The first wave targets the common embedded
families:

1. **Thumb** (ARMv6-M/ARMv7-M/ARMv7E-M/ARMv8-M): Cortex-M0/M0+/M3/M4/M7/M33.
2. **RISC-V** 32/64 (including compressed instructions).
3. **AArch64**.
4. **x86-64**.

The architecture layer is designed so that ARMv7-A/R, Xtensa, MIPS, PowerPC and
TriCore decoders can be added without changing the graph model. Timing models
are added per core, not per decoder: an architecture can be fully decoded while
its timing is reported as unavailable. That is preferable to fabricating
numbers. AArch64 and x86-64 now have generic statistical tables, while specific
cores still need calibration data for meaningful bounds.

## 12. Versioning and compatibility

- `schema_version` is `1.2` for this document. Version 1.2 adds the optional
  top-level `locks` event list and lock/semaphore enums; v1.0/v1.1 documents
  remain readable.
- Minor versions add optional fields and new enum values; consumers should
  ignore unknown fields and treat unknown edge kinds/confidence values as
  `unknown` where their language permits.
- Major versions change graph semantics or remove fields.
- The generated JSON Schema is checked in and regenerated by `make schema`.
- The tool version, rule database version and timing table version are recorded
  in `tool` for reproducibility.

## 13. Non-goals for v1

- Full field-sensitive heap/data-flow points-to analysis; only bounded vtable
  candidate resolution is implemented.
- A WCET proof or automatic loop-bound inference.
- Executing the firmware or reconstructing runtime traces.
- Perfect recovery from fully stripped, LTO+ICF images (symbols are expected;
  best-effort diagnostics are still emitted).
- Exhaustive RTOS queue/event/condition-variable modeling. Common mutex and
  semaphore APIs are covered by lock events; spawn/join/scope/ISR/locks are the
  v1 core.

## 14. M0/M1/M2 implementation notes

M0 and M1 implement the base graph and runtime semantics of this document:

- ELF loading with symbols, entry point, ARM attributes and Cortex-M vector
  tables;
- Thumb/A32, AArch64, RISC-V 32/64 and x86-64 decoding;
- function discovery, recursive-descent basic blocks, direct calls and tail
  calls;
- `startup`, `main` and Cortex-M `isr` contexts with `isr-activate` edges;
- Cortex-M0/M0+/M3/M4/M7/M33 and generic RV32/RV64 cycle tables, with
  `--freq` converting cycles to `time_ns`;
- JSON, DOT and Mermaid emitters, schema validation and diagnostics.

M1 adds the runtime rule engine:

- Embassy and RTIC no_std Rust rules;
- pthread, FreeRTOS, Zephyr and ThreadX C API rules;
- closure/future type recovery from monomorphized Rust symbols, producing real
  async task contexts and entries;
- join edges for C/C++ and RTOS handles, OpenMP parallel-region scopes with
  spawn members, and the Embassy task-handle poll await rule;
- bounded entry-argument recovery for Thumb/A32 and x86-64 C spawn APIs;
- orphan task contexts for Rust spawn APIs whose call sites were fully inlined
  and left no usable DWARF record: the closure/future type is recovered from
  the instantiated spawn symbol and marked with
  `ext["elf2tdg.orphan_spawn_api"]`; no spawn edge/site exists in that case.

M2 adds debug-info-assisted recovery and hardened optimized-code heuristics:

- DWARF unit/DIE parsing for `subprogram` and `inlined_subroutine` records,
  resolving names through `DW_AT_abstract_origin`/`DW_AT_specification` and
  concrete address ranges through `DW_AT_low_pc`/`DW_AT_high_pc`;
- inlined Embassy spawn recovery: the shallowest user-facing inline DIE for a
  given caller and task future type wins, and implementation-layer
  instantiations inside the executor are filtered out;
- logical task-entry functions and contexts for spawns whose concrete entry is
  not a callable symbol, marked with `ext["elf2tdg.logical_task"]`;
- inline and direct lock/semaphore event recovery with source call sites for
  C/C++ and RTOS APIs;
- a bounded linear call scan of undecoded gaps after unresolved indirect jumps,
  accepting only direct calls to known function entries and marking them
  `low` confidence with a `heuristic-direct-calls` diagnostic;
- bounded scanning limits and diagnostics for malformed or truncated DWARF.

M3 analysis extensions currently implement:

- a petgraph-based `FunctionCfg` intermediate representation, CFG JSON/DOT/
  Mermaid output, function selection, raw instruction/byte retention,
  call-return block boundaries and noreturn continuation pruning;
- AArch64 entry recovery through absolute `adr`/`adrp` + `add`, literal `ldr`,
  register loads, copies and `movz`/`movk` chains;
- RISC-V entry recovery through `auipc` + `addi`, `lui` + `addi`, loads,
  copies and compressed aliases; argument registers `a0`–`a7`;
- generic AArch64 and x86-64 statistical timing models, selected explicitly
  with `--cpu aarch64` or `--cpu x86-64`;
- x86-64 32-bit register zero-extension for function pointers emitted as
  `mov $imm32, %edi` at `-O0`;
- named PLT stubs for dynamic ELF images, so imported runtime APIs participate
  in rule matching and call-graph edges;
- C++ `std::thread`/`jthread` constructor/join/detach and `std::async`
  recognition from Itanium-mangled names, plus conservative `_M_run` callable
  entry recovery from the constructor marker;
- GCC GOMP and LLVM libomp OpenMP spawn rules with outlined-entry recovery and
  implicit parallel-region scopes;
- helper-wrapper entry forwarding, including `-O0` stack spill/reload pairs;
- function-pointer values loaded from globals or recoverable memory slots, and
  indirect calls through a register or direct memory pointer (`direct: false`,
  medium confidence);
- Embassy task-handle poll await rule;
- DWARF line-program source file/line/column extraction for functions;
- per-function DWARF inline-frame ranges with source call sites, and typed
  lock/semaphore events for direct and inlined operations;
- indexed jump tables and C++ vtable/function-pointer dispatch recovery;
- stripped-image prologue seeding when no local code symbols exist;
- real C, C++ and OpenMP integration fixtures in addition to the Rust fixtures.

Still deferred: arbitrary computed pointer targets; full C++ callable/type
demangling; OpenMP task/barrier edges; general `.await` lowering; DWARF
variable/type data; multi-level wrapper forwarding and transformed forwarded
values. Function names still come from
the symbol table in normal images. M7 auto-detection from `7E-M` attributes
falls back to the Cortex-M4 table, so use `--cpu cortex-m7` when the exact core
is known.
