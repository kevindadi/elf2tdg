# elf2tdg

CFG-first static analysis for embedded real-time ELF images. The target input is a linked ELF produced by Rust, C or C++ toolchains;
the target output is a versioned JSON graph plus human-readable diagrams.

The analyzer keeps an explicit per-function **control-flow graph** (`FunctionCfg`,
backed by `petgraph::StableDiGraph`) between the ELF and the CFG. Basic blocks,
raw instruction bytes, typed edges, call sites, timing and source locations are
preserved for the CLI and a future IDA-style UI. CFG blocks and call edges are
extends this CFG with program roots, an interprocedural call graph and concurrency annotations.

## Status: M0 + M1 + M2 complete; M3 core analysis implemented

Implemented:

- ELF loading via `object`: sections, symbols, entry point, ARM attributes,
  Cortex-M vector tables, relocation/debug-info flags.
- Capstone decoding for Thumb/A32, AArch64, RISC-V 32/64 and x86-64.
- Symbol, DWARF-subprogram, entry, vector/trap, init/fini and pointer-seeded
  function discovery, plus recursive-descent basic blocks represented as
  `FunctionCfg` values in a petgraph `StableDiGraph`. Cortex-M vector tables are recognized both by
  section name and by their initial-SP/handler pattern when embedded in
  another allocated section; ARM/AArch64 exception vectors and RISC-V trap
  vectors provide roots even without calls. Typed intra-function edges, call sites, raw instruction
  bytes and terminators are retained for the CFG view and downstream consumers.
- CFG-first analysis metadata: `ProgramCfg` owns execution roots, the
  interprocedural call graph, concurrency call-site annotations
  (spawn/join/await/callback/scope), lock events, diagnostics, image and timing
  metadata. CFG JSON is self-contained and is the primary analysis document.
- Execution roots for startup, main, ISR, task, callback and pointer entries;
  ISR roots retain vector and IRQ numbers.
- Timing models for Cortex-M0/M0+/M3/M4/M7/M33 and generic in-order RV32/RV64:
  per-block cycles and optional wall-clock time from `--freq`. M3 adds opt-in
  generic AArch64 and x86-64 statistical throughput models
  (`--cpu aarch64` / `--cpu x86-64`); they are never enabled silently.
- Optional TOML/JSON board profiles (`--board-profile`, schema v2) supply clock
  domains, memory regions with fetch wait states, and class/mnemonic-specific
  cycle overrides. A Cortex-M4 resource/dependency pipeline model schedules
  block instructions using register hazards, resource occupancy and branch
  penalties. The CFG timing metadata records the profile ID, SHA-256 and source, and
  profile files are strictly validated before analysis. Optional LRU
  instruction-cache and data-cache profiles propagate concrete cache states
  over each CFG, report per-block hit/miss ranges and add modeled miss
  penalties; data-cache analysis also records decoded read/write memory
  accesses. Optional branch-prediction profiles model static, BTFN or two-bit
  bimodal direction prediction with configurable misprediction penalties.
  Per-region data-memory timing models read/write bus widths and wait states and
  reports access coverage plus per-region latency. Optional WCET profiles bound
  loops and compute per-function/per-root longest-path estimates across the
  call graph. See [docs/board-profile.md](docs/board-profile.md).
- Versioned CFG JSON plus DOT and Mermaid renderers.
- Runtime rule engine for spawn/join/scope/await:
  - Rust no-std: Embassy (`Spawner::spawn`, task poll) and RTIC;
    `std::thread`, Rayon, crossbeam, Tokio, async-std and smol are outside the
    supported Rust profile;
  - POSIX pthread, FreeRTOS, Zephyr and ThreadX C APIs;
  - C++ `std::thread`/`jthread` constructors, joins/detach, and `std::async`
    from Itanium-mangled symbols. A callable type marker is matched against
    generated `_State_impl<...>::_M_run` symbols to recover a conservative
    thread entry instead of leaving every C++ spawn opaque;
  - GCC `GOMP_parallel`/`GOMP_parallel_start` and LLVM libomp
    `__kmpc_fork_call`/`__kmpc_fork_teams` OpenMP regions.
- Dynamic-ELF PLT synthesis: imported functions get named `plt` nodes and
  direct call edges, so runtime rules can match `GOMP_parallel`,
  `pthread_create`, `xTaskCreate`, and similar imports instead of folding
  several PLT stubs into one anonymous function. GLOB_DAT-only imports
  without a local PLT stub (`malloc`, `free`, `syscall`, ...) become zero-size
  `external` function nodes, so GOT-indirect calls resolve instead of remaining
  unresolved.
- Rust monomorphized future/task types are recovered from symbols, so resolved
  Embassy spawns produce real async-task roots and entries. A task generic
  such as `app::sensor_task` is mapped to the generated
  `TaskStorage<...>::poll` machine function.
- DWARF parsing recovers inlined subroutine call sites. Embassy
  `Spawner::spawn` calls that disappear from the machine call graph at
  `-O1`/`-O2` are reconstructed from inline DIEs, including source-level
  call-site ranges and task future types. CFG functions expose the unique
  `DW_TAG_inlined_subroutine` ranges as `inline_frames`, with demangled/raw
  linkage names, source call sites, concrete `low`/`high` addresses and depth.
- Direct and DWARF-inlined lock operations produce typed CFG `locks` events:
  acquire/try-acquire/release, lock/semaphore kind, concrete inline ranges,
  source call sites and containing context. Supported rules cover pthread,
  FreeRTOS, Zephyr, ThreadX and C++ `std::mutex`/`shared_mutex`; the default
  no-std Rust profile does not define std/`parking_lot` lock rules. Lock
  identity/order is not guessed.
- When an inlined spawn entry cannot be mapped to a callable symbol, the
  analyzer emits a synthetic zero-size `task-entry` function and a task root,
  so the task stays visible without inventing an address.
- If a Rust spawn API has no call-site or DWARF evidence at all, the fallback
  recovers the task/future type from the instantiated spawn symbol and emits an
  orphan task annotation.
- After an unresolved indirect jump, a bounded heuristic scan of the undecoded
  gap recovers direct calls to known function entries. These edges are
  `low`-confidence and reported with a `heuristic-direct-calls` diagnostic,
  without treating the scan as ground truth.
- Join annotations use a conservative unique-spawn heuristic for C/C++ and
  RTOS APIs. OpenMP parallel regions become scope-enter/scope-exit annotations;
  structured Rust thread scopes remain vocabulary only in the no-std profile.
- Bounded spawn-entry recovery for Thumb/A32, x86-64, AArch64 and RISC-V C
  APIs: literal-pool loads, RIP-relative `lea`/memory loads, `adr`/`adrp` +
  `add`, `auipc` + `addi`, register copies, immediate adds and simple
  `movz`/`movk` chains. FreeRTOS `xTaskCreate` has a real Cortex-M fixture;
  OpenMP `GOMP_parallel` entry recovery has a real host fixture.
- Helper-wrapper forwarding: when a runtime API receives an entry register
  that came from the wrapper's own argument, call sites of that wrapper are
  inspected and a unique entry is resolved. Stack spill/reload pairs
  (`mov [rbp-16], rsi` / `mov rdx, [rbp-16]`) are followed, so `-O0` C wrappers
  and function pointers stored in memory are covered.
- Embassy executor task-poll dispatch is expanded into bounded multi-target
  call edges. The analyzer reads the task-header field load and collects
  concrete `TaskStorage<...>::poll`/`poll_exited` values stored to the same
  field across the image; multiple `Call` edges share the call site.
- Bounded trait-object points-to: valid Rust vtable layouts in read-only data
  are matched against pointer constants from related caller/callee functions.
  DWARF fat-pointer layouts (`&dyn`, `Box<dyn>`) also supply vtable bases from
  static fat pointers, arrays/registries and nested aggregate fields when code
  constants do not. Method calls become low-confidence candidate call or
  tail-call edges; `GlobalAlloc`/allocator calls remain direct edges.
- Indirect-call and tail-call recovery for register-held function pointers,
  static pointer chains, vtable slots, relocated GOT entries and
  caller-argument expressions. Import GOT slots resolve to synthesized PLT
  stubs when one exists. Switch jump tables are expanded into CFG case edges,
  bounded by a preceding comparison when available: x86-64 absolute,
  base-less indexed and PIE-relative tables, ARM Thumb `tbb`/`tbh`, common
  AArch64 byte/halfword/word-offset table sequences, ARM A32
  `ldrls pc, [pc, rN, lsl #2]` absolute-address tables and
  `addls pc, pc, rN, lsl #2` branch tables, AArch64 absolute-pointer
  tables, and RISC-V absolute-pointer and table-relative offset tables.
  Guarded tables may span up to 4096 entries; unguarded scans stay
  conservative. Indirect jumps that stay in the function become CFG edges;
  jumps that leave it become `tail: true` call edges.
  Caller-argument
  propagation resolves dispatch helpers and static C++ virtual calls when every
  known caller agrees on one target. These edges carry `direct: false` and
  medium confidence; ambiguous or dynamic targets remain unresolved with
  diagnostics.
- Indexed function-pointer call tables are expanded into bounded candidate
  sets, covering `call [table + index*scale]`, register loads from an indexed
  table, and RISC-V table-relative call sequences. Table scans use a recovered
  comparison bound plus allocated data-symbol or DWARF variable sizes.
- Direct callee return values feed indirect calls: getters/factories such as
  `get_handler()()` resolve through branch-sensitive return-register
  summaries. Local stack slots initialized with immediate or register function
  pointers are also followed, including branchy assignments. These produce
  `resolved-call-table` and `resolved-returned-indirect-call` diagnostics.
- DWARF-typed function-pointer fields resolve dynamic calls such as
  `ops->run()` when aggregate member metadata identifies the loaded field and
  typed global objects or global pointers provide concrete candidates. The
  result is a bounded `resolved-typed-field-candidates` call set.
- OpenMP parallel-region `Scope` nodes with implicit join membership.
- Embassy task-handle poll await rule in addition to spawn detection.
- DWARF line-program extraction: functions receive source file/line/column
  information when debug info is present.
- DWARF type and variable extraction: aggregate layouts and member offsets,
  pointer/subroutine/array types, global variable addresses and sizes, and
  frame-relative locals/parameters. Function-pointer fields validate dynamic
  field calls, typed global objects and pointers-to-objects provide bounded
  candidate sets, and variable bounds keep indexed table scans from crossing
  into adjacent data when symbols are stripped.
- Stripped-image fallback: when no local code symbols exist, entry/vector
  seeds are supplemented by architecture-aware prologue scanning
  (`endbr64`/`push rbp; mov rbp,rsp`, `push {...,lr}`, `stp x29,x30`, RISC-V
  stack adjustment), with a `stripped-heuristic-seeds` diagnostic.
- DWARF `DW_TAG_subprogram` entries seed functions whose symbol was stripped
  and provide a display name and concrete range. All named code symbols and
  DWARF subprogram entries are system roots, so uncalled static functions and
  local library helpers remain in the default CFG scope even without a call,
  callback or pointer-table reference.
- Statically null indirect call targets (for example an empty vtable drop slot)
  are marked `null_target` instead of being reported as unresolved; when the
  call is unconditional, its dead continuation is removed as well.
- Noreturn classification covers API terminators (`abort`, `_exit`, panic
  entry points, C++ termination helpers) and CFG-derived halt loops. Calls to
  noreturn functions get a `noreturn-call` terminator and no `call-return`
  continuation; unreachable continuation blocks are removed, while shared
  return blocks stay reachable from their other predecessors.
- Callback registration rules emit `callback-bind` CFG edges when the callback
  argument resolves to a concrete function. Rules cover libc/POSIX
  `atexit`/`signal`/`qsort`/`pthread_atfork`, FreeRTOS timers, Zephyr
  timer/work initialization and ThreadX timers; callbacks become system roots.
- Global pointer roots are recovered from init/fini arrays, writable data, GOT
  slots and read-only pointer tables. They seed the default CFG system scope
  and appear in CFG JSON as `pointer_roots`. Code that references a data table
  also follows a bounded run of function pointers, so callback/dispatch tables
  remain in a single-root CFG slice.
- CFG root semantics separate execution roots (startup/main/task/ISR contexts,
  callbacks, architecture entries and pointer roots) from discovery roots
  (uncalled code symbols and DWARF subprograms). `ProgramCfg::execution_roots`
  and `reachable_from_execution_roots` are the conservative base for
  reachability and dead-code passes; the default export still includes all
  discovered functions.
- Unresolved indirect call and tail-jump sites are explicit `unresolved-call`
  CFG edges with `confidence: unknown`, so graph passes do not mistake an
  unknown call for the absence of a call.
- External imports and zero-size logical task entries remain selectable CFG
  functions. Their JSON view carries a `no_code` reason and empty block list;
  DOT/Mermaid render an explicit dashed no-code note instead of an empty graph.
- CFG task-name mapping: `--function sensor_task` and `--reachable-from
  sensor_task` resolve an execution-context alias to its entry function, so
  async task names select their real `TaskStorage<...>::poll` CFG rather than a
  helper symbol that merely contains the name.
- CFG structural validation checks entry/map/node consistency, block and
  instruction ranges, call-site ownership and flag combinations, terminator
  semantics, edge kinds/sites and cross-function target references.
  `ProgramCfg`, `CfgFunction` and `FunctionCfg` expose
  `validate`/`validate_with_limit`/`ensure_valid`; analysis refuses to publish
  an invalid CFG.
- CFG graph analysis: `FunctionCfg::analyze_graph` reports reachable and
  unreachable blocks, SCCs, natural loops, dominator/post-dominator sets and
  immediate dominators. `FunctionCfg::normalize` removes proven-unreachable
  blocks and merges contiguous fallthrough-only blocks. Unreachable removal is
  skipped when a reachable unresolved control transfer could target unknown
  code.
- CFG CLI view: the default `--view cfg` exports lossless per-function JSON or
  DOT/Mermaid CFGs, with function selection (`--function`), typed control-flow
  edges, call/return blocks, noreturn continuation pruning, call targets,
  indirect-target expressions, raw instruction bytes and source locations. CFG
  JSON also carries execution roots, the interprocedural call graph,
  concurrency annotations and lock events. Concrete instructions can be omitted
  from JSON and graph labels with `--no-cfg-instructions`. By default the CFG
  is a multi-root system slice: main/startup, every valid vector-table ISR,
  ARM/AArch64 exception vectors, RISC-V trap vectors, ELF init/fini entry
  points, task/async contexts, callback registrations, global function-pointer
  roots, and every function represented by a code symbol or DWARF subprogram.
  Default-handler stubs shared by unused vectors are excluded.
  `--reachable-from ROOT` narrows the export to one root, and `--all-functions`
  exports the complete image.
- Loader/ELF view: `--view elf` renders the loaded ELF directly as a Mermaid
  layout diagram, without running CFG analysis. It shows `PT_LOAD`
  segments, allocated sections, file/memory sizes, entry point, permissions and
  a color-coded linear disassembly. Segment colors distinguish RX/RW/R/RWX and
  instruction colors distinguish calls, branches, returns, stack, memory,
  arithmetic, system and other instructions. `--elf-max-insns N` caps the
  disassembly per executable section (default 256; 0 means unlimited).
- DOT/Mermaid render the selected function CFGs, call targets, no-code
  functions and control-flow edges. Program-level roots and concurrency
  annotations are carried in CFG JSON.
- Typed errors, recoverable diagnostics, resource limits, and fixture tests.
- Worked, reproducible examples with checked-in ELF, JSON, DOT and SVG output:
  a no-std Embassy task image, plus a Cortex-M0 ISR/timing image.

Still deferred:

- Fully computed pointer targets beyond the bounded patterns above, such as
  values transformed through arbitrary arithmetic, indirect callees, or
  pointer state that crosses more than a few call levels.
- Fully type-aware C++ callable recovery and libc++ demangling; the current
  `_M_run` marker heuristic is conservative and does not recover the lambda
  body itself.
- OpenMP task/barrier edges beyond the parallel-region scope and spawn.
- General `.await` lowering beyond recognized runtime handle poll functions.
- Full DWARF type/location coverage beyond the bounded extraction above:
  location lists, split-DWARF cross-unit references, nested anonymous
  aggregates, and complete C++ class/vtable reconstruction.
- Name-aware stripped-image recovery beyond prologue and DWARF-subprogram
  seeding (for example recovery of C++ lambdas and virtual methods without
  symbols).
- Wrapper forwarding through multiple user levels and through values that are
  transformed before the runtime call.

The milestones are intentionally a foundation, not a WCET tool. Static cycle
counts are explicitly **not** execution-time or WCET bounds.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The normal test suite includes deterministic malformed-ELF and CFG-invariant
smoke coverage. The libFuzzer harness under [`fuzz/`](fuzz/) requires a nightly
toolchain and `cargo-fuzz`:

```sh
make fuzz-seed
make fuzz
```

The C fixtures are built with `arm-none-eabi-gcc`:

```sh
make -C tests/fixtures/cortex_m0
make -C tests/fixtures/cortex_m_spawn
```

The checked-in Rust example is a `thumbv7em-none-eabi` no-std Embassy ELF; its
integration test loads that artifact directly. The allocator/trait-object and
static trait-registry fixtures also target `thumbv7em-none-eabi` and are
rebuilt with `make alloc-fixture` and `make static-trait-fixture`. Rebuilding
them requires `rustup target add thumbv7em-none-eabi`. C++ and OpenMP fixtures
are compiled on demand with `g++`/`gcc`. Tests that build fixtures report a
skip when the required toolchain is absent.

## Usage

```sh
# Loader-backed ELF layout: colored segments, sections and disassembly
cargo run -p elf2tdg -- firmware.elf --view elf --output elf-layout.mmd

# Dynamic C/C++/OpenMP host binary: PLT imports become named function nodes
cargo run -p elf2tdg -- app.elf --cpu x86-64 --freq 3GHz \
    --format json --output app-cfg.json

# Lossless function CFG for one function
cargo run -p elf2tdg -- firmware.elf --view cfg --format json \
    --function main --output main-cfg.json

# Readable CFG and compact CFG JSON
cargo run -p elf2tdg -- firmware.elf --view cfg --format dot \
    --function main --output main.dot
cargo run -p elf2tdg -- firmware.elf --view cfg --format json \
    --function main --no-cfg-instructions --output main-blocks.json

# Default CFG: all async roots (main, startup, ISR vectors, tasks, callbacks)
cargo run -p elf2tdg -- firmware.elf --view cfg --format json \
    --output system-cfg.json

# Single-root slice for focused analysis
cargo run -p elf2tdg -- firmware.elf --view cfg --format json \
    --reachable-from main --output main-cfg.json
cargo run -p elf2tdg -- firmware.elf --view cfg --format json \
    --reachable-from sensor_task --output sensor-task-cfg.json

# Complete image CFG, including functions unreachable from any root
cargo run -p elf2tdg -- firmware.elf --view cfg --format json \
    --all-functions --output full-cfg.json
```

The CFG JSON format is documented in [docs/cfg-format.md](docs/cfg-format.md).
CFG diagnostics are scoped to the selected/reachable functions, with the number
of omitted image-wide diagnostics reported as `diagnostics_omitted`.
For the recommended `opt-level=1` + full-debug-info firmware profile, see
[docs/analysis-profile.md](docs/analysis-profile.md).

Useful flags:

| Flag | Meaning |
|---|---|
| `--cpu cortex-m4` | explicit timing model; Cortex-M/RISC-V are auto-detected when omitted. `aarch64` and `x86-64` select statistical generic models |
| `--board-profile PATH` | board timing profile in TOML (or JSON with a `.json` extension); supplies CPU, clocks, memory fetch costs and instruction-cost overrides |
| `--freq 168MHz` | core clock; enables `time_ns` in blocks and overrides the profile's core clock |
| `--format json|dot|mermaid` | output format; defaults to `json`, or `mermaid` for `--view elf` |
| `--view cfg|elf` | program CFG (default) or loader-backed ELF layout |
| `--elf-max-insns N` | maximum disassembly instructions per executable section in `--view elf` (default 256; 0 = unlimited) |
| `--function NAME|CONTEXT|0xADDR` | select one function or task alias for CFG output; task names map to their poll entry |
| `--reachable-from NAME|CONTEXT|0xADDR` | narrow the CFG to one function or task root |
| `--no-prune-runtime` | expand panic/format/compiler-builtins/drop-glue boundaries during CFG reachability |
| `--all-functions` | export CFGs for every function, including unreachable code |
| `--no-cfg-instructions` | omit concrete instructions from CFG JSON and DOT/Mermaid labels |
| `--output PATH` | write to a file instead of stdout |
| `--max-diagnostics N` | cap retained diagnostics (default 500) |
| `--verbose` | print a summary to stderr |

Cortex-M auto-detection maps ARM `Tag_CPU_arch` values (`6S-M`, `7-M`, `7E-M`,
`8-M`) to the closest timing family. A `7E-M` image is treated as Cortex-M4;
pass `--cpu cortex-m7` if it is actually an M7. Generic AArch64/x86-64 cycle
tables are opt-in because their results are statistical throughput estimates,
not bounds for a specific core.

`--board-profile` is opt-in and never enabled by auto-detection. The profile's
CPU model must match the ELF architecture and any explicit `--cpu`; `--freq`
overrides its core clock while keeping its source visible in the CFG/CFG timing
metadata. Without a
profile, timing output is unchanged. The examples
[`examples/profiles/cortex-m0-isr.toml`](examples/profiles/cortex-m0-isr.toml)
and
[`examples/profiles/cortex-m4-pipeline.toml`](examples/profiles/cortex-m4-pipeline.toml)
and
[`examples/profiles/cortex-m7-icache.toml`](examples/profiles/cortex-m7-icache.toml)
and
[`examples/profiles/cortex-m7-dcache.toml`](examples/profiles/cortex-m7-dcache.toml)
and
[`examples/profiles/cortex-m7-branch-prediction.toml`](examples/profiles/cortex-m7-branch-prediction.toml)
and
[`examples/profiles/cortex-m7-data-memory.toml`](examples/profiles/cortex-m7-data-memory.toml)
and
[`examples/profiles/cortex-m7-wcet.toml`](examples/profiles/cortex-m7-wcet.toml)
show the board-cost, Cortex-M4 pipeline, instruction-cache, data-cache,
branch-prediction, data-memory and WCET formats.

`--function`, `--reachable-from`, `--no-prune-runtime`,
`--all-functions` and `--no-cfg-instructions` apply only to `--view cfg`.
With no CFG selector, the export is a multi-root system slice: call, spawn,
callback, join and await edges are followed from main/startup, vector-table
ISRs, task roots and callbacks, plus code addresses that escape through
literal/function pointers. Recursion stops at panic/format/compiler-builtins
and drop-glue boundaries by default; use `--no-prune-runtime` to expand them.
Use `--reachable-from ROOT` for one root or `--all-functions` for the complete
image. CFG output includes instructions and raw bytes by default; DOT and
Mermaid labels show the first eight instructions per block. Without them,
blocks still retain addresses, terminators, timing and call sites.

`--view elf` reads only the loader data and exits before analysis; it currently
emits Mermaid only (the default format for that view). See
[docs/elf-view.md](docs/elf-view.md) for the diagram semantics and color
legend.

## Example

`tests/fixtures/cortex_m0/main.c` defines a reset handler, a main loop, a
sensor task, USART1 IRQ 37, and a Cortex-M vector table. The analyzer recovers:

- function nodes and basic blocks for all functions;
- direct calls `Reset_Handler -> main`, `main -> sensor_task`,
  `sensor_task -> delay`, `main -> delay`;
- `ctx:startup`, `ctx:main` and `ctx:isr:53` with an `isr-activate` edge
  (vector 53, IRQ 37);
- Cortex-M0 cycle ranges and nanosecond estimates at 48 MHz.

`examples/rust-concurrency/` is a `#![no_std]` Cortex-M Embassy image. It
starts a thread-mode executor, runs an `app_main` async task, and spawns sensor
and monitor tasks. The analyzer recovers six contexts (startup, main, app_main,
sensor, monitor, HardFault), three `rust-embassy` spawn edges, and resolves each
task to its `TaskStorage<...>::poll` entry. The executor's dynamic poll dispatch
is expanded into four low-confidence candidate call edges. Inlined
`Spawner::spawn` call sites are recovered from DWARF. Unused Cortex-M vectors
that alias `DefaultHandler` are filtered instead of producing false ISR
contexts.

`tests/fixtures/cortex_m_spawn/main.c` calls `xTaskCreate(my_task, ...)`.
M1 resolves the entry pointer from the Thumb literal pool and emits a FreeRTOS
`spawn` edge to a thread context whose entry is `my_task`.

## Worked examples

The [`examples/`](examples/) directory contains complete, reproducible examples
with source, ELF, JSON, DOT and rendered SVG:

- [`examples/rust-concurrency/`](examples/rust-concurrency/README.md) builds the
  no-std Cortex-M Embassy image with the recommended `analysis` profile (`-O1`,
  full DWARF, ThinLTO, `panic=abort`). It shows async task roots,
  DWARF-recovered inline spawns and realistic `TaskStorage::poll` entries, plus
  per-`start_tasks` CFG JSON/SVG/Mermaid artifacts.
- [`examples/cortex-m0-isr/`](examples/cortex-m0-isr/README.md) is a small
  Cortex-M0 image with reset/main/ISR contexts, USART1 IRQ 37, direct calls,
  48 MHz cycle-to-nanosecond estimates, and a per-`main` CFG export.

See [docs/cfg-format.md](docs/cfg-format.md) for the program CFG document and
[docs/board-profile.md](docs/board-profile.md) for timing profiles. Each
example's `make` target regenerates its artifacts.

## Layout

```
crates/elf2tdg-schema/    shared IDs, diagnostics, timing and runtime records
crates/elf2tdg/           loader, decoders, CFG/call graph, timing, runtime rules,
                          origin tracking, emitters, CLI
docs/cfg-format.md        program CFG, roots, calls, concurrency and timing
docs/board-profile.md     board clocks, memory fetch costs and cycle overrides
docs/analysis-profile.md  recommended firmware build flags and inline DWARF
docs/elf-view.md          loader-backed ELF layout, colors and disassembly limits
examples/                 worked Rust and Cortex-M examples plus artifacts
tests/fixtures/           C firmware and Rust allocator/static-trait fixtures
fuzz/                     cargo-fuzz ELF/CFG validation harness
```

See [docs/cfg-format.md](docs/cfg-format.md) for the CFG model,
[docs/analysis-profile.md](docs/analysis-profile.md) for the recommended
firmware build profile, and [docs/elf-view.md](docs/elf-view.md) for the
loader-backed ELF layout view.
