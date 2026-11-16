# elf2tdg

Static Task Dependency Graph (TDG) extraction for embedded real-time ELF
images. The target input is a linked ELF produced by Rust, C or C++ toolchains;
the target output is a versioned JSON graph plus human-readable diagrams.

The analyzer keeps an explicit per-function **control-flow graph** (`FunctionCfg`,
backed by `petgraph::StableDiGraph`) between the ELF and the TDG. Basic blocks,
raw instruction bytes, typed edges, call sites, timing and source locations are
preserved for the CLI and a future IDA-style UI. TDG blocks and call edges are
derived from this CFG; cross-function task/concurrency edges are layered on top.

## Status: M0 + M1 + M2 complete; M3 core analysis implemented

Implemented:

- ELF loading via `object`: sections, symbols, entry point, ARM attributes,
  Cortex-M vector tables, relocation/debug-info flags.
- Capstone decoding for Thumb/A32, AArch64, RISC-V 32/64 and x86-64.
- Symbol/entry/vector-seeded function discovery and recursive-descent basic
  blocks, represented as `FunctionCfg` values in a petgraph
  `StableDiGraph`. Typed intra-function edges, call sites, raw instruction
  bytes and terminators are retained for the CFG view and downstream consumers.
- TDG function blocks and call edges are derived from the CFG instead of a
  second control-flow representation.
- Startup/main/ISR contexts; Cortex-M vector activation edges
  (`isr-activate`, vector/IRQ numbers).
- Timing models for Cortex-M0/M0+/M3/M4/M7/M33 and generic in-order RV32/RV64:
  per-block cycles and optional wall-clock time from `--freq`. M3 adds opt-in
  generic AArch64 and x86-64 statistical throughput models
  (`--cpu aarch64` / `--cpu x86-64`); they are never enabled silently.
- JSON output validated against the versioned schema, plus DOT and Mermaid
  renderers.
- Runtime rule engine for spawn/join/scope/await:
  - Rust `std::thread` (spawn, Builder, scope, JoinHandle), Rayon, crossbeam,
    Tokio, async-std, smol, Embassy and RTIC;
  - POSIX pthread, FreeRTOS, Zephyr and ThreadX C APIs;
  - C++ `std::thread`/`jthread` constructors, joins/detach, and `std::async`
    from Itanium-mangled symbols. A callable type marker is matched against
    generated `_State_impl<...>::_M_run` symbols to recover a conservative
    thread entry instead of leaving every C++ spawn opaque;
  - GCC `GOMP_parallel`/`GOMP_parallel_start` and LLVM libomp
    `__kmpc_fork_call`/`__kmpc_fork_teams` OpenMP regions.
- Dynamic-ELF PLT synthesis: imported functions get named `plt` nodes and
  direct call edges, so runtime rules can match `GOMP_parallel`,
  `std::thread::join`, `pthread_create`, and similar imports instead of
  folding several PLT stubs into one anonymous function.
- Rust monomorphized closure/future types are recovered from symbols
  (`spawn::<app::main::{closure#0}>`), so resolved Rust spawns produce real
  thread/scoped-thread/async contexts and entries.
- DWARF parsing recovers inlined subroutine call sites. Rust spawn/scope calls
  that disappear from the machine call graph at `-O1`/`-O2` are reconstructed
  from inline DIEs, including source-level call-site ranges and closure types.
- When an inlined spawn entry cannot be mapped to a callable symbol, M2 emits a
  synthetic zero-size `task-entry` function and matching context marked with
  `ext["elf2tdg.logical_task"]`, so the task stays visible without inventing an
  address. Inline `join` and scope-exit relations are linked to those contexts.
- If a Rust spawn API has no call-site or DWARF evidence at all, M1's fallback
  still recovers the task/closure type from the instantiated spawn symbol and
  emits an *orphan* task context with `ext["elf2tdg.orphan_spawn_api"]`.
- After an unresolved indirect jump, a bounded heuristic scan of the undecoded
  gap recovers direct calls to known function entries. These edges are
  `low`-confidence and reported with a `heuristic-direct-calls` diagnostic;
  this is what makes optimized Tokio dispatch recoverable without treating the
  scan as ground truth.
- Join edges use a conservative unique-spawn heuristic; structured scopes
  (`thread::scope`, Rayon/crossbeam scopes) become `Scope` nodes with members.
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
- Indirect-call and tail-call recovery for register-held function pointers,
  static pointer chains, vtable slots, relocated GOT entries and
  caller-argument expressions. Import GOT slots resolve to synthesized PLT
  stubs when one exists. Switch jump tables are expanded into CFG case edges,
  bounded by a preceding comparison when available: x86-64 absolute and
  PIE-relative indexed tables, ARM Thumb `tbb`/`tbh`, common AArch64
  byte-offset table sequences, ARM A32 `ldrls pc, [pc, rN, lsl #2]`
  absolute-address tables and `addls pc, pc, rN, lsl #2` branch tables, and
  RISC-V absolute-pointer tables. Indirect jumps that stay in the function become
  CFG edges; jumps that leave it become `tail: true` call edges.
  Caller-argument
  propagation resolves dispatch helpers and static C++ virtual calls when every
  known caller agrees on one target. These edges carry `direct: false` and
  medium confidence; ambiguous or dynamic targets remain unresolved with
  diagnostics.
- OpenMP parallel-region `Scope` nodes with implicit join membership.
- Async handle poll rules for Tokio, async-std, smol and Embassy in addition to
  spawn/join detection.
- DWARF line-program extraction: functions receive source file/line/column
  information when debug info is present.
- Stripped-image fallback: when no local code symbols exist, entry/vector
  seeds are supplemented by architecture-aware prologue scanning
  (`endbr64`/`push rbp; mov rbp,rsp`, `push {...,lr}`, `stp x29,x30`, RISC-V
  stack adjustment), with a `stripped-heuristic-seeds` diagnostic.
- CFG CLI view: `--view cfg` exports lossless per-function JSON or
  DOT/Mermaid CFGs, with function selection (`--function`), typed control-flow
  edges, call/return blocks, call targets, indirect-target expressions, raw
  instruction bytes and source locations. Concrete instructions can be omitted
  from JSON and graph labels with `--no-cfg-instructions`. By default the CFG
  is a multi-root system slice: main/startup, every valid vector-table ISR,
  task/async contexts, callbacks and function-pointer escapes. Default-handler
  stubs shared by unused vectors are excluded. `--reachable-from ROOT` narrows
  the export to one root, and `--all-functions` exports the complete image.
- Loader/ELF view: `--view elf` renders the loaded ELF directly as a Mermaid
  layout diagram, without running CFG or TDG analysis. It shows `PT_LOAD`
  segments, allocated sections, file/memory sizes, entry point, permissions and
  a color-coded linear disassembly. Segment colors distinguish RX/RW/R/RWX and
  instruction colors distinguish calls, branches, returns, stack, memory,
  arithmetic, system and other instructions. `--elf-max-insns N` caps the
  disassembly per executable section (default 256; 0 means unlimited).
- DOT/Mermaid render scopes, spawn/join edges and runtime contexts, with a
  concurrency-only projection and a built-in node/edge legend for large
  optimized binaries. The renderers mark synthesized logical/orphan task
  contexts with dashed borders and low-confidence spawn/join/await edges with
  dashed lines and `?`.
- Typed errors, recoverable diagnostics, resource limits, and fixture tests.
- Worked, reproducible examples with checked-in ELF, JSON, DOT and SVG output:
  Rust spawn/join/scope at `-O0` and `-O2`, plus a Cortex-M0 ISR/timing image.

Still deferred:

- Indexed jump tables, C++ vtable dispatch and fully computed pointer targets;
  the current indirect resolver handles register/memory-held pointers only.
- Fully type-aware C++ callable recovery and libc++ demangling; the current
  `_M_run` marker heuristic is conservative and does not recover the lambda
  body itself.
- OpenMP task/barrier edges beyond the parallel-region scope and spawn.
- General `.await` lowering beyond recognized runtime handle poll functions.
- DWARF variable/type data; source locations and inline call sites are
  extracted, but function names still come from the symbol table.
- Name-aware stripped-image recovery beyond prologue seeding (for example
  recovery of C++ lambdas and virtual methods without symbols).
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

The C fixtures are built with `arm-none-eabi-gcc`:

```sh
make -C tests/fixtures/cortex_m0
make -C tests/fixtures/cortex_m_spawn
```

The Rust thread fixture is compiled with the host `rustc` at `-O0` and `-O2` by
its integration test. C++ and OpenMP fixtures are compiled on demand with
`g++`/`gcc`. All integration tests build their fixture on demand and report a
skip when the required toolchain is absent.

## Usage

```sh
# JSON for downstream analysis
cargo run -p elf2tdg -- firmware.elf --cpu cortex-m4 --freq 168MHz \
    --format json --output tdg.json

# Graphviz
cargo run -p elf2tdg -- firmware.elf --freq 168MHz --format dot --output tdg.dot
dot -Tsvg tdg.dot -o tdg.svg

# Mermaid
cargo run -p elf2tdg -- firmware.elf --format mermaid --output tdg.mmd

# Loader-backed ELF layout: colored segments, sections and disassembly
cargo run -p elf2tdg -- firmware.elf --view elf --output elf-layout.mmd

# Readable concurrency-only view with a legend (recommended for large Rust binaries)
cargo run -p elf2tdg -- firmware.elf --format dot \
    --projection concurrency --legend --output tdg-concurrency.dot
dot -Tsvg tdg-concurrency.dot -o tdg-concurrency.svg

# Dynamic C/C++/OpenMP host binary: PLT imports become named function nodes
cargo run -p elf2tdg -- app.elf --cpu x86-64 --freq 3GHz \
    --format json --output app-tdg.json

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

Useful flags:

| Flag | Meaning |
|---|---|
| `--cpu cortex-m4` | explicit timing model; Cortex-M/RISC-V are auto-detected when omitted. `aarch64` and `x86-64` select statistical generic models |
| `--freq 168MHz` | core clock; enables `time_ns` in blocks |
| `--instructions` | include per-instruction text and cycle costs (requires a timing model) |
| `--format json|dot|mermaid` | output format; defaults to `json`, or `mermaid` for `--view elf` |
| `--view tdg|cfg|elf` | final TDG (default), per-function CFG, or loader-backed ELF layout |
| `--elf-max-insns N` | maximum disassembly instructions per executable section in `--view elf` (default 256; 0 = unlimited) |
| `--function NAME|0xADDR` | select one function for CFG output |
| `--reachable-from NAME|0xADDR` | narrow the CFG to one reachability root |
| `--no-prune-runtime` | expand panic/format/compiler-builtins/drop-glue boundaries during CFG reachability |
| `--all-functions` | export CFGs for every function, including unreachable code |
| `--no-cfg-instructions` | omit concrete instructions from CFG JSON and DOT/Mermaid labels |
| `--projection full|concurrency` | TDG graph projection; `concurrency` omits ordinary call edges |
| `--legend` | append a TDG node/edge legend to DOT or Mermaid output |
| `--output PATH` | write to a file instead of stdout |
| `--max-diagnostics N` | cap retained diagnostics (default 500) |
| `--verbose` | print a summary to stderr |

Cortex-M auto-detection maps ARM `Tag_CPU_arch` values (`6S-M`, `7-M`, `7E-M`,
`8-M`) to the closest timing family. A `7E-M` image is treated as Cortex-M4;
pass `--cpu cortex-m7` if it is actually an M7. Generic AArch64/x86-64 cycle
tables are opt-in because their results are statistical throughput estimates,
not bounds for a specific core.

`--instructions`, `--projection` and `--legend` apply to TDG output.
`--function`, `--reachable-from`, `--no-prune-runtime`,
`--all-functions` and `--no-cfg-instructions` apply only to `--view cfg`.
With no CFG selector, the export is a multi-root system slice: call, spawn,
callback, join and await edges are followed from main/startup, vector-table
ISRs, task contexts and callbacks, plus code addresses that escape through
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

`tests/fixtures/rust_threads/main.rs` exercises `thread::spawn`,
`JoinHandle::join` and `thread::scope`. At `-O0` the output includes a real
`thread` context pointing at `main::{closure#0}`, a `scoped-thread` context, a
`join` edge from `ctx:main`, and a `rust-thread-scope` scope containing the
scoped spawn. At `-O2` both spawn calls are inlined; M2 reconstructs the two
spawn call sites from DWARF, creates logical task-entry functions/contexts, and
still links the join and scope exit to them. The integration test runs both
optimization levels.

`tests/fixtures/cortex_m_spawn/main.c` calls `xTaskCreate(my_task, ...)`.
M1 resolves the entry pointer from the Thumb literal pool and emits a FreeRTOS
`spawn` edge to a thread context whose entry is `my_task`.

## Worked examples

The [`examples/`](examples/) directory contains complete, reproducible examples
with source, ELF, JSON, DOT and rendered SVG:

- [`examples/rust-concurrency/`](examples/rust-concurrency/README.md) builds the
  same Rust program at `-O0` and `-O2` and shows concrete thread/scope contexts
  versus DWARF-recovered inline spawns and logical task entries, plus per-main
  CFG JSON/SVG/Mermaid artifacts.
- [`examples/cortex-m0-isr/`](examples/cortex-m0-isr/README.md) is a small
  Cortex-M0 image with reset/main/ISR contexts, USART1 IRQ 37, direct calls,
  48 MHz cycle-to-nanosecond estimates, and a per-`main` CFG export.

A rendered walkthrough with both diagrams and the full legend is in
[`examples/tdg-example.html`](examples/tdg-example.html). See
[`docs/tdg-legend.md`](docs/tdg-legend.md) for the schema-level legend. Each
example's `make` target regenerates its artifacts.

## Layout

```
crates/elf2tdg-schema/    TDG data model, validation, JSON Schema
crates/elf2tdg/           loader, decoders, CFG/call graph, timing, runtime rules,
                          origin tracking, emitters, CLI
docs/tdg-schema.md        graph and timing semantics
docs/cfg-format.md        function CFG JSON, call/return blocks and CLI view
docs/elf-view.md          loader-backed ELF layout, colors and disassembly limits
docs/tdg-legend.md        diagram shapes, colors, edge styles and confidence
schema/tdg.schema.json    generated JSON Schema (2020-12)
examples/                 worked Rust and Cortex-M examples plus artifacts
tests/fixtures/           C/Rust firmware fixtures
```

See [docs/tdg-schema.md](docs/tdg-schema.md) for the TDG model,
[docs/cfg-format.md](docs/cfg-format.md) for the CFG intermediate format, and
[docs/elf-view.md](docs/elf-view.md) for the loader-backed ELF layout view.
