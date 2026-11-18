# Build profile for static analysis

The target firmware should be built with symbols and DWARF debug information.
`-O0` and stripped `-O2` are both poor defaults for a whole-image static
analysis, for different reasons:

- `-O0` preserves call instructions, but it also keeps wrapper functions,
  trait shims, stack spills and redundant reloads. The CFG is larger and much
  of it is compiler scaffolding rather than application control flow.
- `-O2` removes most of that scaffolding, but it also inlines concurrency
  wrappers and pointer helpers. A removed call leaves no call instruction in
  the machine code, so a symbol-only call graph silently loses the site.

Inlining is not itself the problem. The problem is losing an inlined call site
because the image was stripped or built without full debug information.

## Recommended Cargo profile

Put this in the **analyzed firmware crate's** `Cargo.toml`, not in a consumer's
manifest:

```toml
[profile.analysis]
inherits = "release"
opt-level = 1          # optimize away wrapper/stack noise, but inline less than O2
debug = true           # full DWARF, including inlined_subroutine DIEs
lto = "thin"           # remove dead code, retain cross-crate debug information
strip = "none"         # keep .symtab and .debug_* sections
panic = "abort"        # no unwind tables; panic must not be a control-flow path
```

Build and analyze it with:

```sh
cargo build --profile analysis
# For the bundled Cortex-M example:
cargo build --profile analysis --target thumbv7em-none-eabi

elf2tdg target/analysis/firmware --view cfg --format json \
    --function my_crate::main --output main-cfg.json
```

For C/C++, use the equivalent `-O1 -g` build and pass `-g` through to the
linker; do not let a packaging step run `strip` on the final image. Keep
`.symtab` and the DWARF sections in the artifact that is given to the analyzer.

## Why the settings help

- `opt-level = 1` is a pragmatic starting point. It normally removes simple
  wrappers and stack traffic while inlining less aggressively than `-O2`.
  It is not a guarantee: compilers can still inline, and some `-O1` code is
  larger than expected.
- `debug = true` writes full DIEs, not just line tables. Rust and C/C++
  toolchains emit `DW_TAG_inlined_subroutine` records with concrete low/high
  PC ranges. `debug = "line-tables-only"` is not the right choice: exact
  contents are toolchain-dependent, and it can omit the full inline/type
  information needed for reliable recovery.
- `strip = "none"` preserves both the symbol table and debug sections. If a
  separate linker or packaging step strips the ELF, the profile cannot help.
- `lto = "thin"` removes dead code and retains ThinLTO debug information. It
  can also create more cross-crate inlining. If direct call edges matter more
  than code size, compare with `lto = false`; keeping `debug = true` is more
  important than the LTO choice.
- `inherits = "release"` makes this an opt-in profile. Normal `cargo build`
  behavior is unchanged; use `--profile analysis` for the analyzed image.
- `panic = "abort"` treats panics as fatal rather than recoverable control
  flow. It removes unwind landing pads and makes the image a closer match for
  an embedded real-time target. For a `std` image, it is not a general fix:
  precompiled `std` still contains panic/formatting paths. The supported Rust
  profile is `no_std`, so the application does not link that runtime at all.

## Rust support profile: no_std only

The Rust side of this project targets freestanding embedded images:

- Embassy (`embassy_executor::Spawner::spawn`, task polling) and RTIC;
- `core` and optional `alloc` code in the analyzed image;
- no `std::thread`, Tokio, async-std, smol, Rayon, or crossbeam rules.

C/C++/OpenMP and native RTOS APIs remain supported separately. A Rust image that
does link `std` or Tokio is outside the supported profile; the analyzer will not
synthesize task roots for those APIs.

## Keep formatting and panic scaffolding out of the application

Build settings cannot remove code that the application actually calls. Avoid
`println!`, `format!`, `expect`, and `unwrap` in the default analyzed example:

- `println!`/`format!` pull in `core::fmt` dispatch and formatting trait
  implementations, even in `no_std`; on a host profile they also pull in stdio
  and allocation.
- `expect`/`unwrap` pull in panic formatting and unwinding paths even when the
  fallible case is not expected to occur at runtime.
- The CFG then contains runtime support code that is not part of the
  application's real-time control flow, and unresolved indirect calls in
  `core::fmt` look like application uncertainty.

The bundled Embassy example uses `#![no_std]`, matches fallible spawn results
with `if let`, and observes task results with `core::hint::black_box`; it does
not format or print them. Its analysis profile also sets `panic = "abort"`.
These are example and profile policies, not requirements that `elf2tdg` imposes
on every analyzed image.

## What elf2tdg recovers

The loader reads `DW_TAG_inlined_subroutine` DIEs and resolves names through
`DW_AT_abstract_origin`/`DW_AT_specification`. CFG functions now carry a compact
list of the unique inline ranges inside them, ordered by address and depth:

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

This is the same information an `addr2line` inline backtrace uses, but exposed
as address ranges for downstream tools. The `low`/`high` range describes the
concrete code generated for that inline instance. Nested entries have larger
`depth`; their ranges can be used directly, or an instruction can be attributed
to every frame whose `[low, high)` contains its address. The ranges are stored
once per function rather than repeated on every instruction, which keeps
optimized Rust JSON manageable.

It does not turn an inlined function into a fake machine-level `call`
instruction. The CFG remains the real instruction graph; inline frames are
metadata on the instruction ranges. The Embassy `Spawner::spawn` rule still
creates async-task roots and spawn annotations described in
[cfg-format.md](cfg-format.md), even when the call was inlined.

The same DWARF pass extracts a compact type/variable view: aggregate member
offsets and sizes, pointer/subroutine/array types, global addresses, and
frame-relative locals and parameters. Function-pointer fields validate
dynamic field calls; typed global objects and pointers provide bounded
candidate targets; variable extents bound indexed table scans even after a
data symbol is stripped; and `&dyn`/`Box<dyn>` fat-pointer layouts recover
vtable bases from static registries and nested fields. This is not a full type
database: location lists, split-DWARF cross-unit references and flattened
anonymous aggregates are outside the bounded extraction.

The CFG also exposes typed `locks` events for acquire/try-acquire/release
operations. The supported rules cover pthread mutex/RW-lock/semaphores,
FreeRTOS/Zephyr/ThreadX semaphores/mutexes, and C++
`std::mutex`/`shared_mutex`. Lock identity and ordering are deliberately not
guessed. The default Rust `no_std` profile does not define std/`parking_lot`
lock rules.

## Limits

- Debug information is compiler output, not a proof of reachability. Missing
  or truncated DWARF produces a diagnostic and leaves inline frames empty.
- LTO, split DWARF, external debug files and linker garbage collection can
  remove or relocate debug data. Verify the final image, not just an object
  file, with `readelf -S` (look for `.debug_info` and `.symtab`).
- `addr2line` maps an address to source and inline frames; enumerating ranges
  still requires walking the DWARF DIE tree, which elf2tdg does with `gimli`.
- An inline lock range identifies where a lock operation was generated. It does
  not by itself prove lock ordering, contention behavior or absence of
  deadlocks; those require additional synchronization analysis.
