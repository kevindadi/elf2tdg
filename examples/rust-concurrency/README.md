# Rust no-std Embassy example

[`main.rs`](main.rs) is a small `#![no_std]` Cortex-M firmware image built with
`cortex-m-rt`, `embassy-executor`, and `static_cell`. It does **not** depend on `std`,
`std::thread`, or Tokio.

The application:

- starts the Embassy thread-mode executor from `cortex_m_rt::entry`;
- runs an `app_main` async task;
- spawns a `sensor_task` and a `monitor_task` through
  `embassy_executor::Spawner::spawn`;
- keeps the spawn sites in one `#[inline(never)] start_tasks` function so the
  example CFG has a stable user function to inspect;
- uses only `core` plus Embassy (no heap or `alloc` allocator in this build).

`#[embassy_executor::task]` turns each task into a `TaskStorage<...>::poll`
machine function. The analyzer resolves each `Spawner::spawn` generic back to
that poll function instead of emitting a placeholder entry.

## Build and analyze

The target is `thumbv7em-none-eabi` (Cortex-M4 compatible). Install it once:

```sh
rustup target add thumbv7em-none-eabi
```

The example reads its target and `link.x` flags from
[`.cargo/config.toml`](.cargo/config.toml), and uses
[`memory.x`](memory.x) for the FLASH/RAM layout.

```sh
make
```

Or with an offline cargo cache:

```sh
make CARGO_FLAGS=--offline
```

The build needs the target above and Graphviz `dot`. The `analysis` Cargo
profile uses `-O1`, full DWARF, ThinLTO, `panic=abort`, and no symbol stripping.
The analyzer is given an explicit Cortex-M4 timing model at 168 MHz.

## Artifacts

| File | Contents |
|---|---|
| [`artifacts/rust-concurrency-analysis.elf`](artifacts/rust-concurrency-analysis.elf) | `thumbv7em-none-eabi` no-std ELF with DWARF and symbols |
| [`artifacts/cfg-analysis-main.json`](artifacts/cfg-analysis-main.json) | lossless CFG JSON for `rust_concurrency::start_tasks`, including `inline_frames` |
| [`artifacts/cfg-analysis-main.svg`](artifacts/cfg-analysis-main.svg) | function CFG diagram for the analysis build |
| [`artifacts/cfg-analysis-main.mmd`](artifacts/cfg-analysis-main.mmd) | Mermaid source for the analysis CFG |
| [`artifacts/cfg-analysis-executor.json`](artifacts/cfg-analysis-executor.json) | executor CFG with the four candidate poll-dispatch calls |
| [`artifacts/cfg-analysis-executor.svg`](artifacts/cfg-analysis-executor.svg) | rendered executor CFG |
| [`artifacts/cfg-analysis-executor.mmd`](artifacts/cfg-analysis-executor.mmd) | Mermaid source for the executor CFG |
| [`artifacts/cfg-analysis-sensor.json`](artifacts/cfg-analysis-sensor.json) | CFG selected by task name `sensor_task`, mapped to its poll entry |
| [`artifacts/cfg-analysis-sensor.svg`](artifacts/cfg-analysis-sensor.svg) | rendered sensor-task CFG |
| [`artifacts/cfg-analysis-sensor.mmd`](artifacts/cfg-analysis-sensor.mmd) | Mermaid source for the sensor-task CFG |
| [`artifacts/elf-layout-analysis.mmd`](artifacts/elf-layout-analysis.mmd) | loader-backed ELF layout for the analysis build |

CFG output is documented in [`../../docs/cfg-format.md`](../../docs/cfg-format.md);
the loader view is documented in [`../../docs/elf-view.md`](../../docs/elf-view.md).

## What the analyzer recovers

The program CFG contains six execution roots:

- `startup` and `main` from the Cortex-M reset path;
- task roots for `app_main`, `sensor_task` and `monitor_task`;
- one ISR root for the real `HardFault` vector.

Three `rust-embassy` spawn annotations are recovered. The executor's bootstrap spawn
of `app_main` points at its `TaskStorage::poll` function. The two user spawns
occur at inlined `Spawner::spawn` sites inside
`rust_concurrency::start_tasks`, and resolve to the corresponding sensor/monitor
poll functions. Their DWARF inline ranges and `main.rs` source lines remain in
[`cfg-analysis-main.json`](artifacts/cfg-analysis-main.json).

Cortex-M vector tables alias every unused exception to `DefaultHandler` (often
with a second weak name such as `PendSV`). The analyzer checks all symbol
aliases at a vector address and skips these shared default stubs, so the example
has one real ISR root instead of hundreds of false ones.

The executor's task-poll dispatch (`blx r1` at `0x80005da`) is no longer left
unresolved. The analyzer recognizes the load from task-header field `+12`,
collects the executable values stored to that field across the image, and emits
four bounded low-confidence call targets in one CFG call site:

- `app_main` `TaskStorage::poll`
- `sensor_task` `TaskStorage::poll`
- `monitor_task` `TaskStorage::poll`
- `embassy_executor::raw::poll_exited`

The CFG keeps one informational `resolved-indirect-call-candidates` diagnostic
for this site and no `unresolved-indirect-call` warning. CFG JSON has one call
record with four `candidates`, and the program call graph has one alternative
per candidate. See
[`cfg-analysis-executor.json`](artifacts/cfg-analysis-executor.json) /
[`cfg-analysis-executor.svg`](artifacts/cfg-analysis-executor.svg) for the CFG
view.

The executor event loop is classified `noreturn` from its recovered CFG. The
`panic_const_async_fn_resumed` path in each task poll is an API-level noreturn
call, so those CFG blocks end with `noreturn-call` and have no return
continuation. The shared return paths of the task polls remain reachable from
their other branches.

## Select a task CFG by source name

Task aliases are first-class CFG selectors. Both forms select the real task
poll body, not the future-initialization helper:

```sh
elf2tdg artifacts/rust-concurrency-analysis.elf --view cfg --format json \
    --function sensor_task --output sensor-task-cfg.json

elf2tdg artifacts/rust-concurrency-analysis.elf --view cfg --format json \
    --reachable-from sensor_task --output sensor-task-reachable.json
```

`app_main` and `monitor_task` work the same way. Function names such as
`rust_concurrency::start_tasks` still select the concrete user function.

## Scope

The supported Rust runtime profile for this project is no-std embedded Rust:

- Embassy (`Spawner::spawn`, task polling) and RTIC;
- `core` and optional `alloc` symbols in the analyzed image;
- no `std::thread`, Rayon, crossbeam, Tokio, async-std, or smol rules.

C/C++/OpenMP and native RTOS APIs remain supported separately. The example
itself does not use heap allocation; real-time firmware should normally prefer
static task pools unless an allocator has a bounded, analyzed policy.

See [`../../docs/analysis-profile.md`](../../docs/analysis-profile.md) for the
profile, inline DWARF recovery and source-level rules.
