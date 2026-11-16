# elf2tdg examples

Each example is self-contained and generates a linked ELF, TDG JSON, Graphviz
DOT/SVG, Mermaid output, lossless per-function CFG artifacts, and a colored loader-backed ELF layout
under its `artifacts/` directory. The Cortex example also includes a multi-root
system CFG that retains the ISR and reset paths.

[`tdg-example.html`](tdg-example.html) is a visual walkthrough of both examples,
including the rendered diagrams and the complete node/edge legend. Open it
directly in a browser, or publish it as an HTML artifact.

## Rust concurrency

[`rust-concurrency/`](rust-concurrency/README.md) is a `#![no_std]`
Cortex-M Embassy image. It exercises `embassy_executor::Spawner::spawn`, async
task contexts, inline DWARF recovery, and Cortex-M vector-table default-handler
filtering. It uses the recommended `analysis` Cargo profile (`-O1`, full DWARF,
ThinLTO, `panic=abort`). `std::thread`, Tokio, Rayon, crossbeam, async-std and
smol are not part of the supported Rust profile.

- [Concurrency TDG](rust-concurrency/artifacts/tdg-analysis-concurrency.svg)

## Cortex-M0 interrupt and timing

[`cortex-m0-isr/`](cortex-m0-isr/README.md) is a freestanding ARM Cortex-M0
image with a reset handler, a call chain, USART1 IRQ 37 on vector 53, and
Cortex-M0 cycle/time estimates at 48 MHz.

- [Full TDG diagram](cortex-m0-isr/artifacts/tdg-full.svg)

## Regenerate everything

```sh
make -C examples/rust-concurrency CARGO_FLAGS=--offline
make -C examples/cortex-m0-isr CARGO_FLAGS=--offline
```

For the complete visual vocabulary, see
[`docs/tdg-legend.md`](../docs/tdg-legend.md).
