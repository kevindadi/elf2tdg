# elf2tdg examples

Each example is self-contained and generates a linked ELF, TDG JSON, Graphviz
DOT/SVG, and Mermaid output under its `artifacts/` directory.

[`tdg-example.html`](tdg-example.html) is a visual walkthrough of both examples,
including the rendered diagrams and the complete node/edge legend. Open it
directly in a browser, or publish it as an HTML artifact.

## Rust concurrency

[`rust-concurrency/`](rust-concurrency/README.md) exercises `std::thread`,
`JoinHandle::join`, `thread::scope`, and `Scope::spawn`. It builds both `-O0`
and `-O2` ELFs so you can compare concrete closure functions with DWARF-based
inline recovery and logical task entries.

- [O0 diagram](rust-concurrency/artifacts/tdg-o0-concurrency.svg)
- [O2 diagram](rust-concurrency/artifacts/tdg-o2-concurrency.svg)

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
