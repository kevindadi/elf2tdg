# elf2tdg examples

Each example is self-contained and generates a linked ELF, program CFG JSON,
Graphviz DOT/SVG, Mermaid output and a colored loader-backed ELF layout under
its `artifacts/` directory. The Cortex example also includes a multi-root system
CFG that retains the ISR and reset paths.

## Rust concurrency

[`rust-concurrency/`](rust-concurrency/README.md) is a `#![no_std]`
Cortex-M Embassy image. It exercises `embassy_executor::Spawner::spawn`, async
task roots, inline DWARF recovery, and Cortex-M vector-table default-handler
filtering. It uses the recommended `analysis` Cargo profile (`-O1`, full DWARF,
ThinLTO, `panic=abort`). `std::thread`, Tokio, Rayon, crossbeam, async-std and
smol are not part of the supported Rust profile.

- [Executor CFG](rust-concurrency/artifacts/cfg-analysis-executor.svg)
- [Sensor-task CFG](rust-concurrency/artifacts/cfg-analysis-sensor.svg)

## Cortex-M0 interrupt and timing

[`cortex-m0-isr/`](cortex-m0-isr/README.md) is a freestanding ARM Cortex-M0
image with a reset handler, a call chain, USART1 IRQ 37 on vector 53, and
Cortex-M0 cycle/time estimates at 48 MHz.

- [System CFG](cortex-m0-isr/artifacts/cfg-system.svg)
- [Main CFG](cortex-m0-isr/artifacts/cfg-main.svg)

## Regenerate everything

```sh
make -C examples/rust-concurrency CARGO_FLAGS=--offline
make -C examples/cortex-m0-isr CARGO_FLAGS=--offline
```

See [`docs/cfg-format.md`](../docs/cfg-format.md) for the program CFG document.
