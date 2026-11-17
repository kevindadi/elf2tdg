# Fuzzing

The harness parses arbitrary bytes as an ELF image, runs the bounded analyzer,
and asserts that both the TDG and the intermediate CFG pass validation. Inputs
that are not valid ELF or exceed analysis limits are ignored.

Install the nightly toolchain and `cargo-fuzz` once:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run from the repository root:

```sh
cargo +nightly fuzz run elf_analysis -- -max_len=2097152
```

Seed the corpus with the checked-in examples:

```sh
mkdir -p fuzz/corpus/elf_analysis
cp examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf \
    fuzz/corpus/elf_analysis/rust-concurrency.elf
cp examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf \
    fuzz/corpus/elf_analysis/cortex-m0-isr.elf
cp tests/fixtures/rust_alloc_trait/firmware.elf \
    fuzz/corpus/elf_analysis/rust-alloc-trait.elf
```

`fuzz/target`, `fuzz/corpus` and `fuzz/artifacts` are ignored by git;
reproducers from `fuzz/artifacts/elf_analysis/` should be minimized and added
as regression fixtures when they expose a bug.
