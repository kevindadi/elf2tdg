# Timing models

The analyzer exposes several timing-model classes. The model determines the
per-instruction cycle table, the `determinism` field in CFG timing metadata and
whether `--require-safe` accepts the result.

| Model | Selection | Determinism | Notes |
|---|---|---|---|
| Cortex-M0/M0+/M3/M4/M33 | auto-detected from ARM attributes | `bounded` | table-based instruction/block costs |
| Cortex-M7 | `--cpu cortex-m7` or ARM attributes | `statistical` | branch prediction, caches and dual-issue are not modeled |
| generic RV32/RV64 | auto-detected | `statistical` | generic in-order throughput table |
| bounded RV32/RV64 | `--cpu riscv32-bounded` / `riscv64-bounded` | `bounded` | additive upper bounds for an abstract single-issue in-order core |
| generic AArch64 | `--cpu aarch64` | `statistical` | out-of-order throughput table |
| bounded AArch64 | `--cpu aarch64-bounded` | `bounded` | additive upper bounds for an abstract single-issue in-order core |
| generic x86-64 | `--cpu x86-64` | `statistical` | throughput table, not a bound |

A board profile can pin the same model with the top-level `cpu = "..."` field
(instead of `--cpu`). The profile CPU must match the ELF architecture.

## Bounded abstract AArch64/RISC-V models

These models are explicit and conservative:

- instruction costs are **additive**; pipeline overlap is not assumed;
- base costs assume single-cycle instruction/data memory;
- branch/call/return includes a fixed pipeline-restart allowance;
- cache and data-memory wait-state analyses add their upper-bound penalties on
  top of the base block cost when enabled by the profile; IPET may replace the
  cache part with a per-function cache-state product when that analysis
  completes and `invalidate_on_call = true`, or with a per-loop working-set
  persistence model when the state product is unavailable;
- branch-prediction penalties are added when a `[branch_prediction]` profile is
  enabled; IPET may replace the per-block maximum with a concrete
  predictor-state product when the branch analysis completes.

Base per-class upper bounds:

| Class | RV32 | RV64 | AArch64 |
|---|---:|---:|---:|
| ALU/NOP/system/other | 2 | 2 | 4 |
| load/store | 4 | 4 | 4 |
| push/pop or LDM/STM | 4 | 4 | 4 |
| multiply | 4 | 4 | 4 |
| branch/call/return | 20 | 20 | 20 |
| divide | 64 | 128 | 64 |
| barrier/fence | 64 | 64 | 64 |

The table version is `0.3.0-bounded`. The model records these assumptions in
`timing.models[].params.extras` (`bounded_semantics`, `base_memory_model`,
`pipeline_overlap`, `branch_allowance`).

Example:

```sh
elf2tdg firmware.elf --cpu aarch64-bounded --freq 1.5GHz \
  --board-profile board.toml --path-analysis ipet --require-safe \
  --flowfacts loops.ff --format json --output wcet.json
```

`--require-safe` additionally requires a board profile with at least one memory
region for bounded abstract models, and rejects any run where an unrecognized
mnemonic used fallback costs. Define the actual instruction/data memory
geometry and wait states in the profile; otherwise the single-cycle base
assumption is not tied to a board.

Multicore interference is configured separately by `[multicore]`; see
[board-profile.md](board-profile.md#multicore-interference). It is an explicit
per-access budget, not part of the base timing table.

## What "bounded" means

`determinism = bounded` means the reported range is an upper bound **for the
modeled configuration and its documented assumptions**, not a hardware proof.
For certified use, the board profile must describe the memory system, caches,
branch predictor and clock; interrupts, DMA and multicore interference are
still outside the model. `--require-safe` rejects cache profiles with
`invalidate_on_call = false`, unresolved data-cache addresses and data-memory
unmapped accesses because those make the local cost optimistic.

The board-profile `[pipeline]` model currently supports Cortex-M4 only. Bounded
AArch64/RISC-V models deliberately use additive upper bounds instead of that
pipeline schedule. The Cortex-M4 pipeline model remains `statistical`: block
schedules assume ready registers at entry, and IPET only adds a first-order
edge-context stall from the source block's local exit state. It is not a safe
upper bound and is rejected by `--require-safe`.

## Selection hints

- Generic RISC-V is auto-selected for convenience. Use the `-bounded` variant
  when you need a bound for a documented in-order core.
- Generic AArch64 and x86-64 are statistical and rejected by `--require-safe`.
- Cortex-M7 is currently statistical; use a Cortex-M4/M33 model only when the
  target actually matches.
