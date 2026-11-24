# Analysis architecture and precision roadmap

This document records the intended analysis architecture. It separates what is
implemented today from the planned multicore and precision work;
`--list-passes` is the authoritative status report for a build/profile.

## Goals

- Target multicore AArch64 and RISC-V images.
- Produce **certifiable safe upper bounds** when the selected models and flow
  facts support that claim; never silently turn an incomplete model into a
  bound.
- Keep analyses modular and removable at compile time.
- Emit human-readable CFG/WCET text in addition to machine-readable JSON.

## Pass model

The build uses a compile-time pass catalog, not a runtime dynamic-library ABI.
Each pass declares:

- a stable ID (`domain.role`, for example `wcet.longest-path`);
- its kind (`frontend`, `timing`, `analysis`, `path-analysis`, `report`);
- consumed and produced fact IDs;
- a soundness claim (`model-only`, `model-dependent`, `safe-upper-bound`,
  `estimate`, `planned`).

The catalog lives in `crates/elf2tdg/src/passes.rs` and is exposed by:

```sh
elf2tdg --list-passes
elf2tdg --list-passes --board-profile board.toml
```

The analyzer still invokes the current analyses directly. The catalog is the
scheduler contract for the next refactor: passes will read/write typed facts
through a `PassContext`, and the registry will topologically order them. The
public pass IDs and the JSON schema remain stable across that migration.

### Why compile-time

Rust trait objects do not have a stable cross-`cdylib` ABI. Compile-time
registration with Cargo features is type-safe, testable and sufficient for
built-in analyses. If third-party runtime plugins are needed later, the
recommended boundary is an out-of-process JSON/IPC or WASM provider, not a raw
Rust `dylib` interface.

## Precision ladder

| Level | Capability | Status |
|---|---|---|
| P0 | CFG recovery, roots, runtime rules, longest-path WCET | implemented |
| P1 | Flow facts and IPET/ILP backend | implemented: profile bounds, F4 `.ff`/FFX import, per-function IPET, pure-Rust `microlp`; automatic inference and non-loop facts are next |
| P2 | Cache, pipeline and branch constraints in IPET | partial models exist; constraint integration planned |
| P3 | Context-sensitive summaries, recursion, SMT infeasible paths | planned |
| P4 | Interrupt/CRPD and multicore shared-resource interference | first versions implemented: `[multicore]` per-access/per-fetch budget, a layered task/place/transition model, its state-equation ILP relaxation, `[system]` activation/periodic/resource/link constraints and a first discrete-time-expanded deadline-feasibility model; finer timed-PN response bounds, automatic link derivation, arbitration schedules, shared caches, CRPD and interrupt effects are next |
| P5 | Probabilistic/measurement-based or ML-assisted modes | out of scope until P1-P4 are sound |

The IPET first version is available with:

```sh
elf2tdg firmware.elf --board-profile board.toml \
  --path-analysis ipet --view cfg --format text --function main
```

It builds a per-function integer program with flow conservation, natural-loop
bounds and callee summaries, solves it with `microlp`, and records the positive
block execution counts. The remaining P1 work is:

1. Automatic loop-bound inference and non-loop flow facts (branch/call counts).
2. A convenience API for programmatic flow facts beyond files and `[wcet]`.
3. Larger benchmarks comparing IPET and longest-path precision and solve time.
4. Making IPET the default only after the bounded-results contract is validated.

The irreducible-cycle guard is deliberate: if removing all natural-loop
backedges still leaves a cycle, the function is reported `unbounded` rather than
emitting an unsound finite number.

## Soundness contract

Every pass result must carry:

- the model/solver version and configuration hash;
- the soundness claim and the assumptions it depends on;
- unsupported or unresolved inputs;
- a status (`bounded`, `partial`, `unbounded`, `unknown`).

`partial` results are never presented as safe bounds. IPET output is a safe
upper bound only when the flow facts, block costs and microarchitecture models
are all conservative. Unresolved calls, missing callee summaries, unresolved
control flow, missing block timing and non-terminating loops that were bound by
assumption all mark a result `partial`. Irreducible cycles are reported
`unbounded` because no configured loop bound covers them. The text report
prints these statuses and caveats; later passes must preserve them. The
`--require-safe` CLI gate requires the IPET backend, a timing model classified
as `deterministic` or `bounded` (not `statistical`), complete cache/memory
address coverage, and a `bounded` result for every execution root; otherwise the
run fails before emitting a CFG.

## Multicore direction

The current `[multicore]` access-budget model is a conservative, auditable first
step: it charges explicit per-access/per-fetch budgets and records every
charged event. The layered `system_model` then converts per-root WCET results
into tasks, Petri-net-shaped places/transitions and solves the state-equation
ILP relaxation for a coarse analyzed-core bound. The bound is intentionally
only a total-work relaxation; it is not exact reachability or a timed model. It
is not the final interference model. The next step is a resource-aware
interference pass with explicit models:

- shared bus/memory arbitration (TDMA, round-robin, priority);
- cache sharing, cache coloring and CRPD;
- bank/channel contention;
- interrupt and preemption effects.

These facts should feed the same IPET constraints as the single-core analyses,
so a system-level bound is composed from sound per-resource bounds rather than
from summed local estimates.

## Current limits

- IPET is implemented but still context-insensitive; loop bounds come from the
  profile or imported F4/FFX files, and automatic inference is not implemented.
- Cache/branch/data-memory analyses are per-function and not path-sensitive.
- Multicore interference is an explicit access/fetch budget; arbitration
  schedules, shared caches, DMA, CRPD and concurrency are not modeled.
- The layered system model solves only the state-equation relaxation. It does
  not model task periods, exact reachability or per-task response times;
  spawn/join dependencies are recorded but not constrained.
- Cortex-M7, generic RISC-V, generic AArch64 and x86-64 models are statistical.
  Opt-in bounded abstract AArch64/RISC-V models (`aarch64-bounded`,
  `riscv32-bounded`, `riscv64-bounded`) are available, but they require a board
  profile with memory regions for `--require-safe` and still exclude multicore
  interference.
- The default backend remains `longest-path` until IPET has broader benchmark
  validation.
