# Board timing profiles

A board profile is an optional, versioned description of the timing facts for a
concrete board. It lets the same ELF be analyzed with board-specific clocks,
memory fetch costs and instruction-cycle overrides without recompiling the
analyzer or hard-coding board constants into the CFG document.

Profiles are disabled by default. Passing `--board-profile PATH` is the only way
to enable one. Profiles apply to CFG analysis; `--view elf` reads only
loader data and rejects the option.

```bash
elf2tdg firmware.elf \
  --board-profile examples/profiles/cortex-m0-isr.toml \
  --output cfg.json
```

The file is parsed as TOML unless its extension is `.json`. Schema version 1
profiles remain valid; version 2 adds the optional pipeline, cache,
branch-prediction, data-memory timing and WCET models. The profile is strictly
validated before analysis:
unknown fields, duplicate selectors, overlapping memory regions, zero
frequencies and invalid cycle ranges are errors.
[`examples/profiles/cortex-m4-pipeline.toml`](../examples/profiles/cortex-m4-pipeline.toml)
shows the Cortex-M4 pipeline model,
[`examples/profiles/cortex-m7-icache.toml`](../examples/profiles/cortex-m7-icache.toml)
shows an instruction-cache profile,
[`examples/profiles/cortex-m7-dcache.toml`](../examples/profiles/cortex-m7-dcache.toml)
shows a data-cache profile, and
[`examples/profiles/cortex-m7-branch-prediction.toml`](../examples/profiles/cortex-m7-branch-prediction.toml)
shows a branch-prediction profile, and
[`examples/profiles/cortex-m7-data-memory.toml`](../examples/profiles/cortex-m7-data-memory.toml)
shows per-region data-memory timing, and
[`examples/profiles/cortex-m7-wcet.toml`](../examples/profiles/cortex-m7-wcet.toml)
shows a WCET profile.

## Resolution order

1. `--freq` overrides the profile's `clocks.core`.
2. The board profile supplies the CPU model, other clock domains, memory
   regions and instruction-cost overrides.
3. Built-in architecture/core tables fill every instruction the profile does
   not override.
4. No profile means the pre-profile behavior: built-in tables and `--freq`
   only.

The profile pins its CPU model. An explicit `--cpu` must name the same model;
a conflict is a configuration error. The profile architecture must match both
the CPU model and the loaded ELF.

## File format

```toml
schema_version = 2
id = "board:nucleo-f401re"
name = "NUCLEO-F401RE at 84 MHz"
arch = "thumb"
cpu = "cortex-m4"
confidence = "medium"
unknown_instructions = "warn"
caveats = [
  "Values measured on the target board; instrumentation overhead is removed.",
]

[clocks.core]
hz = 84_000_000
confidence = "high"

[[memory]]
name = "flash"
start = 0x0800_0000
size = 0x0010_0000
kind = "flash"
executable = true
fetch_wait_states = 2
fetch_width_bytes = 4

[[memory]]
name = "sram"
start = 0x2000_0000
size = 0x0002_0000
kind = "ram"

[[instruction_costs]]
mnemonic = "ldr"
cycles = { min = 2, max = 3 }

[[instruction_costs]]
class = "divide"
cycles = { min = 2, max = 12 }

[pipeline]
issue_width = 1
branch_penalty = { min = 1, max = 3 }

[[pipeline.instructions]]
mnemonic = "ldr"
resources = ["load_store"]
latency = 2
occupancy = 2
```

### Top-level fields

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | `1` for board-cost-only profiles, `2` for profiles that use `[pipeline]`, `[instruction_cache]`, `[data_cache]`, `[branch_prediction]`, `[wcet]` or per-region data-memory timing. |
| `id` | yes | Stable profile identifier recorded in the CFG timing metadata. |
| `name` | no | Human-readable board name. |
| `arch` | yes | `thumb`, `aarch64`, `riscv32`, `riscv64` or `x86-64`; architecture-family spellings such as `thumbv7em` and `x86_64` are normalized. |
| `cpu` | yes | Built-in timing-model name, for example `cortex-m0`, `cortex-m4`, `riscv32` or `aarch64`. |
| `confidence` | no | Overrides block-timing confidence (`high`, `medium`, `low`, `unknown`); otherwise the base model's confidence is used. |
| `unknown_instructions` | no | `warn` (default) emits a `timing-unknown-instruction` diagnostic; `ignore` suppresses it. The fallback cost still applies. |
| `caveats` | no | Extra caveats copied into the CFG timing metadata and block timing. |
| `[pipeline]` | no | Enables the Cortex-M4 in-order resource/dependency model; see below. |
| `[instruction_cache]` | no | Enables LRU instruction-cache analysis; see below. |
| `[data_cache]` | no | Enables LRU data-cache analysis; see below. |
| `[branch_prediction]` | no | Enables conditional-branch prediction analysis; see below. |
| `[wcet]` | no | Enables CFG longest-path WCET analysis; see below. |

### Clocks

`[clocks.NAME]` declares a frequency domain `clk:NAME`. `core` is special: it is
used for block `time_ns`, context timing and the default frequency domain.
Other domains are exported in `timing.frequency_domains` for consumers, but
blocks currently reference only `clk:core`.

| Field | Required | Meaning |
|---|---|---|
| `hz` | yes | Clock frequency in hertz; must be positive. |
| `confidence` | no | Frequency confidence; defaults to `medium`. |

When `--freq` is present it replaces the `clk:core` value and source with
`cli`/`high`, while other profile clocks remain `board-profile`. Fetch wait
states are not rescaled: the profile values remain unchanged, and the CFG timing metadata adds a
caveat when the CLI frequency differs from the profile core clock.

### Memory regions

Memory regions must not overlap and must fit in the 64-bit address space.
Executable regions contribute instruction-fetch costs; regions with `data_*`
fields also contribute data-memory wait cycles.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique region name. |
| `start` | yes | First address, inclusive. |
| `size` | yes | Region size in bytes; must be non-zero. |
| `kind` | no | `flash`, `ram`, `peripheral` or `other`; defaults to `other`. |
| `executable` | no | Enables fetch costing for instructions in this region; defaults to `false`. |
| `fetch_wait_states` | no | Wait states added per fetch transaction; defaults to `0`. |
| `fetch_width_bytes` | no | Bytes per instruction-fetch transaction; defaults to `4`. |
| `data_width_bytes` | no | Bytes per data transaction; defaults to `4`; must be positive. |
| `data_read_wait_states` | no | Extra core cycles per data-read transaction; defaults to `0`. |
| `data_write_wait_states` | no | Extra core cycles per data-write transaction; defaults to `0`. |

For each instruction whose address is inside an executable region, the profile
adds:

```text
fetch_cycles = ceil(instruction_size / fetch_width_bytes) * fetch_wait_states
```

This is a deliberately simple first-order model. It does not model prefetch,
bus contention, flash accelerator behavior or exception entry. Data-access
timing, instruction-cache effects and data-cache effects are modeled separately
when the corresponding region fields or profile sections are enabled below.
The generated caveat says so in the CFG metadata. Use a measured
`fetch_wait_states`/`fetch_width_bytes` pair or leave fetch costing disabled
when those effects dominate.

### Data-memory latency

Data-access timing is declared per memory region. The analysis is enabled when
any region declares at least one `data_*` field; it requires
`schema_version = 2`.

```toml
[[memory]]
name = "sram"
start = 0x2000_0000
size = 0x0001_0000
kind = "ram"
data_width_bytes = 4
data_read_wait_states = 1
data_write_wait_states = 1
```

For each statically resolved data access, the analyzer splits the address range
at region boundaries and charges:

```text
wait_cycles = ceil(fragment_bytes / data_width_bytes) * wait_states
```

Reads use `data_read_wait_states`; writes use `data_write_wait_states`; a
read-modify-write access charges both. Wait cycles are added to block `cycles`.
Per-block metadata records resolved, unresolved, mapped and unmapped access
counts, total read/write wait cycles, and a per-region breakdown. Unresolved
stack/indexed accesses and addresses outside every configured region are
counted but add no cycles. Register-derived addresses use the same bounded
backward recovery as data-cache analysis and are not path-sensitive.

This is a standalone bus-timing model. When `[data_cache]` is also enabled,
data-cache miss penalties and data-memory wait cycles are both added, which can
double-count memory latency. Bus contention, arbitration, outstanding requests,
write buffers, prefetch and per-region cacheability are not modeled.

### Pipeline / resource model

The optional `[pipeline]` table switches block costing from independent
instruction sums to an in-order resource/dependency schedule. It requires
`schema_version = 2`. This phase supports `cpu = "cortex-m4"` and single issue
only; other cores are rejected until their models exist.

| Field | Required | Meaning |
|---|---|---|
| `issue_width` | no | Must be `1` in the current implementation; defaults to `1`. |
| `branch_penalty` | no | Extra cycles for the block's final branch/call/return, exact or `{ min, max }`; default `1..3`. |

Each `[[pipeline.instructions]]` entry overrides the built-in Cortex-M4 class
mapping:

| Field | Required | Meaning |
|---|---|---|
| `class` | one selector | Same class names as `[[instruction_costs]]`. |
| `mnemonic` | one selector | Canonical, case-insensitive mnemonic. |
| `resources` | yes | Resource names occupied while issuing, for example `load_store`, `alu`, `mul`, `div`, `branch` or `fpu`. |
| `latency` | yes | Cycles from issue until a written register is ready; must be positive. |
| `occupancy` | no | Cycles the resources stay busy; defaults to `1`. |

Built-in defaults when no override matches:

| Class | Resources | Latency | Occupancy |
|---|---|---|---|
| load | `load_store` | 2 | 1 |
| store | `load_store` | 1 | 1 |
| push/pop | `load_store` | 2 | 1 |
| ldm/stm | `load_store` | 2 | 2 |
| branch/call/return | `branch` | 1 | 1 |
| multiply | `mul` | 1 | 1 |
| divide | `div` | 12 | 1 |
| alu/nop/barrier/other | `alu` | 1 | 1 |

The scheduler consumes Capstone's explicit and implicit register read/write
sets. It stalls an instruction until its source registers and resources are
ready, then marks destination registers ready `latency` cycles after issue.
`branch_penalty` is added when the block's last instruction is a branch, call
or return; conditional transfers use the worst case.

Register readiness is assumed at block entry. Memory dependencies,
store-to-load forwarding, inter-block pipeline state, exception entry and
multi-issue are not modeled in this phase; caches and branch prediction are
modeled separately when their profile sections are enabled.
Block costs are therefore local pipeline-aware costs, not WCET bounds. While
the pipeline model is active the CFG marks the timing model `statistical`, and
a generated caveat records the limitation.

When `[pipeline]` is active, block `cycles` come from this schedule, including
profile fetch wait states. `[[instruction_costs]]` remains the fallback for
non-pipeline analysis and per-instruction detail; it is not added to the
pipeline schedule.

### Instruction cache

The optional `[instruction_cache]` table enables intra-function instruction-cache
analysis. It requires `schema_version = 2`.

| Field | Required | Meaning |
|---|---|---|
| `size` | yes | Total cache size in bytes; must be divisible by `line_bytes * ways`. |
| `line_bytes` | yes | Line size in bytes; must be a positive power of two. |
| `ways` | yes | Associativity; must be positive. |
| `replacement` | no | `lru` (the only supported policy). |
| `miss_penalty` | yes | Extra core cycles charged for each modeled miss; must be positive. |
| `invalidate_on_call` | no | Clear modeled state across call-return edges; defaults to `true`. |
| `max_states` | no | Maximum concrete cache states per block; defaults to `128`. |

```toml
[instruction_cache]
size = 16_384
line_bytes = 32
ways = 4
replacement = "lru"
miss_penalty = 20
invalidate_on_call = true
max_states = 128
```

Each function is analyzed from a **cold** cache at its entry. The analyzer
propagates concrete LRU states along intra-function CFG edges, classifies line
hits and misses, and adds `misses * miss_penalty` to block cycles. Multiple
states reaching a block produce a min/max cost range; each line is classified
as `always-hit`, `always-miss` or `may-hit` across those states. If a block
exceeds `max_states`, the function falls back to an all-miss upper bound.

The analysis is local: it does not model inter-function cache state, prefetch,
data-cache effects, bus contention or execution-count/loop bounds. With
`invalidate_on_call = true`, call-return edges conservatively clear the state.

### Data cache

The optional `[data_cache]` table enables intra-function data-cache analysis.
It requires `schema_version = 2`.

| Field | Required | Meaning |
|---|---|---|
| `size` | yes | Total cache size in bytes; must be divisible by `line_bytes * ways`. |
| `line_bytes` | yes | Line size in bytes; must be a positive power of two. |
| `ways` | yes | Associativity; must be positive. |
| `replacement` | no | `lru` (the only supported policy). |
| `miss_penalty` | yes | Extra core cycles charged for each modeled miss; must be positive. |
| `write_allocate` | no | Allocate a line on a store miss; defaults to `true`. |
| `invalidate_on_call` | no | Clear modeled state across call-return edges; defaults to `true`. |
| `max_states` | no | Maximum concrete cache states per block; defaults to `128`. |

```toml
[data_cache]
size = 32_768
line_bytes = 32
ways = 4
replacement = "lru"
miss_penalty = 20
write_allocate = true
invalidate_on_call = true
max_states = 128
```

The analyzer consumes explicit data-memory operands decoded by Capstone plus
implicit `push`/`pop` stack traffic. A PC-relative or absolute operand is used
directly. A base register is resolved
with the same bounded backward value recovery used for pointer roots; stack,
indexed and otherwise unknown addresses are counted in the metadata but are
not simulated. Each function starts from a **cold** cache. The analyzer
propagates concrete LRU states along intra-function CFG edges, adds
`misses * miss_penalty` to block cycles, and reports min/max ranges and
per-line `always-hit`, `always-miss` or `may-hit` classifications. With
`write_allocate = false`, a store miss does not install a line. If a block
exceeds `max_states`, the function falls back to an all-miss bound for its
resolved accesses.

The data-cache model is local and partial: it treats every resolved address
as cacheable, and does not model dirty-line writeback, store buffers, prefetch,
stack addresses, inter-function cache state, execution counts or bus
contention. Base-register recovery is not path-sensitive. Unresolved accesses are reported as
`unresolved_memory_accesses`; they are excluded from miss penalties and cache
state propagation, so modeled hits are optimistic. With
`invalidate_on_call = true`, call-return edges conservatively clear the state.

### Branch prediction

The optional `[branch_prediction]` table enables conditional-branch direction
analysis. It requires `schema_version = 2`.

| Field | Required | Meaning |
|---|---|---|
| `model` | yes | `static-not-taken`, `static-taken`, `btfn` (backward-taken/forward-not-taken) or `bimodal`. |
| `mispredict_penalty` | yes | Extra core cycles charged for each modeled misprediction; must be positive. |
| `initial_state` | no | Initial two-bit counter for `bimodal`: `strongly-not-taken`, `weakly-not-taken` (default), `weakly-taken` or `strongly-taken`. Used only by `bimodal`. |
| `max_states` | no | Maximum concrete predictor states per block; defaults to `128`. |

```toml
[branch_prediction]
model = "btfn"
mispredict_penalty = 3
max_states = 128
```

Static policies predict every conditional branch in one direction. `btfn`
predicts taken when the taken target lies below the branch instruction, and
not-taken when it lies forward. `bimodal` keeps a two-bit local
saturating counter per branch site, starts each function from `initial_state`,
and updates the counter with each modeled taken/not-taken outcome. Only
conditional branches with exactly one taken edge and one fallthrough edge are
modeled. Indirect/table target prediction, return-address stacks,
branch-target buffers and global history are not modeled.

The analyzer propagates concrete predictor states over each function CFG and
adds `mispredicts * mispredict_penalty` to block cycle ranges. Because a block
can branch to either successor, its cost range includes the minimum and
maximum misprediction count across both outcomes and all modeled entry states;
path-specific branch/predictor correlation is not modeled. If a block exceeds
`max_states`, the function falls back to an all-mispredict bound. Each function
starts from the configured predictor state and call-return edges do not reset
it, but callee branches remain outside the analysis.

### WCET

The optional `[wcet]` table enables CFG longest-path worst-case execution-time
analysis. It requires `schema_version = 2`.

| Field | Required | Meaning |
|---|---|---|
| `default_loop_bound` | no | Maximum iterations for natural loops without a specific bound. If omitted, unbounded loops make the containing function unbounded. |
| `bound_nonterminating_loops` | no | Apply loop bounds to natural loops with no static exit and mark the result `partial`; defaults to `false`. |
| `max_states` | no | Maximum unrolled predictor-free CFG states per function; defaults to `100000`. |
| `[[wcet.loop_bounds]]` | no | Per-loop overrides with `header` (block address) and `bound` (positive maximum iterations). |

```toml
[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true
max_states = 20_000

[[wcet.loop_bounds]]
header = 0x0800_0100
bound = 100
```

The analyzer takes each block's upper cycle bound, computes the longest path
through the function CFG, and adds callee WCET summaries at call sites. Loop
visit counts are bounded; nested inner-loop counters reset when an outer
backedge is taken. Functions in recursive call-graph SCCs are unbounded.
Functions with unresolved calls, external calls, unresolved control flow or
missing block timing are reported as `partial`; functions whose natural loop has
no static exit are `unbounded` unless `bound_nonterminating_loops` is enabled.

When a core frequency is known, per-function and per-root `time_ns` values are
emitted. Results are per execution root from `ProgramCfg.roots`; they are not a
system-level WCET across preempting interrupts or concurrent tasks. The model is
a static estimate, not a hardware proof: cache/branch/data-memory results are
local, loop bounds must be supplied, and interrupts, DMA, bus contention and
concurrency are outside the analysis.

### Instruction-cost overrides

Each `[[instruction_costs]]` entry must select by `class`, `mnemonic`, or both.

| Field | Required | Meaning |
|---|---|---|
| `class` | one selector | `load`, `store`, `push-pop`, `ldm-stm`, `branch`, `call`, `return`, `multiply`, `divide`, `barrier`, `nop`, `alu` or `other`. |
| `mnemonic` | one selector | Canonical mnemonic, for example `ldr`, `ldrex`, `csel`; matching is case-insensitive. A trailing `.w`/`.n` and a `c.` conditional prefix are removed before matching. |
| `cycles` | yes | Exact number, for example `2`, or `{ min = 2, max = 3 }`. Bounds must be finite, non-negative and ordered. |
| `note` | no | Reserved for profile documentation; currently validated but not emitted per instruction. |

Selection precedence is deterministic: a selector naming both fields beats a
mnemonic-only selector, which beats a class-only selector. Duplicate selectors
are rejected. Overrides are applied before fetch wait states.

A mnemonic that matches neither a built-in class nor an override uses the
fallback `other` class. With the default `warn` policy the analyzer emits one
`timing-unknown-instruction` diagnostic per mnemonic and adds a caveat to the
timing metadata. Built-in models use the same fallback and warning behavior;
a profile only adds overrides and can set `ignore`.

## What is recorded in the CFG

`timing.models[].params.extras` records:

- `board_profile_id`
- `board_profile_sha256` (SHA-256 of the exact file bytes)
- `board_profile_source`
- `board_profile_schema_version`
- `board_profile_clocks`
- `board_profile_memory_regions`
- `board_profile_max_fetch_wait_states`
- `board_profile_instruction_cost_overrides`
- `board_profile_pipeline`
- `board_profile_pipeline_issue_width`
- `board_profile_pipeline_instruction_overrides`
- `board_profile_instruction_cache`
- `board_profile_instruction_cache_miss_penalty`
- `board_profile_data_cache`
- `board_profile_data_cache_miss_penalty`
- `board_profile_data_cache_write_allocate`
- `board_profile_branch_prediction`
- `board_profile_branch_mispredict_penalty`
- `board_profile_branch_initial_state` (bimodal only)
- `board_profile_branch_max_states`
- `board_profile_data_memory`
- `board_profile_data_memory_regions`
- `board_profile_wcet`
- `board_profile_wcet_default_loop_bound`
- `board_profile_wcet_bound_nonterminating_loops`
- `board_profile_wcet_max_states`
- `board_profile_wcet_loop_bounds`
- `unknown_instruction_mnemonics`, the count of distinct fallback mnemonics,
  when at least one fallback was used

The model's `params.flash_wait_states` is set from the largest executable
`flash` region. Explicit profile caveats and the generated fetch/unknown caveats
are attached to the model and to block timing. Frequency domains supplied by the
profile use `source: "board-profile"`; a CLI override uses `source: "cli"`.

## Semantics and limits

- Without `[pipeline]`, a block's `cycles` is the sum of static instruction
  costs. With `[pipeline]`, it is the local in-order resource/dependency
  schedule. Neither is an execution path time, a loop cost or a WCET bound.
- Cost values are issue/resource estimates, not per-instruction wall-clock
  latency.
- Instruction caches are simulated only when `[instruction_cache]` is present;
  data caches only when `[data_cache]` is present, and branch prediction only
  when `[branch_prediction]` is present. Dual issue and out-of-order behavior
  are not modeled. For such cores the profile can refine table values, but the
  result remains statistical.
- Branch prediction covers conditional direction only. Indirect/table target
  prediction, return prediction, branch-target buffers and global history are
  not modeled.
- Data-memory latency is region-based. Only statically resolved accesses with
  addresses inside configured regions contribute wait cycles. If data-cache
  analysis is enabled too, its miss penalties and the wait cycles are additive.
- WCET is a CFG longest-path estimate. Loops need configured bounds; recursive
  calls are unbounded; unresolved calls and missing timing make results
  partial. It is not a hardware proof or a system-level bound across
  interrupts and concurrent roots.
- Data-cache results cover only statically resolved addresses. Stack, indexed
  and unresolved accesses are counted but do not contribute miss penalties.
  Dirty writeback, store buffers, prefetch and inter-function cache state are
  not modeled.
- Pipeline state is not propagated across basic blocks yet. The first
  instruction in each block assumes all source registers are ready.
- Interrupt entry, exception return, wait-for-interrupt and peripheral
  interaction are outside this model.
- The same ELF can be analyzed repeatedly with different profiles; the CFG
  names the profile hash used for each result.
