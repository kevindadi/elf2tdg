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
profiles remain valid; version 2 adds the optional pipeline model. The profile
is strictly validated before analysis: unknown fields, duplicate selectors,
overlapping memory regions, zero frequencies and invalid cycle ranges are
errors. [`examples/profiles/cortex-m4-pipeline.toml`](../examples/profiles/cortex-m4-pipeline.toml)
shows the Cortex-M4 pipeline model.

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
| `schema_version` | yes | `1` for board-cost-only profiles, `2` for profiles that use `[pipeline]`. |
| `id` | yes | Stable profile identifier recorded in the CFG timing metadata. |
| `name` | no | Human-readable board name. |
| `arch` | yes | `thumb`, `aarch64`, `riscv32`, `riscv64` or `x86-64`; architecture-family spellings such as `thumbv7em` and `x86_64` are normalized. |
| `cpu` | yes | Built-in timing-model name, for example `cortex-m0`, `cortex-m4`, `riscv32` or `aarch64`. |
| `confidence` | no | Overrides block-timing confidence (`high`, `medium`, `low`, `unknown`); otherwise the base model's confidence is used. |
| `unknown_instructions` | no | `warn` (default) emits a `timing-unknown-instruction` diagnostic; `ignore` suppresses it. The fallback cost still applies. |
| `caveats` | no | Extra caveats copied into the CFG timing metadata and block timing. |
| `[pipeline]` | no | Enables the Cortex-M4 in-order resource/dependency model; see below. |

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

Memory regions must not overlap and must fit in the 64-bit address space. The
current model uses them for **instruction fetch** costs only; data-access
region latency is not yet modeled.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique region name. |
| `start` | yes | First address, inclusive. |
| `size` | yes | Region size in bytes; must be non-zero. |
| `kind` | no | `flash`, `ram`, `peripheral` or `other`; defaults to `other`. |
| `executable` | no | Enables fetch costing for instructions in this region; defaults to `false`. |
| `fetch_wait_states` | no | Wait states added per fetch transaction; defaults to `0`. |
| `fetch_width_bytes` | no | Bytes per instruction-fetch transaction; defaults to `4`. |

For each instruction whose address is inside an executable region, the profile
adds:

```text
fetch_cycles = ceil(instruction_size / fetch_width_bytes) * fetch_wait_states
```

This is a deliberately simple first-order model. It does not model prefetch,
instruction caches, bus contention, flash accelerator behavior, exception entry
or data accesses. The generated caveat says so in the CFG metadata. Use a measured
`fetch_wait_states`/`fetch_width_bytes` pair or leave fetch costing disabled
when those effects dominate.

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
store-to-load forwarding, inter-block pipeline state, caches, branch
prediction, exception entry and multi-issue are not modeled in this phase.
Block costs are therefore local pipeline-aware costs, not WCET bounds. While
the pipeline model is active the CFG marks the timing model `statistical`, and
a generated caveat records the limitation.

When `[pipeline]` is active, block `cycles` come from this schedule, including
profile fetch wait states. `[[instruction_costs]]` remains the fallback for
non-pipeline analysis and per-instruction detail; it is not added to the
pipeline schedule.

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
- Caches, branch prediction, dual issue and out-of-order behavior are not
  simulated. For such cores the profile can refine table values, but the result
  remains statistical.
- Pipeline state is not propagated across basic blocks yet. The first
  instruction in each block assumes all source registers are ready.
- Interrupt entry, exception return, wait-for-interrupt and peripheral
  interaction are outside this model.
- The same ELF can be analyzed repeatedly with different profiles; the CFG
  names the profile hash used for each result.
