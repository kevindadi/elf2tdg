# Board timing profiles

A board profile is an optional, versioned description of the timing facts for a
concrete board. It lets the same ELF be analyzed with board-specific clocks,
memory fetch costs and instruction-cycle overrides without recompiling the
analyzer or hard-coding board constants into the TDG schema.

Profiles are disabled by default. Passing `--board-profile PATH` is the only way
to enable one. Profiles apply to TDG and CFG analysis; `--view elf` reads only
loader data and rejects the option.

```bash
elf2tdg firmware.elf \
  --board-profile examples/profiles/cortex-m0-isr.toml \
  --output tdg.json
```

The file is parsed as TOML unless its extension is `.json`. The profile is
strictly validated before analysis: unknown fields, duplicate selectors,
overlapping memory regions, zero frequencies and invalid cycle ranges are
errors.

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
schema_version = 1
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
```

### Top-level fields

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | Must be `1`. |
| `id` | yes | Stable profile identifier recorded in the TDG. |
| `name` | no | Human-readable board name. |
| `arch` | yes | `thumb`, `aarch64`, `riscv32`, `riscv64` or `x86-64`; architecture-family spellings such as `thumbv7em` and `x86_64` are normalized. |
| `cpu` | yes | Built-in timing-model name, for example `cortex-m0`, `cortex-m4`, `riscv32` or `aarch64`. |
| `confidence` | no | Overrides block-timing confidence (`high`, `medium`, `low`, `unknown`); otherwise the base model's confidence is used. |
| `unknown_instructions` | no | `warn` (default) emits a `timing-unknown-instruction` diagnostic; `ignore` suppresses it. The fallback cost still applies. |
| `caveats` | no | Extra caveats copied into the TDG timing metadata and block timing. |

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
states are not rescaled: the profile values remain unchanged, and the TDG adds a
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
or data accesses. The generated caveat says so in the TDG. Use a measured
`fetch_wait_states`/`fetch_width_bytes` pair or leave fetch costing disabled
when those effects dominate.

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

## What is recorded in the TDG

`timing.models[].params.extras` records:

- `board_profile_id`
- `board_profile_sha256` (SHA-256 of the exact file bytes)
- `board_profile_source`
- `board_profile_schema_version`
- `board_profile_clocks`
- `board_profile_memory_regions`
- `board_profile_max_fetch_wait_states`
- `board_profile_instruction_cost_overrides`
- `unknown_instruction_mnemonics`, the count of distinct fallback mnemonics,
  when at least one fallback was used

The model's `params.flash_wait_states` is set from the largest executable
`flash` region. Explicit profile caveats and the generated fetch/unknown caveats
are attached to the model and to block timing. Frequency domains supplied by the
profile use `source: "board-profile"`; a CLI override uses `source: "cli"`.

## Semantics and limits

- A block's `cycles` remains the sum of static instruction costs. It is not an
  execution path time, a loop cost or a WCET bound.
- Cost values are issue/throughput estimates, not per-instruction latency.
- Caches, branch prediction, dual issue and out-of-order behavior are not
  simulated. For such cores the profile can refine table values, but the result
  remains statistical.
- Interrupt entry, exception return, wait-for-interrupt and peripheral
  interaction are outside this model.
- The same ELF can be analyzed repeatedly with different profiles; the TDG
  names the profile hash used for each result.
