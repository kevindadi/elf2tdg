# Function CFG format

The analyzer now has two layers:

```text
ELF
  -> Image (sections, symbols, imports, DWARF)
  -> ProgramCfg (one petgraph StableDiGraph per function)
  -> TDG (contexts and spawn/join/scope edges)
```

## Why a function CFG layer

The CFG is the lossless intermediate representation. It keeps:

- every decoded instruction, including raw bytes;
- basic-block boundaries and typed control-flow edges;
- direct and indirect call expressions;
- call sites inside the block that performs them;
- timing cost, source file/line, function metadata and diagnostics.

The TDG is derived from this CFG; it is not a second, independently built
control-flow graph. The same representation is intended for a later IDA-style
UI and other downstream consumers.

## CLI

The default view remains the TDG:

```sh
elf2tdg firmware.elf --format json
```

Use `--view cfg` for the intermediate CFG:

```sh
# Complete CFG JSON for one function
elf2tdg firmware.elf --view cfg --format json \
    --function main --output main.cfg.json

# Default global export: functions reachable from main
elf2tdg firmware.elf --view cfg --format json --output reachable.cfg.json

# Reachability from another root
elf2tdg firmware.elf --view cfg --format json \
    --reachable-from sensor_task --output sensor-task.cfg.json

# Complete image export (can be very large)
elf2tdg firmware.elf --view cfg --format json \
    --all-functions --output program.cfg.json

# Graphviz and Mermaid
elf2tdg firmware.elf --view cfg --format dot --function main --output main.dot
elf2tdg firmware.elf --view cfg --format mermaid --function main --output main.mmd

# Block/call skeleton without instruction arrays
elf2tdg firmware.elf --view cfg --format json --function main \
    --no-cfg-instructions --output main-blocks.json
```

`--function` accepts an exact function name or symbol, a unique substring, or a
`0x` address. Without a selector, CFG output contains every function reachable
from `main` through ordinary calls, task/callback creation and context
parenting. `--reachable-from ROOT` changes the root, and `--all-functions`
exports the complete image.

Reachability is resolved from the TDG, so the default scope includes spawned
thread/task entries and scoped-concurrency closures even when the spawn call
was indirect. Interrupt handlers and other independent roots are not reachable
from `main`; include them with `--all-functions` or select their root
explicitly. Filtering happens after analysis, so it reduces export size and
layout time but does not change ELF decoding or TDG construction time.

CFG output includes concrete instructions by default: JSON carries the full
`instructions` arrays with raw bytes, and DOT/Mermaid block labels print the
first eight decoded instructions. `--no-cfg-instructions` omits the arrays and
the label text while retaining addresses, sizes, cycle costs, terminators and
call sites. The TDG-only flags `--instructions`, `--projection` and `--legend`
do not change CFG output.

## JSON document

`cfg_schema_version` is `1.0` and is independent of the TDG schema version.
Every document contains image metadata, diagnostics, and the selected
functions.

```json
{
  "cfg_schema_version": "1.0",
  "image": { "arch": "thumb", "...": "..." },
  "functions": [
    {
      "id": "fn:0x8000138",
      "primary_name": "main",
      "address": "0x8000138",
      "size": 16,
      "entry": "bb:0x8000138",
      "blocks": [
        {
          "id": "bb:0x8000138",
          "address": "0x8000138",
          "size": 4,
          "terminator": "call",
          "instructions": [
            {
              "address": "0x8000138",
              "size": 2,
              "bytes": "10b5",
              "mnemonic": "push",
              "operands": "{r4, lr}",
              "text": "push {r4, lr}",
              "is_call": false,
              "is_jump": false,
              "is_return": false,
              "is_conditional": false,
              "direct_target": null,
              "indirect": null,
              "source": { "file": "main.c", "line": 38 }
            },
            {
              "address": "0x800013a",
              "size": 2,
              "bytes": "fff7f1ff",
              "mnemonic": "bl",
              "operands": "#0x8000120",
              "text": "bl #0x8000120",
              "is_call": true,
              "is_jump": false,
              "is_return": false,
              "is_conditional": false,
              "direct_target": "0x8000120",
              "indirect": null,
              "source": { "file": "main.c", "line": 39 }
            }
          ],
          "calls": [
            {
              "site": "0x800013a",
              "target": "0x8000120",
              "target_function": "fn:0x8000120",
              "target_name": "sensor_task",
              "direct": true,
              "tail": false,
              "conditional": false,
              "heuristic": false,
              "unresolved": false
            }
          ],
          "cycles": { "min": 2.0, "max": 4.0 }
        }
      ],
      "edges": [
        {
          "from": "bb:0x8000138",
          "to": "bb:0x800013c",
          "kind": "call-return",
          "site": "0x800013a",
          "conditional": false
        }
      ],
      "recovered_calls": []
    }
  ],
  "diagnostics": []
}
```

### Node semantics

| Field | Meaning |
|---|---|
| `id` | stable `bb:0x...` block ID; CFG node indices are internal |
| `address`, `size` | linked virtual address and byte size |
| `instructions` | full instruction list with raw bytes and control-flow flags |
| `calls` | call sites owned by this block |
| `cycles` | static instruction-cost sum for the block |
| `terminator` | `fallthrough`, `call`, `return`, `branch`, `jump`, `unresolved` |
| `instructions[].source` | per-instruction file/line/column when DWARF provides it |

`indirect` is retained when known: `register`, `register-memory`,
`memory`, or `register-offset`, with register names and displacement/address.
Unresolved indirect calls and jumps remain explicit rather than being guessed.

### Edge semantics

| `kind` | Meaning |
|---|---|
| `fallthrough` | sequential control flow, including the not-taken side of a conditional |
| `call-return` | continuation after a call; every call ends its own block |
| `branch` | taken conditional branch within the function |
| `jump` | direct unconditional jump, including a self-loop |

Calls are not control-flow edges. They are retained on blocks and are rendered
as dashed call-target edges in DOT/Mermaid.

`recovered_calls` carries call sites found by the bounded gap scan after an
unresolved indirect jump. They have no proven containing basic block, so they
are kept at function level with `heuristic: true`; they are not silently
dropped from the TDG.

## Current limits

- Calls end their basic block and return to a new block; call targets remain
  metadata, not intra-function CFG edges.
- Indexed switch jump tables and computed C++ vtable dispatch are not yet
  expanded into CFG edges; they remain unresolved indirect jumps.
- CFG node IDs are stable within an analysis but are not persisted across
  relinking or address changes.
- Function selection by name requires symbols, unless DWARF provided the name;
  stripped images can still be selected by address.
