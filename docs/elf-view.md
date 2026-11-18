# ELF layout view

`--view elf` exposes the loader model directly as a Mermaid flowchart. It runs
after ELF loading and exits before CFG analysis, so it is useful for
checking what the loader actually saw and for explaining the memory layout of
an embedded image.

```sh
elf2tdg firmware.elf --view elf --output firmware-elf.mmd
```

Mermaid is the default (and currently only) format for this view. Render the
`.mmd` file with any Mermaid-compatible viewer, for example GitHub, VS Code,
or <https://mermaid.live>. `--view loader` is an alias for `--view elf`.

## What is shown

The diagram is a containment hierarchy:

```text
ELF image
  PT_LOAD segment
    allocated section
      linear disassembly (executable sections only)
```

Each `LOAD (PT_LOAD)` segment reports:

- virtual address range;
- `R/W/X` permissions;
- file offset and file-backed byte count;
- memory size and required alignment.

The memory size can be larger than the file-backed size. The extra tail is
zero-filled at run time, which is how `.bss` is represented.

Sections show their allocation/permission flags, address range, memory size,
file-backed size and a `NOBITS` marker for zero-filled sections. Sections that
are not allocated at run time (symbol tables, debug data, comments and similar
metadata) are omitted from the segment tree; the diagram reports how many were
hidden.

## Color legend

Segment colors describe memory permissions:

| Color | Permission | Typical contents |
|---|---|---|
| green | `R-X` | executable code (`.text`, `.init`, `.plt`) |
| orange | `RW-` | writable data and zero-filled `.bss` |
| blue | `R--` | read-only data, vector tables, constants |
| red | `RWX` | writable and executable; unusual and worth reviewing |

Instruction colors describe the mnemonic class:

| Color | Class | Examples |
|---|---|---|
| red | call | `bl`, `call`, `jal` |
| orange | branch | conditional/unconditional jumps |
| purple | return | `bx lr`, `ret`, `jr ra`, interrupt return |
| blue | stack | `push`, `pop`, prologue/epilogue stack frames |
| green | memory | loads and stores |
| gray | arithmetic/logic | arithmetic, logic, moves and address calculation |
| teal | system | barriers, system instructions, CSR access |
| white | other | instructions outside the modeled classes |

The legend is embedded in the Mermaid output, so a rendered diagram explains
its own colors.

## Disassembly limits

Executable sections are disassembled linearly, not as a CFG. Consecutive
instructions are connected with dashed arrows to show listing order; those
arrows are **not** control-flow edges. For branches, call targets and basic
blocks, use `--view cfg` instead.

The default limit is 256 instructions per executable section:

```sh
# Smaller per-section listing
elf2tdg firmware.elf --view elf --elf-max-insns 64 --output layout.mmd

# No limit (can make the diagram very large)
elf2tdg firmware.elf --view elf --elf-max-insns 0 --output layout.mmd
```

When a section is truncated, the diagram contains a note with the remaining
byte count.

## Related views

- default (`--view cfg`): lossless program CFG with roots, call graph,
  concurrency annotations and optional instruction bytes.
