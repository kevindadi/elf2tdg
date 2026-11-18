//! Mermaid visualization of the loaded ELF layout.
//!
//! This view deliberately runs directly on [`crate::loader::Image`], without
//! building the program CFG. It shows program segments, allocated
//! sections and a color-coded linear disassembly of executable sections.

use crate::arch::{DecodedInsn, Decoder};
use crate::loader::{ElfKind, Image, Section, Segment};
use std::fmt::Write as _;

/// Default number of instructions rendered per executable section.
pub const DEFAULT_MAX_INSTRUCTIONS_PER_SECTION: usize = 256;

/// Renders a loaded ELF as a self-contained Mermaid flowchart.
///
/// A `max_instructions_per_section` of zero means no limit.
///
/// # Errors
///
/// Returns an error when the decoder cannot be initialized. Undecodable bytes
/// are rendered as `.byte` nodes instead of failing the whole export.
pub fn render_mermaid(
    image: &Image,
    max_instructions_per_section: usize,
) -> Result<String, String> {
    let decoder = if image
        .sections
        .iter()
        .any(|section| section.executable && !section.data.is_empty())
    {
        Some(Decoder::new(image.arch).map_err(|error| error.to_string())?)
    } else {
        None
    };

    let mut out = String::new();
    let _ = writeln!(out, "flowchart TB");
    write_class_defs(&mut out);

    let allocated: Vec<&Section> = image
        .sections
        .iter()
        .filter(|section| section.alloc)
        .collect();
    let non_allocated = image.sections.len().saturating_sub(allocated.len());
    let file_name = image
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| image.path.to_str().unwrap_or("ELF image"));
    let summary = format!(
        "{} | {} | entry {} | {} | {} LOAD segments | {} allocated sections | {} symbols",
        image.arch.schema_name(),
        elf_kind_name(image.elf_kind),
        hex(image.entry),
        byte_order_name(image.byte_order),
        image.segments.len(),
        allocated.len(),
        image.symbols.len()
    );
    let _ = writeln!(
        out,
        "  subgraph ELF[\"ELF: {}<br/>{}<br/>PT_LOAD = bytes mapped into memory; R/W/X are permissions\"]",
        escape_text(file_name),
        escape_text(&summary)
    );
    let _ = writeln!(out, "    direction TB");

    let mut mapped = vec![false; allocated.len()];
    let mut state = RenderState {
        decoder: decoder.as_ref(),
        max_instructions: max_instructions_per_section,
        instruction_index: 0,
    };
    for (segment_index, segment) in image.segments.iter().enumerate() {
        write_segment(
            &mut out,
            segment,
            segment_index,
            &allocated,
            &mut mapped,
            &mut state,
        );
    }

    let orphan_indices: Vec<usize> = allocated
        .iter()
        .enumerate()
        .filter(|(index, _)| !mapped[*index])
        .map(|(index, _)| index)
        .collect();
    if !orphan_indices.is_empty() {
        let _ = writeln!(
            out,
            "    subgraph ORPHAN[\"Allocated sections without a containing LOAD segment\"]"
        );
        let _ = writeln!(out, "      direction TB");
        for section_index in orphan_indices {
            write_section(
                &mut out,
                allocated[section_index],
                section_index,
                &mut state,
            );
        }
        let _ = writeln!(out, "    end");
    }

    if non_allocated > 0 {
        let _ = writeln!(
            out,
            "    ELF_META[\"{non_allocated} non-allocated section(s) not shown (symbols/debug/metadata)\"]:::elfNote"
        );
    }
    let _ = writeln!(out, "  end");

    write_legend(&mut out);
    Ok(out)
}

struct RenderState<'a> {
    decoder: Option<&'a Decoder>,
    max_instructions: usize,
    instruction_index: usize,
}

fn write_segment(
    out: &mut String,
    segment: &Segment,
    segment_index: usize,
    allocated: &[&Section],
    mapped: &mut [bool],
    state: &mut RenderState<'_>,
) {
    let visual = segment_visual(segment);
    let _ = writeln!(
        out,
        "    subgraph SEG{segment_index}[\"LOAD (PT_LOAD) {}..{}<br/>{} | file {} + {} bytes | mem {} bytes | align {} bytes\"]",
        hex(segment.address),
        hex(segment.end()),
        segment.permissions(),
        hex(segment.file_offset),
        hex(segment.file_size),
        hex(segment.size),
        hex(segment.align)
    );
    let _ = writeln!(out, "      direction TB");
    let section_indices: Vec<usize> = allocated
        .iter()
        .enumerate()
        .filter(|(index, section)| !mapped[*index] && segment.contains_section(section))
        .map(|(index, _)| index)
        .collect();
    if section_indices.is_empty() {
        let _ = writeln!(
            out,
            "      SEG{segment_index}_empty[\"(no allocated section header falls in this segment)\"]:::elfNote"
        );
    }
    for section_index in section_indices {
        mapped[section_index] = true;
        write_section(out, allocated[section_index], section_index, state);
    }
    let _ = writeln!(out, "    end");
    let _ = writeln!(
        out,
        "    style SEG{segment_index} fill:{},stroke:{},stroke-width:2px,color:{};",
        visual.fill, visual.stroke, visual.text
    );
}

fn write_section(
    out: &mut String,
    section: &Section,
    section_index: usize,
    state: &mut RenderState<'_>,
) {
    let visual = section_visual(section);
    let flags = section_permissions(section);
    let kind = if section.is_nobits() {
        " | NOBITS (zero-filled)"
    } else {
        ""
    };
    let _ = writeln!(
        out,
        "      subgraph SEC{section_index}[\"{}<br/>{flags} | {}..{} | mem {} bytes | file {} bytes{}\"]",
        escape_text(&section.name),
        hex(section.address),
        hex(section.end()),
        hex(section.size),
        hex(section.data.len() as u64),
        kind
    );
    let _ = writeln!(out, "        direction TB");

    if section.executable && !section.data.is_empty() {
        if let Some(decoder) = state.decoder {
            write_instructions(out, decoder, section, state);
        }
    } else if section.data.is_empty() {
        let _ = writeln!(
            out,
            "        SEC{section_index}_empty[\"no file-backed bytes (zero-filled at run time)\"]:::elfNote"
        );
    } else {
        let _ = writeln!(
            out,
            "        SEC{section_index}_data[\"data / metadata bytes (not executable, not disassembled)\"]:::elfNote"
        );
    }

    let _ = writeln!(out, "      end");
    let _ = writeln!(
        out,
        "      style SEC{section_index} fill:#ffffff,stroke:{},stroke-width:1.5px,color:{};",
        visual.stroke, visual.text
    );
}

fn write_instructions(
    out: &mut String,
    decoder: &Decoder,
    section: &Section,
    state: &mut RenderState<'_>,
) {
    let mut offset = 0usize;
    let mut previous: Option<String> = None;
    let mut emitted = 0usize;
    let mut truncated = false;

    while offset < section.data.len() {
        if state.max_instructions > 0 && emitted >= state.max_instructions {
            truncated = true;
            break;
        }
        let address = section.address.saturating_add(offset as u64);
        let decoded_instruction = decoder
            .decode_one(&section.data[offset..], address)
            .ok()
            .flatten();
        let (text, size, class) = if let Some(insn) = decoded_instruction {
            let size = usize::from(insn.size.max(1));
            (instruction_text(&insn), size, instruction_class(&insn))
        } else {
            let byte = section.data[offset];
            (format!(".byte {byte:#04x}"), 1, "insnOther")
        };
        let size = size.min(section.data.len() - offset);
        if size == 0 {
            break;
        }
        let id = format!("insn{}", state.instruction_index);
        state.instruction_index += 1;
        let _ = writeln!(
            out,
            "        {id}[\"{}  {}\"]:::{class}",
            hex(address),
            escape_text(&text)
        );
        if let Some(previous) = &previous {
            let _ = writeln!(out, "        {previous} -.-> {id}");
        }
        previous = Some(id);
        offset += size;
        emitted += 1;
    }

    if truncated {
        let id = format!("insn{}", state.instruction_index);
        state.instruction_index += 1;
        let remaining = section.data.len().saturating_sub(offset);
        let _ = writeln!(
            out,
            "        {id}[\"truncated after {emitted} instruction(s); {remaining} byte(s) remain (raise --elf-max-insns)\"]:::insnNote"
        );
        if let Some(previous) = &previous {
            let _ = writeln!(out, "        {previous} -.-> {id}");
        }
    } else if emitted == 0 {
        let _ = writeln!(
            out,
            "        SEC_{}[\"no decodable instructions\"]:::elfNote",
            hex(section.address)
        );
    }
}

fn instruction_text(insn: &DecodedInsn) -> String {
    if insn.operands.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} {}", insn.mnemonic, insn.operands)
    }
}

fn instruction_class(insn: &DecodedInsn) -> &'static str {
    if insn.is_call {
        return "insnCall";
    }
    if insn.is_return {
        return "insnReturn";
    }
    if insn.is_jump {
        return "insnBranch";
    }
    let mnemonic = insn.mnemonic.as_str();
    if is_stack(mnemonic, &insn.operands) {
        "insnStack"
    } else if is_memory(mnemonic, &insn.operands) {
        "insnMemory"
    } else if is_system(mnemonic) {
        "insnSystem"
    } else if is_alu(mnemonic) {
        "insnAlu"
    } else {
        "insnOther"
    }
}

fn is_stack(mnemonic: &str, operands: &str) -> bool {
    matches!(
        mnemonic,
        "push" | "pop" | "pusha" | "popa" | "enter" | "leave"
    ) || (matches!(mnemonic, "stp" | "ldp") && uses_register(operands, "sp"))
}

fn uses_register(operands: &str, register: &str) -> bool {
    operands
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|token| token == register)
}

fn is_memory(mnemonic: &str, operands: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ldr", "str", "ldp", "stp", "ldur", "stur", "ldxr", "stxr", "ldaxr", "stlxr", "ldar",
        "stlr", "ld1", "st1", "vld", "vst", "lb", "lh", "lw", "ld", "sb", "sh", "sw", "sd", "flw",
        "fld", "fsw", "fsd",
    ];
    PREFIXES.iter().any(|prefix| mnemonic.starts_with(prefix))
        || (mnemonic.starts_with("mov") && (operands.contains('[') || operands.contains("ptr")))
}

fn is_alu(mnemonic: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "add", "adc", "sub", "sbc", "mul", "imul", "div", "idiv", "and", "or", "xor", "not", "neg",
        "shl", "shr", "sar", "rol", "ror", "cmp", "test", "mov", "lea", "adr", "adrp", "sll",
        "srl", "sra", "slt", "lui", "auipc", "inc", "dec", "eor", "orn", "bic", "mvn", "rsb",
        "rsc", "teq", "tst", "asr", "lsl", "lsr", "rrx", "rev", "clz", "crc32",
    ];
    PREFIXES.iter().any(|prefix| mnemonic.starts_with(prefix))
}

fn is_system(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "nop"
            | "wfi"
            | "wfe"
            | "sev"
            | "svc"
            | "bkpt"
            | "mrs"
            | "msr"
            | "dmb"
            | "dsb"
            | "isb"
            | "cpsid"
            | "cpsie"
            | "fence"
            | "ecall"
            | "ebreak"
            | "uret"
            | "mret"
            | "sret"
            | "syscall"
            | "int3"
            | "hlt"
            | "ud2"
    ) || mnemonic.starts_with("csr")
}

fn section_permissions(section: &Section) -> String {
    format!(
        "{}{}{}",
        if section.alloc { 'R' } else { '-' },
        if section.writable { 'W' } else { '-' },
        if section.executable { 'X' } else { '-' }
    )
}

#[derive(Clone, Copy)]
struct Visual {
    fill: &'static str,
    stroke: &'static str,
    text: &'static str,
}

fn segment_visual(segment: &Segment) -> Visual {
    match (segment.executable, segment.writable) {
        (true, true) => Visual {
            fill: "#fadbd8",
            stroke: "#c0392b",
            text: "#78281f",
        },
        (true, false) => Visual {
            fill: "#e8f8f5",
            stroke: "#117a65",
            text: "#0b5345",
        },
        (false, true) => Visual {
            fill: "#fef5e7",
            stroke: "#b9770e",
            text: "#7e5109",
        },
        (false, false) => Visual {
            fill: "#eaf2f8",
            stroke: "#2471a3",
            text: "#1b4f72",
        },
    }
}

fn section_visual(section: &Section) -> Visual {
    if section.executable {
        Visual {
            fill: "#ffffff",
            stroke: "#117a65",
            text: "#0b5345",
        }
    } else if section.writable {
        Visual {
            fill: "#ffffff",
            stroke: "#b9770e",
            text: "#7e5109",
        }
    } else {
        Visual {
            fill: "#ffffff",
            stroke: "#2471a3",
            text: "#1b4f72",
        }
    }
}

fn write_class_defs(out: &mut String) {
    let _ = writeln!(
        out,
        "  classDef segmentRx fill:#e8f8f5,stroke:#117a65,stroke-width:2px,color:#0b5345;"
    );
    let _ = writeln!(
        out,
        "  classDef segmentRw fill:#fef5e7,stroke:#b9770e,stroke-width:2px,color:#7e5109;"
    );
    let _ = writeln!(
        out,
        "  classDef segmentR fill:#eaf2f8,stroke:#2471a3,stroke-width:2px,color:#1b4f72;"
    );
    let _ = writeln!(
        out,
        "  classDef segmentRwx fill:#fadbd8,stroke:#c0392b,stroke-width:2px,color:#78281f;"
    );
    let _ = writeln!(
        out,
        "  classDef insnCall fill:#fadbd8,stroke:#c0392b,color:#78281f;"
    );
    let _ = writeln!(
        out,
        "  classDef insnBranch fill:#fdebd0,stroke:#b9770e,color:#7e5109;"
    );
    let _ = writeln!(
        out,
        "  classDef insnReturn fill:#e8daef,stroke:#7d3c98,color:#512e5f;"
    );
    let _ = writeln!(
        out,
        "  classDef insnStack fill:#d6eaf8,stroke:#2471a3,color:#1b4f72;"
    );
    let _ = writeln!(
        out,
        "  classDef insnMemory fill:#eafaf1,stroke:#1e8449,color:#145a32;"
    );
    let _ = writeln!(
        out,
        "  classDef insnAlu fill:#f4f6f7,stroke:#566573,color:#283747;"
    );
    let _ = writeln!(
        out,
        "  classDef insnSystem fill:#e8f6f3,stroke:#138d75,color:#0b5345;"
    );
    let _ = writeln!(
        out,
        "  classDef insnOther fill:#fdfefe,stroke:#999999,color:#424949;"
    );
    let _ = writeln!(
        out,
        "  classDef insnNote fill:#f4f6f7,stroke:#999999,color:#566573,stroke-dasharray:3 3;"
    );
    let _ = writeln!(
        out,
        "  classDef elfNote fill:#fdf2e9,stroke:#b9770e,color:#7e5109;"
    );
}

fn write_legend(out: &mut String) {
    let _ = writeln!(out, "  subgraph LEGEND[\"Legend\"]");
    let _ = writeln!(out, "    direction LR");
    let _ = writeln!(
        out,
        "    legend_rx[\"LOAD R-X<br/>read + execute: code\"]:::segmentRx"
    );
    let _ = writeln!(
        out,
        "    legend_rw[\"LOAD RW-<br/>read + write: data / BSS\"]:::segmentRw"
    );
    let _ = writeln!(
        out,
        "    legend_r[\"LOAD R--<br/>read-only: constants / vector table\"]:::segmentR"
    );
    let _ = writeln!(
        out,
        "    legend_rwx[\"LOAD RWX<br/>writable + executable (unusual)\"]:::segmentRwx"
    );
    let _ = writeln!(out, "    legend_call[\"call / bl / jal\"]:::insnCall");
    let _ = writeln!(
        out,
        "    legend_branch[\"conditional / unconditional branch\"]:::insnBranch"
    );
    let _ = writeln!(
        out,
        "    legend_return[\"return / interrupt return\"]:::insnReturn"
    );
    let _ = writeln!(
        out,
        "    legend_stack[\"push / pop / stack frame\"]:::insnStack"
    );
    let _ = writeln!(out, "    legend_memory[\"load / store\"]:::insnMemory");
    let _ = writeln!(
        out,
        "    legend_alu[\"arithmetic / logic / move\"]:::insnAlu"
    );
    let _ = writeln!(
        out,
        "    legend_system[\"barrier / system / CSR\"]:::insnSystem"
    );
    let _ = writeln!(
        out,
        "    legend_note[\"dashed sequence = linear disassembly order<br/>use --view cfg for control flow\"]:::elfNote"
    );
    let _ = writeln!(out, "  end");
}

fn escape_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push('\''),
            '[' | '{' => escaped.push('('),
            ']' | '}' => escaped.push(')'),
            '|' => escaped.push('/'),
            '\n' | '\r' => escaped.push(' '),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn elf_kind_name(kind: ElfKind) -> &'static str {
    match kind {
        ElfKind::Exec => "executable",
        ElfKind::Dyn => "shared object / PIE",
        ElfKind::Rel => "relocatable object",
        ElfKind::Unknown => "unknown ELF type",
    }
}

fn byte_order_name(order: crate::loader::ByteOrder) -> &'static str {
    match order {
        crate::loader::ByteOrder::Little => "little-endian",
        crate::loader::ByteOrder::Big => "big-endian",
    }
}
