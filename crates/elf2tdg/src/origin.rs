//! Bounded register-value recovery for spawn entry arguments.
//!
//! This is deliberately not a general data-flow engine. It scans backwards
//! through the decoded instructions of one function for the latest simple
//! definition of the ABI argument register. It understands literal-pool
//! loads, `lea`/`adr`/`adrp`/`auipc`, register copies, immediate additions and
//! simple `movz`/`movk` sequences, covering the common
//! `pthread_create`/RTOS/OpenMP call patterns at `-O0`/`-O1`.
//!
//! Parameter forwarding through user wrappers is not modeled; unresolved
//! entries stay opaque rather than being guessed.

use crate::arch::{
    DecodedInsn, IndirectTarget, ValueSource, argument_index_for_register, argument_register,
    pc_register, pointer_size,
};
use crate::loader::Image;

/// Resolves the function pointer passed in argument `arg_index` at `site`.
///
/// Returns a canonical executable address, or `None` when the value cannot be
/// recovered safely.
#[must_use]
pub fn resolve_argument_pointer(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    arg_index: usize,
) -> Option<u64> {
    let value = resolve_argument_value(image, decoded, site, arg_index)?;
    let canonical = image.canonical_address(value);
    image.is_executable(canonical).then_some(canonical)
}

/// Resolves the statically known value of an ABI argument at a call site.
///
/// The value may be a code address, a vtable/object address or another data
/// address; callers decide whether code is required.
#[must_use]
pub fn resolve_argument_value(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    arg_index: usize,
) -> Option<u64> {
    let register = argument_register(image.arch, arg_index)?;
    let before = decoded.partition_point(|instruction| instruction.address < site);
    resolve_register(image, decoded, before, register, 0)
}

fn resolve_register(
    image: &Image,
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
    depth: usize,
) -> Option<u64> {
    if depth > 32 {
        return None;
    }
    let mut register = register;
    let mut before = before;
    for _ in 0..64 {
        let found = (0..before).rev().find_map(|index| {
            let effect = decoded[index].value?;
            (effect.dest == register).then_some((index, effect))
        });
        let (index, effect) = found?;
        match effect.source {
            ValueSource::Immediate(value) | ValueSource::Address(value) => return Some(value),
            ValueSource::LoadAddress(address) => {
                // Keep data addresses here: a loaded value can be a vtable or
                // an object whose slot is dereferenced by the caller. The
                // top-level indirect-target check still requires code.
                return image.read_uint(address, pointer_size(image.arch));
            }
            ValueSource::LoadFromRegister { base, disp } => {
                let base_value = if Some(base) == pc_register(image.arch) {
                    Some(pc_value(
                        image.arch,
                        decoded[index].address,
                        decoded[index].size,
                    )?)
                } else {
                    resolve_register(image, decoded, index, base, depth + 1)
                };
                if let Some(base_value) = base_value {
                    let address = base_value.wrapping_add_signed(disp);
                    if let Some(value) = image.read_uint(address, pointer_size(image.arch)) {
                        return Some(value);
                    }
                }
                // A stack spill is a common `-O0` pattern: the pointer is
                // stored through `[rbp+disp]` and loaded back later. Follow
                // the matching store when the base register has no known
                // absolute value.
                if let Some((store_index, source)) = memory_slot_source(decoded, index, base, disp)
                {
                    return resolve_register(image, decoded, store_index, source, depth + 1);
                }
                return None;
            }
            ValueSource::Copy(source) => {
                register = source;
                before = index;
            }
            ValueSource::AddImmediate { base, imm } => {
                let base_value = if Some(base) == pc_register(image.arch) {
                    pc_value(image.arch, decoded[index].address, decoded[index].size)?
                } else {
                    resolve_register(image, decoded, index, base, depth + 1)?
                };
                return Some(base_value.wrapping_add_signed(imm));
            }
            ValueSource::OrImmediate { base, imm } => {
                let base_value = if Some(base) == pc_register(image.arch) {
                    pc_value(image.arch, decoded[index].address, decoded[index].size)?
                } else {
                    resolve_register(image, decoded, index, base, depth + 1)?
                };
                return Some(base_value | imm);
            }
        }
    }
    None
}

/// Resolves a statically identifiable indirect call/branch target expression.
///
/// This handles a register containing a function pointer and a direct memory
/// slot containing one. Indexed jump tables and computed C++ vtable slots are
/// intentionally not guessed.
#[must_use]
pub fn resolve_indirect_target(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<u64> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let value = match target {
        IndirectTarget::Register(register) => {
            resolve_register(image, decoded, before, register, 0)?
        }
        IndirectTarget::RegisterOffset { register, offset } => {
            resolve_register(image, decoded, before, register, 0)?.wrapping_add_signed(offset)
        }
        IndirectTarget::Memory(address) => image.read_uint(address, pointer_size(image.arch))?,
        IndirectTarget::RegisterMemory { base, disp } => {
            if let Some(base_value) = resolve_register(image, decoded, before, base, 0) {
                let address = base_value.wrapping_add_signed(disp);
                image.read_uint(address, pointer_size(image.arch))?
            } else {
                let (store_index, source) = memory_slot_source(decoded, before, base, disp)?;
                resolve_register(image, decoded, store_index, source, 0)?
            }
        }
    };
    let canonical = image.canonical_address(value);
    image.is_executable(canonical).then_some(canonical)
}

fn memory_slot_source(
    decoded: &[DecodedInsn],
    before: usize,
    base: capstone::RegId,
    disp: i64,
) -> Option<(usize, capstone::RegId)> {
    (0..before).rev().find_map(|index| {
        let write = decoded[index].memory_write?;
        (write.base == base && write.disp == disp).then_some((index, write.source))
    })
}

/// A pointer expression rooted at an incoming ABI argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentSpec {
    /// Zero-based ABI argument index.
    pub argument: usize,
    /// Ordered address adjustments and pointer loads from the argument value.
    pub steps: Vec<ArgumentStep>,
}

/// One step in an [`ArgumentSpec`] expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgumentStep {
    /// Signed displacement added before the optional load.
    pub offset: i64,
    /// Whether to load a pointer-sized value after adding the displacement.
    pub dereference: bool,
}

/// Builds an argument-rooted pointer expression for an indirect call target.
///
/// For example, `mov rax, [rdi]; call [rax + 8]` becomes
/// argument 0 with steps `[(0, load), (8, load)]`. Returns `None` when the
/// target depends on a locally computed value or an unsupported operation.
#[must_use]
pub fn indirect_argument_spec(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<ArgumentSpec> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    match target {
        IndirectTarget::Register(register) => trace_argument(image, decoded, before, register, 0),
        IndirectTarget::RegisterMemory { base, disp } => {
            let mut spec = trace_argument(image, decoded, before, base, 0)?;
            spec.steps.push(ArgumentStep {
                offset: disp,
                dereference: true,
            });
            Some(spec)
        }
        IndirectTarget::RegisterOffset { register, offset } => {
            let mut spec = trace_argument(image, decoded, before, register, 0)?;
            spec.steps.push(ArgumentStep {
                offset,
                dereference: false,
            });
            Some(spec)
        }
        IndirectTarget::Memory(_) => None,
    }
}

/// Evaluates an [`ArgumentSpec`] at a caller call site.
#[must_use]
pub fn evaluate_argument_spec(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    spec: &ArgumentSpec,
) -> Option<u64> {
    let mut value = resolve_argument_value(image, decoded, site, spec.argument)?;
    for step in &spec.steps {
        value = value.wrapping_add_signed(step.offset);
        if step.dereference {
            value = image.read_pointer(value)?;
        }
    }
    Some(value)
}

fn trace_argument(
    image: &Image,
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
    depth: usize,
) -> Option<ArgumentSpec> {
    if depth > 32 {
        return None;
    }
    let mut register = register;
    let mut before = before;
    for _ in 0..64 {
        let found = (0..before).rev().find_map(|index| {
            let effect = decoded[index].value?;
            (effect.dest == register).then_some((index, effect))
        });
        let Some((index, effect)) = found else {
            let argument = argument_index_for_register(image.arch, register)?;
            return Some(ArgumentSpec {
                argument,
                steps: Vec::new(),
            });
        };
        match effect.source {
            ValueSource::Copy(source) => {
                register = source;
                before = index;
            }
            ValueSource::AddImmediate { base, imm } => {
                let mut spec = trace_argument(image, decoded, index, base, depth + 1)?;
                spec.steps.push(ArgumentStep {
                    offset: imm,
                    dereference: false,
                });
                return Some(spec);
            }
            ValueSource::LoadFromRegister { base, disp } => {
                if let Some((store_index, source)) = memory_slot_source(decoded, index, base, disp)
                {
                    register = source;
                    before = store_index;
                    continue;
                }
                let mut spec = trace_argument(image, decoded, index, base, depth + 1)?;
                spec.steps.push(ArgumentStep {
                    offset: disp,
                    dereference: true,
                });
                return Some(spec);
            }
            ValueSource::Immediate(_)
            | ValueSource::Address(_)
            | ValueSource::LoadAddress(_)
            | ValueSource::OrImmediate { .. } => return None,
        }
    }
    None
}

/// Returns the caller ABI argument index forwarded to the spawn API argument
/// register at `site`.
///
/// It follows register copies and stack spill/reload pairs back to an incoming
/// argument register. Anything that computes a new value (literal, address,
/// addition) is not treated as forwarding.
#[must_use]
pub fn forwarded_argument_index(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    arg_index: usize,
) -> Option<usize> {
    let mut register = argument_register(image.arch, arg_index)?;
    let mut before = decoded.partition_point(|instruction| instruction.address < site);
    for _ in 0..64 {
        let found = (0..before).rev().find_map(|index| {
            let effect = decoded[index].value?;
            (effect.dest == register).then_some((index, effect))
        });
        let Some((index, effect)) = found else {
            return argument_index_for_register(image.arch, register);
        };
        match effect.source {
            ValueSource::Copy(source) => {
                register = source;
                before = index;
            }
            ValueSource::LoadFromRegister { base, disp } => {
                let (store_index, source) = memory_slot_source(decoded, index, base, disp)?;
                register = source;
                before = store_index;
            }
            ValueSource::Immediate(_)
            | ValueSource::Address(_)
            | ValueSource::LoadAddress(_)
            | ValueSource::AddImmediate { .. }
            | ValueSource::OrImmediate { .. } => return None,
        }
    }
    None
}

fn pc_value(arch: crate::loader::ArchKind, address: u64, size: u8) -> Option<u64> {
    match arch {
        crate::loader::ArchKind::Thumb => Some((address + 4) & !3),
        crate::loader::ArchKind::Arm => Some((address + 8) & !3),
        crate::loader::ArchKind::X86_64 => Some(address.wrapping_add(u64::from(size))),
        crate::loader::ArchKind::Aarch64
        | crate::loader::ArchKind::Riscv32
        | crate::loader::ArchKind::Riscv64 => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_argument_spec, forwarded_argument_index, indirect_argument_spec,
        resolve_argument_pointer, resolve_indirect_target,
    };
    use crate::arch::Decoder;
    use crate::loader::{ArchKind, ByteOrder, ElfKind, Image, Section};

    fn image(arch: ArchKind, address: u64, code: Vec<u8>) -> Image {
        let size = u64::try_from(code.len()).unwrap_or(0).max(0x200);
        Image {
            path: "synthetic.elf".into(),
            arch,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0,
            relocated_pointers: std::collections::BTreeMap::default(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".text".to_owned(),
                address,
                size,
                data: code,
                executable: true,
                writable: false,
                alloc: true,
            }],
            symbols: Vec::new(),
            has_symbols: false,
            has_debug_info: false,
            has_relocations: false,
            arm_cpu: None,
            vector_table: Vec::new(),
            dwarf: None,
            dwarf_error: None,
        }
    }

    #[test]
    fn resolves_x86_lea_argument() {
        let image = image(
            ArchKind::X86_64,
            0x1000,
            vec![0x48, 0x8d, 0x15, 0x09, 0x00, 0x00, 0x00],
        );
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let instruction = engine
            .decode_one(&image.sections[0].data, 0x1000)
            .unwrap()
            .expect("lea");
        let decoded = vec![instruction];
        assert_eq!(
            resolve_argument_pointer(&image, &decoded, 0x1007, 2),
            Some(0x1010)
        );
    }

    #[test]
    fn resolves_thumb_literal_pointer() {
        // ldr r0, [pc, #4] at 0x08000000; literal at 0x08000008 points to
        // 0x08000101 (Thumb bit set).
        let mut code = vec![0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        code.extend_from_slice(&0x0800_0101u32.to_le_bytes());
        code.resize(0x200, 0);
        let image = image(ArchKind::Thumb, 0x0800_0000, code);
        let engine = Decoder::new(ArchKind::Thumb).unwrap();
        let instruction = engine
            .decode_one(&image.sections[0].data[..2], 0x0800_0000)
            .unwrap()
            .expect("ldr");
        let decoded = vec![instruction];
        assert_eq!(
            resolve_argument_pointer(&image, &decoded, 0x0800_0002, 0),
            Some(0x0800_0100)
        );
    }

    #[test]
    fn resolves_aarch64_adr_argument() {
        // adr x0, #0x1024 at 0x1000.
        let image = image(
            ArchKind::Aarch64,
            0x1000,
            0x1000_0120u32.to_le_bytes().to_vec(),
        );
        let engine = Decoder::new(ArchKind::Aarch64).unwrap();
        let instruction = engine
            .decode_one(&image.sections[0].data, 0x1000)
            .unwrap()
            .expect("adr");
        assert_eq!(
            resolve_argument_pointer(&image, &[instruction], 0x1004, 0),
            Some(0x1024)
        );
    }

    #[test]
    fn resolves_aarch64_got_load_chain() {
        // adrp x0, #0x1000; add x0, x0, #0x100; ldr x0, [x0]
        // with the pointer 0x1108 stored at 0x1100.
        let mut code = Vec::new();
        for word in [0x9000_0000u32, 0x9104_0000, 0xf940_0000] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        code.resize(0x200, 0);
        code[0x100..0x108].copy_from_slice(&0x1108u64.to_le_bytes());
        let image = image(ArchKind::Aarch64, 0x1000, code);
        let engine = Decoder::new(ArchKind::Aarch64).unwrap();
        let decoded = (0..3)
            .map(|index| {
                let offset = index * 4;
                engine
                    .decode_one(
                        &image.sections[0].data[offset..offset + 4],
                        0x1000 + offset as u64,
                    )
                    .unwrap()
                    .expect("AArch64 instruction")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_argument_pointer(&image, &decoded, 0x100c, 0),
            Some(0x1108)
        );
    }

    #[test]
    fn forwards_x86_stack_spilled_wrapper_argument() {
        // -O0 wrapper prologue from:
        // start_worker(pthread_t *t, void *(*entry)(void *), void *arg)
        //   { pthread_create(t, 0, entry, arg); }
        let code = vec![
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89,
            0x75, 0xf0, 0x48, 0x89, 0x55, 0xe8, 0x48, 0x8b, 0x4d, 0xe8, 0x48, 0x8b, 0x55, 0xf0,
            0x48, 0x8b, 0x45, 0xf8, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc7, 0xe8, 0x00,
            0x00, 0x00, 0x00,
        ];
        let image = image(ArchKind::X86_64, 0x1000, code);
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let mut decoded = Vec::new();
        let mut offset = 0usize;
        while offset < image.sections[0].data.len() {
            let instruction = engine
                .decode_one(&image.sections[0].data[offset..], 0x1000 + offset as u64)
                .unwrap()
                .expect("x86 instruction");
            offset += usize::from(instruction.size);
            decoded.push(instruction);
        }
        assert_eq!(
            forwarded_argument_index(&image, &decoded, 0x1028, 2),
            Some(1)
        );
    }

    #[test]
    fn resolves_riscv_auipc_argument() {
        // auipc a0, 0; addi a0, a0, 0x24 at 0x2000 -> 0x2024.
        let mut code = Vec::new();
        for word in [0x0000_0517u32, 0x0245_0513] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let image = image(ArchKind::Riscv64, 0x2000, code);
        let engine = Decoder::new(ArchKind::Riscv64).unwrap();
        let decoded = (0..2)
            .map(|index| {
                let offset = index * 4;
                engine
                    .decode_one(
                        &image.sections[0].data[offset..offset + 4],
                        0x2000 + offset as u64,
                    )
                    .unwrap()
                    .expect("RISC-V instruction")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_argument_pointer(&image, &decoded, 0x2008, 0),
            Some(0x2024)
        );
    }

    #[test]
    fn resolves_x86_vtable_slot_through_static_pointer_chain() {
        // mov rax, [rip + 0xff9]   ; rax = *0x2000 = 0x2010
        // call qword ptr [rax + 8] ; vtable slot 0x2018 = 0x1010
        let code = vec![0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xff, 0x50, 0x08];
        let mut vtable = vec![0u8; 16];
        vtable[8..16].copy_from_slice(&0x1010u64.to_le_bytes());
        let image = Image {
            path: "vtable.elf".into(),
            arch: ArchKind::X86_64,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".text".to_owned(),
                    address: 0x1000,
                    size: 0x20,
                    data: code,
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".data".to_owned(),
                    address: 0x2000,
                    size: 8,
                    data: 0x2010u64.to_le_bytes().to_vec(),
                    executable: false,
                    writable: true,
                    alloc: true,
                },
                Section {
                    name: ".rodata".to_owned(),
                    address: 0x2010,
                    size: 16,
                    data: vtable,
                    executable: false,
                    writable: false,
                    alloc: true,
                },
            ],
            symbols: Vec::new(),
            has_symbols: false,
            has_debug_info: false,
            has_relocations: false,
            arm_cpu: None,
            vector_table: Vec::new(),
            dwarf: None,
            dwarf_error: None,
        };
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let load = engine
            .decode_one(&image.sections[0].data[..7], 0x1000)
            .unwrap()
            .expect("mov");
        let call = engine
            .decode_one(&image.sections[0].data[7..], 0x1007)
            .unwrap()
            .expect("call");
        let indirect = call.indirect.expect("vtable call is indirect");
        assert_eq!(
            resolve_indirect_target(&image, &[load, call], 0x1007, indirect),
            Some(0x1010)
        );
    }

    #[test]
    fn resolves_indirect_target_through_caller_argument() {
        // callee: call qword ptr [rdi + 8]
        // caller: lea rdi, [rip + disp] -> 0x2000
        // object+8 contains the address of the target function (0x1010).
        let mut object = vec![0u8; 16];
        object[8..16].copy_from_slice(&0x1010u64.to_le_bytes());
        let image = Image {
            path: "vtable-arg.elf".into(),
            arch: ArchKind::X86_64,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".callee".to_owned(),
                    address: 0x1000,
                    size: 3,
                    data: vec![0xff, 0x57, 0x08],
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".caller".to_owned(),
                    address: 0x3000,
                    size: 7,
                    data: vec![0x48, 0x8d, 0x3d, 0xf9, 0xef, 0xff, 0xff],
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".objects".to_owned(),
                    address: 0x2000,
                    size: 16,
                    data: object,
                    executable: false,
                    writable: true,
                    alloc: true,
                },
            ],
            symbols: Vec::new(),
            has_symbols: false,
            has_debug_info: false,
            has_relocations: false,
            arm_cpu: None,
            vector_table: Vec::new(),
            dwarf: None,
            dwarf_error: None,
        };
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let call = engine
            .decode_one(&image.sections[0].data, 0x1000)
            .unwrap()
            .expect("call");
        let lea = engine
            .decode_one(&image.sections[1].data, 0x3000)
            .unwrap()
            .expect("lea");
        let target = call.indirect.expect("indirect call");
        let spec =
            indirect_argument_spec(&image, &[call], 0x1000, target).expect("argument dependency");
        assert_eq!(spec.argument, 0);
        assert_eq!(
            evaluate_argument_spec(&image, &[lea], 0x3007, &spec),
            Some(0x1010)
        );
    }
}
