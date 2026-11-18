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
    DecodedInsn, IndirectTarget, MemoryWriteSource, ValueSource, argument_index_for_register,
    argument_register, pc_register, pointer_size,
};
use crate::loader::Image;
use std::collections::BTreeSet;

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

/// Resolves the value produced by the value effect at `index`.
///
/// This is used for return-value summaries: the caller identifies a write to
/// the ABI return register and asks origin tracking to resolve its source.
#[must_use]
pub fn resolve_definition_value(
    image: &Image,
    decoded: &[DecodedInsn],
    index: usize,
) -> Option<u64> {
    let effect = decoded.get(index)?.value?;
    resolve_effect(image, decoded, index, effect.source, 0)
}

/// Resolves the statically known value of `register` immediately before
/// `before`.
///
/// This is the same bounded backward scan used for pointer recovery. It is
/// evidence for memory-address resolution, not a proof of the value on every
/// path through the function.
#[must_use]
pub(crate) fn resolve_register_value(
    image: &Image,
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
) -> Option<u64> {
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
            ValueSource::Copy(source) => {
                register = source;
                before = index;
            }
            source => return resolve_effect(image, decoded, index, source, depth),
        }
    }
    None
}

fn resolve_effect(
    image: &Image,
    decoded: &[DecodedInsn],
    index: usize,
    source: ValueSource,
    depth: usize,
) -> Option<u64> {
    if depth > 32 {
        return None;
    }
    match source {
        ValueSource::Immediate(value) | ValueSource::Address(value) => Some(value),
        ValueSource::LoadAddress(address) => {
            // Keep data addresses here: a loaded value can be a vtable or an
            // object whose slot is dereferenced by the caller. Import GOT
            // slots resolve to their synthetic external-function
            // pseudo-address.
            memory_pointer_value(image, address)
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
                if let Some(value) = memory_pointer_value(image, address) {
                    return Some(value);
                }
            }
            // A stack spill is a common `-O0` pattern: the pointer is stored
            // through `[rbp+disp]` and loaded back later. Follow the matching
            // store when the base register has no known absolute value.
            match memory_slot_source(decoded, index, base, disp)? {
                (store_index, MemoryWriteSource::Register(source)) => {
                    resolve_register(image, decoded, store_index, source, depth + 1)
                }
                (_, MemoryWriteSource::Immediate(value)) => Some(value),
            }
        }
        ValueSource::Copy(source) => resolve_register(image, decoded, index, source, depth + 1),
        ValueSource::AddImmediate { base, imm } => {
            let base_value = if Some(base) == pc_register(image.arch) {
                pc_value(image.arch, decoded[index].address, decoded[index].size)?
            } else {
                resolve_register(image, decoded, index, base, depth + 1)?
            };
            Some(base_value.wrapping_add_signed(imm))
        }
        ValueSource::OrImmediate { base, imm } => {
            let base_value = if Some(base) == pc_register(image.arch) {
                pc_value(image.arch, decoded[index].address, decoded[index].size)?
            } else {
                resolve_register(image, decoded, index, base, depth + 1)?
            };
            Some(base_value | imm)
        }
        ValueSource::AddRegister { .. }
        | ValueSource::IndexedLoad { .. }
        | ValueSource::ShiftRegister { .. }
        | ValueSource::Select { .. } => None,
    }
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
    let value = resolve_indirect_target_value(image, decoded, site, target)?;
    // A GOT slot without a local PLT stub resolves to a synthetic external
    // function whose pseudo-address is the slot itself.
    if image.import_name_at(value).is_some() {
        return Some(image.canonical_address(value));
    }
    let canonical = image.canonical_address(value);
    image.is_executable(canonical).then_some(canonical)
}

/// Returns the raw statically known register/memory value at an indirect
/// target, before requiring the value to name executable code.
///
/// A `Some(0)` result is a statically null function pointer; callers can
/// distinguish that from an unknown dynamic target and avoid reporting a
/// spurious unresolved call.
#[must_use]
pub fn resolve_indirect_target_value(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<u64> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    match target {
        IndirectTarget::Register(register) => resolve_register(image, decoded, before, register, 0),
        IndirectTarget::RegisterOffset { register, offset } => {
            Some(resolve_register(image, decoded, before, register, 0)?.wrapping_add_signed(offset))
        }
        IndirectTarget::Memory(address) => memory_pointer_value(image, address),
        IndirectTarget::IndexedMemory { .. }
        | IndirectTarget::TableBranch { .. }
        | IndirectTarget::TableLoad { .. }
        | IndirectTarget::BranchTable { .. } => None,
        IndirectTarget::RegisterMemory { base, disp } => {
            if let Some(base_value) = resolve_register(image, decoded, before, base, 0) {
                let address = base_value.wrapping_add_signed(disp);
                memory_pointer_value(image, address)
            } else {
                match memory_slot_source(decoded, before, base, disp)? {
                    (store_index, MemoryWriteSource::Register(source)) => {
                        resolve_register(image, decoded, store_index, source, 0)
                    }
                    (_, MemoryWriteSource::Immediate(value)) => Some(value),
                }
            }
        }
    }
}

/// Returns the direct call whose ABI return value produced `register` at
/// `site`, together with the call site.
///
/// The scan stops at any modeled write to the register or at control flow that
/// leaves the sequential path. Unmodeled register writes can still slip
/// through, so callers treat the result as candidate evidence rather than a
/// proven data-flow fact.
#[must_use]
pub fn returned_call_before(
    decoded: &[DecodedInsn],
    site: u64,
    register: capstone::RegId,
) -> Option<(u64, u64)> {
    let mut register = register;
    let mut before = decoded.partition_point(|instruction| instruction.address < site);
    for _ in 0..16 {
        let mut copy = None;
        for index in (0..before).rev() {
            let instruction = &decoded[index];
            if let Some(effect) = instruction.value
                && effect.dest == register
            {
                let ValueSource::Copy(source) = effect.source else {
                    return None;
                };
                copy = Some((index, source));
                break;
            }
            if instruction.is_return || instruction.is_jump {
                return None;
            }
            if instruction.is_call {
                return instruction
                    .direct_target
                    .map(|target| (target, instruction.address));
            }
        }
        let (index, source) = copy?;
        register = source;
        before = index;
    }
    None
}

/// Maximum number of distinct field-store values considered for a bounded
/// multi-target indirect call.
const MAX_FIELD_STORE_CANDIDATES: usize = 32;

/// Returns the field displacement loaded by an indirect call target.
///
/// `blx r1` after `ldr r1, [r0, #12]` has an unresolved base register, but the
/// field offset is still statically known. The caller can then look for stores
/// to the same field offset elsewhere in the image.
#[must_use]
pub fn indirect_field_load(
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<i64> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    match target {
        IndirectTarget::Register(register) => {
            field_offset_from_register(decoded, before, register, 0)
        }
        IndirectTarget::RegisterMemory { disp, .. } => Some(disp),
        IndirectTarget::RegisterOffset { .. }
        | IndirectTarget::Memory(_)
        | IndirectTarget::IndexedMemory { .. }
        | IndirectTarget::TableBranch { .. }
        | IndirectTarget::TableLoad { .. }
        | IndirectTarget::BranchTable { .. } => None,
    }
}

fn field_offset_from_register(
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
    depth: usize,
) -> Option<i64> {
    if depth > 16 {
        return None;
    }
    let (index, effect) = (0..before).rev().find_map(|index| {
        let effect = decoded[index].value?;
        (effect.dest == register).then_some((index, effect))
    })?;
    match effect.source {
        ValueSource::LoadFromRegister { disp, .. } => Some(disp),
        ValueSource::Copy(source) => field_offset_from_register(decoded, index, source, depth + 1),
        _ => None,
    }
}

/// Maximum number of vtable method targets returned for one slot offset.
const MAX_VTABLE_CANDIDATES: usize = 32;
/// Safety bound on candidate data pointers inspected for one call site.
const MAX_VTABLE_BASES: usize = 4096;

/// Resolves possible method targets for a Rust trait-object vtable slot.
///
/// `slot` is the byte offset loaded from the vtable base. Rust trait-object
/// vtables start with drop/size/align entries, so method slots begin at
/// `3 * pointer_size`. Candidate vtable bases come only from pointer constants
/// in the supplied decoded functions, which keeps unrelated rodata tables from
/// leaking into a call site. The scan validates the vtable header and collects
/// executable methods at the requested slot.
#[must_use]
pub fn resolve_vtable_slot_candidates(
    image: &Image,
    decoded_functions: &[&[DecodedInsn]],
    slot: i64,
) -> Vec<u64> {
    let pointer = pointer_size(image.arch);
    let Ok(slot) = usize::try_from(slot) else {
        return Vec::new();
    };
    let header = pointer.saturating_mul(3);
    if slot < header || !(slot - header).is_multiple_of(pointer) {
        return Vec::new();
    }
    let mut candidates = BTreeSet::new();
    collect_vtable_methods(
        image,
        collect_vtable_bases(image, decoded_functions),
        slot,
        pointer,
        &mut candidates,
    );
    if candidates.is_empty() {
        collect_vtable_methods(
            image,
            collect_dwarf_vtable_bases(image),
            slot,
            pointer,
            &mut candidates,
        );
    }
    candidates.into_iter().collect()
}

fn collect_vtable_methods(
    image: &Image,
    bases: BTreeSet<u64>,
    slot: usize,
    pointer: usize,
    candidates: &mut BTreeSet<u64>,
) {
    for base in bases {
        let Some(method) = vtable_slot_value(image, base, slot, pointer) else {
            continue;
        };
        let method = image.canonical_address(method);
        if image.is_executable(method) {
            candidates.insert(method);
            if candidates.len() > MAX_VTABLE_CANDIDATES {
                candidates.clear();
                return;
            }
        }
    }
}

/// Returns raw values stored at `slot` in candidate vtable-shaped tables.
///
/// This includes header slots such as the drop entry at offset zero, allowing
/// callers to recognize a statically null drop target even when the vtable base
/// itself is not statically known.
#[must_use]
pub fn resolve_vtable_slot_values(
    image: &Image,
    decoded_functions: &[&[DecodedInsn]],
    slot: i64,
) -> Vec<u64> {
    let pointer = pointer_size(image.arch);
    let Ok(slot) = usize::try_from(slot) else {
        return Vec::new();
    };
    if !slot.is_multiple_of(pointer) {
        return Vec::new();
    }
    let mut values = BTreeSet::new();
    collect_vtable_values(
        image,
        collect_vtable_bases(image, decoded_functions),
        slot,
        pointer,
        &mut values,
    );
    if values.is_empty() {
        collect_vtable_values(
            image,
            collect_dwarf_vtable_bases(image),
            slot,
            pointer,
            &mut values,
        );
    }
    values.into_iter().collect()
}

fn collect_vtable_values(
    image: &Image,
    bases: BTreeSet<u64>,
    slot: usize,
    pointer: usize,
    values: &mut BTreeSet<u64>,
) {
    for base in bases {
        let Some(value) = vtable_slot_value(image, base, slot, pointer) else {
            continue;
        };
        values.insert(value);
        if values.len() > MAX_VTABLE_CANDIDATES {
            values.clear();
            return;
        }
    }
}

fn collect_vtable_bases(image: &Image, decoded_functions: &[&[DecodedInsn]]) -> BTreeSet<u64> {
    let mut bases = BTreeSet::new();
    for decoded in decoded_functions {
        for (index, instruction) in decoded.iter().enumerate() {
            let Some(effect) = instruction.value else {
                continue;
            };
            let Some(value) = resolve_register(image, decoded, index + 1, effect.dest, 0) else {
                continue;
            };
            let value = image.canonical_address(value);
            if is_read_only_data(image, value) {
                bases.insert(value);
                if bases.len() > MAX_VTABLE_BASES {
                    return BTreeSet::new();
                }
            }
        }
    }
    bases
}

fn collect_dwarf_vtable_bases(image: &Image) -> BTreeSet<u64> {
    let Some(dwarf) = image.dwarf.as_ref() else {
        return BTreeSet::new();
    };
    let mut bases = BTreeSet::new();
    for vtable in &dwarf.vtables {
        add_vtable_base(image, &mut bases, vtable.address);
    }
    let mut visited = BTreeSet::new();
    for variable in &dwarf.variables {
        let Some(address) = variable.address else {
            continue;
        };
        if let Some(aggregate) = variable.aggregate_index {
            collect_typed_trait_vtables(
                image,
                dwarf,
                aggregate,
                address,
                0,
                &mut bases,
                &mut visited,
            );
        }
        if let Some(element) = variable.element_aggregate_index
            && let Some(count) = variable.array_count
            && let Some(size) = dwarf
                .aggregates
                .get(element)
                .and_then(|aggregate| aggregate.byte_size)
        {
            for index in 0..count.min(256) {
                let Some(object) = index
                    .checked_mul(size)
                    .and_then(|offset| address.checked_add(offset))
                else {
                    break;
                };
                collect_typed_trait_vtables(
                    image,
                    dwarf,
                    element,
                    object,
                    0,
                    &mut bases,
                    &mut visited,
                );
            }
        }
    }
    if bases.len() > MAX_VTABLE_BASES {
        BTreeSet::new()
    } else {
        bases
    }
}

fn add_vtable_base(image: &Image, bases: &mut BTreeSet<u64>, address: u64) -> bool {
    let address = image.canonical_address(address);
    if is_read_only_data(image, address) {
        bases.insert(address);
        bases.len() <= MAX_VTABLE_BASES
    } else {
        true
    }
}

fn collect_typed_trait_vtables(
    image: &Image,
    dwarf: &crate::dwarf::DwarfInfo,
    aggregate_index: usize,
    object: u64,
    depth: usize,
    bases: &mut BTreeSet<u64>,
    visited: &mut BTreeSet<(usize, u64)>,
) {
    if depth > 8 || bases.len() > MAX_VTABLE_BASES || !visited.insert((aggregate_index, object)) {
        return;
    }
    if let Some(layout) = dwarf.trait_object_layout(aggregate_index) {
        if let Some(slot) = object.checked_add(layout.vtable_offset)
            && let Some(value) = image.read_uint(slot, pointer_size(image.arch))
        {
            add_vtable_base(image, bases, value);
        }
        return;
    }
    let Some(aggregate) = dwarf.aggregates.get(aggregate_index) else {
        return;
    };
    for member in &aggregate.members {
        let Some(member_address) = object.checked_add(member.offset) else {
            continue;
        };
        if let Some(child) = member.aggregate_index {
            collect_typed_trait_vtables(
                image,
                dwarf,
                child,
                member_address,
                depth + 1,
                bases,
                visited,
            );
        }
        if let Some(element) = member.element_aggregate_index
            && let Some(size) = dwarf
                .aggregates
                .get(element)
                .and_then(|aggregate| aggregate.byte_size)
        {
            for index in 0..member.array_count.unwrap_or(0).min(256) {
                let Some(object) = index
                    .checked_mul(size)
                    .and_then(|offset| member_address.checked_add(offset))
                else {
                    break;
                };
                collect_typed_trait_vtables(
                    image,
                    dwarf,
                    element,
                    object,
                    depth + 1,
                    bases,
                    visited,
                );
            }
        }
    }
}

fn vtable_slot_value(image: &Image, base: u64, slot: usize, pointer: usize) -> Option<u64> {
    let drop = image.read_uint(base, pointer)?;
    let _size = image.read_uint(base + pointer as u64, pointer)?;
    let align = image.read_uint(base + (pointer * 2) as u64, pointer)?;
    let drop_ok = drop == 0 || image.is_executable(image.canonical_address(drop));
    let align_ok = align != 0 && align.is_power_of_two() && align <= 4096;
    if !drop_ok || !align_ok {
        return None;
    }
    image.read_uint(base + slot as u64, pointer)
}

fn is_read_only_data(image: &Image, address: u64) -> bool {
    image.sections.iter().any(|section| {
        section.alloc
            && !section.executable
            && !section.writable
            && address >= section.address
            && address < section.address.saturating_add(section.size)
    })
}

/// Collects executable values stored to `[base + disp]` anywhere in the
/// decoded image.
///
/// This is deliberately a bounded, object-insensitive candidate search. The
/// caller must additionally restrict the result to plausible functions before
/// turning it into multi-target CFG edges.
#[must_use]
pub fn resolve_field_store_candidates(
    image: &Image,
    decoded_functions: &[&[DecodedInsn]],
    disp: i64,
) -> Vec<u64> {
    let mut candidates = BTreeSet::new();
    for decoded in decoded_functions {
        for (index, instruction) in decoded.iter().enumerate() {
            let Some(write) = instruction.memory_write else {
                continue;
            };
            if write.disp != disp {
                continue;
            }
            let value = match write.source {
                MemoryWriteSource::Register(source) => {
                    resolve_register(image, decoded, index, source, 0)
                }
                MemoryWriteSource::Immediate(value) => Some(value),
            };
            let Some(value) = value else {
                continue;
            };
            let canonical = image.canonical_address(value);
            if image.is_executable(canonical) {
                candidates.insert(canonical);
                if candidates.len() > MAX_FIELD_STORE_CANDIDATES {
                    return Vec::new();
                }
            }
        }
    }
    candidates.into_iter().collect()
}

/// Collects executable values stored to the stack slot `[base + disp]`.
///
/// A branchy assignment such as `fn = cond ? a : b` writes the same local
/// slot from different paths. The bounded search accepts only slots whose
/// every modeled store resolves to executable code.
#[must_use]
pub fn resolve_stack_slot_candidates(
    image: &Image,
    decoded: &[DecodedInsn],
    base: capstone::RegId,
    disp: i64,
) -> Option<Vec<u64>> {
    let mut values = BTreeSet::new();
    for (index, instruction) in decoded.iter().enumerate() {
        let Some(write) = instruction.memory_write else {
            continue;
        };
        if write.base != base || write.disp != disp {
            continue;
        }
        let value = match write.source {
            MemoryWriteSource::Register(source) => {
                resolve_register(image, decoded, index, source, 0)
            }
            MemoryWriteSource::Immediate(value) => Some(value),
        }?;
        let canonical = image.canonical_address(value);
        if !image.is_executable(canonical) {
            return None;
        }
        values.insert(canonical);
        if values.len() > MAX_FIELD_STORE_CANDIDATES {
            return None;
        }
    }
    (!values.is_empty()).then(|| values.into_iter().collect())
}

fn memory_pointer_value(image: &Image, address: u64) -> Option<u64> {
    if image.import_name_at(address).is_some() {
        Some(address)
    } else {
        image.read_uint(address, pointer_size(image.arch))
    }
}

/// Maximum number of entries scanned when a comparison guard is recovered.
pub const MAX_JUMP_TABLE_ENTRIES: usize = 4096;

/// Conservative scan limit when no comparison guard can be recovered.
const FALLBACK_JUMP_TABLE_ENTRIES: usize = 256;

/// Enumerates the targets of an indexed jump table.
///
/// Entry size follows the operand scale (4 or 8 bytes). Absolute pointers are
/// preferred; 4-byte relative table entries are also accepted. Scanning stops
/// at the first entry that does not resolve to executable code, at the section
/// boundary, at the recovered guard, or after [`MAX_JUMP_TABLE_ENTRIES`].
#[must_use]
pub fn resolve_jump_table(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<Vec<u64>> {
    let IndirectTarget::IndexedMemory {
        base,
        index,
        scale,
        disp,
    } = target
    else {
        return None;
    };
    if !matches!(scale, 4 | 8) {
        return None;
    }
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let table_base = if let Some(base) = base {
        resolve_register(image, decoded, before, base, 0)?.wrapping_add_signed(disp)
    } else {
        u64::try_from(disp).ok()?
    };
    let limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let targets = enumerate_jump_table(image, table_base, usize::from(scale), false, limit);
    (!targets.is_empty()).then_some(targets)
}

/// Resolves ARM `tbb`/`tbh` table branches.
#[must_use]
pub fn resolve_table_branch(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<Vec<u64>> {
    let IndirectTarget::TableBranch {
        base,
        index,
        halfword,
    } = target
    else {
        return None;
    };
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let table_base = if let Some(base) = base {
        resolve_register(image, decoded, before, base, 0)?
    } else {
        match image.arch {
            crate::loader::ArchKind::Thumb => site.checked_add(4)?,
            crate::loader::ArchKind::Arm => site.checked_add(8)?,
            _ => return None,
        }
    };
    let entry_size = if halfword { 2 } else { 1 };
    let limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let mut targets = Vec::new();
    for raw in read_table_entries(image, table_base, entry_size, limit) {
        let Some(offset) = raw.checked_mul(2) else {
            break;
        };
        let target = image.canonical_address(table_base.wrapping_add(offset));
        if !image.is_executable(target) {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    (!targets.is_empty()).then_some(targets)
}

/// Resolves an indexed table whose entries are absolute code pointers.
///
/// This covers `AArch64` `ldr xN, [table, xIndex, lsl #3]; br xN` and similar
/// fixed-width pointer tables.
#[must_use]
pub fn resolve_indexed_pointer_table(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    jump_register: capstone::RegId,
) -> Option<Vec<u64>> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let (load_index, effect) = latest_definition(decoded, before, jump_register)?;
    let ValueSource::IndexedLoad {
        base: table_register,
        index,
        scale,
        disp,
        ..
    } = effect.source
    else {
        return None;
    };
    let table_base =
        indexed_table_base(image, decoded, table_register, disp, load_index, load_index)?;
    indexed_pointer_table_targets(image, decoded, site, index, table_base, scale)
}

/// Resolves an indirect call that loads its target from an indexed table of
/// absolute function pointers.
///
/// Handles both `call [table + index*scale]` operands and a register loaded
/// from an indexed table immediately before the call. The table is bounded by
/// a recovered comparison when available and by the containing section.
#[must_use]
pub fn resolve_indexed_call_targets(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<Vec<u64>> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    match target {
        IndirectTarget::Register(register) => {
            let (load_index, effect) = latest_definition(decoded, before, register)?;
            let ValueSource::IndexedLoad {
                base,
                index,
                scale,
                disp,
                ..
            } = effect.source
            else {
                return None;
            };
            // A call or control transfer between the table load and the call
            // can replace the register or bypass the load on another path.
            if decoded[load_index.saturating_add(1)..before]
                .iter()
                .any(|instruction| {
                    instruction.is_call || instruction.is_jump || instruction.is_return
                })
            {
                return None;
            }
            let table_base =
                indexed_table_base(image, decoded, base, disp, load_index, load_index)?;
            indexed_pointer_table_targets(image, decoded, site, index, table_base, scale)
        }
        IndirectTarget::IndexedMemory {
            base,
            index,
            scale,
            disp,
        } => {
            let call_index = before.checked_sub(1)?;
            let table_base = indexed_table_base(image, decoded, base, disp, call_index, before)?;
            indexed_pointer_table_targets(image, decoded, site, index, table_base, scale)
        }
        IndirectTarget::Memory(_)
        | IndirectTarget::RegisterMemory { .. }
        | IndirectTarget::RegisterOffset { .. }
        | IndirectTarget::TableBranch { .. }
        | IndirectTarget::TableLoad { .. }
        | IndirectTarget::BranchTable { .. } => None,
    }
}

fn indexed_table_base(
    image: &Image,
    decoded: &[DecodedInsn],
    base: Option<capstone::RegId>,
    disp: i64,
    instruction_index: usize,
    resolve_before: usize,
) -> Option<u64> {
    let Some(base) = base else {
        return u64::try_from(disp).ok();
    };
    let base_value = if Some(base) == pc_register(image.arch) {
        pc_value(
            image.arch,
            decoded.get(instruction_index)?.address,
            decoded[instruction_index].size,
        )?
    } else {
        resolve_register(image, decoded, resolve_before, base, 0)?
    };
    Some(base_value.wrapping_add_signed(disp))
}

fn indexed_pointer_table_targets(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    index: capstone::RegId,
    table_base: u64,
    scale: u8,
) -> Option<Vec<u64>> {
    if !matches!(scale, 4 | 8) {
        return None;
    }
    let mut limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let object_size = image.data_symbols.get(&table_base).copied().or_else(|| {
        image.dwarf.as_ref().and_then(|dwarf| {
            dwarf
                .object_end_at(table_base)
                .map(|end| end.saturating_sub(table_base))
        })
    });
    if let Some(size) = object_size
        && let Ok(entry_size) = u64::try_from(usize::from(scale))
        && let Ok(symbol_entries) = usize::try_from(size / entry_size)
    {
        limit = limit.min(symbol_entries);
    }
    let mut targets = Vec::new();
    for raw in read_table_entries(image, table_base, usize::from(scale), limit) {
        let target = image.canonical_address(raw);
        if !image.is_executable(target) {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    (!targets.is_empty()).then_some(targets)
}

/// Resolves the common RISC-V switch sequences:
///
/// - absolute pointers:
///   `slli index, index, 2; ...; add index, index, table; lw target, 0(index); jr target`;
/// - table-relative offsets:
///   `...; add index, index, table; lw target, 0(index); add target, target, table; jr target`.
#[must_use]
pub fn resolve_riscv_jump_table(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    jump_register: capstone::RegId,
) -> Option<Vec<u64>> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let (definition_index, definition) = latest_definition(decoded, before, jump_register)?;
    if decoded[definition_index.saturating_add(1)..before]
        .iter()
        .any(|instruction| instruction.is_call || instruction.is_jump || instruction.is_return)
    {
        return None;
    }
    let (load_index, load_effect, relative_base) = match definition.source {
        ValueSource::LoadFromRegister { .. } => (definition_index, definition, None),
        ValueSource::AddRegister {
            base,
            addend,
            shift: 0,
        } => {
            let (loaded_register, base_register) =
                if is_load_definition(decoded, definition_index, base) {
                    (base, addend)
                } else if is_load_definition(decoded, definition_index, addend) {
                    (addend, base)
                } else {
                    return None;
                };
            let relative_base =
                resolve_register(image, decoded, definition_index, base_register, 0)?;
            let (load_index, load_effect) =
                latest_definition(decoded, definition_index, loaded_register)?;
            (load_index, load_effect, Some(relative_base))
        }
        _ => return None,
    };
    let ValueSource::LoadFromRegister {
        base: address_register,
        disp,
    } = load_effect.source
    else {
        return None;
    };
    let (add_index, add_effect) = latest_definition(decoded, load_index, address_register)?;
    let ValueSource::AddRegister {
        base,
        addend,
        shift: 0,
    } = add_effect.source
    else {
        return None;
    };
    let (index, scale, table_register) =
        if let Some((index, scale)) = shifted_index(decoded, add_index, base) {
            (index, scale, addend)
        } else if let Some((index, scale)) = shifted_index(decoded, add_index, addend) {
            (index, scale, base)
        } else {
            return None;
        };
    let table_base =
        resolve_register(image, decoded, add_index, table_register, 0)?.wrapping_add_signed(disp);
    let entry_size = 1usize.checked_shl(u32::from(scale))?;
    if !matches!(entry_size, 1 | 2 | 4 | 8) {
        return None;
    }
    let entry_width = u8::try_from(entry_size).ok()?;
    let limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let mut targets = Vec::new();
    for raw in read_table_entries(image, table_base, entry_size, limit) {
        let target = if let Some(base) = relative_base {
            let offset = sign_extend(raw, entry_width);
            image.canonical_address(base.wrapping_add_signed(offset))
        } else {
            image.canonical_address(raw)
        };
        if !image.is_executable(target) {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn is_load_definition(decoded: &[DecodedInsn], before: usize, register: capstone::RegId) -> bool {
    latest_definition(decoded, before, register)
        .is_some_and(|(_, effect)| matches!(effect.source, ValueSource::LoadFromRegister { .. }))
}

fn shifted_index(
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
) -> Option<(capstone::RegId, u8)> {
    let (_, effect) = latest_definition(decoded, before, register)?;
    let ValueSource::ShiftRegister { base, shift } = effect.source else {
        return None;
    };
    Some((base, shift))
}

/// Resolves ARM A32 `ldr pc, [table + index*4]` absolute-address tables.
#[must_use]
pub fn resolve_table_load(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<Vec<u64>> {
    let IndirectTarget::TableLoad { base, index, disp } = target else {
        return None;
    };
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let table_base = if let Some(base) = base {
        resolve_register(image, decoded, before, base, 0)?.wrapping_add_signed(disp)
    } else {
        match image.arch {
            crate::loader::ArchKind::Thumb => site.checked_add(4)?,
            crate::loader::ArchKind::Arm => site.checked_add(8)?,
            _ => return None,
        }
    };
    let limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let mut targets = Vec::new();
    for raw in read_table_entries(image, table_base, 4, limit) {
        let target = image.canonical_address(raw);
        if !image.is_executable(target) {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    (!targets.is_empty()).then_some(targets)
}

/// Resolves ARM A32 `add pc, base, index, lsl #2` branch tables.
#[must_use]
pub fn resolve_branch_table(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    target: IndirectTarget,
) -> Option<Vec<u64>> {
    let IndirectTarget::BranchTable { base, index } = target else {
        return None;
    };
    if image.arch != crate::loader::ArchKind::Arm {
        return None;
    }
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let table_base = if let Some(base) = base {
        resolve_register(image, decoded, before, base, 0)?
    } else {
        site.checked_add(8)?
    };
    let limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let table_end = image.allocation_end_for(table_base);
    let mut targets = Vec::new();
    for index in 0..limit.min(MAX_JUMP_TABLE_ENTRIES) {
        let Some(offset) = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(4))
        else {
            break;
        };
        let Some(address) = table_base.checked_add(offset) else {
            break;
        };
        if table_end.is_some_and(|end| address >= end) {
            break;
        }
        let Some(word) = image.read_uint(address, 4) else {
            break;
        };
        if word & 0x0e00_0000 != 0x0a00_0000 || !image.is_executable(address) {
            break;
        }
        targets.push(address);
    }
    (!targets.is_empty()).then_some(targets)
}

/// Resolves a switch table whose entry is added to a base address.
///
/// Supported patterns include PIE x86-64
/// `lea table; movslq [table+index*4]; add table; jmp` and `AArch64`
/// `adr base; adrp/add table; ldrb [table+index]; add base, base, entry, lsl #2; br`.
#[must_use]
pub fn resolve_offset_jump_table(
    image: &Image,
    decoded: &[DecodedInsn],
    site: u64,
    jump_register: capstone::RegId,
) -> Option<Vec<u64>> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let (add_index, add_effect) = latest_definition(decoded, before, jump_register)?;
    let ValueSource::AddRegister {
        base,
        addend,
        shift,
    } = add_effect.source
    else {
        return None;
    };
    let (load_effect, code_register) = if let Some((_, effect)) =
        latest_definition(decoded, add_index, addend)
        && matches!(effect.source, ValueSource::IndexedLoad { .. })
    {
        (effect, base)
    } else if let Some((_, effect)) = latest_definition(decoded, add_index, base)
        && matches!(effect.source, ValueSource::IndexedLoad { .. })
    {
        (effect, addend)
    } else {
        return None;
    };
    let ValueSource::IndexedLoad {
        base: table_register,
        index,
        scale,
        disp,
        signed,
    } = load_effect.source
    else {
        return None;
    };
    if !matches!(scale, 1 | 2 | 4 | 8) {
        return None;
    }
    let table_base = if let Some(table_register) = table_register {
        resolve_register(image, decoded, add_index, table_register, 0)?.wrapping_add_signed(disp)
    } else {
        u64::try_from(disp).ok()?
    };
    let code_base = resolve_register(image, decoded, add_index, code_register, 0)?;
    let limit = jump_table_bound(decoded, site, index).unwrap_or(FALLBACK_JUMP_TABLE_ENTRIES);
    let mut targets = Vec::new();
    for raw in read_table_entries(image, table_base, usize::from(scale), limit) {
        let value = if signed {
            sign_extend(raw, scale)
        } else {
            i64::from_ne_bytes(raw.to_ne_bytes())
        };
        let Some(offset) = value.checked_shl(u32::from(shift)) else {
            break;
        };
        let target = image.canonical_address(code_base.wrapping_add_signed(offset));
        if !image.is_executable(target) {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn read_table_entries(image: &Image, table_base: u64, entry_size: usize, limit: usize) -> Vec<u64> {
    let table_end = image.allocation_end_for(table_base);
    let mut entries = Vec::new();
    for index in 0..limit.min(MAX_JUMP_TABLE_ENTRIES) {
        let Some(offset) = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(u64::try_from(entry_size).ok()?))
        else {
            break;
        };
        let Some(address) = table_base.checked_add(offset) else {
            break;
        };
        if table_end.is_some_and(|end| address >= end) {
            break;
        }
        let Some(raw) = image.read_uint(address, entry_size) else {
            break;
        };
        entries.push(raw);
    }
    entries
}

fn sign_extend(raw: u64, size: u8) -> i64 {
    let bits = u32::from(size) * 8;
    let Some(shift) = 64u32.checked_sub(bits) else {
        return i64::from_ne_bytes(raw.to_ne_bytes());
    };
    let signed = raw << shift;
    i64::from_ne_bytes(signed.to_ne_bytes()) >> shift
}

fn enumerate_jump_table(
    image: &Image,
    table_base: u64,
    entry_size: usize,
    relative_only: bool,
    limit: usize,
) -> Vec<u64> {
    let table_end = image.allocation_end_for(table_base);
    let mut targets = Vec::new();
    for index in 0..limit.min(MAX_JUMP_TABLE_ENTRIES) {
        let Some(offset) = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(u64::try_from(entry_size).ok()?))
        else {
            break;
        };
        let Some(address) = table_base.checked_add(offset) else {
            break;
        };
        if table_end.is_some_and(|end| address >= end) {
            break;
        }
        let Some(raw) = image.read_uint(address, entry_size) else {
            break;
        };
        let absolute = image.canonical_address(raw);
        let relative = if entry_size == 4 {
            let value = i32::from_ne_bytes(u32::try_from(raw).unwrap_or_default().to_ne_bytes());
            table_base.wrapping_add_signed(i64::from(value))
        } else {
            table_base.wrapping_add_signed(i64::from_ne_bytes(raw.to_ne_bytes()))
        };
        let resolved = if !relative_only && image.is_executable(absolute) {
            Some(absolute)
        } else {
            image.is_executable(relative).then_some(relative)
        };
        let Some(resolved) = resolved else {
            break;
        };
        if !targets.contains(&resolved) {
            targets.push(resolved);
        }
    }
    targets
}

fn jump_table_bound(
    decoded: &[DecodedInsn],
    site: u64,
    register: capstone::RegId,
) -> Option<usize> {
    let before = decoded.partition_point(|instruction| instruction.address < site);
    let candidates = decoded[..before].iter().rev().take(32);
    let exact = candidates.clone().find_map(|instruction| {
        let (compared, value) = instruction.compare?;
        (compared == register).then(|| {
            usize::try_from(value)
                .ok()
                .map(|value| value.saturating_add(1))
        })?
    });
    if exact.is_some() {
        return exact;
    }
    if let Some(bound) = register_compare_bound(decoded, before, site, register)
        .or_else(|| riscv_jump_table_bound(decoded, before, site, register))
    {
        return Some(bound);
    }
    candidates.take(16).find_map(|instruction| {
        let (_, value) = instruction.compare?;
        usize::try_from(value)
            .ok()
            .map(|value| value.saturating_add(1))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnsignedRelation {
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

impl UnsignedRelation {
    /// Same comparison with the operands swapped.
    fn swap(self) -> Self {
        match self {
            Self::Less => Self::Greater,
            Self::LessEqual => Self::GreaterEqual,
            Self::Greater => Self::Less,
            Self::GreaterEqual => Self::LessEqual,
        }
    }

    /// Negated comparison, used when the table is on the fallthrough edge.
    fn negate(self) -> Self {
        match self {
            Self::Less => Self::GreaterEqual,
            Self::LessEqual => Self::Greater,
            Self::Greater => Self::LessEqual,
            Self::GreaterEqual => Self::Less,
        }
    }
}

/// Parses an unsigned conditional-branch mnemonic (ARM/AArch64 `bhi`/`b.hi`,
/// x86 `ja`, RISC-V `bltu` and aliases).
fn unsigned_relation(mnemonic: &str) -> Option<UnsignedRelation> {
    let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
    let mnemonic = mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
        .unwrap_or(mnemonic);
    match mnemonic {
        "blo" | "b.lo" | "bcc" | "b.cc" | "blt" | "b.lt" | "jb" | "jc" | "jnae" | "jl" | "jnge"
        | "bltu" => Some(UnsignedRelation::Less),
        "bls" | "b.ls" | "ble" | "b.le" | "jbe" | "jna" | "jle" | "jng" | "bleu" => {
            Some(UnsignedRelation::LessEqual)
        }
        "bhi" | "b.hi" | "bgt" | "b.gt" | "ja" | "jnbe" | "jg" | "jnle" | "bgtu" => {
            Some(UnsignedRelation::Greater)
        }
        "bhs" | "b.hs" | "bcs" | "b.cs" | "bge" | "b.ge" | "jae" | "jnb" | "jnc" | "jge"
        | "jnl" | "bgeu" => Some(UnsignedRelation::GreaterEqual),
        _ => None,
    }
}

/// Converts an index-vs-bound relation into a table entry count.
///
/// `branch_to_table` distinguishes the usual `cmp index, bound; bhi default`
/// form from the inverted `bgeu bound, index, table` form used when the
/// default block is out of conditional-branch range.
fn guarded_table_entries(
    index_relation: UnsignedRelation,
    branch_to_table: bool,
    bound: u64,
) -> Option<usize> {
    let table_relation = if branch_to_table {
        index_relation
    } else {
        index_relation.negate()
    };
    let entries = match table_relation {
        UnsignedRelation::LessEqual => bound.checked_add(1)?,
        UnsignedRelation::Less => bound,
        UnsignedRelation::Greater | UnsignedRelation::GreaterEqual => return None,
    };
    usize::try_from(entries)
        .ok()
        .map(|entries| entries.min(MAX_JUMP_TABLE_ENTRIES))
}

/// Recovers a bound when the comparison threshold was materialized in a
/// register, as in Thumb `movw r3, #299; cmp r0, r3; bhi default`.
fn register_compare_bound(
    decoded: &[DecodedInsn],
    before: usize,
    site: u64,
    register: capstone::RegId,
) -> Option<usize> {
    let start = before.saturating_sub(32);
    for index in (start..before).rev() {
        let instruction = &decoded[index];
        let Some((lhs, rhs)) = instruction.compare_registers else {
            continue;
        };
        let lhs_is_index = lhs == register;
        let bound_register = if lhs_is_index {
            rhs
        } else if rhs == register {
            lhs
        } else {
            continue;
        };
        let Some(guard) = decoded.get(index + 1) else {
            continue;
        };
        if !guard.is_jump || !guard.is_conditional {
            continue;
        }
        let Some(relation) = unsigned_relation(&guard.mnemonic) else {
            continue;
        };
        let Some(bound) = immediate_definition(decoded, index, bound_register) else {
            continue;
        };
        let branch_to_table = guard
            .direct_target
            .is_some_and(|target| target > instruction.address && target < site);
        let index_relation = if lhs_is_index {
            relation
        } else {
            relation.swap()
        };
        if let Some(entries) = guarded_table_entries(index_relation, branch_to_table, bound) {
            return Some(entries);
        }
    }
    None
}

/// Recovers the table bound from the RISC-V register guard emitted before a
/// switch, for example `li t0, 15; bltu t0, index, default` or the inverted
/// `li t0, 299; bgeu t0, index, table`.
fn riscv_jump_table_bound(
    decoded: &[DecodedInsn],
    before: usize,
    site: u64,
    register: capstone::RegId,
) -> Option<usize> {
    let start = before.saturating_sub(32);
    for index in (start..before).rev() {
        let instruction = &decoded[index];
        let Some((lhs, rhs)) = instruction.branch_registers else {
            continue;
        };
        let lhs_is_index = lhs == register;
        let bound_register = if lhs_is_index {
            rhs
        } else if rhs == register {
            lhs
        } else {
            continue;
        };
        let Some(relation) = unsigned_relation(&instruction.mnemonic) else {
            continue;
        };
        let Some(bound) = immediate_definition(decoded, index, bound_register) else {
            continue;
        };
        let branch_to_table = instruction
            .direct_target
            .is_some_and(|target| target > instruction.address && target < site);
        let index_relation = if lhs_is_index {
            relation
        } else {
            relation.swap()
        };
        if let Some(entries) = guarded_table_entries(index_relation, branch_to_table, bound) {
            return Some(entries);
        }
    }
    None
}

fn immediate_definition(
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
) -> Option<u64> {
    let (_, effect) = latest_definition(decoded, before, register)?;
    match effect.source {
        ValueSource::Immediate(value) => Some(value),
        _ => None,
    }
}

fn latest_definition(
    decoded: &[DecodedInsn],
    before: usize,
    register: capstone::RegId,
) -> Option<(usize, crate::arch::ValueEffect)> {
    (0..before).rev().find_map(|index| {
        let effect = decoded[index].value?;
        (effect.dest == register).then_some((index, effect))
    })
}

fn memory_slot_source(
    decoded: &[DecodedInsn],
    before: usize,
    base: capstone::RegId,
    disp: i64,
) -> Option<(usize, MemoryWriteSource)> {
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
        IndirectTarget::Memory(_)
        | IndirectTarget::IndexedMemory { .. }
        | IndirectTarget::TableBranch { .. }
        | IndirectTarget::TableLoad { .. }
        | IndirectTarget::BranchTable { .. } => None,
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
                    let MemoryWriteSource::Register(source) = source else {
                        return None;
                    };
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
            | ValueSource::OrImmediate { .. }
            | ValueSource::AddRegister { .. }
            | ValueSource::IndexedLoad { .. }
            | ValueSource::ShiftRegister { .. }
            | ValueSource::Select { .. } => return None,
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
                let MemoryWriteSource::Register(source) = source else {
                    return None;
                };
                register = source;
                before = store_index;
            }
            ValueSource::Immediate(_)
            | ValueSource::Address(_)
            | ValueSource::LoadAddress(_)
            | ValueSource::AddImmediate { .. }
            | ValueSource::OrImmediate { .. }
            | ValueSource::AddRegister { .. }
            | ValueSource::IndexedLoad { .. }
            | ValueSource::ShiftRegister { .. }
            | ValueSource::Select { .. } => return None,
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
        indirect_field_load, jump_table_bound, read_table_entries, resolve_argument_pointer,
        resolve_field_store_candidates, resolve_indirect_target, resolve_indirect_target_value,
        resolve_vtable_slot_candidates, resolve_vtable_slot_values,
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
            imported_slots: std::collections::BTreeMap::default(),
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
            data_symbols: std::collections::BTreeMap::default(),
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
    fn models_thumb_register_field_load() {
        // ldr r1, [r0, #12]; blx r1
        let text = [0xc1, 0x68, 0x88, 0x47];
        let engine = Decoder::new(ArchKind::Thumb).unwrap();
        let load = engine.decode_one(&text[..2], 0x1000).unwrap().expect("ldr");
        let call = engine.decode_one(&text[2..], 0x1002).unwrap().expect("blx");
        let target = call.indirect.expect("register target");
        assert_eq!(indirect_field_load(&[load, call], 0x1002, target), Some(12));
    }

    #[test]
    fn distinguishes_null_indirect_target_value() {
        // mov rax, 0; call rax
        let code = vec![0x48, 0xc7, 0xc0, 0, 0, 0, 0, 0xff, 0xd0];
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let mov = engine.decode_one(&code[..7], 0x1000).unwrap().expect("mov");
        let call = engine
            .decode_one(&code[7..], 0x1007)
            .unwrap()
            .expect("call");
        let target = call.indirect.expect("register target");
        assert_eq!(
            resolve_indirect_target_value(
                &image(ArchKind::X86_64, 0x1000, code),
                &[mov, call],
                0x1007,
                target
            ),
            Some(0)
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
            imported_slots: std::collections::BTreeMap::default(),
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
            data_symbols: std::collections::BTreeMap::default(),
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
    fn recovers_riscv_register_guard_bound() {
        let engine = Decoder::new(ArchKind::Riscv64).unwrap();
        // c.li a1, 15; bltu a1, a0, default
        let li = engine
            .decode_one(&[0xbd, 0x45], 0x0040_011e)
            .unwrap()
            .expect("c.li");
        let branch = engine
            .decode_one(&[0x63, 0xe8, 0xa5, 0x0a], 0x0040_0120)
            .unwrap()
            .expect("bltu");
        let (_, index) = branch.branch_registers.expect("two register operands");
        assert_eq!(
            jump_table_bound(&[li, branch], 0x0040_0124, index),
            Some(16)
        );
    }

    #[test]
    fn recovers_inverted_riscv_register_guard_bound() {
        let engine = Decoder::new(ArchKind::Riscv64).unwrap();
        // c.li a1, 15; bgeu a1, a0, table
        let li = engine
            .decode_one(&[0xbd, 0x45], 0x0040_011e)
            .unwrap()
            .expect("c.li");
        let branch = engine
            .decode_one(&[0x63, 0xf8, 0xa5, 0x0a], 0x0040_0120)
            .unwrap()
            .expect("bgeu");
        let (_, index) = branch.branch_registers.expect("two register operands");
        // The branch target (0x4001d0) lies before this dispatch site, so the
        // table is reached on the taken edge.
        assert_eq!(
            jump_table_bound(&[li, branch], 0x0040_0200, index),
            Some(16)
        );
    }

    #[test]
    fn jump_table_scan_stops_at_section_end() {
        let mut image = image(ArchKind::X86_64, 0x1000, Vec::new());
        image.sections = vec![
            Section {
                name: ".rodata".to_owned(),
                address: 0x2000,
                size: 8,
                data: vec![1, 0, 0, 0, 2, 0, 0, 0],
                executable: false,
                writable: false,
                alloc: true,
            },
            Section {
                name: ".data".to_owned(),
                address: 0x2008,
                size: 8,
                data: vec![3, 0, 0, 0, 4, 0, 0, 0],
                executable: false,
                writable: true,
                alloc: true,
            },
        ];
        assert_eq!(read_table_entries(&image, 0x2000, 4, 100), vec![1, 2]);
    }

    #[test]
    fn resolves_import_slot_loaded_into_a_register() {
        // mov rbp, [rip + 0xff9] -> 0x2000; call rbp
        let text = vec![0x48, 0x8b, 0x2d, 0xf9, 0x0f, 0x00, 0x00, 0xff, 0xd5];
        let mut imported_slots = std::collections::BTreeMap::new();
        imported_slots.insert(0x2000, "malloc".to_owned());
        let image = Image {
            path: "import-register.elf".into(),
            arch: ArchKind::X86_64,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Dyn,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
            imported_slots,
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".text".to_owned(),
                    address: 0x1000,
                    size: 9,
                    data: text,
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".got".to_owned(),
                    address: 0x2000,
                    size: 8,
                    data: vec![0; 8],
                    executable: false,
                    writable: true,
                    alloc: true,
                },
            ],
            symbols: Vec::new(),
            has_symbols: false,
            has_debug_info: false,
            has_relocations: true,
            arm_cpu: None,
            vector_table: Vec::new(),
            dwarf: None,
            dwarf_error: None,
            data_symbols: std::collections::BTreeMap::default(),
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
        let target = call.indirect.expect("register target");
        assert_eq!(
            resolve_indirect_target(&image, &[load, call], 0x1007, target),
            Some(0x2000)
        );
    }

    #[test]
    fn resolves_import_slot_loaded_through_a_got_pointer() {
        // lea rax, [rip + 0xff9] -> 0x2000; mov rbp, [rax]; call rbp
        let text = vec![
            0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x48, 0x8b, 0x28, 0xff, 0xd5,
        ];
        let mut imported_slots = std::collections::BTreeMap::new();
        imported_slots.insert(0x2000, "free".to_owned());
        let image = Image {
            path: "import-got-pointer.elf".into(),
            arch: ArchKind::X86_64,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Dyn,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
            imported_slots,
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".text".to_owned(),
                    address: 0x1000,
                    size: 12,
                    data: text,
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".got".to_owned(),
                    address: 0x2000,
                    size: 8,
                    data: vec![0; 8],
                    executable: false,
                    writable: true,
                    alloc: true,
                },
            ],
            symbols: Vec::new(),
            has_symbols: false,
            has_debug_info: false,
            has_relocations: true,
            arm_cpu: None,
            vector_table: Vec::new(),
            dwarf: None,
            dwarf_error: None,
            data_symbols: std::collections::BTreeMap::default(),
        };
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let lea = engine
            .decode_one(&image.sections[0].data[..7], 0x1000)
            .unwrap()
            .expect("lea");
        let load = engine
            .decode_one(&image.sections[0].data[7..10], 0x1007)
            .unwrap()
            .expect("mov");
        let call = engine
            .decode_one(&image.sections[0].data[10..], 0x100a)
            .unwrap()
            .expect("call");
        let target = call.indirect.expect("register target");
        assert_eq!(
            resolve_indirect_target(&image, &[lea, load, call], 0x100a, target),
            Some(0x2000)
        );
    }

    #[test]
    fn recovers_field_offset_from_register_load() {
        // mov rbp, [rdi + 0x0c]; call rbp
        let text = [0x48, 0x8b, 0x6f, 0x0c, 0xff, 0xd5];
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let load = engine
            .decode_one(&text[..4], 0x1000)
            .unwrap()
            .expect("load");
        let call = engine
            .decode_one(&text[4..], 0x1004)
            .unwrap()
            .expect("call");
        let target = call.indirect.expect("register target");
        assert_eq!(indirect_field_load(&[load, call], 0x1004, target), Some(12));
    }

    #[test]
    fn collects_executable_values_stored_to_a_field_offset() {
        // mov eax, 0x1000; mov [rbx + 0x0c], rax;
        // mov eax, 0x1010; mov [rbx + 0x0c], rax
        let text = [
            0xb8, 0x00, 0x10, 0x00, 0x00, 0x48, 0x89, 0x43, 0x0c, 0xb8, 0x10, 0x10, 0x00, 0x00,
            0x48, 0x89, 0x43, 0x0c,
        ];
        let image = image(ArchKind::X86_64, 0x1000, text.to_vec());
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let decode = |range: std::ops::Range<usize>, address: u64| {
            engine
                .decode_one(&text[range], address)
                .unwrap()
                .expect("instruction")
        };
        let decoded = vec![
            decode(0..5, 0x1000),
            decode(5..9, 0x1005),
            decode(9..14, 0x1009),
            decode(14..18, 0x100e),
        ];
        assert_eq!(
            resolve_field_store_candidates(&image, &[&decoded], 12),
            vec![0x1000, 0x1010]
        );
    }

    #[test]
    fn collects_trait_object_vtable_slot_candidates() {
        let mut code = Vec::new();
        for value in [0x2000u64, 0x2100, 0x2200] {
            code.extend_from_slice(&[0x48, 0xb8]);
            code.extend_from_slice(&value.to_le_bytes());
        }
        code.push(0xc3);
        let engine = Decoder::new(ArchKind::X86_64).unwrap();
        let mut decoded = Vec::new();
        let mut offset = 0usize;
        while offset < code.len() {
            let instruction = engine
                .decode_one(&code[offset..], 0x1000 + offset as u64)
                .unwrap()
                .expect("x86 instruction");
            offset += usize::from(instruction.size);
            decoded.push(instruction);
        }
        let mut rodata = vec![0u8; 0x300];
        rodata[16..24].copy_from_slice(&1u64.to_le_bytes());
        rodata[24..32].copy_from_slice(&0x1010u64.to_le_bytes());
        rodata[0x100 + 16..0x100 + 24].copy_from_slice(&1u64.to_le_bytes());
        rodata[0x100 + 24..0x100 + 32].copy_from_slice(&0x1020u64.to_le_bytes());
        // Invalid shape: alignment is not a power of two.
        rodata[0x200 + 8..0x200 + 16].copy_from_slice(&0u64.to_le_bytes());
        rodata[0x200 + 16..0x200 + 24].copy_from_slice(&3u64.to_le_bytes());
        rodata[0x200 + 24..0x200 + 32].copy_from_slice(&0x1010u64.to_le_bytes());
        let image = Image {
            path: "vtables.elf".into(),
            arch: ArchKind::X86_64,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
            imported_slots: std::collections::BTreeMap::default(),
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".text".to_owned(),
                    address: 0x1000,
                    size: 0x200,
                    data: vec![0; 0x200],
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".rodata".to_owned(),
                    address: 0x2000,
                    size: rodata.len() as u64,
                    data: rodata,
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
            data_symbols: std::collections::BTreeMap::default(),
        };
        assert_eq!(
            resolve_vtable_slot_candidates(&image, &[&decoded], 24),
            vec![0x1010, 0x1020]
        );
        assert_eq!(
            resolve_vtable_slot_candidates(&image, &[&decoded], 16),
            Vec::<u64>::new()
        );
        assert_eq!(resolve_vtable_slot_values(&image, &[&decoded], 0), vec![0]);
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
            imported_slots: std::collections::BTreeMap::default(),
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
            data_symbols: std::collections::BTreeMap::default(),
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
