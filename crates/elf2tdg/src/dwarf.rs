//! DWARF extraction for inlined call-site recovery.
//!
//! Symbols describe direct calls. Debug information additionally describes
//! calls that were inlined, including the inlined function's linkage name and
//! concrete address ranges. M2 uses those records to recover spawn/join/scope
//! sites that would otherwise disappear at higher optimization levels.
//!
//! This module deliberately avoids a general DWARF database. It extracts
//! subprograms and inlined subroutines with names and address ranges, plus a
//! bounded type/variable view: aggregate members, pointer/subroutine/array
//! facts, global addresses and frame-relative locals used by points-to.

use std::collections::{BTreeMap, BTreeSet};

use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, constants};
use object::{Object, ObjectSection};

use crate::loader::ByteOrder;

const MAX_INLINED_CALLS: usize = 200_000;
const MAX_DWARF_FUNCTIONS: usize = 200_000;
const MAX_SOURCE_RANGES: usize = 500_000;
const MAX_DWARF_TYPES: usize = 200_000;
const MAX_DWARF_AGGREGATES: usize = 100_000;
const MAX_DWARF_MEMBERS: usize = 1_000_000;
const MAX_DWARF_VARIABLES: usize = 500_000;
const MAX_DWARF_VTABLES: usize = 100_000;
const MAX_TYPE_DEPTH: usize = 16;

type DwarfReader<'a> = EndianSlice<'a, RunTimeEndian>;
type DwarfUnit<'a> = gimli::Unit<DwarfReader<'a>>;
type DwarfEntry<'a> = gimli::DebuggingInformationEntry<DwarfReader<'a>>;

/// Extracted DWARF information.
#[derive(Debug, Clone, Default)]
pub struct DwarfInfo {
    /// Concrete subprograms.
    pub functions: Vec<DwarfFunction>,
    /// Inlined subroutine instances and their concrete address ranges, sorted
    /// by `low_pc`.
    pub inlined_calls: Vec<DwarfInlinedCall>,
    /// Source-line ranges from the line-number programs.
    pub sources: Vec<DwarfSourceRange>,
    /// Variables and formal parameters with a recoverable location.
    pub variables: Vec<DwarfVariable>,
    /// Structure, class and union layouts.
    pub aggregates: Vec<DwarfAggregate>,
    /// Aggregate layouts that represent a Rust trait-object fat pointer.
    pub trait_object_layouts: Vec<DwarfTraitObjectLayout>,
    /// Rust vtable objects described by global variables.
    pub vtables: Vec<DwarfVtable>,
    /// Extraction stopped at a safety limit.
    pub truncated: bool,
    /// Prefix maximum of `high_pc`, parallel to `inlined_calls`.
    inline_max_high: Vec<u64>,
    /// Number of global (address-located) variables at the start of
    /// `variables`; the remainder are frame-relative locals.
    global_variables_end: usize,
    /// First member typed as a function pointer for each field offset.
    function_pointer_fields: BTreeMap<u64, (usize, usize)>,
    /// Total aggregate members retained.
    member_count: usize,
}

impl DwarfInfo {
    /// Returns the source location covering `address`, if the line program
    /// described it.
    #[must_use]
    pub fn source_at(&self, address: u64) -> Option<&DwarfSourceRange> {
        let index = self
            .sources
            .partition_point(|source| source.low_pc <= address)
            .checked_sub(1)?;
        let source = &self.sources[index];
        (address < source.high_pc).then_some(source)
    }

    /// Returns every inlined subroutine whose concrete range contains
    /// `address`, outermost first.
    ///
    /// This is the address-level counterpart of `addr2line`'s inline frames:
    /// nested calls such as `main -> spawn -> Builder::spawn` produce one
    /// entry per inline DIE layer. Empty when the image has no debug info or
    /// the address is not inside an inline range.
    #[must_use]
    pub fn inline_frames_at(&self, address: u64) -> Vec<&DwarfInlinedCall> {
        let mut index = self
            .inlined_calls
            .partition_point(|call| call.low_pc <= address);
        let mut frames = Vec::new();
        while index > 0 {
            index -= 1;
            // Prefix maxima let us stop as soon as no earlier interval can
            // reach the query address.
            if self
                .inline_max_high
                .get(index)
                .is_none_or(|high| *high <= address)
            {
                break;
            }
            let call = &self.inlined_calls[index];
            if address < call.high_pc {
                frames.push(call);
            }
        }
        frames.sort_by_key(|call| (call.depth, call.low_pc, call.high_pc));
        frames
    }

    /// Returns every inlined subroutine range that overlaps `[low, high)`.
    ///
    /// Ranges are ordered by start address, then depth. Used by CFG export to
    /// attach a compact, unique inline list to each function instead of
    /// repeating the same frame on every instruction.
    #[must_use]
    pub fn inline_frames_in(&self, low: u64, high: u64) -> Vec<&DwarfInlinedCall> {
        if high <= low {
            return Vec::new();
        }
        let mut index = self
            .inlined_calls
            .partition_point(|call| call.low_pc < high);
        let mut frames = Vec::new();
        while index > 0 {
            index -= 1;
            if self
                .inline_max_high
                .get(index)
                .is_none_or(|max_high| *max_high <= low)
            {
                break;
            }
            let call = &self.inlined_calls[index];
            if call.high_pc > low && call.low_pc < high {
                frames.push(call);
            }
        }
        frames.sort_by_key(|call| (call.low_pc, call.depth, call.high_pc));
        frames
    }

    /// Returns the global/static variable whose address is exactly `address`.
    #[must_use]
    pub fn variable_at(&self, address: u64) -> Option<&DwarfVariable> {
        let globals = &self.variables[..self.global_variables_end];
        let index = globals
            .binary_search_by_key(&address, |variable| variable.address.unwrap_or(0))
            .ok()?;
        globals.get(index)
    }

    /// Returns the end address of the global/static object containing
    /// `address`, when DWARF describes a sized variable there.
    #[must_use]
    pub fn object_end_at(&self, address: u64) -> Option<u64> {
        let globals = &self.variables[..self.global_variables_end];
        let mut index =
            globals.partition_point(|variable| variable.address.unwrap_or(0) <= address);
        while index > 0 {
            index -= 1;
            let variable = &globals[index];
            let Some(start) = variable.address else {
                continue;
            };
            if start > address {
                continue;
            }
            let Some(size) = variable.byte_size else {
                if Some(start) != globals.get(index.wrapping_sub(1)).and_then(|v| v.address) {
                    break;
                }
                continue;
            };
            let Some(end) = start.checked_add(size) else {
                break;
            };
            if address < end {
                return Some(end);
            }
            if index == 0 || globals[index - 1].address != Some(start) {
                break;
            }
        }
        None
    }

    /// Returns a member at `offset` whose type is a function pointer.
    #[must_use]
    pub fn function_pointer_field_at(&self, offset: u64) -> Option<&DwarfMember> {
        let (aggregate, member) = *self.function_pointer_fields.get(&offset)?;
        self.aggregates.get(aggregate)?.members.get(member)
    }

    /// Returns the trait-object fat-pointer layout for `aggregate_index`.
    #[must_use]
    pub fn trait_object_layout(&self, aggregate_index: usize) -> Option<&DwarfTraitObjectLayout> {
        self.trait_object_layouts
            .binary_search_by_key(&aggregate_index, |layout| layout.aggregate_index)
            .ok()
            .and_then(|index| self.trait_object_layouts.get(index))
    }

    /// Returns the DWARF vtable starting at `address`.
    #[must_use]
    pub fn vtable_at(&self, address: u64) -> Option<&DwarfVtable> {
        let index = self
            .vtables
            .binary_search_by_key(&address, |vtable| vtable.address)
            .ok()?;
        self.vtables.get(index)
    }

    /// Returns a non-header vtable entry at `offset`.
    #[must_use]
    pub fn vtable_method_at(&self, offset: u64) -> Option<&DwarfVtableEntry> {
        self.vtables
            .iter()
            .flat_map(|vtable| vtable.entries.iter())
            .find(|entry| entry.offset == offset && !entry.header)
    }

    /// Returns the frame-relative variable at `frame_offset` in the function
    /// starting at `function_low`.
    #[must_use]
    pub fn local_variable_at(
        &self,
        function_low: u64,
        frame_offset: i64,
    ) -> Option<&DwarfVariable> {
        self.variables[self.global_variables_end..]
            .iter()
            .find(|variable| {
                variable.function_low == Some(function_low)
                    && variable.frame_offset == Some(frame_offset)
            })
    }

    fn build_type_indexes(&mut self) {
        self.variables.sort_by_key(|variable| {
            (
                variable.address.is_none(),
                variable.address.unwrap_or(0),
                variable.function_low.unwrap_or(0),
                variable.frame_offset.unwrap_or(i64::MAX),
                variable.call_frame_offset.unwrap_or(i64::MAX),
            )
        });
        self.global_variables_end = self
            .variables
            .partition_point(|variable| variable.address.is_some());
        self.function_pointer_fields.clear();
        self.trait_object_layouts.clear();
        self.vtables.clear();
        let mut seen_vtables = BTreeSet::new();
        for (aggregate_index, aggregate) in self.aggregates.iter().enumerate() {
            for (member_index, member) in aggregate.members.iter().enumerate() {
                if member.function_pointer {
                    self.function_pointer_fields
                        .entry(member.offset)
                        .or_insert((aggregate_index, member_index));
                }
            }
            if let Some(name) = aggregate.name.as_deref()
                && name.contains("dyn ")
                && let Some(vtable) = aggregate
                    .members
                    .iter()
                    .find(|member| member.name.as_deref() == Some("vtable"))
            {
                let data = aggregate
                    .members
                    .iter()
                    .find(|member| matches!(member.name.as_deref(), Some("pointer" | "data")));
                self.trait_object_layouts.push(DwarfTraitObjectLayout {
                    name: Some(name.to_owned()),
                    aggregate_index,
                    byte_size: aggregate.byte_size,
                    data_offset: data.map_or(0, |member| member.offset),
                    vtable_offset: vtable.offset,
                    data_type_name: data.and_then(|member| member.type_name.clone()),
                    vtable_type_name: vtable.type_name.clone(),
                });
            }
        }
        self.trait_object_layouts
            .sort_by_key(|layout| layout.aggregate_index);
        for variable in &self.variables[..self.global_variables_end] {
            let Some(address) = variable.address else {
                continue;
            };
            let Some(aggregate) = variable
                .aggregate_index
                .and_then(|index| self.aggregates.get(index))
            else {
                continue;
            };
            if !is_vtable_aggregate(aggregate) || !seen_vtables.insert(address) {
                continue;
            }
            if self.vtables.len() >= MAX_DWARF_VTABLES {
                self.truncated = true;
                break;
            }
            self.vtables.push(DwarfVtable {
                address,
                name: variable.name.clone(),
                type_name: variable.type_name.clone(),
                byte_size: variable.byte_size,
                entries: aggregate
                    .members
                    .iter()
                    .map(|member| DwarfVtableEntry {
                        name: member.name.clone(),
                        offset: member.offset,
                        type_name: member.type_name.clone(),
                        header: member.name.as_deref().is_some_and(is_vtable_header_name),
                    })
                    .collect(),
            });
        }
        self.vtables.sort_by_key(|vtable| vtable.address);
    }

    fn build_inline_index(&mut self) {
        self.inlined_calls
            .sort_by_key(|call| (call.low_pc, call.high_pc));
        self.inline_max_high.clear();
        self.inline_max_high.reserve(self.inlined_calls.len());
        let mut max_high = 0;
        for call in &self.inlined_calls {
            max_high = max_high.max(call.high_pc);
            self.inline_max_high.push(max_high);
        }
    }
}

/// A source-line range from a DWARF line program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfSourceRange {
    /// Start address of the range.
    pub low_pc: u64,
    /// Exclusive end address.
    pub high_pc: u64,
    /// Source file path.
    pub file: String,
    /// One-based line number.
    pub line: u32,
    /// One-based column number.
    pub column: Option<u32>,
}

/// A DWARF subprogram.
#[derive(Debug, Clone, Default)]
pub struct DwarfFunction {
    /// `DW_AT_name`.
    pub name: Option<String>,
    /// `DW_AT_linkage_name` (or the GNU equivalent).
    pub linkage_name: Option<String>,
    /// Concrete address ranges.
    pub ranges: Vec<(u64, u64)>,
}

impl DwarfFunction {
    /// Returns the lowest concrete address range, which is the function entry
    /// range for split or cold/hot DWARF layouts.
    #[must_use]
    pub fn primary_range(&self) -> Option<(u64, u64)> {
        self.ranges.iter().copied().min_by_key(|(low, _)| *low)
    }

    /// Returns a demangled display name, preferring the linkage name.
    #[must_use]
    pub fn display_name(&self) -> Option<String> {
        display_name(&NameInfo {
            name: self.name.clone(),
            linkage_name: self.linkage_name.clone(),
        })
    }
}

/// An inlined subroutine instance.
#[derive(Debug, Clone, Default)]
pub struct DwarfInlinedCall {
    /// `DW_AT_name` from the concrete or abstract DIE.
    pub name: Option<String>,
    /// `DW_AT_linkage_name` from the concrete or abstract DIE.
    pub linkage_name: Option<String>,
    /// Demangled display name, preferring `linkage_name`.
    pub display_name: Option<String>,
    /// `DW_AT_call_file` resolved through the unit line table.
    pub call_file: Option<String>,
    /// `DW_AT_call_line`.
    pub call_line: Option<u32>,
    /// `DW_AT_call_column`.
    pub call_column: Option<u32>,
    /// Start of the concrete inline range.
    pub low_pc: u64,
    /// End of the concrete inline range.
    pub high_pc: u64,
    /// DIE depth, used to prefer the outermost runtime API among nested
    /// inlinings.
    pub depth: u32,
}

/// A variable or formal parameter with a recoverable location.
#[derive(Debug, Clone, Default)]
pub struct DwarfVariable {
    /// `DW_AT_name`.
    pub name: Option<String>,
    /// Resolved type name, when the type chain provides one.
    pub type_name: Option<String>,
    /// Static/global storage address.
    pub address: Option<u64>,
    /// `DW_AT_frame_base`-relative offset for a local or parameter.
    pub frame_offset: Option<i64>,
    /// CFA-relative offset for a local or parameter.
    pub call_frame_offset: Option<i64>,
    /// Start of the containing subprogram for frame-relative variables.
    pub function_low: Option<u64>,
    /// Size of the variable's type in bytes.
    pub byte_size: Option<u64>,
    /// The variable's type is a function pointer.
    pub function_pointer: bool,
    /// The variable's type is an array of function pointers.
    pub function_pointer_array: bool,
    /// Element count for an array-typed variable.
    pub array_count: Option<u64>,
    /// Aggregate type index for an inline aggregate variable.
    pub aggregate_index: Option<usize>,
    /// Aggregate type index for the pointee of a pointer variable.
    pub pointee_aggregate_index: Option<usize>,
    /// Aggregate element type index for an array variable.
    pub element_aggregate_index: Option<usize>,
    /// The variable is a formal parameter rather than a local.
    pub is_parameter: bool,
}

/// A structure, class or union layout.
#[derive(Debug, Clone, Default)]
pub struct DwarfAggregate {
    /// `DW_AT_name`.
    pub name: Option<String>,
    /// Type size in bytes.
    pub byte_size: Option<u64>,
    /// Data members in DWARF order.
    pub members: Vec<DwarfMember>,
}

/// One aggregate data member.
#[derive(Debug, Clone, Default)]
pub struct DwarfMember {
    /// `DW_AT_name`.
    pub name: Option<String>,
    /// Resolved type name, when available.
    pub type_name: Option<String>,
    /// Byte offset from the aggregate start.
    pub offset: u64,
    /// Size of the member type in bytes.
    pub byte_size: Option<u64>,
    /// The member's type is a function pointer.
    pub function_pointer: bool,
    /// The member's type is an array of function pointers.
    pub function_pointer_array: bool,
    /// Aggregate type index when the member itself is an aggregate.
    pub aggregate_index: Option<usize>,
    /// Aggregate element type index when the member is an array.
    pub element_aggregate_index: Option<usize>,
    /// Array element count when the member is an array.
    pub array_count: Option<u64>,
}

/// A Rust trait-object fat-pointer layout recovered from DWARF.
#[derive(Debug, Clone, Default)]
pub struct DwarfTraitObjectLayout {
    /// Type name, for example `&dyn Trait` or `Box<dyn Trait>`.
    pub name: Option<String>,
    /// Aggregate type index.
    pub aggregate_index: usize,
    /// Size of one fat pointer.
    pub byte_size: Option<u64>,
    /// Offset of the data pointer.
    pub data_offset: u64,
    /// Offset of the vtable pointer.
    pub vtable_offset: u64,
    /// Type name of the data member.
    pub data_type_name: Option<String>,
    /// Type name of the vtable member.
    pub vtable_type_name: Option<String>,
}

/// A Rust vtable object described by a global DWARF variable.
#[derive(Debug, Clone, Default)]
pub struct DwarfVtable {
    /// Vtable object address.
    pub address: u64,
    /// DWARF variable name.
    pub name: Option<String>,
    /// Resolved vtable structure type name.
    pub type_name: Option<String>,
    /// Vtable size in bytes.
    pub byte_size: Option<u64>,
    /// Header and method entries in offset order.
    pub entries: Vec<DwarfVtableEntry>,
}

/// One vtable slot.
#[derive(Debug, Clone, Default)]
pub struct DwarfVtableEntry {
    /// Member name.
    pub name: Option<String>,
    /// Byte offset in the vtable.
    pub offset: u64,
    /// Resolved member type name.
    pub type_name: Option<String>,
    /// Whether this is a Rust vtable header entry.
    pub header: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum TypeClass {
    Pointer,
    Reference,
    Typedef,
    Qualifier,
    Subroutine,
    Array,
    Aggregate,
    #[default]
    Other,
}

#[derive(Default)]
struct RawType {
    class: TypeClass,
    name: Option<String>,
    byte_size: Option<u64>,
    type_ref: Option<usize>,
    array_count: Option<u64>,
    aggregate_index: Option<usize>,
}

#[derive(Default)]
struct RawAggregate {
    name: Option<String>,
    byte_size: Option<u64>,
    is_union: bool,
    members: Vec<RawMember>,
}

struct RawMember {
    name: Option<String>,
    offset: u64,
    byte_size: Option<u64>,
    type_ref: Option<usize>,
}

enum RawLocation {
    Address(u64),
    Frame(i64),
    CallFrame(i64),
}

struct RawVariable {
    name: Option<String>,
    type_ref: Option<usize>,
    location: RawLocation,
    function_low: Option<u64>,
    is_parameter: bool,
}

#[derive(Default)]
struct UnitRecords {
    types: BTreeMap<usize, RawType>,
    aggregates: Vec<RawAggregate>,
    variables: Vec<RawVariable>,
    aggregate_stack: Vec<(u32, usize)>,
    array_stack: Vec<(u32, usize)>,
    subprogram_stack: Vec<(u32, Option<u64>)>,
}

impl UnitRecords {
    fn pop_to_depth(&mut self, depth: u32) {
        while self
            .aggregate_stack
            .last()
            .is_some_and(|(entry_depth, _)| *entry_depth >= depth)
        {
            self.aggregate_stack.pop();
        }
        while self
            .array_stack
            .last()
            .is_some_and(|(entry_depth, _)| *entry_depth >= depth)
        {
            self.array_stack.pop();
        }
        while self
            .subprogram_stack
            .last()
            .is_some_and(|(entry_depth, _)| *entry_depth >= depth)
        {
            self.subprogram_stack.pop();
        }
    }
}

#[derive(Clone, Default)]
struct TypeFacts {
    name: Option<String>,
    byte_size: Option<u64>,
    function_pointer: bool,
    function_pointer_array: bool,
    is_subroutine: bool,
    array_count: Option<u64>,
    aggregate: Option<usize>,
    pointee_aggregate: Option<usize>,
    element_aggregate: Option<usize>,
}

fn is_vtable_header_name(name: &str) -> bool {
    matches!(name, "drop_in_place" | "drop" | "size" | "align")
}

fn is_vtable_aggregate(aggregate: &DwarfAggregate) -> bool {
    aggregate
        .name
        .as_deref()
        .is_some_and(|name| name.contains("vtable"))
        || ["drop_in_place", "size", "align"].iter().all(|name| {
            aggregate
                .members
                .iter()
                .any(|member| member.name.as_deref() == Some(*name))
        })
}

fn raw_type_class(tag: gimli::DwTag) -> Option<TypeClass> {
    Some(match tag {
        constants::DW_TAG_pointer_type => TypeClass::Pointer,
        constants::DW_TAG_reference_type | constants::DW_TAG_rvalue_reference_type => {
            TypeClass::Reference
        }
        constants::DW_TAG_typedef => TypeClass::Typedef,
        constants::DW_TAG_const_type
        | constants::DW_TAG_volatile_type
        | constants::DW_TAG_restrict_type
        | constants::DW_TAG_atomic_type => TypeClass::Qualifier,
        constants::DW_TAG_subroutine_type => TypeClass::Subroutine,
        constants::DW_TAG_base_type
        | constants::DW_TAG_enumeration_type
        | constants::DW_TAG_unspecified_type
        | constants::DW_TAG_ptr_to_member_type => TypeClass::Other,
        _ => return None,
    })
}

fn string_attribute(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    attribute: gimli::DwAt,
) -> Option<String> {
    let value = entry.attr_value(attribute)?;
    let string = dwarf.attr_string(unit, value).ok()?;
    let string = string.to_string_lossy().into_owned();
    (!string.is_empty()).then_some(string)
}

fn byte_size_attribute(entry: &DwarfEntry<'_>) -> Option<u64> {
    entry
        .attr_value(constants::DW_AT_byte_size)
        .and_then(|value| value.udata_value())
}

fn type_reference(entry: &DwarfEntry<'_>) -> Option<usize> {
    match entry.attr_value(constants::DW_AT_type)? {
        AttributeValue::UnitRef(offset) => Some(offset.0),
        _ => None,
    }
}

fn constant_attribute(
    value: &AttributeValue<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
) -> Option<u64> {
    if let Some(value) = value.udata_value() {
        return Some(value);
    }
    let expression = value.exprloc_value()?;
    let mut total = 0u64;
    let mut saw_value = false;
    for operation in expression.operations(unit.encoding()) {
        match operation.ok()? {
            gimli::Operation::PlusConstant { value }
            | gimli::Operation::UnsignedConstant { value } => {
                total = total.checked_add(value)?;
                saw_value = true;
            }
            gimli::Operation::SignedConstant { value } => {
                total = u64::try_from(value).ok()?;
                saw_value = true;
            }
            _ => return None,
        }
    }
    saw_value.then_some(total)
}

fn variable_location(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
) -> Option<RawLocation> {
    match entry.attr_value(constants::DW_AT_location)? {
        AttributeValue::Addr(address) => Some(RawLocation::Address(address)),
        AttributeValue::DebugAddrIndex(index) => {
            dwarf.address(unit, index).ok().map(RawLocation::Address)
        }
        value => {
            let expression = value.exprloc_value()?;
            let mut cfa_offset = None;
            for operation in expression.operations(unit.encoding()) {
                match operation.ok()? {
                    gimli::Operation::Address { address } => {
                        return Some(RawLocation::Address(address));
                    }
                    gimli::Operation::AddressIndex { index } => {
                        return dwarf.address(unit, index).ok().map(RawLocation::Address);
                    }
                    gimli::Operation::FrameOffset { offset } => {
                        return Some(RawLocation::Frame(offset));
                    }
                    gimli::Operation::CallFrameCFA => {
                        cfa_offset = Some(0i64);
                    }
                    gimli::Operation::PlusConstant { value }
                    | gimli::Operation::UnsignedConstant { value } => {
                        cfa_offset = Some(cfa_offset?.checked_add(i64::try_from(value).ok()?)?);
                    }
                    gimli::Operation::SignedConstant { value } => {
                        cfa_offset = Some(cfa_offset?.checked_add(value)?);
                    }
                    _ => return None,
                }
            }
            cfa_offset.map(RawLocation::CallFrame)
        }
    }
}

fn resolve_type_facts(
    types: &BTreeMap<usize, RawType>,
    offset: usize,
    pointer_size: u64,
    cache: &mut BTreeMap<usize, TypeFacts>,
    depth: usize,
) -> TypeFacts {
    if depth > MAX_TYPE_DEPTH {
        return TypeFacts::default();
    }
    if let Some(facts) = cache.get(&offset) {
        return facts.clone();
    }
    let Some(raw) = types.get(&offset) else {
        return TypeFacts::default();
    };
    let target = raw
        .type_ref
        .map(|target| resolve_type_facts(types, target, pointer_size, cache, depth + 1));
    let mut facts = TypeFacts {
        name: raw.name.clone(),
        byte_size: raw.byte_size,
        ..TypeFacts::default()
    };
    match raw.class {
        TypeClass::Pointer | TypeClass::Reference => {
            facts.byte_size = raw.byte_size.or(Some(pointer_size));
            if let Some(target) = &target {
                facts.name = raw.name.clone().or_else(|| target.name.clone());
                facts.function_pointer = target.is_subroutine;
                facts.pointee_aggregate = target.aggregate;
            }
        }
        TypeClass::Typedef | TypeClass::Qualifier => {
            if let Some(target) = &target {
                facts = target.clone();
                if raw.name.is_some() {
                    facts.name.clone_from(&raw.name);
                }
                if raw.byte_size.is_some() {
                    facts.byte_size = raw.byte_size;
                }
            }
        }
        TypeClass::Subroutine => {
            facts.is_subroutine = true;
        }
        TypeClass::Array => {
            if let Some(target) = &target {
                facts.name = raw.name.clone().or_else(|| target.name.clone());
                facts.function_pointer_array = target.function_pointer;
                facts.array_count = raw.array_count;
                facts.element_aggregate = target.aggregate;
                facts.byte_size = raw.byte_size.or_else(|| {
                    target
                        .byte_size
                        .zip(raw.array_count)
                        .and_then(|(size, count)| size.checked_mul(count))
                });
            }
        }
        TypeClass::Aggregate => {
            facts.aggregate = raw.aggregate_index;
        }
        TypeClass::Other => {}
    }
    cache.insert(offset, facts.clone());
    facts
}

fn collect_type_record(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    class: TypeClass,
    records: &mut UnitRecords,
    truncated: &mut bool,
) {
    if records.types.len() >= MAX_DWARF_TYPES {
        *truncated = true;
        return;
    }
    records.types.insert(
        entry.offset().0,
        RawType {
            class,
            name: string_attribute(dwarf, unit, entry, constants::DW_AT_name),
            byte_size: byte_size_attribute(entry),
            type_ref: type_reference(entry),
            array_count: None,
            aggregate_index: None,
        },
    );
}

fn collect_aggregate_record(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    is_union: bool,
    records: &mut UnitRecords,
    truncated: &mut bool,
) {
    if records.aggregates.len() >= MAX_DWARF_AGGREGATES {
        *truncated = true;
        return;
    }
    let index = records.aggregates.len();
    records.aggregates.push(RawAggregate {
        name: string_attribute(dwarf, unit, entry, constants::DW_AT_name),
        byte_size: byte_size_attribute(entry),
        is_union,
        members: Vec::new(),
    });
    if records.types.len() < MAX_DWARF_TYPES {
        records.types.insert(
            entry.offset().0,
            RawType {
                class: TypeClass::Aggregate,
                name: records.aggregates[index].name.clone(),
                byte_size: records.aggregates[index].byte_size,
                type_ref: None,
                array_count: None,
                aggregate_index: Some(index),
            },
        );
    } else {
        *truncated = true;
    }
    records.aggregate_stack.push((entry_depth(entry), index));
}

fn collect_array_record(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    records: &mut UnitRecords,
    truncated: &mut bool,
) {
    if records.types.len() >= MAX_DWARF_TYPES {
        *truncated = true;
        return;
    }
    let offset = entry.offset().0;
    records.types.insert(
        offset,
        RawType {
            class: TypeClass::Array,
            name: string_attribute(dwarf, unit, entry, constants::DW_AT_name),
            byte_size: byte_size_attribute(entry),
            type_ref: type_reference(entry),
            array_count: None,
            aggregate_index: None,
        },
    );
    records.array_stack.push((entry_depth(entry), offset));
}

fn collect_subrange_record(
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    records: &mut UnitRecords,
) {
    let Some((_, offset)) = records.array_stack.last().copied() else {
        return;
    };
    let count = entry
        .attr_value(constants::DW_AT_count)
        .and_then(|value| constant_attribute(&value, unit))
        .or_else(|| {
            entry
                .attr_value(constants::DW_AT_upper_bound)
                .and_then(|value| constant_attribute(&value, unit))
                .and_then(|value| value.checked_add(1))
        });
    let Some(count) = count else {
        return;
    };
    if let Some(raw) = records.types.get_mut(&offset) {
        raw.array_count = match raw.array_count {
            Some(current) => current.checked_mul(count),
            None => Some(count),
        };
    }
}

fn collect_member_record(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    records: &mut UnitRecords,
    truncated: &mut bool,
) {
    let Some((_, aggregate_index)) = records.aggregate_stack.last().copied() else {
        return;
    };
    if entry.attr_value(constants::DW_AT_bit_size).is_some()
        || entry.attr_value(constants::DW_AT_data_bit_offset).is_some()
    {
        return;
    }
    let offset = entry
        .attr_value(constants::DW_AT_data_member_location)
        .and_then(|value| constant_attribute(&value, unit))
        .or_else(|| {
            let aggregate = records.aggregates.get(aggregate_index)?;
            aggregate.is_union.then_some(0)
        });
    let Some(offset) = offset else {
        return;
    };
    if records
        .aggregates
        .get(aggregate_index)
        .is_none_or(|aggregate| aggregate.members.len() >= MAX_DWARF_MEMBERS)
    {
        *truncated = true;
        return;
    }
    records.aggregates[aggregate_index].members.push(RawMember {
        name: string_attribute(dwarf, unit, entry, constants::DW_AT_name),
        offset,
        byte_size: byte_size_attribute(entry),
        type_ref: type_reference(entry),
    });
}

fn collect_variable_record(
    dwarf: &Dwarf<DwarfReader<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_>,
    records: &mut UnitRecords,
    is_parameter: bool,
    truncated: &mut bool,
) {
    if records.variables.len() >= MAX_DWARF_VARIABLES {
        *truncated = true;
        return;
    }
    let Some(location) = variable_location(dwarf, unit, entry) else {
        return;
    };
    records.variables.push(RawVariable {
        name: string_attribute(dwarf, unit, entry, constants::DW_AT_name),
        type_ref: type_reference(entry),
        location,
        function_low: records.subprogram_stack.last().and_then(|(_, low)| *low),
        is_parameter,
    });
}

fn entry_depth(entry: &DwarfEntry<'_>) -> u32 {
    u32::try_from(entry.depth().max(0)).unwrap_or(u32::MAX)
}

fn append_unit_records(info: &mut DwarfInfo, records: UnitRecords, pointer_size: u64) {
    let aggregate_base = info.aggregates.len();
    let UnitRecords {
        types,
        aggregates,
        variables,
        ..
    } = records;
    let mut cache = BTreeMap::new();
    for raw in aggregates {
        let mut aggregate = DwarfAggregate {
            name: raw.name,
            byte_size: raw.byte_size,
            members: Vec::new(),
        };
        for member in raw.members {
            if info.member_count >= MAX_DWARF_MEMBERS {
                info.truncated = true;
                continue;
            }
            let facts = member
                .type_ref
                .map(|offset| resolve_type_facts(&types, offset, pointer_size, &mut cache, 0))
                .unwrap_or_default();
            info.member_count = info.member_count.saturating_add(1);
            aggregate.members.push(DwarfMember {
                name: member.name,
                type_name: facts.name,
                offset: member.offset,
                byte_size: member.byte_size.or(facts.byte_size),
                function_pointer: facts.function_pointer,
                function_pointer_array: facts.function_pointer_array,
                aggregate_index: facts.aggregate.map(|index| aggregate_base + index),
                element_aggregate_index: facts
                    .element_aggregate
                    .map(|index| aggregate_base + index),
                array_count: facts.array_count,
            });
        }
        info.aggregates.push(aggregate);
    }
    for raw in variables {
        if info.variables.len() >= MAX_DWARF_VARIABLES {
            info.truncated = true;
            break;
        }
        let facts = raw
            .type_ref
            .map(|offset| resolve_type_facts(&types, offset, pointer_size, &mut cache, 0))
            .unwrap_or_default();
        let (address, frame_offset, call_frame_offset) = match raw.location {
            RawLocation::Address(address) => (Some(address), None, None),
            RawLocation::Frame(offset) => (None, Some(offset), None),
            RawLocation::CallFrame(offset) => (None, None, Some(offset)),
        };
        info.variables.push(DwarfVariable {
            name: raw.name,
            type_name: facts.name,
            address,
            frame_offset,
            call_frame_offset,
            function_low: raw.function_low,
            byte_size: facts.byte_size,
            function_pointer: facts.function_pointer,
            function_pointer_array: facts.function_pointer_array,
            array_count: facts.array_count,
            aggregate_index: facts.aggregate.map(|index| aggregate_base + index),
            pointee_aggregate_index: facts.pointee_aggregate.map(|index| aggregate_base + index),
            element_aggregate_index: facts.element_aggregate.map(|index| aggregate_base + index),
            is_parameter: raw.is_parameter,
        });
    }
}

fn finish_info(mut info: DwarfInfo) -> DwarfInfo {
    info.sources
        .sort_by_key(|source| (source.low_pc, source.high_pc));
    info.build_inline_index();
    info.build_type_indexes();
    info
}

/// Extracts subprograms and inlined subroutines from the image's DWARF
/// sections.
///
/// # Errors
///
/// Returns a human-readable error for malformed or unsupported DWARF. Callers
/// should treat this as a non-fatal diagnostic.
#[allow(clippy::too_many_lines)]
pub fn parse(
    file: &object::File<'_>,
    byte_order: ByteOrder,
    pointer_size: usize,
) -> Result<DwarfInfo, String> {
    let endian = match byte_order {
        ByteOrder::Little => RunTimeEndian::Little,
        ByteOrder::Big => RunTimeEndian::Big,
    };
    let dwarf = Dwarf::load(|id| {
        let data = file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok::<_, gimli::Error>(EndianSlice::new(data, endian))
    })
    .map_err(|error| error.to_string())?;
    let pointer_size = u64::try_from(pointer_size).unwrap_or(0);

    let mut info = DwarfInfo::default();
    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        let unit = dwarf.unit(header).map_err(|error| error.to_string())?;
        let mut name_cache: BTreeMap<usize, NameInfo> = BTreeMap::new();
        let mut records = UnitRecords::default();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().map_err(|error| error.to_string())? {
            let depth = entry_depth(entry);
            records.pop_to_depth(depth);
            match entry.tag() {
                constants::DW_TAG_subprogram => {
                    let names = resolve_names(&dwarf, &unit, entry, &mut name_cache, 0);
                    let ranges = die_ranges(&dwarf, &unit, entry)?;
                    let function_low = ranges.iter().map(|(low, _)| *low).min();
                    records.subprogram_stack.push((depth, function_low));
                    if names.name.is_some() || names.linkage_name.is_some() || !ranges.is_empty() {
                        info.functions.push(DwarfFunction {
                            name: names.name,
                            linkage_name: names.linkage_name,
                            ranges,
                        });
                    }
                    if info.functions.len() >= MAX_DWARF_FUNCTIONS {
                        info.truncated = true;
                        append_unit_records(&mut info, records, pointer_size);
                        return Ok(finish_info(info));
                    }
                }
                constants::DW_TAG_inlined_subroutine => {
                    let names = resolve_names(&dwarf, &unit, entry, &mut name_cache, 0);
                    if names.name.is_none() && names.linkage_name.is_none() {
                        continue;
                    }
                    let display_name = display_name(&names);
                    let (call_file, call_line, call_column) =
                        inlined_call_site(&dwarf, &unit, entry);
                    let inline_depth = u32::try_from(entry.depth().max(0)).unwrap_or(u32::MAX);
                    for (low_pc, high_pc) in die_ranges(&dwarf, &unit, entry)? {
                        info.inlined_calls.push(DwarfInlinedCall {
                            name: names.name.clone(),
                            linkage_name: names.linkage_name.clone(),
                            display_name: display_name.clone(),
                            call_file: call_file.clone(),
                            call_line,
                            call_column,
                            low_pc,
                            high_pc,
                            depth: inline_depth,
                        });
                        if info.inlined_calls.len() >= MAX_INLINED_CALLS {
                            info.truncated = true;
                            append_unit_records(&mut info, records, pointer_size);
                            return Ok(finish_info(info));
                        }
                    }
                }
                constants::DW_TAG_structure_type | constants::DW_TAG_class_type => {
                    collect_aggregate_record(
                        &dwarf,
                        &unit,
                        entry,
                        false,
                        &mut records,
                        &mut info.truncated,
                    );
                }
                constants::DW_TAG_union_type => {
                    collect_aggregate_record(
                        &dwarf,
                        &unit,
                        entry,
                        true,
                        &mut records,
                        &mut info.truncated,
                    );
                }
                constants::DW_TAG_array_type => {
                    collect_array_record(&dwarf, &unit, entry, &mut records, &mut info.truncated);
                }
                constants::DW_TAG_subrange_type => {
                    collect_subrange_record(&unit, entry, &mut records);
                }
                constants::DW_TAG_member => {
                    collect_member_record(&dwarf, &unit, entry, &mut records, &mut info.truncated);
                }
                constants::DW_TAG_variable => {
                    collect_variable_record(
                        &dwarf,
                        &unit,
                        entry,
                        &mut records,
                        false,
                        &mut info.truncated,
                    );
                }
                constants::DW_TAG_formal_parameter => {
                    collect_variable_record(
                        &dwarf,
                        &unit,
                        entry,
                        &mut records,
                        true,
                        &mut info.truncated,
                    );
                }
                tag => {
                    if let Some(class) = raw_type_class(tag) {
                        collect_type_record(
                            &dwarf,
                            &unit,
                            entry,
                            class,
                            &mut records,
                            &mut info.truncated,
                        );
                    }
                }
            }
        }
        append_unit_records(&mut info, records, pointer_size);
        if let Some(program) = unit.line_program.clone() {
            collect_sources(&dwarf, &unit, program, &mut info);
        }
    }
    Ok(finish_info(info))
}

fn display_name(names: &NameInfo) -> Option<String> {
    let raw = names
        .linkage_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .or(names.name.as_deref())?
        .trim();
    if raw.is_empty() {
        return None;
    }
    if (raw.starts_with("_R") || raw.starts_with("_ZN"))
        && let Ok(demangled) = rustc_demangle::try_demangle(raw)
    {
        return Some(demangled.to_string());
    }
    Some(raw.to_owned())
}

fn inlined_call_site(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'_, RunTimeEndian>>,
) -> (Option<String>, Option<u32>, Option<u32>) {
    let file = match entry.attr_value(constants::DW_AT_call_file) {
        Some(AttributeValue::FileIndex(index)) => unit
            .line_program
            .as_ref()
            .and_then(|program| program.header().file(index))
            .and_then(|file| dwarf.attr_string(unit, file.path_name()).ok())
            .map(|name| name.to_string_lossy().into_owned()),
        _ => None,
    };
    let line = entry
        .attr_value(constants::DW_AT_call_line)
        .and_then(|value| value.udata_value())
        .and_then(|value| u32::try_from(value).ok());
    let column = entry
        .attr_value(constants::DW_AT_call_column)
        .and_then(|value| value.udata_value())
        .and_then(|value| u32::try_from(value).ok());
    (file, line, column)
}

fn collect_sources(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    program: gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>,
    info: &mut DwarfInfo,
) {
    let mut rows = program.rows();
    let mut sequence: Vec<(u64, Option<DwarfSourceRange>)> = Vec::new();
    while let Ok(Some((header, row))) = rows.next_row() {
        if row.end_sequence() {
            finalize_sequence(&mut sequence, row.address(), info);
            if info.sources.len() >= MAX_SOURCE_RANGES {
                info.truncated = true;
                return;
            }
            continue;
        }
        let source = row.file(header).and_then(|file| {
            let name = dwarf.attr_string(unit, file.path_name()).ok()?;
            let file = name.to_string_lossy().into_owned();
            if file.is_empty() {
                return None;
            }
            let line = u32::try_from(row.line()?.get()).ok()?;
            let column = match row.column() {
                gimli::ColumnType::Column(column) => u32::try_from(column.get()).ok(),
                gimli::ColumnType::LeftEdge => None,
            };
            Some(DwarfSourceRange {
                low_pc: row.address(),
                high_pc: row.address(),
                file,
                line,
                column,
            })
        });
        sequence.push((row.address(), source));
    }
    // A well-formed program ends with an end_sequence row. If it does not,
    // discard the incomplete tail rather than inventing an end address.
}

fn finalize_sequence(
    sequence: &mut Vec<(u64, Option<DwarfSourceRange>)>,
    end: u64,
    info: &mut DwarfInfo,
) {
    for index in 0..sequence.len() {
        let start = sequence[index].0;
        let next = sequence.get(index + 1).map_or(end, |(address, _)| *address);
        if next <= start {
            continue;
        }
        if let Some(mut source) = sequence[index].1.take() {
            source.low_pc = start;
            source.high_pc = next;
            info.sources.push(source);
            if info.sources.len() >= MAX_SOURCE_RANGES {
                info.truncated = true;
                sequence.clear();
                return;
            }
        }
    }
    sequence.clear();
}

#[derive(Clone, Default)]
struct NameInfo {
    name: Option<String>,
    linkage_name: Option<String>,
}

fn resolve_names<'a>(
    dwarf: &Dwarf<EndianSlice<'a, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'a, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'a, RunTimeEndian>>,
    cache: &mut BTreeMap<usize, NameInfo>,
    depth: usize,
) -> NameInfo {
    let cache_key = entry.offset().0;
    if let Some(cached) = cache.get(&cache_key) {
        return cached.clone();
    }
    let mut info = NameInfo::default();
    if let Some(value) = entry.attr_value(constants::DW_AT_name)
        && let Ok(string) = dwarf.attr_string(unit, value)
    {
        info.name = Some(string.to_string_lossy().into_owned());
    }
    for attribute in [
        constants::DW_AT_linkage_name,
        constants::DW_AT_MIPS_linkage_name,
    ] {
        if let Some(value) = entry.attr_value(attribute)
            && let Ok(string) = dwarf.attr_string(unit, value)
        {
            info.linkage_name = Some(string.to_string_lossy().into_owned());
            break;
        }
    }
    if info.linkage_name.is_none() && depth < 8 {
        for attribute in [
            constants::DW_AT_abstract_origin,
            constants::DW_AT_specification,
        ] {
            if let Some(AttributeValue::UnitRef(offset)) = entry.attr_value(attribute)
                && let Ok(origin) = unit.entry(offset)
            {
                let resolved = resolve_names(dwarf, unit, &origin, cache, depth + 1);
                info.name = info.name.or(resolved.name);
                info.linkage_name = info.linkage_name.or(resolved.linkage_name);
                if info.linkage_name.is_some() {
                    break;
                }
            }
        }
    }
    cache.insert(cache_key, info.clone());
    info
}

fn die_ranges<'a>(
    dwarf: &Dwarf<EndianSlice<'a, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'a, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianSlice<'a, RunTimeEndian>>,
) -> Result<Vec<(u64, u64)>, String> {
    let mut ranges = Vec::new();
    let mut iter = dwarf
        .die_ranges(unit, entry)
        .map_err(|error| error.to_string())?;
    while let Some(range) = iter.next().map_err(|error| error.to_string())? {
        if range.begin < range.end {
            ranges.push((range.begin, range.end));
        }
    }
    Ok(ranges)
}
