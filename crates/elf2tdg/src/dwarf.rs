//! DWARF extraction for inlined call-site recovery.
//!
//! Symbols describe direct calls. Debug information additionally describes
//! calls that were inlined, including the inlined function's linkage name and
//! concrete address ranges. M2 uses those records to recover spawn/join/scope
//! sites that would otherwise disappear at higher optimization levels.
//!
//! This module deliberately avoids a general DWARF database: it extracts only
//! subprograms and inlined subroutines, with names and address ranges.

use std::collections::BTreeMap;

use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, constants};
use object::{Object, ObjectSection};

use crate::loader::ByteOrder;

const MAX_INLINED_CALLS: usize = 200_000;
const MAX_DWARF_FUNCTIONS: usize = 200_000;
const MAX_SOURCE_RANGES: usize = 500_000;

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
    /// Extraction stopped at a safety limit.
    pub truncated: bool,
    /// Prefix maximum of `high_pc`, parallel to `inlined_calls`.
    inline_max_high: Vec<u64>,
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

/// Extracts subprograms and inlined subroutines from the image's DWARF
/// sections.
///
/// # Errors
///
/// Returns a human-readable error for malformed or unsupported DWARF. Callers
/// should treat this as a non-fatal diagnostic.
pub fn parse(file: &object::File<'_>, byte_order: ByteOrder) -> Result<DwarfInfo, String> {
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

    let mut info = DwarfInfo::default();
    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        let unit = dwarf.unit(header).map_err(|error| error.to_string())?;
        let mut name_cache: BTreeMap<usize, NameInfo> = BTreeMap::new();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().map_err(|error| error.to_string())? {
            match entry.tag() {
                constants::DW_TAG_subprogram => {
                    let names = resolve_names(&dwarf, &unit, entry, &mut name_cache, 0);
                    let ranges = die_ranges(&dwarf, &unit, entry)?;
                    if names.name.is_some() || names.linkage_name.is_some() || !ranges.is_empty() {
                        info.functions.push(DwarfFunction {
                            name: names.name,
                            linkage_name: names.linkage_name,
                            ranges,
                        });
                    }
                    if info.functions.len() >= MAX_DWARF_FUNCTIONS {
                        info.truncated = true;
                        info.build_inline_index();
                        return Ok(info);
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
                    let depth = u32::try_from(entry.depth().max(0)).unwrap_or(u32::MAX);
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
                            depth,
                        });
                        if info.inlined_calls.len() >= MAX_INLINED_CALLS {
                            info.truncated = true;
                            info.build_inline_index();
                            return Ok(info);
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(program) = unit.line_program.clone() {
            collect_sources(&dwarf, &unit, program, &mut info);
        }
    }
    info.sources
        .sort_by_key(|source| (source.low_pc, source.high_pc));
    info.build_inline_index();
    Ok(info)
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
