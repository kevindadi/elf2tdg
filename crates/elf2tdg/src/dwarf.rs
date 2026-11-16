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
    /// Inlined subroutine instances and their concrete address ranges.
    pub inlined_calls: Vec<DwarfInlinedCall>,
    /// Source-line ranges from the line-number programs.
    pub sources: Vec<DwarfSourceRange>,
    /// Extraction stopped at a safety limit.
    pub truncated: bool,
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

/// An inlined subroutine instance.
#[derive(Debug, Clone, Default)]
pub struct DwarfInlinedCall {
    /// `DW_AT_name` from the concrete or abstract DIE.
    pub name: Option<String>,
    /// `DW_AT_linkage_name` from the concrete or abstract DIE.
    pub linkage_name: Option<String>,
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
                        return Ok(info);
                    }
                }
                constants::DW_TAG_inlined_subroutine => {
                    let names = resolve_names(&dwarf, &unit, entry, &mut name_cache, 0);
                    if names.name.is_none() && names.linkage_name.is_none() {
                        continue;
                    }
                    let depth = u32::try_from(entry.depth().max(0)).unwrap_or(u32::MAX);
                    for (low_pc, high_pc) in die_ranges(&dwarf, &unit, entry)? {
                        info.inlined_calls.push(DwarfInlinedCall {
                            name: names.name.clone(),
                            linkage_name: names.linkage_name.clone(),
                            low_pc,
                            high_pc,
                            depth,
                        });
                        if info.inlined_calls.len() >= MAX_INLINED_CALLS {
                            info.truncated = true;
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
    Ok(info)
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
