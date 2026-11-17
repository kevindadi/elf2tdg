//! ELF loading into a small, architecture-neutral image model.
//!
//! Symbols, entry points, Cortex-M vector tables, DWARF sections and dynamic
//! PLT imports are extracted here. PLT stubs receive synthetic names from the
//! dynamic relocation table so later rule matching sees the imported API.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, RelocationFlags, RelocationKind,
    RelocationTarget, SectionFlags, SectionKind, SymbolKind,
};

use crate::error::{Error, Result};

/// Instruction-set family selected for decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchKind {
    /// ARM Thumb/Thumb-2 (`Cortex-M`).
    Thumb,
    /// 32-bit ARM (A32).
    Arm,
    /// `AArch64`.
    Aarch64,
    /// 32-bit RISC-V.
    Riscv32,
    /// 64-bit RISC-V.
    Riscv64,
    /// x86-64.
    X86_64,
}

impl ArchKind {
    /// Architecture string used in the TDG schema.
    #[must_use]
    pub fn schema_name(self) -> &'static str {
        match self {
            Self::Thumb => "thumb",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
            Self::X86_64 => "x86_64",
        }
    }

    /// Whether this is an ARM-family architecture whose addresses may carry
    /// the Thumb interworking bit.
    #[must_use]
    pub fn is_arm_family(self) -> bool {
        matches!(self, Self::Thumb | Self::Arm)
    }
}

/// ELF byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// Little endian.
    Little,
    /// Big endian.
    Big,
}

impl ByteOrder {
    fn read_u16(self, bytes: &[u8], offset: usize) -> Option<u16> {
        let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
        Some(match self {
            Self::Little => u16::from_le_bytes(raw),
            Self::Big => u16::from_be_bytes(raw),
        })
    }

    fn read_u32(self, bytes: &[u8], offset: usize) -> Option<u32> {
        let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(match self {
            Self::Little => u32::from_le_bytes(raw),
            Self::Big => u32::from_be_bytes(raw),
        })
    }
}

/// ELF file type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfKind {
    /// Relocatable object.
    Rel,
    /// Executable.
    Exec,
    /// Shared object / PIE.
    Dyn,
    /// Unknown.
    Unknown,
}

/// One loaded section.
#[derive(Clone, Debug)]
pub struct Section {
    /// Section name.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Size in memory.
    pub size: u64,
    /// File-backed bytes (may be shorter than `size`).
    pub data: Vec<u8>,
    /// Executable permission.
    pub executable: bool,
    /// Writable permission.
    pub writable: bool,
    /// Allocated in memory at run time (`SHF_ALLOC`).
    pub alloc: bool,
}

impl Section {
    /// Exclusive end address, saturating on overflow.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Whether the section has no file bytes and is zero-filled at run time.
    #[must_use]
    pub fn is_nobits(&self) -> bool {
        self.size > 0 && self.data.is_empty()
    }
}

/// One loadable ELF program segment (`PT_LOAD`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Virtual address where the segment is mapped.
    pub address: u64,
    /// Size in memory.
    pub size: u64,
    /// File offset of the segment contents.
    pub file_offset: u64,
    /// Number of file-backed bytes.
    pub file_size: u64,
    /// Required alignment.
    pub align: u64,
    /// Read permission.
    pub readable: bool,
    /// Write permission.
    pub writable: bool,
    /// Execute permission.
    pub executable: bool,
}

impl Segment {
    /// Exclusive end address, saturating on overflow.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Permission string such as `R-X` or `RW-`.
    #[must_use]
    pub fn permissions(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable { 'R' } else { '-' },
            if self.writable { 'W' } else { '-' },
            if self.executable { 'X' } else { '-' }
        )
    }

    /// Whether `section` belongs to this segment.
    #[must_use]
    pub fn contains_section(&self, section: &Section) -> bool {
        section.alloc && section.address >= self.address && section.end() <= self.end()
    }
}

/// A symbol with an address in an executable section.
#[derive(Clone, Debug)]
pub struct ImageSymbol {
    /// Raw symbol name.
    pub name: String,
    /// Raw ELF address (may retain the Thumb bit).
    pub address: u64,
    /// Canonical address (Thumb bit cleared).
    pub canonical_address: u64,
    /// Symbol size in bytes (zero if unknown).
    pub size: u64,
    /// ELF symbol kind.
    pub kind: SymbolKind,
    /// Section name, when known.
    pub section: Option<String>,
    /// Whether the raw address selected Thumb mode.
    pub thumb: bool,
}

/// A Cortex-M vector table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorEntry {
    /// Raw word index in the vector table (0 is the initial SP).
    pub index: u32,
    /// Raw word value.
    pub raw: u64,
    /// Handler address with the Thumb bit cleared.
    pub handler: u64,
}

/// Loaded image.
#[derive(Clone, Debug)]
pub struct Image {
    /// Input path.
    pub path: PathBuf,
    /// Instruction-set family.
    pub arch: ArchKind,
    /// Byte order.
    pub byte_order: ByteOrder,
    /// ELF file type.
    pub elf_kind: ElfKind,
    /// Raw ELF entry point.
    pub entry: u64,
    /// Resolved pointer-sized memory slots from dynamic relocations.
    pub relocated_pointers: BTreeMap<u64, u64>,
    /// Dynamic-import GOT slots that have no local PLT stub, keyed by slot
    /// address.
    pub imported_slots: BTreeMap<u64, String>,
    /// Loaded program segments (`PT_LOAD`).
    pub segments: Vec<Segment>,
    /// Loaded sections.
    pub sections: Vec<Section>,
    /// Function-like symbols in executable sections.
    pub symbols: Vec<ImageSymbol>,
    /// Whether a symbol table exists.
    pub has_symbols: bool,
    /// Whether DWARF debug sections exist.
    pub has_debug_info: bool,
    /// Whether relocations exist.
    pub has_relocations: bool,
    /// ARM CPU name recovered from `.ARM.attributes`, if any.
    pub arm_cpu: Option<String>,
    /// Cortex-M vector table entries, excluding the initial SP.
    pub vector_table: Vec<VectorEntry>,
    /// Extracted DWARF subprograms/inlined subroutines, when available.
    pub dwarf: Option<crate::dwarf::DwarfInfo>,
    /// Non-fatal DWARF extraction error.
    pub dwarf_error: Option<String>,
}

impl Image {
    /// Returns the executable section containing `address`.
    #[must_use]
    pub fn executable_section_for(&self, address: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.executable && section.contains(address))
    }

    /// Returns whether `address` lies in an executable section.
    #[must_use]
    pub fn is_executable(&self, address: u64) -> bool {
        self.executable_section_for(address).is_some()
    }

    /// Returns the imported symbol stored in a dynamic GOT slot that has no
    /// local PLT stub.
    #[must_use]
    pub fn import_name_at(&self, address: u64) -> Option<&str> {
        if self.relocated_pointers.contains_key(&address) {
            return None;
        }
        self.imported_slots.get(&address).map(String::as_str)
    }

    /// Returns between 1 and `max_len` bytes at `address`, without crossing a
    /// section boundary.
    #[must_use]
    pub fn bytes_at(&self, address: u64, max_len: usize) -> Option<&[u8]> {
        let section = self.executable_section_for(address)?;
        let offset = usize::try_from(address.checked_sub(section.address)?).ok()?;
        let available = section.data.len().saturating_sub(offset);
        if available == 0 {
            return None;
        }
        let len = max_len.min(available);
        Some(&section.data[offset..offset + len])
    }

    /// Returns the section end address for the executable section containing
    /// `address`.
    #[must_use]
    pub fn section_end_for(&self, address: u64) -> Option<u64> {
        self.executable_section_for(address).map(Section::end)
    }

    /// Returns the section name containing `address`.
    #[must_use]
    pub fn section_name_for(&self, address: u64) -> Option<&str> {
        self.executable_section_for(address)
            .map(|section| section.name.as_str())
    }

    /// Returns the end of the allocated section containing `address`.
    ///
    /// Jump-table scans use this to avoid reading across a section boundary
    /// into unrelated data.
    #[must_use]
    pub fn allocation_end_for(&self, address: u64) -> Option<u64> {
        self.sections
            .iter()
            .filter(|section| section.alloc && section.contains(address))
            .map(Section::end)
            .max()
    }

    /// Returns bytes at `address` from any section (not just executable ones).
    /// This is used for literal pools and read-only pointer tables.
    #[must_use]
    pub fn bytes_at_any(&self, address: u64, max_len: usize) -> Option<&[u8]> {
        let section = self
            .sections
            .iter()
            .find(|section| section.contains(address))?;
        let offset = usize::try_from(address.checked_sub(section.address)?).ok()?;
        let available = section.data.len().saturating_sub(offset);
        if available == 0 {
            return None;
        }
        let len = max_len.min(available);
        Some(&section.data[offset..offset + len])
    }

    /// Reads a 4- or 8-byte unsigned value at `address` using the image's byte
    /// order.
    #[must_use]
    pub fn read_uint(&self, address: u64, size: usize) -> Option<u64> {
        if matches!(size, 4 | 8)
            && let Some(value) = self.relocated_pointers.get(&address)
        {
            return Some(if size == 4 {
                value & u64::from(u32::MAX)
            } else {
                *value
            });
        }
        let bytes = self.bytes_at_any(address, size)?;
        if bytes.len() < size {
            return None;
        }
        match (self.byte_order, size) {
            (_, 1) => Some(u64::from(bytes[0])),
            (ByteOrder::Little, 2) => {
                Some(u64::from(u16::from_le_bytes(bytes[..2].try_into().ok()?)))
            }
            (ByteOrder::Little, 4) => {
                Some(u64::from(u32::from_le_bytes(bytes[..4].try_into().ok()?)))
            }
            (ByteOrder::Little, 8) => Some(u64::from_le_bytes(bytes[..8].try_into().ok()?)),
            (ByteOrder::Big, 2) => Some(u64::from(u16::from_be_bytes(bytes[..2].try_into().ok()?))),
            (ByteOrder::Big, 4) => Some(u64::from(u32::from_be_bytes(bytes[..4].try_into().ok()?))),
            (ByteOrder::Big, 8) => Some(u64::from_be_bytes(bytes[..8].try_into().ok()?)),
            _ => None,
        }
    }

    /// Returns the pointer width for the image architecture.
    #[must_use]
    pub fn pointer_size(&self) -> usize {
        match self.arch {
            ArchKind::Thumb | ArchKind::Arm | ArchKind::Riscv32 => 4,
            ArchKind::Aarch64 | ArchKind::Riscv64 | ArchKind::X86_64 => 8,
        }
    }

    /// Reads a pointer-sized value, preferring a resolved dynamic relocation.
    #[must_use]
    pub fn read_pointer(&self, address: u64) -> Option<u64> {
        self.read_uint(address, self.pointer_size())
    }

    /// Returns the canonical address for the image's instruction set.
    #[must_use]
    pub fn canonical_address(&self, address: u64) -> u64 {
        if self.arch.is_arm_family() {
            address & !1
        } else {
            address
        }
    }
}

impl Section {
    fn contains(&self, address: u64) -> bool {
        address >= self.address && address < self.end()
    }
}

/// Loads an ELF image from disk.
///
/// # Errors
///
/// Returns an error for I/O failures, malformed ELF files, unsupported
/// architectures and images without executable sections.
#[allow(clippy::too_many_lines)]
pub fn load(path: &Path) -> Result<Image> {
    let bytes = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    load_from_bytes(&bytes, path)
}

/// Loads an ELF image from an in-memory byte buffer.
///
/// `path` is retained as the image label and is not opened. This entry point
/// is useful for fuzzing and archive/embedded workflows.
///
/// # Errors
///
/// Returns the same errors as [`load`] for invalid ELF data.
#[allow(clippy::too_many_lines)]
pub fn load_from_bytes(bytes: &[u8], path: impl AsRef<Path>) -> Result<Image> {
    let path = path.as_ref();
    let file = object::File::parse(bytes).map_err(|error| Error::Elf(error.to_string()))?;

    let byte_order = match file.endianness() {
        object::Endianness::Little => ByteOrder::Little,
        object::Endianness::Big => ByteOrder::Big,
    };
    let elf_kind = elf_kind(bytes, byte_order);
    let entry = file.entry();

    let mut sections = Vec::new();
    let mut section_names: BTreeMap<usize, String> = BTreeMap::new();
    let mut has_debug_info = false;
    let mut has_relocations = false;
    let mut executable_sections = 0usize;

    for section in file.sections() {
        let index = section.index();
        let name = section.name().unwrap_or("<unnamed>").to_owned();
        section_names.insert(index.0, name.clone());
        if name.starts_with(".debug_") || name.starts_with(".zdebug_") {
            has_debug_info = true;
            continue;
        }
        if section.relocations().next().is_some() {
            has_relocations = true;
        }
        let kind = section.kind();
        let flags = section.flags();
        let (executable, writable, alloc) = match flags {
            SectionFlags::Elf { sh_flags } => (
                sh_flags & 0x4 != 0,
                sh_flags & 0x1 != 0,
                sh_flags & 0x2 != 0,
            ),
            _ => (
                kind == SectionKind::Text,
                matches!(kind, SectionKind::Data | SectionKind::UninitializedData),
                matches!(
                    kind,
                    SectionKind::Text
                        | SectionKind::Data
                        | SectionKind::ReadOnlyData
                        | SectionKind::ReadOnlyString
                        | SectionKind::UninitializedData
                        | SectionKind::Tls
                        | SectionKind::UninitializedTls
                ),
            ),
        };
        let data = match section.data() {
            Ok(data) => data.to_vec(),
            Err(_) => Vec::new(),
        };
        if data.is_empty() && section.size() == 0 {
            continue;
        }
        if executable {
            executable_sections += 1;
        }
        sections.push(Section {
            name,
            address: section.address(),
            size: section.size(),
            data,
            executable,
            writable,
            alloc,
        });
    }

    if executable_sections == 0 {
        return Err(Error::NoExecutableSections);
    }

    let segments: Vec<Segment> = file
        .segments()
        .map(|segment| {
            let permissions = segment.permissions();
            let (file_offset, file_size) = segment.file_range();
            Segment {
                address: segment.address(),
                size: segment.size(),
                file_offset,
                file_size,
                align: segment.align(),
                readable: permissions.readable(),
                writable: permissions.writable(),
                executable: permissions.executable(),
            }
        })
        .collect();

    let arm_cpu = detect_arm_cpu(&sections);
    let arch = detect_arch(&file, entry, arm_cpu.as_deref())?;

    let mut symbols = Vec::new();
    let mut seen = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let kind = symbol.kind();
        if !matches!(kind, SymbolKind::Text | SymbolKind::Unknown) {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() || name.starts_with('$') || name.starts_with(".L") {
            continue;
        }
        let raw_address = symbol.address();
        let canonical_address = if arch.is_arm_family() {
            raw_address & !1
        } else {
            raw_address
        };
        if !is_executable_in(&sections, canonical_address) {
            continue;
        }
        if kind == SymbolKind::Unknown && symbol.size() == 0 && !symbol.is_global() {
            continue;
        }
        let size = symbol.size();
        if !seen.insert((canonical_address, name.to_owned(), size)) {
            continue;
        }
        symbols.push(ImageSymbol {
            name: name.to_owned(),
            address: raw_address,
            canonical_address,
            size,
            kind,
            section: symbol
                .section_index()
                .and_then(|index| section_names.get(&index.0).cloned()),
            thumb: arch.is_arm_family() && raw_address & 1 == 1,
        });
    }

    synthesize_plt_symbols(&file, &sections, arch, &mut seen, &mut symbols);
    let has_symbols = !symbols.is_empty();
    let vector_table = if matches!(arch, ArchKind::Thumb | ArchKind::Arm) {
        detect_vector_table(&sections, byte_order, arch)
    } else {
        Vec::new()
    };
    let (relocated_pointers, imported_slots) =
        collect_pointer_relocations(&file, &sections, byte_order, arch, &symbols);
    let (dwarf, dwarf_error) = if has_debug_info {
        match crate::dwarf::parse(&file, byte_order) {
            Ok(info) => (Some(info), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };

    Ok(Image {
        path: path.to_path_buf(),
        arch,
        byte_order,
        elf_kind,
        entry,
        relocated_pointers,
        imported_slots,
        segments,
        sections,
        symbols,
        has_symbols,
        has_debug_info,
        has_relocations,
        arm_cpu,
        vector_table,
        dwarf,
        dwarf_error,
    })
}

fn collect_pointer_relocations(
    file: &object::File<'_>,
    sections: &[Section],
    byte_order: ByteOrder,
    arch: ArchKind,
    symbols: &[ImageSymbol],
) -> (BTreeMap<u64, u64>, BTreeMap<u64, String>) {
    let Some(relocations) = file.dynamic_relocations() else {
        return (BTreeMap::new(), BTreeMap::new());
    };
    let pointer_size = match arch {
        ArchKind::Thumb | ArchKind::Arm | ArchKind::Riscv32 => 4,
        ArchKind::Aarch64 | ArchKind::Riscv64 | ArchKind::X86_64 => 8,
    };
    let dynamic_symbols: BTreeMap<usize, (String, u64)> = file
        .dynamic_symbols()
        .filter_map(|symbol| {
            let name = symbol.name().ok()?.to_owned();
            Some((symbol.index().0, (name, symbol.address())))
        })
        .collect();
    let mut relocated = BTreeMap::new();
    let mut imported = BTreeMap::new();
    for (address, relocation) in relocations {
        let flags = relocation.flags();
        if let RelocationFlags::Elf { r_type } = flags
            && import_relocation(arch, r_type)
        {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Some((name, _)) = dynamic_symbols.get(&index.0) else {
                continue;
            };
            imported.insert(address, name.clone());
            if let Some(symbol) = symbols.iter().find(|symbol| {
                symbol.name == *name
                    && symbol
                        .section
                        .as_deref()
                        .is_some_and(|section| section == ".plt" || section == ".plt.sec")
            }) {
                relocated.insert(address, symbol.address & !1);
            }
            continue;
        }
        let addend = if relocation.has_implicit_addend() {
            raw_uint_at(sections, byte_order, address, pointer_size)
        } else {
            u64::try_from(relocation.addend()).ok()
        };
        let is_relative = match flags {
            RelocationFlags::Elf { r_type } => relative_pointer_relocation(arch, r_type),
            _ => relocation.kind() == RelocationKind::Relative,
        };
        let is_absolute = match flags {
            RelocationFlags::Elf { r_type } => absolute_pointer_relocation(arch, r_type),
            _ => relocation.kind() == RelocationKind::Absolute,
        };
        let value = if is_relative {
            addend
        } else if is_absolute {
            let Some(addend) = addend else {
                continue;
            };
            let base = match relocation.target() {
                RelocationTarget::Symbol(index) => {
                    dynamic_symbols.get(&index.0).and_then(|(name, address)| {
                        if *address == 0 {
                            symbols
                                .iter()
                                .find(|symbol| symbol.name == *name)
                                .map(|symbol| symbol.address & !1)
                        } else {
                            Some(*address)
                        }
                    })
                }
                RelocationTarget::Section(index) => file
                    .section_by_index(index)
                    .ok()
                    .map(|section| section.address()),
                _ => None,
            };
            base.and_then(|base| base.checked_add(addend))
        } else {
            None
        };
        if let Some(value) = value
            && value != 0
        {
            relocated.insert(address, value);
        }
    }
    (relocated, imported)
}

fn import_relocation(arch: ArchKind, r_type: u32) -> bool {
    match arch {
        ArchKind::X86_64 => {
            r_type == object::elf::R_X86_64_GLOB_DAT || r_type == object::elf::R_X86_64_JUMP_SLOT
        }
        ArchKind::Aarch64 => {
            r_type == object::elf::R_AARCH64_GLOB_DAT || r_type == object::elf::R_AARCH64_JUMP_SLOT
        }
        ArchKind::Riscv32 | ArchKind::Riscv64 => r_type == object::elf::R_RISCV_JUMP_SLOT,
        ArchKind::Thumb | ArchKind::Arm => {
            r_type == object::elf::R_ARM_GLOB_DAT || r_type == object::elf::R_ARM_JUMP_SLOT
        }
    }
}

fn relative_pointer_relocation(arch: ArchKind, r_type: u32) -> bool {
    match arch {
        ArchKind::X86_64 => r_type == object::elf::R_X86_64_RELATIVE,
        ArchKind::Aarch64 => r_type == object::elf::R_AARCH64_RELATIVE,
        ArchKind::Riscv32 | ArchKind::Riscv64 => r_type == object::elf::R_RISCV_RELATIVE,
        ArchKind::Thumb | ArchKind::Arm => r_type == object::elf::R_ARM_RELATIVE,
    }
}

fn absolute_pointer_relocation(arch: ArchKind, r_type: u32) -> bool {
    match arch {
        ArchKind::X86_64 => r_type == object::elf::R_X86_64_64,
        ArchKind::Aarch64 => r_type == object::elf::R_AARCH64_ABS64,
        ArchKind::Riscv32 => r_type == object::elf::R_RISCV_32,
        ArchKind::Riscv64 => r_type == object::elf::R_RISCV_64,
        ArchKind::Thumb | ArchKind::Arm => r_type == object::elf::R_ARM_ABS32,
    }
}

fn raw_uint_at(
    sections: &[Section],
    byte_order: ByteOrder,
    address: u64,
    size: usize,
) -> Option<u64> {
    let size_u64 = u64::try_from(size).ok()?;
    let end = address.checked_add(size_u64)?;
    let section = sections
        .iter()
        .find(|section| address >= section.address && end <= section.end())?;
    let offset = usize::try_from(address.checked_sub(section.address)?).ok()?;
    let bytes = section.data.get(offset..offset + size)?;
    match (byte_order, size) {
        (ByteOrder::Little, 4) => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        (ByteOrder::Little, 8) => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        (ByteOrder::Big, 4) => Some(u64::from(u32::from_be_bytes(bytes.try_into().ok()?))),
        (ByteOrder::Big, 8) => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

/// Adds synthetic function symbols for dynamic PLT stubs.
///
/// Calls in dynamic executables target PLT entries rather than the imported
/// function itself. Without these symbols a whole PLT block can be folded into
/// one function, so a call to `GOMP_parallel` or `std::thread::join` becomes a
/// call into another stub's body and no runtime rule can match it.
fn synthesize_plt_symbols(
    file: &object::File<'_>,
    sections: &[Section],
    arch: ArchKind,
    seen: &mut BTreeSet<(u64, String, u64)>,
    symbols: &mut Vec<ImageSymbol>,
) {
    // The 16-byte entry layout below is the x86-64/AArch64/RISC-V convention.
    if matches!(arch, ArchKind::Thumb | ArchKind::Arm) {
        return;
    }
    let Some(relocations) = file.dynamic_relocations() else {
        return;
    };
    // Relocation symbol indices refer to .dynsym, not to the unified symbol
    // table indexed by Object::symbol_by_index.
    let dynamic_names: BTreeMap<usize, String> = file
        .dynamic_symbols()
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            (!name.is_empty()).then(|| (symbol.index().0, name.to_owned()))
        })
        .collect();
    let mut jump_slots = Vec::new();
    for (offset, relocation) in relocations {
        let RelocationFlags::Elf { r_type } = relocation.flags() else {
            continue;
        };
        if !is_plt_jump_slot(arch, r_type) {
            continue;
        }
        let RelocationTarget::Symbol(index) = relocation.target() else {
            continue;
        };
        if let Some(name) = dynamic_names.get(&index.0) {
            jump_slots.push((offset, name.clone()));
        }
    }
    if jump_slots.is_empty() {
        return;
    }

    for section in sections
        .iter()
        .filter(|section| section.name == ".plt" || section.name == ".plt.sec")
    {
        let stub_size = 16u64;
        let first = if section.name == ".plt" {
            // x86-64 PLT0 is 16 bytes; AArch64/RISC-V reserve a 32-byte header.
            let header = if arch == ArchKind::X86_64 { 16 } else { 32 };
            section.address.saturating_add(header)
        } else {
            section.address
        };
        let mut address = first;
        let mut ordered = jump_slots.iter();
        while address.saturating_add(stub_size) <= section.end() {
            let name = if arch == ArchKind::X86_64 {
                plt_got_address(section, address).and_then(|got| {
                    jump_slots
                        .iter()
                        .find(|(offset, _)| *offset == got)
                        .map(|(_, name)| name.as_str())
                })
            } else {
                ordered.next().map(|(_, name)| name.as_str())
            };
            if let Some(name) = name
                && seen.insert((address, name.to_owned(), stub_size))
            {
                symbols.push(ImageSymbol {
                    name: name.to_owned(),
                    address,
                    canonical_address: address,
                    size: stub_size,
                    kind: SymbolKind::Text,
                    section: Some(section.name.clone()),
                    thumb: false,
                });
            }
            address = address.saturating_add(stub_size);
        }
    }
}

fn is_plt_jump_slot(arch: ArchKind, r_type: u32) -> bool {
    match arch {
        ArchKind::X86_64 => r_type == object::elf::R_X86_64_JUMP_SLOT,
        ArchKind::Aarch64 => r_type == object::elf::R_AARCH64_JUMP_SLOT,
        ArchKind::Riscv32 | ArchKind::Riscv64 => r_type == object::elf::R_RISCV_JUMP_SLOT,
        ArchKind::Thumb | ArchKind::Arm => r_type == object::elf::R_ARM_JUMP_SLOT,
    }
}

/// Extracts the GOT slot referenced by a 16-byte x86-64 PLT/PLT.sec stub.
fn plt_got_address(section: &Section, address: u64) -> Option<u64> {
    let offset = usize::try_from(address.checked_sub(section.address)?).ok()?;
    let stub = section.data.get(offset..offset + 16)?;
    let jmp = if stub.get(4..6) == Some(&[0xff, 0x25]) {
        4
    } else if stub.get(0..2) == Some(&[0xff, 0x25]) {
        0
    } else {
        return None;
    };
    let displacement = i32::from_le_bytes(stub.get(jmp + 2..jmp + 6)?.try_into().ok()?);
    Some(
        address
            .saturating_add(jmp as u64)
            .saturating_add(6)
            .wrapping_add_signed(i64::from(displacement)),
    )
}

fn detect_arch(file: &object::File<'_>, entry: u64, arm_cpu: Option<&str>) -> Result<ArchKind> {
    use object::Architecture;
    match file.architecture() {
        Architecture::Arm => {
            let cpu_is_mclass = arm_cpu.is_some_and(|cpu| cpu.contains("Cortex-M"));
            let entry_is_thumb = entry & 1 == 1;
            let any_thumb_symbol = file.symbols().any(|symbol| {
                symbol.kind() == SymbolKind::Text
                    && symbol.address() != 0
                    && symbol.address() & 1 == 1
            });
            if entry_is_thumb || any_thumb_symbol || cpu_is_mclass {
                Ok(ArchKind::Thumb)
            } else {
                Ok(ArchKind::Arm)
            }
        }
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => Ok(ArchKind::Aarch64),
        Architecture::Riscv32 => Ok(ArchKind::Riscv32),
        Architecture::Riscv64 => Ok(ArchKind::Riscv64),
        Architecture::X86_64 | Architecture::X86_64_X32 => Ok(ArchKind::X86_64),
        other => Err(Error::UnsupportedArchitecture(format!("{other:?}"))),
    }
}

fn is_executable_in(sections: &[Section], address: u64) -> bool {
    sections
        .iter()
        .any(|section| section.executable && section.contains(address))
}

fn elf_kind(bytes: &[u8], byte_order: ByteOrder) -> ElfKind {
    if bytes.len() < 18 || &bytes[..4] != b"\x7fELF" {
        return ElfKind::Unknown;
    }
    match byte_order.read_u16(bytes, 16) {
        Some(1) => ElfKind::Rel,
        Some(2) => ElfKind::Exec,
        Some(3) => ElfKind::Dyn,
        _ => ElfKind::Unknown,
    }
}

fn detect_arm_cpu(sections: &[Section]) -> Option<String> {
    // Prefer explicit CPU names. GCC often emits only the Tag_CPU_arch value
    // (for example "6S-M" or "7E-M"), so map those to the closest M0 timing
    // family. Users can always override with --cpu.
    const MARKERS: &[(&[u8], &str)] = &[
        (b"Cortex-M0+", "Cortex-M0+"),
        (b"Cortex-M0", "Cortex-M0"),
        (b"Cortex-M3", "Cortex-M3"),
        (b"Cortex-M4", "Cortex-M4"),
        (b"Cortex-M7", "Cortex-M7"),
        (b"Cortex-M23", "Cortex-M23"),
        (b"Cortex-M33", "Cortex-M33"),
        (b"Cortex-M35P", "Cortex-M35P"),
        (b"Cortex-M55", "Cortex-M55"),
        (b"Cortex-M85", "Cortex-M85"),
        (b"6S-M", "Cortex-M0"),
        (b"6-M", "Cortex-M0"),
        (b"7E-M", "Cortex-M4"),
        (b"7-M", "Cortex-M3"),
        (b"8-M", "Cortex-M33"),
    ];
    let attributes = sections
        .iter()
        .find(|section| section.name == ".ARM.attributes")?;
    MARKERS
        .iter()
        .find(|(marker, _)| contains_ascii(&attributes.data, marker))
        .map(|(_, cpu)| (*cpu).to_owned())
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn detect_vector_table(
    sections: &[Section],
    byte_order: ByteOrder,
    arch: ArchKind,
) -> Vec<VectorEntry> {
    let mut named: Vec<(&Section, usize)> = sections
        .iter()
        .filter(|section| is_vector_table_section_name(&section.name))
        .map(|section| (section, 0usize))
        .collect();
    named.sort_by_key(|(section, _)| section.address);

    for (section, offset) in named {
        let entries = parse_vector_table(section, offset, sections, byte_order);
        if !entries.is_empty() {
            return entries;
        }
    }

    // Cortex-M images do not always keep the vector table in a specially
    // named section. Look for the characteristic initial-SP word followed by
    // Thumb reset/handler addresses anywhere in the first part of an allocated
    // section, preferring non-executable data but also covering tables placed
    // at the start of `.text`.
    if arch == ArchKind::Thumb {
        let mut candidates: Vec<&Section> = sections
            .iter()
            .filter(|section| section.alloc && !section.data.is_empty())
            .collect();
        candidates.sort_by_key(|section| (!section.executable, section.address));
        for section in candidates {
            let search_end = section.data.len().min(0x2000);
            let mut offset = 0usize;
            while offset + 8 <= search_end {
                if looks_like_cortex_m_vector_table(section, offset, sections, byte_order) {
                    let entries = parse_vector_table(section, offset, sections, byte_order);
                    if !entries.is_empty() {
                        return entries;
                    }
                }
                offset += 4;
            }
        }
    }
    Vec::new()
}

fn is_vector_table_section_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == ".isr_vector"
        || name == ".vector_table"
        || name == ".vectors"
        || name == ".vector"
        || name.starts_with(".isr_vector.")
        || name.starts_with(".vector_table.")
        || name.starts_with(".vectors.")
        || name.ends_with("_vector_table")
        || name.ends_with("_vectors")
        || name.ends_with(".isr_vector")
        || name.ends_with(".vector_table")
        || name.ends_with(".vectors")
        || name.ends_with(".vector")
}

fn looks_like_cortex_m_vector_table(
    section: &Section,
    offset: usize,
    sections: &[Section],
    byte_order: ByteOrder,
) -> bool {
    let Some(initial_sp) = byte_order.read_u32(&section.data, offset) else {
        return false;
    };
    if initial_sp == 0 || initial_sp % 4 != 0 {
        return false;
    }
    if !points_into_writable_memory(sections, u64::from(initial_sp)) {
        return false;
    }
    let mut handlers = 0usize;
    for index in 1..8 {
        let Some(raw) = byte_order.read_u32(&section.data, offset + index * 4) else {
            break;
        };
        let raw = u64::from(raw);
        if raw == 0 || raw == u64::from(u32::MAX) {
            continue;
        }
        if raw & 1 == 0 || !is_executable_in(sections, raw & !1) {
            continue;
        }
        handlers += 1;
    }
    handlers >= 2
}

fn points_into_writable_memory(sections: &[Section], address: u64) -> bool {
    sections.iter().any(|section| {
        section.alloc && section.writable && address >= section.address && address <= section.end()
    })
}

fn parse_vector_table(
    section: &Section,
    offset: usize,
    sections: &[Section],
    byte_order: ByteOrder,
) -> Vec<VectorEntry> {
    let Some(remaining) = section.data.len().checked_sub(offset) else {
        return Vec::new();
    };
    let words = remaining / 4;
    let mut entries = Vec::new();
    for index in 1..words.min(1024) {
        let Some(raw) = byte_order.read_u32(&section.data, offset + index * 4) else {
            break;
        };
        let raw = u64::from(raw);
        if raw == 0 || raw == u64::from(u32::MAX) {
            continue;
        }
        let handler = raw & !1;
        if !is_executable_in(sections, handler) {
            continue;
        }
        entries.push(VectorEntry {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            raw,
            handler,
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::{ArchKind, ByteOrder, ElfKind, Section, detect_vector_table, elf_kind, load};

    fn section(
        name: &str,
        address: u64,
        size: u64,
        data: Vec<u8>,
        executable: bool,
        writable: bool,
    ) -> Section {
        Section {
            name: name.to_owned(),
            address,
            size,
            data,
            executable,
            writable,
            alloc: true,
        }
    }

    fn vector_words(initial_sp: u32, handlers: &[u32]) -> Vec<u8> {
        let mut words = vec![initial_sp];
        words.extend_from_slice(handlers);
        words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<u8>>()
    }

    #[test]
    fn detects_elf_kind() {
        let mut bytes = vec![0u8; 18];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[16] = 2;
        assert_eq!(elf_kind(&bytes, ByteOrder::Little), ElfKind::Exec);
        bytes[16] = 3;
        assert_eq!(elf_kind(&bytes, ByteOrder::Little), ElfKind::Dyn);
    }

    #[test]
    fn detects_named_cortex_m_vector_table() {
        let sections = vec![
            section(
                ".isr_vector",
                0x0800_0000,
                16,
                vector_words(0x2000_00f0, &[0x0800_0101, 0x0800_0201, 0x0800_0301]),
                false,
                false,
            ),
            section(".text", 0x0800_0100, 0x300, vec![0; 0x300], true, false),
            section(".ram", 0x2000_0000, 0x100, vec![0; 0x100], false, true),
        ];
        let entries = detect_vector_table(&sections, ByteOrder::Little, ArchKind::Thumb);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].index, 1);
        assert_eq!(entries[0].handler, 0x0800_0100);
        assert_eq!(entries[2].handler, 0x0800_0300);
    }

    #[test]
    fn detects_embedded_cortex_m_vector_table() {
        let mut text = vec![0u8; 0x300];
        text[0x100..0x110].copy_from_slice(&vector_words(
            0x2000_00f0,
            &[0x0800_0201, 0x0800_0301, 0x0800_0101],
        ));
        let sections = vec![
            section(".text", 0x0800_0100, 0x300, text, true, false),
            section(".ram", 0x2000_0000, 0x100, vec![0; 0x100], false, true),
        ];
        let entries = detect_vector_table(&sections, ByteOrder::Little, ArchKind::Thumb);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].index, 1);
        assert_eq!(entries[0].handler, 0x0800_0200);
        assert_eq!(entries[1].handler, 0x0800_0300);
    }

    #[test]
    fn loads_current_test_executable() {
        let exe = std::env::current_exe().expect("test executable path");
        let image = load(&exe).expect("host test executable is a valid ELF");
        assert!(!image.sections.is_empty());
        assert!(image.sections.iter().any(|section| section.executable));
        assert!(!image.symbols.is_empty());
        assert_ne!(image.segments.len(), 0);
        assert!(image.segments.iter().any(|segment| segment.executable));
        assert!(image.segments.iter().all(|segment| segment.size > 0));
        assert!(
            image
                .sections
                .iter()
                .any(|section| section.alloc && section.executable)
        );
    }
}
