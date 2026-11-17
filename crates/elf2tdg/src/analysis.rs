//! Function discovery, CFG/call-graph recovery and TDG assembly for M0.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use elf2tdg_schema::{
    Addr, BasicBlock, BlockId, Confidence, Context, ContextId, ContextKind, Diagnostic, Edge,
    EdgeId, ElfType, Endianness, FrequencyDomain, FrequencyDomainId, FrequencySource, Function,
    FunctionId, FunctionKind, FunctionTiming, ImageInfo, InstructionTiming, Language,
    SCHEMA_VERSION, Scheduling, Severity, SourceLoc, Tdg, TimingInfo, ToolInfo,
};

use petgraph::stable_graph::NodeIndex;

use crate::arch::{
    DecodedInsn, Decoder, IndirectTarget, ValueSource, is_frame_register, pointer_size,
    return_register,
};
use crate::cfg;
use crate::dwarf::DwarfInfo;
use crate::error::{Error, Result};
use crate::loader::{ArchKind, ByteOrder, ElfKind, Image, Section, VectorEntry};
use crate::origin;
use crate::rules;
use crate::timing::{CORE_DOMAIN, TimingModel};

const DEFAULT_MAX_FUNCTIONS: usize = 20_000;
const DEFAULT_MAX_INSTRUCTIONS_PER_FUNCTION: usize = 200_000;
const DEFAULT_MAX_DIAGNOSTICS: usize = 500;
const MAX_COMPUTED_CALL_CANDIDATES: usize = 32;

/// Analysis configuration.
#[derive(Clone, Debug)]
pub struct AnalysisOptions {
    /// Explicit CPU/timing model name. `None` auto-detects.
    pub cpu: Option<String>,
    /// Core frequency in Hz.
    pub frequency_hz: Option<u64>,
    /// Include per-instruction disassembly and timing.
    pub include_instructions: bool,
    /// Maximum number of function nodes.
    pub max_functions: usize,
    /// Maximum decoded instructions per function.
    pub max_instructions_per_function: usize,
    /// Maximum diagnostics retained in the TDG.
    pub max_diagnostics: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            cpu: None,
            frequency_hz: None,
            include_instructions: false,
            max_functions: DEFAULT_MAX_FUNCTIONS,
            max_instructions_per_function: DEFAULT_MAX_INSTRUCTIONS_PER_FUNCTION,
            max_diagnostics: DEFAULT_MAX_DIAGNOSTICS,
        }
    }
}

/// Result of an analysis run: the validated TDG and the intermediate CFGs.
#[derive(Clone, Debug)]
pub struct AnalysisOutput {
    /// Validated Task Dependency Graph.
    pub tdg: Tdg,
    /// Validated function-level control-flow graphs used to derive the TDG.
    pub cfg: cfg::ProgramCfg,
}

/// Analyzes an image and returns a validated TDG.
///
/// # Errors
///
/// Returns an error for unsupported architectures, invalid configuration,
/// resource limits, and TDG/CFG validation failures. Recoverable problems are
/// represented as TDG diagnostics.
pub fn analyze(image: &Image, options: &AnalysisOptions) -> Result<Tdg> {
    analyze_with_cfg(image, options).map(|output| output.tdg)
}

/// Analyzes an image and returns both the TDG and the function CFGs.
///
/// # Errors
///
/// Returns the same errors as [`analyze`].
pub fn analyze_with_cfg(image: &Image, options: &AnalysisOptions) -> Result<AnalysisOutput> {
    Analyzer::new(image, options)?.run()
}

struct Analyzer<'a> {
    image: &'a Image,
    options: &'a AnalysisOptions,
    decoder: Decoder,
    timing: Option<TimingModel>,
    functions: BTreeMap<u64, FunctionDraft>,
    queue: VecDeque<u64>,
    calls: Vec<CallDraft>,
    decoded_by_function: BTreeMap<u64, Vec<DecodedInsn>>,
    diagnostics: Vec<Diagnostic>,
    diagnostic_keys: BTreeSet<(String, Option<u64>, Option<u64>)>,
    startup_address: Option<u64>,
    isr_vectors: Vec<VectorEntry>,
    pointer_roots: BTreeSet<u64>,
    dwarf_function_names: BTreeMap<u64, NameChoice>,
}

#[derive(Clone, Debug)]
struct Seed {
    names: Vec<String>,
    size: u64,
    section: Option<String>,
}

#[derive(Clone, Debug)]
struct FunctionDraft {
    address: u64,
    size: u64,
    section: String,
    names: Vec<String>,
    display: String,
    demangled: Option<String>,
    language: Language,
    kind: FunctionKind,
    noreturn: Option<cfg::CfgNoreturnReason>,
    cfg: cfg::FunctionCfg,
    analyzed: bool,
}

struct CandidateCallResolution {
    caller: u64,
    site: u64,
    targets: Vec<u64>,
    tail: bool,
    conditional: bool,
    code: &'static str,
    message: String,
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct CallDraft {
    caller: u64,
    site: u64,
    target: u64,
    tail: bool,
    conditional: bool,
    heuristic: bool,
    direct: bool,
}

impl<'a> Analyzer<'a> {
    fn new(image: &'a Image, options: &'a AnalysisOptions) -> Result<Self> {
        if image.byte_order == ByteOrder::Big {
            return Err(Error::Config(
                "big-endian ELF images are not supported in M0".to_owned(),
            ));
        }
        let decoder = Decoder::new(image.arch)?;
        let timing = TimingModel::select(options.cpu.as_deref(), image)?;
        let mut analyzer = Self {
            image,
            options,
            decoder,
            timing,
            functions: BTreeMap::new(),
            queue: VecDeque::new(),
            calls: Vec::new(),
            decoded_by_function: BTreeMap::new(),
            diagnostics: Vec::new(),
            diagnostic_keys: BTreeSet::new(),
            startup_address: None,
            isr_vectors: Vec::new(),
            pointer_roots: BTreeSet::new(),
            dwarf_function_names: BTreeMap::new(),
        };
        analyzer.discover_functions()?;
        analyzer.discover_external_imports()?;
        if analyzer.functions.is_empty() {
            return Err(Error::Elf(
                "no function entry points could be recovered from symbols, DWARF subprograms, the ELF entry or the vector table"
                    .to_owned(),
            ));
        }
        Ok(analyzer)
    }

    fn run(mut self) -> Result<AnalysisOutput> {
        if let Some(error) = &self.image.dwarf_error {
            self.diag(
                Severity::Warning,
                "dwarf-parse-failed",
                format!("DWARF inline information ignored: {error}"),
                None,
                None,
            );
        } else if self
            .image
            .dwarf
            .as_ref()
            .is_some_and(|dwarf| dwarf.truncated)
        {
            self.diag(
                Severity::Warning,
                "dwarf-truncated",
                "DWARF extraction stopped at a safety limit; inline call coverage is partial",
                None,
                None,
            );
        }
        if !self.image.has_symbols {
            self.diag(
                Severity::Warning,
                "no-symbol-table",
                "image has no usable function symbols; relying on DWARF subprograms, the ELF entry point, vector tables, direct call targets and pointer roots",
                None,
                None,
            );
        }
        if self.timing.is_none() {
            self.diag(
                Severity::Info,
                "timing-model-unavailable",
                "no M0 instruction timing model is available for this architecture/CPU; cycles and times are omitted",
                None,
                None,
            );
        } else {
            if self.options.cpu.is_none()
                && let Some(model) = self.timing
            {
                self.diag(
                    Severity::Info,
                    "timing-model-auto-detected",
                    format!(
                        "auto-selected timing model {} ({}); use --cpu to override",
                        model.id(),
                        model.core()
                    ),
                    None,
                    None,
                );
            }
            if self.options.frequency_hz.is_none() {
                self.diag(
                    Severity::Info,
                    "frequency-unknown",
                    "no core frequency was supplied; block cycle counts are emitted without wall-clock time",
                    None,
                    None,
                );
            }
        }

        while let Some(address) = self.queue.pop_front() {
            self.analyze_function(address);
        }

        self.resolve_remaining_functions()?;
        self.resolve_computed_indirect_calls();
        self.resolve_embassy_executor_calls();
        self.resolve_trait_object_calls();
        self.resolve_dwarf_typed_field_calls();
        self.resolve_calls();
        self.infer_noreturn_functions();
        self.build_tdg()
    }

    #[allow(clippy::too_many_lines)]
    fn discover_external_imports(&mut self) -> Result<()> {
        for (slot, name) in &self.image.imported_slots {
            if self.image.relocated_pointers.contains_key(slot) || self.functions.contains_key(slot)
            {
                continue;
            }
            let choice = choose_name(std::slice::from_ref(name));
            let display = if choice.display.is_empty() {
                name.clone()
            } else {
                choice.display.clone()
            };
            let noreturn = classify_noreturn_names(
                std::iter::once(name.as_str()).chain(std::iter::once(display.as_str())),
            );
            self.functions.insert(
                *slot,
                FunctionDraft {
                    address: *slot,
                    size: 0,
                    section: ".external".to_owned(),
                    names: vec![name.clone()],
                    display,
                    demangled: choice.demangled,
                    language: choice.language,
                    kind: FunctionKind::External,
                    noreturn,
                    cfg: cfg::FunctionCfg::default(),
                    analyzed: true,
                },
            );
        }
        if self.functions.len() > self.options.max_functions {
            return Err(Error::Limit(format!(
                "{} functions exceed the configured maximum of {}",
                self.functions.len(),
                self.options.max_functions
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn discover_functions(&mut self) -> Result<()> {
        let mut seeds: BTreeMap<u64, Seed> = BTreeMap::new();
        for symbol in &self.image.symbols {
            let address = symbol.canonical_address;
            if !self.image.is_executable(address) {
                continue;
            }
            let seed = seeds.entry(address).or_insert_with(|| Seed {
                names: Vec::new(),
                size: 0,
                section: symbol.section.clone(),
            });
            if !seed.names.contains(&symbol.name) {
                seed.names.push(symbol.name.clone());
            }
            seed.size = seed.size.max(symbol.size);
            if seed.section.is_none() {
                seed.section.clone_from(&symbol.section);
            }
        }

        let entry = self.image.canonical_address(self.image.entry);
        let entry_is_inside = self.image.symbols.iter().any(|symbol| {
            symbol.size > 0
                && entry >= symbol.canonical_address
                && entry < symbol.canonical_address.saturating_add(symbol.size)
        });
        if self.image.is_executable(entry) && !entry_is_inside {
            seeds.entry(entry).or_insert_with(|| Seed {
                names: Vec::new(),
                size: 0,
                section: self.image.section_name_for(entry).map(str::to_owned),
            });
        }

        for vector in &self.image.vector_table {
            let handler = self.image.canonical_address(vector.handler);
            if !self.image.is_executable(handler) {
                continue;
            }
            let inside = self.image.symbols.iter().any(|symbol| {
                symbol.size > 0
                    && handler >= symbol.canonical_address
                    && handler < symbol.canonical_address.saturating_add(symbol.size)
            });
            if !inside {
                seeds.entry(handler).or_insert_with(|| Seed {
                    names: Vec::new(),
                    size: 0,
                    section: self.image.section_name_for(handler).map(str::to_owned),
                });
            }
        }

        if !self.has_code_symbols() {
            let heuristic = self.heuristic_function_seeds();
            if !heuristic.is_empty() {
                self.diag(
                    Severity::Info,
                    "stripped-heuristic-seeds",
                    format!(
                        "image has no code symbols; recovered {} additional function prologue seed(s)",
                        heuristic.len()
                    ),
                    None,
                    None,
                );
            }
            for address in heuristic {
                seeds.entry(address).or_insert_with(|| Seed {
                    names: Vec::new(),
                    size: 0,
                    section: self.image.section_name_for(address).map(str::to_owned),
                });
            }
        }

        self.discover_pointer_roots(&mut seeds);
        self.discover_architecture_roots(&mut seeds);
        self.discover_dwarf_functions(&mut seeds);

        if seeds.is_empty() {
            return Ok(());
        }

        let addresses: Vec<u64> = seeds.keys().copied().collect();
        let reset = self
            .image
            .vector_table
            .iter()
            .find(|entry| entry.index == 1)
            .map(|entry| self.image.canonical_address(entry.handler));
        let isr_addresses: BTreeSet<u64> = self
            .image
            .vector_table
            .iter()
            .filter(|entry| entry.index >= 2)
            .map(|entry| self.image.canonical_address(entry.handler))
            .collect();
        self.isr_vectors = self
            .image
            .vector_table
            .iter()
            .filter(|entry| entry.index >= 2)
            .copied()
            .collect();

        for (index, address) in addresses.iter().copied().enumerate() {
            let Some(seed) = seeds.get(&address) else {
                continue;
            };
            let Some(section_end) = self.image.section_end_for(address) else {
                continue;
            };
            let next = addresses
                .get(index + 1)
                .copied()
                .filter(|next| *next < section_end)
                .unwrap_or(section_end);
            let limit = next.saturating_sub(address);
            let size = if seed.size == 0 {
                limit
            } else {
                seed.size.min(limit)
            };
            let mut choice = choose_name(&seed.names);
            if choice.display.is_empty()
                && let Some(dwarf_choice) = self.dwarf_function_names.get(&address)
            {
                choice = dwarf_choice.clone();
            }
            if choice.display.is_empty() {
                choice.display = format!("sub_0x{address:x}");
                choice.language = Language::Unknown;
            }
            let section = seed
                .section
                .clone()
                .or_else(|| self.image.section_name_for(address).map(str::to_owned))
                .unwrap_or_else(|| "<unknown>".to_owned());
            let is_plt = section == ".plt" || section == ".plt.sec";
            let kind = if reset == Some(address) || entry == address {
                FunctionKind::Entry
            } else if isr_addresses.contains(&address) {
                FunctionKind::Isr
            } else if is_plt {
                FunctionKind::Plt
            } else {
                FunctionKind::Normal
            };
            let noreturn = classify_noreturn_names(
                seed.names
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(choice.display.as_str())),
            );
            self.functions.insert(
                address,
                FunctionDraft {
                    address,
                    size,
                    section,
                    names: seed.names.clone(),
                    display: choice.display,
                    demangled: choice.demangled,
                    language: choice.language,
                    kind,
                    noreturn,
                    cfg: cfg::FunctionCfg::default(),
                    analyzed: false,
                },
            );
            // PLT entries are import trampolines, not user code. Keep a named
            // node for call-graph resolution but do not recursively analyze
            // their jump through the GOT.
            if !is_plt {
                self.queue.push_back(address);
            }
        }
        if self.functions.len() > self.options.max_functions {
            return Err(Error::Limit(format!(
                "{} functions exceed the configured maximum of {}",
                self.functions.len(),
                self.options.max_functions
            )));
        }

        self.startup_address = self.resolve_startup_address(reset, entry);
        if let Some(startup) = self.startup_address
            && let Some(function) = self.functions.get_mut(&startup)
        {
            function.kind = FunctionKind::Entry;
        }
        Ok(())
    }

    /// Adds function entries referenced by pointer-sized words in allocated
    /// data sections and remembers them as pointer roots.
    ///
    /// A value is accepted when it already names a discovered function seed or
    /// when the slot/table itself is strong evidence: a resolved relocation,
    /// an init/fini array, a Thumb function pointer, or a plausible function
    /// prologue. This avoids treating arbitrary integers that happen to look
    /// like code addresses as roots.
    fn discover_pointer_roots(&mut self, seeds: &mut BTreeMap<u64, Seed>) {
        let pointer = u64::try_from(pointer_size(self.image.arch)).unwrap_or(0);
        if pointer == 0 {
            return;
        }
        let mut roots = BTreeSet::new();
        for section in &self.image.sections {
            if !is_pointer_root_section(section) {
                continue;
            }
            let data_len = u64::try_from(section.data.len()).unwrap_or(u64::MAX);
            let mut offset = (pointer - (section.address % pointer)) % pointer;
            while offset.saturating_add(pointer) <= data_len {
                let address = section.address.saturating_add(offset);
                if let Some(value) = self.image.read_pointer(address) {
                    let target = self.image.canonical_address(value);
                    if value != 0 && self.image.is_executable(target) {
                        let known = seeds.contains_key(&target);
                        let strong = self.image.relocated_pointers.contains_key(&address)
                            || is_static_init_array(&section.name)
                            || (self.image.arch.is_arm_family() && (value & 1) == 1)
                            || self.looks_like_function(target);
                        if known || strong {
                            if !known {
                                seeds.entry(target).or_insert_with(|| Seed {
                                    names: Vec::new(),
                                    size: 0,
                                    section: self.image.section_name_for(target).map(str::to_owned),
                                });
                            }
                            roots.insert(target);
                        }
                    }
                }
                offset = offset.saturating_add(pointer);
            }
        }
        if !roots.is_empty() {
            self.diag(
                Severity::Info,
                "pointer-roots",
                format!(
                    "recovered {} function pointer root(s) from allocated data",
                    roots.len()
                ),
                None,
                None,
            );
        }
        self.pointer_roots = roots;
    }

    fn discover_architecture_roots(&mut self, seeds: &mut BTreeMap<u64, Seed>) {
        for target in cfg::architecture_root_addresses(self.image) {
            if !self.image.is_executable(target) {
                continue;
            }
            seeds.entry(target).or_insert_with(|| Seed {
                names: Vec::new(),
                size: 0,
                section: self.image.section_name_for(target).map(str::to_owned),
            });
        }
    }

    fn discover_dwarf_functions(&mut self, seeds: &mut BTreeMap<u64, Seed>) {
        let Some(dwarf) = self.image.dwarf.as_ref() else {
            return;
        };
        for function in &dwarf.functions {
            let Some((low, high)) = function.primary_range() else {
                continue;
            };
            let low = self.image.canonical_address(low);
            if high <= low || !self.image.is_executable(low) {
                continue;
            }
            let size = high - low;
            let seed = seeds.entry(low).or_insert_with(|| Seed {
                names: Vec::new(),
                size: 0,
                section: self.image.section_name_for(low).map(str::to_owned),
            });
            if seed.size == 0 {
                seed.size = size;
            }
            if let Some(raw) = function
                .linkage_name
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .or(function.name.as_deref())
            {
                let choice = choose_name(&[raw.to_owned()]);
                if !choice.display.is_empty() {
                    self.dwarf_function_names.entry(low).or_insert(choice);
                }
            }
        }
    }

    fn looks_like_function(&self, address: u64) -> bool {
        self.image
            .bytes_at(address, 16)
            .and_then(|bytes| self.decoder.decode_one(bytes, address).ok().flatten())
            .is_some_and(|insn| self.is_prologue_seed(&insn, address))
    }

    fn has_code_symbols(&self) -> bool {
        self.image.symbols.iter().any(|symbol| {
            symbol
                .section
                .as_deref()
                .is_none_or(|section| section != ".plt" && section != ".plt.sec")
        })
    }

    /// Scans executable bytes for common function prologues when the symbol
    /// table is absent. This is deliberately conservative and only supplements
    /// entry/vector/call-target seeds.
    fn heuristic_function_seeds(&self) -> Vec<u64> {
        let fallback_step = match self.image.arch {
            crate::loader::ArchKind::X86_64 => 1,
            crate::loader::ArchKind::Thumb
            | crate::loader::ArchKind::Riscv32
            | crate::loader::ArchKind::Riscv64 => 2,
            crate::loader::ArchKind::Arm | crate::loader::ArchKind::Aarch64 => 4,
        };
        let mut seeds = BTreeSet::new();
        let mut scanned = 0usize;
        let limit = self.options.max_instructions_per_function.saturating_mul(8);
        for section in self
            .image
            .sections
            .iter()
            .filter(|section| section.executable)
        {
            let mut address = section.address;
            while address < section.end() && scanned < limit {
                let Some(bytes) = self.image.bytes_at(address, 16) else {
                    break;
                };
                let Ok(Some(insn)) = self.decoder.decode_one(bytes, address) else {
                    address = address.saturating_add(fallback_step);
                    scanned += 1;
                    continue;
                };
                let size = u64::from(insn.size);
                if size == 0 {
                    address = address.saturating_add(fallback_step);
                    scanned += 1;
                    continue;
                }
                if self.is_prologue_seed(&insn, address) {
                    seeds.insert(address);
                }
                address = address.saturating_add(size);
                scanned += 1;
            }
        }
        seeds.into_iter().collect()
    }

    fn is_prologue_seed(&self, insn: &DecodedInsn, address: u64) -> bool {
        let operands = insn.operands.replace(' ', "");
        match self.image.arch {
            crate::loader::ArchKind::X86_64 => {
                if matches!(insn.mnemonic.as_str(), "endbr64" | "endbr32") {
                    return true;
                }
                if insn.mnemonic.starts_with("push") && operands.starts_with("rbp") {
                    let next = address.saturating_add(u64::from(insn.size));
                    return self
                        .image
                        .bytes_at(next, 16)
                        .and_then(|bytes| self.decoder.decode_one(bytes, next).ok().flatten())
                        .is_some_and(|next| {
                            next.mnemonic == "mov"
                                && next.operands.replace(' ', "").starts_with("rbp,rsp")
                        });
                }
                false
            }
            crate::loader::ArchKind::Thumb | crate::loader::ArchKind::Arm => {
                insn.mnemonic.starts_with("push") && operands.contains("lr")
            }
            crate::loader::ArchKind::Aarch64 => {
                insn.mnemonic.starts_with("stp") && operands.starts_with("x29,x30")
            }
            crate::loader::ArchKind::Riscv32 | crate::loader::ArchKind::Riscv64 => {
                insn.mnemonic == "addi" && operands.starts_with("sp,sp,-")
            }
        }
    }

    fn resolve_startup_address(&self, reset: Option<u64>, entry: u64) -> Option<u64> {
        if let Some(reset) = reset
            && let Some(address) = self.resolve_function_address(reset)
        {
            return Some(address);
        }
        if let Some(address) = self.resolve_function_address(entry) {
            return Some(address);
        }
        self.functions.keys().next().copied()
    }

    #[allow(clippy::too_many_lines)]
    fn analyze_function(&mut self, address: u64) {
        let Some(function) = self.functions.get(&address) else {
            return;
        };
        if function.analyzed {
            return;
        }
        let start = function.address;
        let size = function.size;
        if size == 0 {
            if let Some(function) = self.functions.get_mut(&address) {
                function.analyzed = true;
            }
            self.diag(
                Severity::Info,
                "function-size-unknown",
                "function has no known size; basic blocks were not recovered",
                Some(start),
                None,
            );
            return;
        }
        let Some(end) = start.checked_add(size) else {
            self.diag(
                Severity::Warning,
                "function-range-overflow",
                "function address range overflows u64",
                Some(start),
                None,
            );
            if let Some(function) = self.functions.get_mut(&address) {
                function.analyzed = true;
            }
            return;
        };

        let mut decoded: BTreeMap<u64, DecodedInsn> = BTreeMap::new();
        let mut starts: BTreeSet<u64> = BTreeSet::new();
        starts.insert(start);
        let mut work: VecDeque<u64> = VecDeque::new();
        work.push_back(start);
        let mut calls: Vec<CallDraft> = Vec::new();
        let mut unresolved_indirect_calls: Vec<(u64, String)> = Vec::new();
        let mut null_indirect_sites: BTreeSet<u64> = BTreeSet::new();
        let mut unresolved_indirect_jumps: Vec<(u64, String)> = Vec::new();
        let mut resolved_indirect_jumps: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut hit_instruction_limit = false;
        let mut saw_indirect_jump = false;

        while let Some(current) = work.pop_front() {
            if current < start || current >= end {
                continue;
            }
            if decoded.contains_key(&current) {
                continue;
            }
            if decoded.len() >= self.options.max_instructions_per_function {
                hit_instruction_limit = true;
                break;
            }
            let remaining = end - current;
            let max_len = usize::try_from(remaining.min(16)).unwrap_or(16);
            let Some(bytes) = self.image.bytes_at(current, max_len) else {
                self.diag(
                    Severity::Warning,
                    "missing-code-bytes",
                    format!("no file-backed code bytes at 0x{current:x}"),
                    Some(start),
                    Some(current),
                );
                continue;
            };
            let insn = match self.decoder.decode_one(bytes, current) {
                Ok(Some(insn)) => insn,
                Ok(None) => {
                    self.diag(
                        Severity::Warning,
                        "decode-failed",
                        format!("could not decode an instruction at 0x{current:x}"),
                        Some(start),
                        Some(current),
                    );
                    continue;
                }
                Err(error) => {
                    self.diag(
                        Severity::Warning,
                        "decode-failed",
                        error.to_string(),
                        Some(start),
                        Some(current),
                    );
                    continue;
                }
            };
            let insn_size = u64::from(insn.size);
            let Some(next) = current.checked_add(insn_size) else {
                break;
            };
            if insn_size == 0 || next > end {
                self.diag(
                    Severity::Warning,
                    "truncated-instruction",
                    format!(
                        "instruction at 0x{current:x} ({} bytes) crosses the function end 0x{end:x}",
                        insn.size
                    ),
                    Some(start),
                    Some(current),
                );
                continue;
            }
            decoded.insert(current, insn.clone());
            let target = insn
                .direct_target
                .map(|target| self.image.canonical_address(target));

            if insn.is_call {
                let mut direct_noreturn = false;
                if let Some(target) = target {
                    if self.image.is_executable(target) {
                        direct_noreturn = self.function_is_noreturn(target);
                        calls.push(CallDraft {
                            caller: start,
                            site: current,
                            target,
                            tail: false,
                            conditional: insn.is_conditional,
                            heuristic: false,
                            direct: true,
                        });
                        if target >= start && target < end {
                            starts.insert(target);
                            work.push_back(target);
                        }
                    } else {
                        self.diag(
                            Severity::Warning,
                            "call-target-outside-image",
                            format!(
                                "call at 0x{current:x} targets 0x{target:x}, which is not executable"
                            ),
                            Some(start),
                            Some(current),
                        );
                    }
                } else {
                    unresolved_indirect_calls.push((current, insn_text(&insn)));
                }
                if !direct_noreturn && !insn.is_conditional && next < end {
                    starts.insert(next);
                    work.push_back(next);
                }
                continue;
            }

            if insn.is_jump {
                if let Some(target) = target {
                    if target >= start && target < end {
                        starts.insert(target);
                        work.push_back(target);
                    } else if self.image.is_executable(target) {
                        calls.push(CallDraft {
                            caller: start,
                            site: current,
                            target,
                            tail: true,
                            conditional: insn.is_conditional,
                            heuristic: false,
                            direct: true,
                        });
                        if insn.is_conditional {
                            self.diag(
                                Severity::Info,
                                "conditional-external-branch",
                                format!(
                                    "conditional branch at 0x{current:x} leaves the function to 0x{target:x}; modeled as a tail call"
                                ),
                                Some(start),
                                Some(current),
                            );
                        }
                    } else {
                        self.diag(
                            Severity::Warning,
                            "branch-target-outside-image",
                            format!(
                                "branch at 0x{current:x} targets 0x{target:x}, which is not executable"
                            ),
                            Some(start),
                            Some(current),
                        );
                    }
                } else {
                    let decoded_before: Vec<DecodedInsn> = decoded.values().cloned().collect();
                    let targets =
                        self.resolve_indirect_jump_targets(&decoded_before, current, insn.indirect);
                    if targets.is_empty() {
                        saw_indirect_jump = true;
                        unresolved_indirect_jumps.push((current, insn_text(&insn)));
                    } else {
                        for target in &targets {
                            if *target < start || *target >= end {
                                calls.push(CallDraft {
                                    caller: start,
                                    site: current,
                                    target: *target,
                                    tail: true,
                                    conditional: insn.is_conditional,
                                    heuristic: false,
                                    direct: false,
                                });
                            } else {
                                starts.insert(*target);
                                if !decoded.contains_key(target) {
                                    work.push_back(*target);
                                }
                            }
                        }
                        self.diag(
                            Severity::Info,
                            if targets.len() > 1
                                || matches!(
                                    insn.indirect,
                                    Some(IndirectTarget::IndexedMemory { .. })
                                )
                            {
                                "resolved-jump-table"
                            } else {
                                "resolved-indirect-jump"
                            },
                            format!(
                                "resolved indirect jump at 0x{current:x} to {} target(s)",
                                targets.len()
                            ),
                            Some(start),
                            Some(current),
                        );
                        resolved_indirect_jumps.insert(current, targets);
                    }
                }
                if insn.is_conditional && next < end {
                    starts.insert(next);
                    work.push_back(next);
                }
                continue;
            }

            if insn.is_return {
                continue;
            }
            if next < end {
                work.push_back(next);
            }
        }

        if hit_instruction_limit {
            self.diag(
                Severity::Warning,
                "instruction-limit-reached",
                format!(
                    "function at 0x{start:x} exceeded the {} instruction limit; CFG is partial",
                    self.options.max_instructions_per_function
                ),
                Some(start),
                None,
            );
        }

        if saw_indirect_jump {
            let mut seen: BTreeSet<(u64, u64)> =
                calls.iter().map(|call| (call.site, call.target)).collect();
            let mut recovered = Vec::new();
            let mut gaps = Vec::new();
            let mut intervals: Vec<(u64, u64)> = decoded
                .values()
                .map(|instruction| {
                    (
                        instruction.address,
                        instruction.address + u64::from(instruction.size),
                    )
                })
                .collect();
            intervals.sort_unstable();
            let mut cursor = start;
            for (begin, end_of_instruction) in intervals {
                if begin > cursor {
                    gaps.push((cursor, begin));
                }
                cursor = cursor.max(end_of_instruction);
            }
            if cursor < end {
                gaps.push((cursor, end));
            }
            for (gap_start, gap_end) in gaps {
                self.scan_undecoded_calls(start, gap_start, gap_end, &mut seen, &mut recovered);
            }
            if !recovered.is_empty() {
                self.diag(
                    Severity::Info,
                    "heuristic-direct-calls",
                    format!(
                        "recovered {} direct call site(s) after unresolved indirect jumps in 0x{start:x}; edges are low confidence",
                        recovered.len()
                    ),
                    Some(start),
                    None,
                );
                calls.extend(recovered);
            }
        }
        let decoded_sorted: Vec<DecodedInsn> = decoded.values().cloned().collect();
        for (site, text) in &unresolved_indirect_jumps {
            if resolved_indirect_jumps.contains_key(site) {
                continue;
            }
            self.diag(
                Severity::Warning,
                "unresolved-indirect-jump",
                format!("indirect jump at 0x{site:x} ({text}) has no statically known target"),
                Some(start),
                Some(*site),
            );
        }
        let mut resolved_indirect = BTreeSet::new();
        let mut resolved_indirect_sites = BTreeSet::new();
        for insn in &decoded_sorted {
            if !insn.is_call || insn.direct_target.is_some() {
                continue;
            }
            let Some(reference) = insn.indirect else {
                continue;
            };
            let Some(value) = origin::resolve_indirect_target_value(
                self.image,
                &decoded_sorted,
                insn.address,
                reference,
            ) else {
                continue;
            };
            if value == 0 {
                null_indirect_sites.insert(insn.address);
                continue;
            }
            let target = if self.image.import_name_at(value).is_some() {
                self.image.canonical_address(value)
            } else {
                let canonical = self.image.canonical_address(value);
                if !self.image.is_executable(canonical) {
                    continue;
                }
                canonical
            };
            if !self.functions.contains_key(&target)
                || !resolved_indirect.insert((insn.address, target))
            {
                continue;
            }
            calls.push(CallDraft {
                caller: start,
                site: insn.address,
                target,
                tail: false,
                conditional: insn.is_conditional,
                heuristic: false,
                direct: false,
            });
            resolved_indirect_sites.insert(insn.address);
            self.diag(
                Severity::Info,
                "resolved-indirect-call",
                format!(
                    "resolved indirect call at 0x{:x} to 0x{target:x} from a register/memory pointer",
                    insn.address
                ),
                Some(start),
                Some(insn.address),
            );
        }
        for (site, text) in unresolved_indirect_calls {
            if resolved_indirect_sites.contains(&site) || null_indirect_sites.contains(&site) {
                continue;
            }
            self.diag(
                Severity::Warning,
                "unresolved-indirect-call",
                format!("indirect call at 0x{site:x} ({text}) has no statically known target"),
                Some(start),
                Some(site),
            );
        }
        for site in &null_indirect_sites {
            self.diag(
                Severity::Info,
                "null-indirect-call-target",
                format!(
                    "indirect call at 0x{site:x} reads a statically null function pointer; no call edge"
                ),
                Some(start),
                Some(*site),
            );
        }
        self.decoded_by_function
            .insert(start, decoded_sorted.clone());

        let mut call_sites: BTreeMap<u64, cfg::CfgCallSite> = BTreeMap::new();
        for call in &calls {
            call_sites.insert(
                call.site,
                cfg::CfgCallSite {
                    site: call.site,
                    target: Some(call.target),
                    target_function: self
                        .functions
                        .contains_key(&call.target)
                        .then(|| function_id(call.target)),
                    direct: call.direct,
                    tail: call.tail,
                    conditional: call.conditional,
                    heuristic: call.heuristic,
                    unresolved: false,
                    null_target: false,
                    noreturn: !call.conditional && self.function_is_noreturn(call.target),
                    candidates: Vec::new(),
                },
            );
        }
        for insn in decoded_sorted.iter().filter(|insn| insn.is_call) {
            if null_indirect_sites.contains(&insn.address) {
                call_sites.insert(
                    insn.address,
                    cfg::CfgCallSite {
                        site: insn.address,
                        target: None,
                        target_function: None,
                        direct: false,
                        tail: false,
                        conditional: insn.is_conditional,
                        heuristic: false,
                        unresolved: false,
                        null_target: true,
                        noreturn: false,
                        candidates: Vec::new(),
                    },
                );
                continue;
            }
            call_sites.entry(insn.address).or_insert_with(|| {
                let target = insn
                    .direct_target
                    .map(|target| self.image.canonical_address(target));
                cfg::CfgCallSite {
                    site: insn.address,
                    target,
                    target_function: target.and_then(|target| {
                        self.functions
                            .contains_key(&target)
                            .then(|| function_id(target))
                    }),
                    direct: insn.direct_target.is_some(),
                    tail: false,
                    conditional: insn.is_conditional,
                    heuristic: false,
                    unresolved: true,
                    null_target: false,
                    noreturn: false,
                    candidates: Vec::new(),
                }
            });
        }
        for insn in decoded_sorted
            .iter()
            .filter(|insn| insn.is_jump && insn.direct_target.is_none())
        {
            if resolved_indirect_jumps.contains_key(&insn.address) {
                continue;
            }
            call_sites
                .entry(insn.address)
                .or_insert_with(|| cfg::CfgCallSite {
                    site: insn.address,
                    target: None,
                    target_function: None,
                    direct: false,
                    tail: true,
                    conditional: insn.is_conditional,
                    heuristic: false,
                    unresolved: true,
                    null_target: false,
                    noreturn: false,
                    candidates: Vec::new(),
                });
        }

        let block_starts: BTreeSet<u64> = starts
            .into_iter()
            .filter(|start| decoded.contains_key(start))
            .collect();
        let mut block_drafts = Vec::new();
        let mut edge_drafts = Vec::new();
        for block_start in &block_starts {
            let mut instructions = Vec::new();
            let mut cursor = *block_start;
            while let Some(insn) = decoded.get(&cursor) {
                let next = cursor + u64::from(insn.size);
                instructions.push(insn.clone());
                if next >= end || !decoded.contains_key(&next) || block_starts.contains(&next) {
                    break;
                }
                cursor = next;
            }
            if instructions.is_empty() {
                continue;
            }
            let last = instructions.last().expect("non-empty instructions");
            let block_end = last.address + u64::from(last.size);
            let noreturn_call = last.is_call
                && call_sites
                    .get(&last.address)
                    .is_some_and(|call| call.noreturn && !call.conditional);
            let mut successors = Vec::new();
            if last.is_return {
                // no successors
            } else if last.is_jump {
                let direct_target = last
                    .direct_target
                    .map(|target| self.image.canonical_address(target));
                if let Some(target) = direct_target
                    && decoded.contains_key(&target)
                {
                    successors.push(target);
                }
                if let Some(targets) = resolved_indirect_jumps.get(&last.address) {
                    for target in targets {
                        if decoded.contains_key(target) {
                            successors.push(*target);
                        }
                    }
                }
                if last.is_conditional && decoded.contains_key(&block_end) {
                    successors.push(block_end);
                }
            } else if !noreturn_call && decoded.contains_key(&block_end) {
                successors.push(block_end);
            }
            successors.sort_unstable();
            successors.dedup();
            for successor in &successors {
                let kind = if last.is_call {
                    cfg::CfgEdgeKind::CallReturn
                } else if last.is_conditional {
                    let direct_target = last
                        .direct_target
                        .map(|target| self.image.canonical_address(target));
                    let resolved_target = resolved_indirect_jumps
                        .get(&last.address)
                        .is_some_and(|targets| targets.contains(successor));
                    if direct_target == Some(*successor) || resolved_target {
                        cfg::CfgEdgeKind::Branch
                    } else {
                        cfg::CfgEdgeKind::Fallthrough
                    }
                } else if last.is_jump {
                    cfg::CfgEdgeKind::Jump
                } else {
                    cfg::CfgEdgeKind::Fallthrough
                };
                edge_drafts.push(cfg::CfgEdgeDraft {
                    from: *block_start,
                    to: *successor,
                    kind,
                    site: last.address,
                    conditional: last.is_conditional,
                });
            }
            let cycles = self.timing.map(|model| sum_costs(model, &instructions));
            let cfg_instructions = instructions
                .iter()
                .map(|instruction| self.cfg_instruction(instruction))
                .collect();
            let calls = call_sites
                .range(*block_start..block_end)
                .map(|(_, call)| call.clone())
                .collect();
            block_drafts.push(cfg::CfgBlockDraft {
                address: *block_start,
                size: block_end.saturating_sub(*block_start),
                instructions: cfg_instructions,
                calls,
                cycles,
                terminator: self.cfg_terminator(
                    last,
                    start,
                    end,
                    resolved_indirect_jumps
                        .get(&last.address)
                        .map(Vec::as_slice),
                    noreturn_call,
                ),
            });
        }
        let attached_calls: BTreeSet<u64> = block_drafts
            .iter()
            .flat_map(|block| block.calls.iter().map(|call| call.site))
            .collect();
        let mut referenced_addresses = BTreeSet::new();
        for instruction in &decoded_sorted {
            self.collect_code_references(instruction, &mut referenced_addresses);
        }
        let mut function_cfg = cfg::FunctionCfg::build(block_drafts, edge_drafts, Some(start));
        function_cfg.referenced_addresses = referenced_addresses.into_iter().collect();
        function_cfg.recovered_calls = call_sites
            .values()
            .filter(|call| !attached_calls.contains(&call.site))
            .cloned()
            .collect();

        if let Some(function) = self.functions.get_mut(&address) {
            function.cfg = function_cfg;
            function.analyzed = true;
        }
        self.calls.extend(calls);
    }

    fn function_is_noreturn(&self, address: u64) -> bool {
        self.resolve_function_address(address)
            .and_then(|address| self.functions.get(&address))
            .is_some_and(|function| function.noreturn.is_some())
    }

    fn call_is_noreturn(&self, call: &cfg::CfgCallSite) -> bool {
        if call.unresolved || call.conditional {
            return false;
        }
        if call.null_target {
            // A statically null function pointer traps if this path executes.
            return true;
        }
        let targets: Vec<u64> = if call.candidates.is_empty() {
            call.target.into_iter().collect()
        } else {
            call.candidates
                .iter()
                .map(|candidate| candidate.target)
                .collect()
        };
        !targets.is_empty()
            && targets
                .iter()
                .all(|target| self.function_is_noreturn(*target))
    }

    fn refresh_call_noreturn(&mut self) -> bool {
        let mut updates = Vec::new();
        for (address, function) in &self.functions {
            for call in function
                .cfg
                .blocks_by_address
                .values()
                .flat_map(|node| function.cfg.graph[*node].calls.iter())
                .chain(function.cfg.recovered_calls.iter())
            {
                let noreturn = self.call_is_noreturn(call);
                if noreturn != call.noreturn {
                    updates.push((*address, call.site, noreturn));
                }
            }
        }
        let mut changed = false;
        for (address, site, noreturn) in updates {
            changed |= self.set_call_noreturn(address, site, noreturn);
        }
        changed
    }

    fn set_call_noreturn(&mut self, function_address: u64, site: u64, noreturn: bool) -> bool {
        let Some(function) = self.functions.get_mut(&function_address) else {
            return false;
        };
        let nodes: Vec<NodeIndex> = function.cfg.blocks_by_address.values().copied().collect();
        let mut changed = false;
        for node in nodes {
            for call in &mut function.cfg.graph[node].calls {
                if call.site == site && call.noreturn != noreturn {
                    call.noreturn = noreturn;
                    changed = true;
                }
            }
        }
        for call in &mut function.cfg.recovered_calls {
            if call.site == site && call.noreturn != noreturn {
                call.noreturn = noreturn;
                changed = true;
            }
        }
        changed
    }

    /// Iteratively classifies functions whose recovered CFG has no path back
    /// to the caller, then removes return continuations that are impossible.
    ///
    /// The iteration is monotone: a function only ever moves from "may
    /// return" to "noreturn". A reverse call-site index lets a newly inferred
    /// callee dirty only its actual callers instead of rescanning the image.
    fn infer_noreturn_functions(&mut self) {
        let callers_by_callee = self.callers_by_callee();
        self.refresh_call_noreturn();

        let mut dirty: BTreeSet<u64> = BTreeSet::new();
        let addresses: Vec<u64> = self.functions.keys().copied().collect();
        for address in addresses {
            self.classify_function_if_noreturn(address, &callers_by_callee, &mut dirty);
        }
        while let Some(address) = dirty.pop_first() {
            self.classify_function_if_noreturn(address, &callers_by_callee, &mut dirty);
        }

        for function in self.functions.values_mut() {
            function.cfg.prune_noreturn_continuations();
        }
    }

    fn classify_function_if_noreturn(
        &mut self,
        address: u64,
        callers_by_callee: &BTreeMap<u64, Vec<(u64, u64)>>,
        dirty: &mut BTreeSet<u64>,
    ) {
        let should_mark = self.functions.get(&address).is_some_and(|function| {
            function.noreturn.is_none()
                && function.cfg.entry.is_some()
                && !cfg_may_return(&function.cfg)
        });
        if !should_mark {
            return;
        }
        let Some(function) = self.functions.get_mut(&address) else {
            return;
        };
        function.noreturn = Some(cfg::CfgNoreturnReason::ControlFlow);
        self.refresh_callers_of(address, callers_by_callee, dirty);
    }

    fn callers_by_callee(&self) -> BTreeMap<u64, Vec<(u64, u64)>> {
        let mut callers: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        for (address, function) in &self.functions {
            for call in function
                .cfg
                .blocks_by_address
                .values()
                .flat_map(|node| function.cfg.graph[*node].calls.iter())
                .chain(function.cfg.recovered_calls.iter())
            {
                let targets = if call.candidates.is_empty() {
                    call.target.into_iter().collect::<Vec<_>>()
                } else {
                    call.candidates
                        .iter()
                        .map(|candidate| candidate.target)
                        .collect()
                };
                for target in targets {
                    if let Some(callee) = self.resolve_function_address(target) {
                        callers
                            .entry(callee)
                            .or_default()
                            .push((*address, call.site));
                    }
                }
            }
        }
        for sites in callers.values_mut() {
            sites.sort_unstable();
            sites.dedup();
        }
        callers
    }

    fn call_site(&self, caller: u64, site: u64) -> Option<cfg::CfgCallSite> {
        let function = self.functions.get(&caller)?;
        function
            .cfg
            .blocks_by_address
            .values()
            .flat_map(|node| function.cfg.graph[*node].calls.iter())
            .chain(function.cfg.recovered_calls.iter())
            .find(|call| call.site == site)
            .cloned()
    }

    fn refresh_callers_of(
        &mut self,
        callee: u64,
        callers_by_callee: &BTreeMap<u64, Vec<(u64, u64)>>,
        dirty: &mut BTreeSet<u64>,
    ) {
        let Some(sites) = callers_by_callee.get(&callee).cloned() else {
            return;
        };
        for (caller, site) in sites {
            let Some(call) = self.call_site(caller, site) else {
                continue;
            };
            if call.noreturn || !self.call_is_noreturn(&call) {
                continue;
            }
            if self.set_call_noreturn(caller, site, true) {
                dirty.insert(caller);
            }
        }
    }

    fn resolve_indirect_jump_targets(
        &self,
        decoded: &[DecodedInsn],
        site: u64,
        target: Option<IndirectTarget>,
    ) -> Vec<u64> {
        let Some(target) = target else {
            return Vec::new();
        };
        if matches!(target, IndirectTarget::IndexedMemory { .. }) {
            origin::resolve_jump_table(self.image, decoded, site, target).unwrap_or_default()
        } else if matches!(target, IndirectTarget::TableBranch { .. }) {
            origin::resolve_table_branch(self.image, decoded, site, target).unwrap_or_default()
        } else if matches!(target, IndirectTarget::TableLoad { .. }) {
            origin::resolve_table_load(self.image, decoded, site, target).unwrap_or_default()
        } else if matches!(target, IndirectTarget::BranchTable { .. }) {
            origin::resolve_branch_table(self.image, decoded, site, target).unwrap_or_default()
        } else if let IndirectTarget::Register(register) = target {
            origin::resolve_indirect_target(self.image, decoded, site, target)
                .map(|target| vec![target])
                .or_else(|| origin::resolve_offset_jump_table(self.image, decoded, site, register))
                .or_else(|| origin::resolve_riscv_jump_table(self.image, decoded, site, register))
                .or_else(|| {
                    origin::resolve_indexed_pointer_table(self.image, decoded, site, register)
                })
                .unwrap_or_default()
        } else {
            origin::resolve_indirect_target(self.image, decoded, site, target)
                .into_iter()
                .collect()
        }
    }

    fn collect_code_references(&self, instruction: &DecodedInsn, out: &mut BTreeSet<u64>) {
        if let Some(effect) = instruction.value {
            match effect.source {
                ValueSource::Immediate(value) | ValueSource::Address(value) => {
                    self.collect_pointer_references(value, out);
                }
                ValueSource::LoadAddress(address) => {
                    self.collect_loaded_pointer(address, out);
                }
                ValueSource::LoadFromRegister { .. }
                | ValueSource::Copy(_)
                | ValueSource::AddImmediate { .. }
                | ValueSource::OrImmediate { .. }
                | ValueSource::AddRegister { .. }
                | ValueSource::IndexedLoad { .. }
                | ValueSource::ShiftRegister { .. }
                | ValueSource::Select { .. } => {}
            }
        }
        if let Some(IndirectTarget::Memory(address)) = instruction.indirect {
            self.collect_loaded_pointer(address, out);
        }
    }

    fn collect_loaded_pointer(&self, address: u64, out: &mut BTreeSet<u64>) {
        let Some(value) = self.image.read_pointer(address) else {
            return;
        };
        let target = self.image.canonical_address(value);
        if self.image.is_executable(target) {
            out.insert(target);
        }
    }

    /// Adds an executable address, or a bounded run of function pointers
    /// starting at a data address, to this function's referenced addresses.
    ///
    /// Scanning stops at a null word, a non-executable value, a section end or
    /// a small safety limit. This recovers callback/dispatch tables that a
    /// function loads from global data even when the indirect call itself
    /// cannot be resolved.
    fn collect_pointer_references(&self, value: u64, out: &mut BTreeSet<u64>) {
        let address = self.image.canonical_address(value);
        if self.image.is_executable(address) {
            out.insert(address);
            return;
        }
        let pointer = u64::try_from(pointer_size(self.image.arch)).unwrap_or(0);
        if pointer == 0 || !address.is_multiple_of(pointer) {
            return;
        }
        let Some(end) = self.image.allocation_end_for(address) else {
            return;
        };
        let mut slot = address;
        for _ in 0..64_u64 {
            if slot.saturating_add(pointer) > end {
                break;
            }
            let Some(value) = self.image.read_pointer(slot) else {
                break;
            };
            if value == 0 {
                break;
            }
            let target = self.image.canonical_address(value);
            if !self.image.is_executable(target) {
                break;
            }
            out.insert(target);
            slot = slot.saturating_add(pointer);
        }
    }

    fn cfg_terminator(
        &self,
        last: &DecodedInsn,
        start: u64,
        end: u64,
        resolved_jump: Option<&[u64]>,
        noreturn_call: bool,
    ) -> cfg::CfgTerminator {
        if last.is_return {
            return cfg::CfgTerminator::Return;
        }
        if last.is_call {
            return if noreturn_call {
                cfg::CfgTerminator::NoreturnCall
            } else {
                cfg::CfgTerminator::Call
            };
        }
        if last.is_jump {
            let target = last
                .direct_target
                .map(|target| self.image.canonical_address(target));
            if let Some(target) = target {
                if target >= start && target < end && last.is_conditional {
                    return cfg::CfgTerminator::Branch;
                }
                return cfg::CfgTerminator::Jump;
            }
            return if resolved_jump.is_some_and(|targets| !targets.is_empty()) {
                if last.is_conditional {
                    cfg::CfgTerminator::Branch
                } else {
                    cfg::CfgTerminator::Jump
                }
            } else {
                cfg::CfgTerminator::Unresolved
            };
        }
        cfg::CfgTerminator::Fallthrough
    }

    fn cfg_instruction(&self, instruction: &DecodedInsn) -> cfg::CfgInstruction {
        let bytes = self
            .image
            .bytes_at(instruction.address, usize::from(instruction.size))
            .map_or_else(Vec::new, <[u8]>::to_vec);
        cfg::CfgInstruction {
            address: instruction.address,
            size: instruction.size,
            bytes,
            mnemonic: instruction.mnemonic.clone(),
            operands: instruction.operands.clone(),
            text: insn_text(instruction),
            is_call: instruction.is_call,
            is_jump: instruction.is_jump,
            is_return: instruction.is_return,
            is_conditional: instruction.is_conditional,
            direct_target: instruction.direct_target,
            indirect: instruction.indirect.map(|target| self.cfg_indirect(target)),
            cycles: self.timing.map(|model| model.instruction_cost(instruction)),
            source: self
                .image
                .dwarf
                .as_ref()
                .and_then(|dwarf| dwarf.source_at(instruction.address))
                .map(|source| SourceLoc {
                    file: source.file.clone(),
                    line: source.line,
                    column: source.column,
                }),
        }
    }

    fn cfg_indirect(&self, target: crate::arch::IndirectTarget) -> cfg::CfgIndirectTarget {
        use crate::arch::IndirectTarget;
        let name = |register| {
            self.decoder
                .register_name(register)
                .unwrap_or_else(|| format!("reg{}", register.0))
        };
        match target {
            IndirectTarget::Register(register) => cfg::CfgIndirectTarget::Register(name(register)),
            IndirectTarget::RegisterMemory { base, disp } => {
                cfg::CfgIndirectTarget::RegisterMemory {
                    base: name(base),
                    disp,
                }
            }
            IndirectTarget::Memory(address) => cfg::CfgIndirectTarget::Memory(address),
            IndirectTarget::RegisterOffset { register, offset } => {
                cfg::CfgIndirectTarget::RegisterOffset {
                    register: name(register),
                    offset,
                }
            }
            IndirectTarget::IndexedMemory {
                base,
                index,
                scale,
                disp,
            } => cfg::CfgIndirectTarget::IndexedMemory {
                base: base.map(name),
                index: name(index),
                scale,
                disp,
            },
            IndirectTarget::TableBranch {
                base,
                index,
                halfword,
            } => cfg::CfgIndirectTarget::TableBranch {
                base: base.map(name),
                index: name(index),
                halfword,
            },
            IndirectTarget::TableLoad { base, index, disp } => cfg::CfgIndirectTarget::TableLoad {
                base: base.map(name),
                index: name(index),
                disp,
            },
            IndirectTarget::BranchTable { base, index } => cfg::CfgIndirectTarget::BranchTable {
                base: base.map(name),
                index: name(index),
            },
        }
    }

    fn scan_undecoded_calls(
        &self,
        caller: u64,
        gap_start: u64,
        gap_end: u64,
        seen: &mut BTreeSet<(u64, u64)>,
        calls: &mut Vec<CallDraft>,
    ) {
        let mut cursor = gap_start;
        let mut budget = self.options.max_instructions_per_function;
        let step = match self.image.arch {
            crate::loader::ArchKind::Thumb | crate::loader::ArchKind::Arm => 2,
            crate::loader::ArchKind::Aarch64
            | crate::loader::ArchKind::Riscv32
            | crate::loader::ArchKind::Riscv64 => 4,
            crate::loader::ArchKind::X86_64 => 1,
        };
        while cursor < gap_end && budget > 0 {
            let max_len = usize::try_from((gap_end - cursor).min(16)).unwrap_or(16);
            let Some(bytes) = self.image.bytes_at(cursor, max_len) else {
                break;
            };
            let Some(instruction) = self.decoder.decode_one(bytes, cursor).ok().flatten() else {
                cursor = cursor.saturating_add(step);
                continue;
            };
            let size = u64::from(instruction.size);
            if size == 0 || cursor.saturating_add(size) > gap_end {
                cursor = cursor.saturating_add(step);
                continue;
            }
            if instruction.is_call
                && let Some(target) = instruction.direct_target
            {
                let target = self.image.canonical_address(target);
                if self.image.is_executable(target)
                    && self.functions.contains_key(&target)
                    && seen.insert((cursor, target))
                {
                    calls.push(CallDraft {
                        caller,
                        site: cursor,
                        target,
                        tail: false,
                        conditional: instruction.is_conditional,
                        heuristic: true,
                        direct: true,
                    });
                }
            }
            cursor = cursor.saturating_add(size);
            budget -= 1;
        }
    }

    fn resolve_remaining_functions(&mut self) -> Result<()> {
        let mut rounds = 0usize;
        loop {
            let progress = self.resolve_forwarded_indirect_calls();
            let missing: Vec<u64> = self
                .calls
                .iter()
                .map(|call| call.target)
                .filter(|target| {
                    !self.functions.contains_key(target)
                        && self.function_containing(*target).is_none()
                        && self.image.is_executable(*target)
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if missing.is_empty() && !progress {
                return Ok(());
            }
            for target in missing {
                self.add_synthetic_function(target)?;
            }
            while let Some(address) = self.queue.pop_front() {
                self.analyze_function(address);
            }
            rounds += 1;
            if rounds > 32 {
                return Err(Error::Limit(
                    "synthetic function discovery did not converge".to_owned(),
                ));
            }
        }
    }

    /// Resolves indirect calls whose target expression starts from an ABI
    /// argument, by evaluating that expression at direct caller sites.
    ///
    /// Only a unique statically executable target is accepted. This recovers
    /// common vtable/function-pointer dispatch patterns without guessing when
    /// callers disagree or the argument is dynamic.
    /// Expands the Embassy executor's task-poll dispatch into bounded
    /// multi-target call edges.
    ///
    /// `Executor::run` loads a poll function pointer from the task header and
    /// calls it indirectly. The task pointer itself is dynamic, but the field
    /// offset is fixed and the image contains stores of concrete poll entries
    /// to that field. Collecting those values gives a conservative target set.
    fn resolve_embassy_executor_calls(&mut self) -> bool {
        let decoded_functions: Vec<&[DecodedInsn]> = self
            .decoded_by_function
            .values()
            .map(Vec::as_slice)
            .collect();
        let mut resolutions: Vec<CandidateCallResolution> = Vec::new();
        let mut seen_sites = BTreeSet::new();
        for (&function_address, function) in &self.functions {
            if !is_embassy_executor_function(&function.display) {
                continue;
            }
            let Some(decoded) = self.decoded_by_function.get(&function_address) else {
                continue;
            };
            let mut sites = BTreeSet::new();
            for node in function.cfg.blocks_by_address.values() {
                for call in &function.cfg.graph[*node].calls {
                    if call.unresolved {
                        sites.insert(call.site);
                    }
                }
            }
            for call in &function.cfg.recovered_calls {
                if call.unresolved {
                    sites.insert(call.site);
                }
            }
            for site in sites {
                if !seen_sites.insert((function_address, site)) {
                    continue;
                }
                let Some(instruction) = decoded
                    .iter()
                    .find(|instruction| instruction.address == site && instruction.is_call)
                else {
                    continue;
                };
                let Some(target) = instruction.indirect else {
                    continue;
                };
                let Some(disp) = origin::indirect_field_load(decoded, site, target) else {
                    continue;
                };
                if !(0..=0x1000).contains(&disp) {
                    continue;
                }
                let targets: BTreeSet<u64> =
                    origin::resolve_field_store_candidates(self.image, &decoded_functions, disp)
                        .into_iter()
                        .filter_map(|target| self.resolve_function_address(target))
                        .filter(|target| {
                            self.functions
                                .get(target)
                                .is_some_and(|function| is_embassy_poll_target(&function.display))
                        })
                        .collect();
                if (2..=16).contains(&targets.len()) {
                    let count = targets.len();
                    resolutions.push(CandidateCallResolution {
                        caller: function_address,
                        site,
                        targets: targets.into_iter().collect(),
                        tail: false,
                        conditional: false,
                        code: "resolved-indirect-call-candidates",
                        message: format!(
                            "indirect call at 0x{site:x} has {count} candidate target(s) from stores to field +{disp}"
                        ),
                    });
                }
            }
        }
        self.apply_candidate_calls(resolutions)
    }

    /// Resolves unresolved trait-object method calls from vtable-shaped
    /// read-only tables. The vtable base is object-insensitive; candidates are
    /// accepted only when the slot is a Rust method slot and the table header
    /// is plausible.
    #[allow(clippy::too_many_lines)]
    fn resolve_trait_object_calls(&mut self) -> bool {
        let pointer = pointer_size(self.image.arch);
        let min_slot = i64::try_from(pointer.saturating_mul(3)).unwrap_or(i64::MAX);
        let callers = self.callers_by_target();
        let mut resolutions = Vec::new();
        let mut null_resolutions = Vec::new();
        for (&function_address, function) in &self.functions {
            let Some(decoded) = self.decoded_by_function.get(&function_address) else {
                continue;
            };
            let mut related = BTreeSet::new();
            related.insert(function_address);
            for call in function
                .cfg
                .blocks_by_address
                .values()
                .flat_map(|node| function.cfg.graph[*node].calls.iter())
            {
                if let Some(target) = call.target
                    && let Some(callee) = self.resolve_function_address(target)
                    && self.functions.contains_key(&callee)
                {
                    related.insert(callee);
                }
            }
            if let Some(caller_sites) = callers.get(&function_address) {
                for (caller, _) in caller_sites {
                    related.insert(*caller);
                    let Some(caller_function) = self.functions.get(caller) else {
                        continue;
                    };
                    for call in caller_function
                        .cfg
                        .blocks_by_address
                        .values()
                        .flat_map(|node| caller_function.cfg.graph[*node].calls.iter())
                    {
                        if let Some(target) = call.target
                            && let Some(callee) = self.resolve_function_address(target)
                            && self.functions.contains_key(&callee)
                        {
                            related.insert(callee);
                        }
                    }
                }
            }
            let decoded_functions: Vec<&[DecodedInsn]> = related
                .iter()
                .filter_map(|address| self.decoded_by_function.get(address).map(Vec::as_slice))
                .collect();
            let mut function_cache: BTreeMap<i64, Vec<u64>> = BTreeMap::new();
            let mut sites = BTreeSet::new();
            for node in function.cfg.blocks_by_address.values() {
                for call in &function.cfg.graph[*node].calls {
                    if call.unresolved {
                        sites.insert((call.site, call.tail, call.conditional));
                    }
                }
            }
            for call in &function.cfg.recovered_calls {
                if call.unresolved {
                    sites.insert((call.site, call.tail, call.conditional));
                }
            }
            for (site, tail, conditional) in sites {
                let Some(instruction) = decoded.iter().find(|instruction| {
                    instruction.address == site && (instruction.is_call || instruction.is_jump)
                }) else {
                    continue;
                };
                let Some(target) = instruction.indirect else {
                    continue;
                };
                let Some(slot) = origin::indirect_field_load(decoded, site, target) else {
                    continue;
                };
                if slot == 0 {
                    let values =
                        origin::resolve_vtable_slot_values(self.image, &decoded_functions, slot);
                    if !values.is_empty() && values.iter().all(|value| *value == 0) {
                        null_resolutions.push((function_address, site, tail, conditional));
                    }
                    continue;
                }
                if slot < min_slot {
                    continue;
                }
                let candidates = function_cache.entry(slot).or_insert_with(|| {
                    origin::resolve_vtable_slot_candidates(self.image, &decoded_functions, slot)
                });
                let targets: BTreeSet<u64> = candidates
                    .iter()
                    .filter_map(|target| self.resolve_function_address(*target))
                    .collect();
                if (1..=16).contains(&targets.len()) {
                    let count = targets.len();
                    let method = self
                        .image
                        .dwarf
                        .as_ref()
                        .and_then(|dwarf| {
                            u64::try_from(slot).ok().and_then(|slot| {
                                dwarf
                                    .vtable_method_at(slot)
                                    .and_then(|entry| entry.name.as_deref())
                            })
                        })
                        .map_or_else(String::new, |name| format!(" (`{name}`)"));
                    resolutions.push(CandidateCallResolution {
                        caller: function_address,
                        site,
                        targets: targets.into_iter().collect(),
                        tail,
                        conditional,
                        code: "resolved-trait-object-candidates",
                        message: format!(
                            "trait-object call at 0x{site:x} has {count} vtable method candidate(s) at slot +{slot}{method}"
                        ),
                    });
                }
            }
        }
        let null_changed = self.apply_null_indirect_calls(null_resolutions);
        let candidate_changed = self.apply_candidate_calls(resolutions);
        null_changed || candidate_changed
    }

    fn apply_null_indirect_calls(&mut self, resolutions: Vec<(u64, u64, bool, bool)>) -> bool {
        let mut changed = false;
        for (caller, site, tail, conditional) in resolutions {
            let null_call = cfg::CfgCallSite {
                site,
                target: None,
                target_function: None,
                direct: false,
                tail,
                conditional,
                heuristic: false,
                unresolved: false,
                null_target: true,
                noreturn: false,
                candidates: Vec::new(),
            };
            let updated = self.functions.get_mut(&caller).is_some_and(|function| {
                replace_unresolved_cfg_call(&mut function.cfg, site, null_call)
            });
            if !updated {
                continue;
            }
            let caller_id = function_id(caller);
            self.diagnostics.retain(|diagnostic| {
                !((diagnostic.code == "unresolved-indirect-call"
                    || diagnostic.code == "unresolved-indirect-jump")
                    && diagnostic.function.as_ref() == Some(&caller_id)
                    && diagnostic.site == Some(Addr::new(site)))
            });
            self.diagnostic_keys
                .retain(|(diagnostic_code, function, diagnostic_site)| {
                    !((*diagnostic_code == "unresolved-indirect-call"
                        || *diagnostic_code == "unresolved-indirect-jump")
                        && *function == Some(caller)
                        && *diagnostic_site == Some(site))
                });
            self.diag(
                Severity::Info,
                "null-indirect-call-target",
                format!(
                    "indirect call at 0x{site:x} reads a statically null vtable target; no call edge"
                ),
                Some(caller),
                Some(site),
            );
            changed = true;
        }
        changed
    }

    fn apply_candidate_calls(&mut self, resolutions: Vec<CandidateCallResolution>) -> bool {
        let mut changed = false;
        for resolution in resolutions {
            let CandidateCallResolution {
                caller,
                site,
                targets,
                tail,
                conditional,
                code,
                message,
            } = resolution;
            let (target, target_function, candidates) = if targets.len() == 1 {
                let target = targets[0];
                (Some(target), Some(function_id(target)), Vec::new())
            } else {
                (
                    None,
                    None,
                    targets
                        .iter()
                        .map(|target| cfg::CfgCallCandidate {
                            target: *target,
                            target_function: Some(function_id(*target)),
                        })
                        .collect(),
                )
            };
            let noreturn = !conditional
                && targets
                    .iter()
                    .all(|target| self.function_is_noreturn(*target));
            let candidate_call = cfg::CfgCallSite {
                site,
                target,
                target_function,
                direct: false,
                tail,
                conditional,
                heuristic: true,
                unresolved: false,
                null_target: false,
                noreturn,
                candidates,
            };
            let updated = self.functions.get_mut(&caller).is_some_and(|function| {
                replace_unresolved_cfg_call(&mut function.cfg, site, candidate_call)
            });
            if !updated {
                continue;
            }
            for target in &targets {
                self.calls.push(CallDraft {
                    caller,
                    site,
                    target: *target,
                    tail,
                    conditional,
                    heuristic: true,
                    direct: false,
                });
            }
            let caller_id = function_id(caller);
            self.diagnostics.retain(|diagnostic| {
                !((diagnostic.code == "unresolved-indirect-call"
                    || diagnostic.code == "unresolved-indirect-jump")
                    && diagnostic.function.as_ref() == Some(&caller_id)
                    && diagnostic.site == Some(Addr::new(site)))
            });
            self.diagnostic_keys
                .retain(|(diagnostic_code, function, diagnostic_site)| {
                    !((*diagnostic_code == "unresolved-indirect-call"
                        || *diagnostic_code == "unresolved-indirect-jump")
                        && *function == Some(caller)
                        && *diagnostic_site == Some(site))
                });
            self.diag(Severity::Info, code, message, Some(caller), Some(site));
            changed = true;
        }
        changed
    }

    /// Resolves unresolved indirect calls whose target comes from an indexed
    /// function-pointer table or from the return value of a direct callee.
    ///
    /// Both patterns are common at `-O0`: `commands[i]()` and
    /// `get_handler()()`. Only targets that already have function nodes are
    /// accepted, and candidate sets are bounded.
    fn resolve_computed_indirect_calls(&mut self) -> bool {
        let sites = self.unresolved_call_sites();
        if sites.is_empty() {
            return false;
        }
        let mut return_cache: BTreeMap<u64, Option<Vec<u64>>> = BTreeMap::new();
        let mut resolutions = Vec::new();
        for (caller, site, tail, conditional) in sites {
            let Some(decoded) = self.decoded_by_function.get(&caller) else {
                continue;
            };
            let Some(instruction) = decoded
                .iter()
                .find(|instruction| instruction.address == site && instruction.is_call)
            else {
                continue;
            };
            let Some(reference) = instruction.indirect else {
                continue;
            };
            let mut table_targets =
                origin::resolve_indexed_call_targets(self.image, decoded, site, reference)
                    .and_then(|targets| self.known_call_targets(targets));
            if table_targets.is_none()
                && matches!(self.image.arch, ArchKind::Riscv32 | ArchKind::Riscv64)
                && let IndirectTarget::Register(register) = reference
            {
                table_targets =
                    origin::resolve_riscv_jump_table(self.image, decoded, site, register)
                        .and_then(|targets| self.known_call_targets(targets));
            }
            if let Some(table_targets) = table_targets
                && (1..=MAX_COMPUTED_CALL_CANDIDATES).contains(&table_targets.len())
            {
                let count = table_targets.len();
                resolutions.push(CandidateCallResolution {
                    caller,
                    site,
                    targets: table_targets,
                    tail,
                    conditional,
                    code: "resolved-call-table",
                    message: format!(
                        "indirect call at 0x{site:x} has {count} candidate target(s) from an indexed function-pointer table"
                    ),
                });
                continue;
            }
            let IndirectTarget::Register(register) = reference else {
                continue;
            };
            let Some((callee, callee_site)) = origin::returned_call_before(decoded, site, register)
            else {
                continue;
            };
            let Some(callee) = self.resolve_function_address(self.image.canonical_address(callee))
            else {
                continue;
            };
            let candidates = return_cache
                .entry(callee)
                .or_insert_with(|| self.return_pointer_candidates(callee));
            let Some(candidates) = candidates else {
                continue;
            };
            let Some(targets) = self.known_call_targets(candidates.iter().copied()) else {
                continue;
            };
            if !(1..=MAX_COMPUTED_CALL_CANDIDATES).contains(&targets.len()) {
                continue;
            }
            let count = targets.len();
            resolutions.push(CandidateCallResolution {
                caller,
                site,
                targets,
                tail,
                conditional,
                code: "resolved-returned-indirect-call",
                message: format!(
                    "indirect call at 0x{site:x} uses the return value of 0x{callee:x} (call at 0x{callee_site:x}) with {count} candidate target(s)"
                ),
            });
        }
        self.apply_candidate_calls(resolutions)
    }

    fn unresolved_call_sites(&self) -> Vec<(u64, u64, bool, bool)> {
        let mut sites = BTreeSet::new();
        for (&caller, function) in &self.functions {
            for node in function.cfg.blocks_by_address.values() {
                for call in &function.cfg.graph[*node].calls {
                    if call.unresolved {
                        sites.insert((caller, call.site, call.tail, call.conditional));
                    }
                }
            }
            for call in &function.cfg.recovered_calls {
                if call.unresolved {
                    sites.insert((caller, call.site, call.tail, call.conditional));
                }
            }
        }
        sites.into_iter().collect()
    }

    fn known_call_targets(&self, targets: impl IntoIterator<Item = u64>) -> Option<Vec<u64>> {
        let mut known = BTreeSet::new();
        for target in targets {
            let target = self.image.canonical_address(target);
            if !self.functions.contains_key(&target) {
                return None;
            }
            known.insert(target);
        }
        (!known.is_empty()).then(|| known.into_iter().collect())
    }

    /// Summarizes the function-pointer values a direct callee can return.
    ///
    /// The search walks backwards from each reachable return, across basic
    /// blocks, until it finds the latest write to the ABI return register on
    /// every path. A call before that definition makes the path unknowable
    /// because the call clobbers the register. Any unresolved, null or
    /// non-executable return makes the whole summary unusable.
    fn return_pointer_candidates(&self, address: u64) -> Option<Vec<u64>> {
        let function = self.functions.get(&address)?;
        if matches!(function.kind, FunctionKind::Plt | FunctionKind::External) {
            return None;
        }
        let decoded = self.decoded_by_function.get(&address)?;
        let entry = function.cfg.entry?;
        let register = return_register(self.image.arch);
        let mut reachable = BTreeSet::new();
        let mut pending = vec![entry];
        while let Some(node) = pending.pop() {
            if reachable.insert(node) {
                pending.extend(
                    function
                        .cfg
                        .graph
                        .neighbors_directed(node, petgraph::Direction::Outgoing),
                );
            }
        }
        let mut values = BTreeSet::new();
        let mut returns = 0usize;
        for node in reachable {
            let block = &function.cfg.graph[node];
            for instruction in &block.instructions {
                if !instruction.is_return {
                    continue;
                }
                returns += 1;
                let mut visited = BTreeSet::new();
                if !collect_return_definitions(
                    self.image,
                    &function.cfg,
                    decoded,
                    node,
                    Some(instruction.address),
                    register,
                    &mut visited,
                    &mut values,
                ) {
                    return None;
                }
            }
        }
        if returns == 0 || values.is_empty() {
            return None;
        }
        let mut candidates = Vec::new();
        for value in values {
            if value == 0 {
                return None;
            }
            let canonical = self.image.canonical_address(value);
            if !self.image.is_executable(canonical) {
                return None;
            }
            candidates.push(canonical);
        }
        candidates.sort_unstable();
        candidates.dedup();
        (candidates.len() <= MAX_COMPUTED_CALL_CANDIDATES).then_some(candidates)
    }

    /// Resolves dynamic field calls when DWARF types identify the loaded field
    /// as a function pointer and typed global objects provide concrete values.
    fn resolve_dwarf_typed_field_calls(&mut self) -> bool {
        let Some(dwarf) = self.image.dwarf.as_ref() else {
            return false;
        };
        let sites = self.unresolved_call_sites();
        if sites.is_empty() {
            return false;
        }
        let pointer = u64::try_from(pointer_size(self.image.arch)).unwrap_or(0);
        if pointer == 0 {
            return false;
        }
        let mut resolutions = Vec::new();
        let mut typed_cache: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for (caller, site, tail, conditional) in sites {
            let Some(decoded) = self.decoded_by_function.get(&caller) else {
                continue;
            };
            let Some(instruction) = decoded
                .iter()
                .find(|instruction| instruction.address == site && instruction.is_call)
            else {
                continue;
            };
            let Some(reference) = instruction.indirect else {
                continue;
            };
            let Some(offset) = origin::indirect_field_load(decoded, site, reference) else {
                continue;
            };
            let Ok(offset) = u64::try_from(offset) else {
                continue;
            };
            let Some(field) = dwarf.function_pointer_field_at(offset) else {
                continue;
            };
            let candidates = typed_cache
                .entry(offset)
                .or_insert_with(|| self.typed_global_field_candidates(dwarf, offset, pointer));
            let Some(targets) = self.known_call_targets(candidates.iter().copied()) else {
                continue;
            };
            if !(1..=MAX_COMPUTED_CALL_CANDIDATES).contains(&targets.len()) {
                continue;
            }
            let count = targets.len();
            let field_name = field.name.as_deref().unwrap_or("<anonymous>");
            resolutions.push(CandidateCallResolution {
                caller,
                site,
                targets,
                tail,
                conditional,
                code: "resolved-typed-field-candidates",
                message: format!(
                    "indirect call at 0x{site:x} has {count} candidate target(s) from DWARF function-pointer field +{offset} (`{field_name}`)"
                ),
            });
        }
        self.apply_candidate_calls(resolutions)
    }

    fn typed_global_field_candidates(
        &self,
        dwarf: &DwarfInfo,
        offset: u64,
        pointer: u64,
    ) -> Vec<u64> {
        let Ok(pointer_len) = usize::try_from(pointer) else {
            return Vec::new();
        };
        let mut candidates = BTreeSet::new();
        for variable in dwarf
            .variables
            .iter()
            .filter(|variable| variable.address.is_some())
        {
            let Some(address) = variable.address else {
                continue;
            };
            let direct = variable
                .aggregate_index
                .and_then(|index| dwarf.aggregates.get(index))
                .filter(|aggregate| {
                    aggregate
                        .members
                        .iter()
                        .any(|member| member.offset == offset && member.function_pointer)
                });
            let indirect = variable
                .pointee_aggregate_index
                .and_then(|index| dwarf.aggregates.get(index))
                .filter(|aggregate| {
                    aggregate
                        .members
                        .iter()
                        .any(|member| member.offset == offset && member.function_pointer)
                });
            let (object, aggregate, is_direct) = if let Some(aggregate) = direct {
                (address, aggregate, true)
            } else if let Some(aggregate) = indirect {
                let Some(value) = self.image.read_uint(address, pointer_len) else {
                    continue;
                };
                let object = self.image.canonical_address(value);
                if object == 0 || !self.is_allocated_data(object) {
                    continue;
                }
                (object, aggregate, false)
            } else {
                continue;
            };
            if aggregate
                .byte_size
                .is_some_and(|size| offset.checked_add(pointer).is_none_or(|end| end > size))
            {
                continue;
            }
            if is_direct
                && variable
                    .byte_size
                    .is_some_and(|size| offset.checked_add(pointer).is_none_or(|end| end > size))
            {
                continue;
            }
            let Some(slot) = object.checked_add(offset) else {
                continue;
            };
            let Some(value) = self.image.read_uint(slot, pointer_len) else {
                continue;
            };
            let target = self.image.canonical_address(value);
            if target != 0 && self.image.is_executable(target) {
                candidates.insert(target);
                if candidates.len() > MAX_COMPUTED_CALL_CANDIDATES {
                    return Vec::new();
                }
            }
        }
        candidates.into_iter().collect()
    }

    fn is_allocated_data(&self, address: u64) -> bool {
        self.image.sections.iter().any(|section| {
            section.alloc
                && !section.executable
                && address >= section.address
                && address < section.end()
        })
    }

    fn resolve_forwarded_indirect_calls(&mut self) -> bool {
        let callers = self.callers_by_target();
        if callers.is_empty() {
            return false;
        }
        let resolved = self.forwarded_indirect_candidates(&callers);
        self.apply_forwarded_indirect_resolutions(resolved)
    }

    fn callers_by_target(&self) -> BTreeMap<u64, Vec<(u64, u64)>> {
        let mut callers: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        for call in &self.calls {
            callers
                .entry(call.target)
                .or_default()
                .push((call.caller, call.site));
        }
        callers
    }

    fn forwarded_indirect_candidates(
        &self,
        callers: &BTreeMap<u64, Vec<(u64, u64)>>,
    ) -> Vec<(u64, u64, u64, bool, bool)> {
        let mut resolved = Vec::new();
        for (&function_address, function) in &self.functions {
            let Some(decoded) = self.decoded_by_function.get(&function_address) else {
                continue;
            };
            let Some(caller_sites) = callers.get(&function_address) else {
                continue;
            };
            let mut sites = BTreeSet::new();
            for node in function.cfg.blocks_by_address.values() {
                for call in &function.cfg.graph[*node].calls {
                    if call.unresolved {
                        sites.insert(call.site);
                    }
                }
            }
            for call in &function.cfg.recovered_calls {
                if call.unresolved {
                    sites.insert(call.site);
                }
            }
            for site in sites {
                let Some(instruction) = decoded.iter().find(|instruction| {
                    instruction.address == site && (instruction.is_call || instruction.is_jump)
                }) else {
                    continue;
                };
                let tail = instruction.is_jump;
                let Some(target) = instruction.indirect else {
                    continue;
                };
                let Some(spec) = origin::indirect_argument_spec(self.image, decoded, site, target)
                else {
                    continue;
                };
                let mut candidates = BTreeSet::new();
                let mut complete = true;
                for (caller, caller_site) in caller_sites {
                    let Some(caller_decoded) = self.decoded_by_function.get(caller) else {
                        complete = false;
                        break;
                    };
                    let Some(value) = origin::evaluate_argument_spec(
                        self.image,
                        caller_decoded,
                        *caller_site,
                        &spec,
                    ) else {
                        complete = false;
                        break;
                    };
                    let value = self.image.canonical_address(value);
                    if !self.image.is_executable(value) {
                        complete = false;
                        break;
                    }
                    candidates.insert(value);
                }
                if complete
                    && candidates.len() == 1
                    && let Some(target) = candidates.first()
                {
                    if tail
                        && *target >= function_address
                        && *target < function_address.saturating_add(function.size)
                    {
                        continue;
                    }
                    resolved.push((
                        function_address,
                        site,
                        *target,
                        tail,
                        instruction.is_conditional,
                    ));
                }
            }
        }
        resolved
    }

    fn apply_forwarded_indirect_resolutions(
        &mut self,
        resolved: Vec<(u64, u64, u64, bool, bool)>,
    ) -> bool {
        let mut changed = false;
        for (function_address, site, target, tail, conditional) in resolved {
            let target_function = self.resolve_function_address(target).map(function_id);
            let resolved_call = cfg::CfgCallSite {
                site,
                target: Some(target),
                target_function,
                direct: false,
                tail,
                conditional,
                heuristic: false,
                unresolved: false,
                null_target: false,
                noreturn: !conditional && self.function_is_noreturn(target),
                candidates: Vec::new(),
            };
            let Some(function) = self.functions.get_mut(&function_address) else {
                continue;
            };
            if !update_cfg_call_site(&mut function.cfg, resolved_call) {
                continue;
            }
            self.calls.push(CallDraft {
                caller: function_address,
                site,
                target,
                tail,
                conditional,
                heuristic: false,
                direct: false,
            });
            let function_id = function_id(function_address);
            self.diagnostics.retain(|diagnostic| {
                !((diagnostic.code == "unresolved-indirect-call"
                    || diagnostic.code == "unresolved-indirect-jump")
                    && diagnostic.function.as_ref() == Some(&function_id)
                    && diagnostic.site == Some(Addr::new(site)))
            });
            self.diagnostic_keys
                .retain(|(code, function, diagnostic_site)| {
                    !((code == "unresolved-indirect-call" || code == "unresolved-indirect-jump")
                        && *function == Some(function_address)
                        && *diagnostic_site == Some(site))
                });
            self.diag(
                Severity::Info,
                if tail {
                    "resolved-forwarded-indirect-jump"
                } else {
                    "resolved-forwarded-indirect-call"
                },
                if tail {
                    format!(
                        "resolved indirect jump at 0x{site:x} to 0x{target:x} as a tail call through caller argument"
                    )
                } else {
                    format!(
                        "resolved indirect call at 0x{site:x} to 0x{target:x} through caller argument"
                    )
                },
                Some(function_address),
                Some(site),
            );
            changed = true;
        }
        changed
    }

    fn add_synthetic_function(&mut self, target: u64) -> Result<()> {
        if self.functions.contains_key(&target) || self.function_containing(target).is_some() {
            return Ok(());
        }
        if !self.image.is_executable(target) {
            return Ok(());
        }
        if self.functions.len() >= self.options.max_functions {
            return Err(Error::Limit(format!(
                "synthetic function discovery exceeded the configured maximum of {} functions",
                self.options.max_functions
            )));
        }
        let Some(section_end) = self.image.section_end_for(target) else {
            return Ok(());
        };
        let next = self
            .functions
            .keys()
            .copied()
            .filter(|address| *address > target)
            .min()
            .unwrap_or(section_end);
        let end = next.min(section_end);
        let size = end.saturating_sub(target);
        let section = self
            .image
            .section_name_for(target)
            .unwrap_or("<unknown>")
            .to_owned();
        self.functions.insert(
            target,
            FunctionDraft {
                address: target,
                size,
                section,
                names: Vec::new(),
                display: format!("sub_0x{target:x}"),
                demangled: None,
                language: Language::Unknown,
                kind: FunctionKind::Normal,
                noreturn: None,
                cfg: cfg::FunctionCfg::default(),
                analyzed: false,
            },
        );
        self.queue.push_back(target);
        self.diag(
            Severity::Info,
            "synthetic-function",
            format!("created a function node for direct call target 0x{target:x} without a symbol"),
            Some(target),
            None,
        );
        Ok(())
    }

    fn resolve_calls(&mut self) {
        self.calls.sort_by(|left, right| {
            (left.site, left.target, left.tail).cmp(&(right.site, right.target, right.tail))
        });
        self.calls.dedup_by(|left, right| {
            left.caller == right.caller
                && left.site == right.site
                && left.target == right.target
                && left.tail == right.tail
        });
    }

    #[allow(clippy::too_many_lines)]
    fn build_tdg(mut self) -> Result<AnalysisOutput> {
        let mut program_cfg = self.build_program_cfg();
        let isr_vectors = std::mem::take(&mut self.isr_vectors);
        let startup_address = self.startup_address;
        let Some(startup_address) = startup_address else {
            return Err(Error::Elf(
                "could not determine a startup function".to_owned(),
            ));
        };
        let main_address = self
            .find_main_address()
            .filter(|main| *main != startup_address);
        let frequency = self.options.frequency_hz;
        let frequency_domain = frequency.map(|_| FrequencyDomainId::new(CORE_DOMAIN));
        let timing = match self.timing {
            Some(model) => model.timing_info(frequency),
            None => frequency_only_timing_info(frequency),
        };

        let mut functions = Vec::new();
        for draft in self.functions.values() {
            functions.push(self.function_to_schema(draft));
        }

        let mut contexts = Vec::new();
        contexts.push(Context {
            id: ContextId::new("ctx:startup"),
            name: "startup".to_owned(),
            kind: ContextKind::Startup,
            entry: function_id(startup_address),
            parent: None,
            scheduling: Scheduling::Unknown,
            priority: None,
            core: None,
            frequency_domain: frequency_domain.clone(),
            spawn_edge: None,
            ext: BTreeMap::new(),
        });
        if let Some(main_address) = main_address {
            contexts.push(Context {
                id: ContextId::new("ctx:main"),
                name: "main".to_owned(),
                kind: ContextKind::Main,
                entry: function_id(main_address),
                parent: Some(ContextId::new("ctx:startup")),
                scheduling: Scheduling::Preemptive,
                priority: None,
                core: None,
                frequency_domain: frequency_domain.clone(),
                spawn_edge: None,
                ext: BTreeMap::new(),
            });
        }

        let mut edges: Vec<Edge> = Vec::new();
        let mut edge_ids: BTreeSet<String> = BTreeSet::new();
        let cfg_calls: Vec<(u64, cfg::CfgCallSite)> = self
            .functions
            .values()
            .flat_map(|draft| {
                draft
                    .cfg
                    .blocks_by_address
                    .values()
                    .flat_map(|node| draft.cfg.graph[*node].calls.iter().cloned())
                    .chain(draft.cfg.recovered_calls.iter().cloned())
                    .map(|call| (draft.address, call))
            })
            .collect();
        for (caller, call) in &cfg_calls {
            if call.unresolved || call.null_target {
                continue;
            }
            let targets: Vec<u64> = if call.candidates.is_empty() {
                call.target.into_iter().collect()
            } else {
                call.candidates
                    .iter()
                    .map(|candidate| candidate.target)
                    .collect()
            };
            for target in targets {
                let Some(callee) = self.resolve_function_address(target) else {
                    self.diag(
                        Severity::Warning,
                        "call-target-unresolved",
                        format!(
                            "call at 0x{:x} targets 0x{target:x}, but no callee node exists",
                            call.site
                        ),
                        Some(*caller),
                        Some(call.site),
                    );
                    continue;
                };
                let mut confidence = if call.heuristic {
                    Confidence::Low
                } else if !call.direct {
                    Confidence::Medium
                } else if callee == target {
                    Confidence::High
                } else {
                    self.diag(
                        Severity::Info,
                        "call-into-function-body",
                        format!(
                            "call at 0x{:x} targets 0x{target:x} inside function 0x{callee:x}",
                            call.site
                        ),
                        Some(*caller),
                        Some(call.site),
                    );
                    Confidence::Medium
                };
                if call.conditional && !call.heuristic {
                    confidence = Confidence::Medium;
                }
                let id = format!("e:call:0x{:x}:0x{target:x}", call.site);
                if !edge_ids.insert(id.clone()) {
                    continue;
                }
                edges.push(Edge::Call {
                    id: EdgeId::new(id),
                    caller: function_id(*caller),
                    callee: function_id(callee),
                    site: Addr::new(call.site),
                    direct: call.direct,
                    tail: call.tail,
                    inlined: false,
                    confidence,
                });
            }
        }

        for vector in &isr_vectors {
            let handler = self.image.canonical_address(vector.handler);
            let Some(function_address) = self.resolve_function_address(handler) else {
                continue;
            };
            let Some(function) = self.functions.get(&function_address) else {
                continue;
            };
            if function_address == startup_address {
                continue;
            }
            let lower = function.display.to_ascii_lowercase();
            if lower.contains("default_handler")
                || lower.contains("defaulthandler")
                || has_default_handler_alias(self.image, function_address)
            {
                continue;
            }
            let irq = vector.index.checked_sub(16);
            let context_name = if function.display.starts_with("sub_0x") {
                irq.map_or_else(
                    || format!("vector_{}", vector.index),
                    |irq| format!("IRQ{irq}"),
                )
            } else {
                function.display.clone()
            };
            let context_id = ContextId::new(format!("ctx:isr:{}", vector.index));
            contexts.push(Context {
                id: context_id.clone(),
                name: context_name.clone(),
                kind: ContextKind::Isr,
                entry: function_id(function_address),
                parent: None,
                scheduling: Scheduling::Interrupt,
                priority: None,
                core: None,
                frequency_domain: frequency_domain.clone(),
                spawn_edge: None,
                ext: BTreeMap::new(),
            });
            let id = format!("e:isr:{}", vector.index);
            edges.push(Edge::IsrActivate {
                id: EdgeId::new(id),
                to_context: context_id,
                vector: vector.index,
                irq,
                name: Some(context_name),
                confidence: Confidence::High,
            });
        }

        let mut scopes = Vec::new();
        let mut locks = Vec::new();
        let logical_functions = crate::runtime::apply(
            &functions,
            &mut contexts,
            &mut edges,
            &mut locks,
            &mut scopes,
            &mut self.diagnostics,
            self.options.max_diagnostics,
            frequency_domain.as_ref(),
            &self.decoded_by_function,
            self.image,
        );
        for logical in &logical_functions {
            if program_cfg.function(&logical.id).is_none() {
                program_cfg
                    .functions
                    .push(cfg::CfgFunction::from_tdg_function(logical));
            }
        }
        program_cfg.functions.sort_by(|left, right| {
            (left.address, left.id.as_str()).cmp(&(right.address, right.id.as_str()))
        });
        functions.extend(logical_functions);
        functions.sort_by(|left, right| {
            (left.address, left.id.as_str()).cmp(&(right.address, right.id.as_str()))
        });

        edges.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
        contexts.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        scopes.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        locks.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));

        let tool = ToolInfo {
            name: "elf2tdg".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            rules_version: "m0".to_owned(),
            timing_tables_version: "0.1.0-m0".to_owned(),
        };
        let image = ImageInfo {
            path: Some(self.image.path.display().to_string()),
            sha256: None,
            build_id: None,
            arch: self.image.arch.schema_name().to_owned(),
            endianness: match self.image.byte_order {
                ByteOrder::Little => Endianness::Little,
                ByteOrder::Big => Endianness::Big,
            },
            entry: Addr::new(self.image.entry),
            elf_type: match self.image.elf_kind {
                ElfKind::Exec => ElfType::Exec,
                ElfKind::Dyn => ElfType::Dyn,
                ElfKind::Rel => ElfType::Rel,
                ElfKind::Unknown => ElfType::Unknown,
            },
            has_symbols: self.image.has_symbols,
            has_debug_info: self.image.has_debug_info,
            has_relocations: self.image.has_relocations,
            load_segments: Vec::new(),
        };

        let tdg = Tdg {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool,
            image,
            timing,
            functions,
            contexts,
            edges,
            locks,
            scopes,
            diagnostics: self.diagnostics,
            ext: BTreeMap::new(),
        };
        tdg.ensure_valid().map_err(|error| {
            Error::Validation(format!(
                "{error}; first issues: {:#?}",
                error.issues.iter().take(8).collect::<Vec<_>>()
            ))
        })?;
        program_cfg.ensure_valid().map_err(|error| {
            Error::CfgValidation(format!(
                "{error}; first issues: {:#?}",
                error.issues.iter().take(8).collect::<Vec<_>>()
            ))
        })?;
        Ok(AnalysisOutput {
            tdg,
            cfg: program_cfg,
        })
    }

    fn build_program_cfg(&self) -> cfg::ProgramCfg {
        let functions = self
            .functions
            .values()
            .map(|draft| {
                let end = draft.address.saturating_add(draft.size);
                let mut inline_frames = self.image.dwarf.as_ref().map_or_else(Vec::new, |dwarf| {
                    dwarf
                        .inline_frames_in(draft.address, end)
                        .into_iter()
                        .filter_map(|frame| {
                            let name = frame.display_name.as_deref().or(frame.name.as_deref())?;
                            let call_site = match (frame.call_file.clone(), frame.call_line) {
                                (Some(file), Some(line)) => Some(SourceLoc {
                                    file,
                                    line,
                                    column: frame.call_column,
                                }),
                                _ => None,
                            };
                            Some(cfg::CfgInlineFrame {
                                name: crate::rules::normalize_crate_hashes(name),
                                linkage_name: frame.linkage_name.clone(),
                                call_site,
                                low_pc: frame.low_pc,
                                high_pc: frame.high_pc,
                                depth: frame.depth,
                            })
                        })
                        .collect()
                });
                inline_frames.dedup_by(|left, right| {
                    left.name == right.name
                        && left.low_pc == right.low_pc
                        && left.high_pc == right.high_pc
                        && left.depth == right.depth
                });
                cfg::CfgFunction {
                    id: function_id(draft.address),
                    primary_name: draft.display.clone(),
                    demangled_name: draft.demangled.clone(),
                    symbols: draft.names.clone(),
                    language: draft.language,
                    kind: draft.kind,
                    address: draft.address,
                    size: draft.size,
                    section: draft.section.clone(),
                    source: self
                        .image
                        .dwarf
                        .as_ref()
                        .and_then(|dwarf| dwarf.source_at(draft.address))
                        .map(|source| SourceLoc {
                            file: source.file.clone(),
                            line: source.line,
                            column: source.column,
                        }),
                    inline_frames,
                    noreturn: draft.noreturn,
                    cfg: draft.cfg.clone(),
                }
            })
            .collect();
        let mut program = cfg::ProgramCfg::new(functions);
        program.pointer_roots = self.pointer_roots.iter().copied().collect();
        program
    }

    #[allow(clippy::too_many_lines)]
    fn function_to_schema(&self, draft: &FunctionDraft) -> Function {
        let mut blocks = Vec::new();
        for node in draft.cfg.blocks_by_address.values() {
            let block = &draft.cfg.graph[*node];
            let timing = match (self.timing, block.cycles, self.options.frequency_hz) {
                (Some(model), Some(cycles), frequency) => {
                    Some(model.block_timing(cycles, frequency))
                }
                _ => None,
            };
            let instructions = if self.options.include_instructions {
                match self.timing {
                    Some(_model) => block
                        .instructions
                        .iter()
                        .map(|insn| InstructionTiming {
                            address: Addr::new(insn.address),
                            size: insn.size,
                            mnemonic: insn.mnemonic.clone(),
                            text: Some(insn.text.clone()),
                            cycles: insn
                                .cycles
                                .unwrap_or_else(|| elf2tdg_schema::CostRange::exact(0.0)),
                            note: None,
                        })
                        .collect(),
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            };
            let mut successors: Vec<u64> = draft
                .cfg
                .graph
                .neighbors_directed(*node, petgraph::Direction::Outgoing)
                .map(|successor| draft.cfg.graph[successor].address)
                .collect();
            successors.sort_unstable();
            successors.dedup();
            blocks.push(BasicBlock {
                id: block_id(block.address),
                address: Addr::new(block.address),
                size: block.size,
                successors: successors
                    .iter()
                    .map(|address| block_id(*address))
                    .collect(),
                instructions,
                timing,
            });
        }

        let timing = self.timing.and_then(|_model| {
            if draft.cfg.blocks_by_address.is_empty() {
                return None;
            }
            let mut min = 0.0_f64;
            let mut max = 0.0_f64;
            let mut modeled = 0_u32;
            for node in draft.cfg.blocks_by_address.values() {
                if let Some(cycles) = draft.cfg.graph[*node].cycles {
                    min += cycles.min;
                    max += cycles.max;
                    modeled += 1;
                }
            }
            Some(FunctionTiming {
                static_block_sum_cycles: elf2tdg_schema::CostRange::new(min, max),
                modeled_blocks: modeled,
                unmodeled_blocks: u32::try_from(draft.cfg.blocks_by_address.len())
                    .unwrap_or(u32::MAX)
                    .saturating_sub(modeled),
                caveats: vec![
                    "Sum of static block costs; this is not a path time or a WCET bound."
                        .to_owned(),
                ],
            })
        });

        let mut ext = BTreeMap::new();
        if let Some(reason) = draft.noreturn {
            ext.insert("elf2tdg.noreturn".to_owned(), serde_json::Value::Bool(true));
            ext.insert(
                "elf2tdg.noreturn_source".to_owned(),
                serde_json::Value::String(
                    match reason {
                        cfg::CfgNoreturnReason::Api => "api",
                        cfg::CfgNoreturnReason::ControlFlow => "control-flow",
                    }
                    .to_owned(),
                ),
            );
        }

        Function {
            id: function_id(draft.address),
            primary_name: draft.display.clone(),
            demangled_name: draft.demangled.clone(),
            symbols: draft.names.clone(),
            language: draft.language,
            address: Addr::new(draft.address),
            size: draft.size,
            section: Some(draft.section.clone()),
            kind: draft.kind,
            blocks,
            timing,
            source: self
                .image
                .dwarf
                .as_ref()
                .and_then(|dwarf| dwarf.source_at(draft.address))
                .map(|source| SourceLoc {
                    file: source.file.clone(),
                    line: source.line,
                    column: source.column,
                }),
            inline_sites: Vec::new(),
            ext,
        }
    }

    fn find_main_address(&self) -> Option<u64> {
        self.functions
            .values()
            .filter(|function| {
                function.names.iter().any(|name| name == "main")
                    || function.display == "main"
                    || function.display.ends_with("::main")
            })
            .map(|function| function.address)
            .min()
    }

    fn resolve_function_address(&self, address: u64) -> Option<u64> {
        if self.functions.contains_key(&address) {
            Some(address)
        } else {
            self.function_containing(address)
        }
    }

    fn function_containing(&self, address: u64) -> Option<u64> {
        self.functions
            .range(..=address)
            .next_back()
            .and_then(|(start, function)| {
                if address < start.saturating_add(function.size) {
                    Some(*start)
                } else {
                    None
                }
            })
    }

    fn diag(
        &mut self,
        severity: Severity,
        code: &str,
        message: impl Into<String>,
        function: Option<u64>,
        site: Option<u64>,
    ) {
        let key = (code.to_owned(), function, site);
        if !self.diagnostic_keys.insert(key) {
            return;
        }
        if self.diagnostics.len() >= self.options.max_diagnostics {
            return;
        }
        self.diagnostics.push(Diagnostic {
            code: code.to_owned(),
            severity,
            message: message.into(),
            function: function.map(function_id),
            context: None,
            site: site.map(Addr::new),
            details: BTreeMap::new(),
        });
    }
}

fn replace_unresolved_cfg_call(
    function_cfg: &mut cfg::FunctionCfg,
    site: u64,
    resolved: cfg::CfgCallSite,
) -> bool {
    for node in function_cfg.blocks_by_address.values() {
        let block = &mut function_cfg.graph[*node];
        if !block
            .calls
            .iter()
            .any(|call| call.site == site && call.unresolved)
        {
            continue;
        }
        block
            .calls
            .retain(|call| !(call.site == site && call.unresolved));
        block.calls.push(resolved);
        block.calls.sort_by_key(|call| call.site);
        return true;
    }
    if function_cfg
        .recovered_calls
        .iter()
        .any(|call| call.site == site && call.unresolved)
    {
        function_cfg
            .recovered_calls
            .retain(|call| !(call.site == site && call.unresolved));
        function_cfg.recovered_calls.push(resolved);
        function_cfg.recovered_calls.sort_by_key(|call| call.site);
        return true;
    }
    false
}

fn is_pointer_root_section(section: &Section) -> bool {
    if !section.alloc || section.executable || section.data.is_empty() {
        return false;
    }
    let name = section.name.as_str();
    if has_section_prefix(name, ".tdata") || has_section_prefix(name, ".tbss") {
        return false;
    }
    if section.writable || is_static_init_array(name) {
        return true;
    }
    [".rodata", ".srodata", ".data.rel.ro", ".got", ".got.plt"]
        .iter()
        .any(|prefix| has_section_prefix(name, prefix))
}

fn is_static_init_array(name: &str) -> bool {
    [
        ".init_array",
        ".fini_array",
        ".preinit_array",
        ".ctors",
        ".dtors",
    ]
    .iter()
    .any(|prefix| has_section_prefix(name, prefix))
}

fn has_section_prefix(name: &str, prefix: &str) -> bool {
    name == prefix
        || name
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn classify_noreturn_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Option<cfg::CfgNoreturnReason> {
    names
        .into_iter()
        .any(rules::is_noreturn_name)
        .then_some(cfg::CfgNoreturnReason::Api)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn collect_return_definitions(
    image: &Image,
    function_cfg: &cfg::FunctionCfg,
    decoded: &[DecodedInsn],
    node: NodeIndex,
    before: Option<u64>,
    register: capstone::RegId,
    visited: &mut BTreeSet<(NodeIndex, capstone::RegId, u64)>,
    values: &mut BTreeSet<u64>,
) -> bool {
    if visited.len() > 512 {
        return false;
    }
    let key = (node, register, before.unwrap_or(u64::MAX));
    if !visited.insert(key) {
        // A loop back-edge was already explored on another path.
        return true;
    }
    let block = &function_cfg.graph[node];
    let mut definition = None;
    for instruction in block.instructions.iter().rev() {
        if before.is_some_and(|before| instruction.address >= before) {
            continue;
        }
        let Ok(index) =
            decoded.binary_search_by_key(&instruction.address, |decoded| decoded.address)
        else {
            continue;
        };
        if let Some(effect) = decoded[index].value
            && effect.dest == register
        {
            definition = Some((index, effect.source));
            break;
        }
        if decoded[index].is_call {
            // The call clobbers the register; its own return summary would be
            // needed to describe this path.
            return false;
        }
    }
    if let Some((index, source)) = definition {
        return match source {
            ValueSource::Copy(source) => collect_return_definitions(
                image,
                function_cfg,
                decoded,
                node,
                Some(decoded[index].address),
                source,
                visited,
                values,
            ),
            ValueSource::Select { left, right } => {
                for source in [left, right] {
                    if !collect_return_definitions(
                        image,
                        function_cfg,
                        decoded,
                        node,
                        Some(decoded[index].address),
                        source,
                        visited,
                        values,
                    ) {
                        return false;
                    }
                }
                true
            }
            ValueSource::LoadFromRegister { base, disp } if is_frame_register(image.arch, base) => {
                let Some(candidates) =
                    origin::resolve_stack_slot_candidates(image, decoded, base, disp)
                else {
                    return false;
                };
                values.extend(candidates);
                true
            }
            ValueSource::AddRegister { .. }
            | ValueSource::IndexedLoad { .. }
            | ValueSource::ShiftRegister { .. } => false,
            _ => origin::resolve_definition_value(image, decoded, index).is_some_and(|value| {
                values.insert(value);
                true
            }),
        };
    }
    let mut predecessors = function_cfg
        .graph
        .neighbors_directed(node, petgraph::Direction::Incoming)
        .peekable();
    if predecessors.peek().is_none() {
        return false;
    }
    for predecessor in predecessors {
        if !collect_return_definitions(
            image,
            function_cfg,
            decoded,
            predecessor,
            None,
            register,
            visited,
            values,
        ) {
            return false;
        }
    }
    true
}

fn cfg_may_return(function_cfg: &cfg::FunctionCfg) -> bool {
    let Some(entry) = function_cfg.entry else {
        return true;
    };
    let nodes: Vec<NodeIndex> = function_cfg.blocks_by_address.values().copied().collect();
    let mut may_return: BTreeMap<NodeIndex, bool> =
        nodes.iter().map(|node| (*node, false)).collect();
    loop {
        let mut changed = false;
        for node in &nodes {
            if may_return.get(node).copied().unwrap_or(false) {
                continue;
            }
            let block = &function_cfg.graph[*node];
            let successors: Vec<NodeIndex> = function_cfg
                .graph
                .neighbors_directed(*node, petgraph::Direction::Outgoing)
                .collect();
            if block_may_return(block, &successors, &may_return) {
                may_return.insert(*node, true);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    may_return.get(&entry).copied().unwrap_or(true)
}

fn block_may_return(
    block: &cfg::CfgBlock,
    successors: &[NodeIndex],
    may_return: &BTreeMap<NodeIndex, bool>,
) -> bool {
    let successor_returns = || {
        successors
            .iter()
            .any(|successor| may_return.get(successor).copied().unwrap_or(false))
    };
    let call = block
        .instructions
        .last()
        .and_then(|last| block.calls.iter().find(|call| call.site == last.address));
    match block.terminator {
        cfg::CfgTerminator::NoreturnCall => false,
        cfg::CfgTerminator::Return | cfg::CfgTerminator::Unresolved => true,
        cfg::CfgTerminator::Call => {
            if call.is_some_and(|call| call.noreturn && !call.conditional) {
                false
            } else if successors.is_empty() {
                true
            } else {
                successor_returns()
            }
        }
        cfg::CfgTerminator::Jump => {
            if let Some(call) = call.filter(|call| call.tail) {
                // A tail call transfers the caller's return to the callee.
                !call.noreturn
            } else if successors.is_empty() {
                true
            } else {
                successor_returns()
            }
        }
        cfg::CfgTerminator::Fallthrough | cfg::CfgTerminator::Branch => {
            successors.is_empty() || successor_returns()
        }
    }
}

fn is_embassy_executor_function(name: &str) -> bool {
    let name = rules::normalize_crate_hashes(name);
    name.contains("embassy_executor::") && name.contains("Executor")
}

fn is_embassy_poll_target(name: &str) -> bool {
    let name = rules::normalize_crate_hashes(name);
    (name.contains("TaskStorage<") && name.ends_with("::poll")) || name.ends_with("poll_exited")
}

fn update_cfg_call_site(function_cfg: &mut cfg::FunctionCfg, call: cfg::CfgCallSite) -> bool {
    for node in function_cfg.blocks_by_address.values() {
        let block = &mut function_cfg.graph[*node];
        if let Some(existing) = block
            .calls
            .iter_mut()
            .find(|existing| existing.site == call.site)
        {
            *existing = call;
            return true;
        }
    }
    if let Some(existing) = function_cfg
        .recovered_calls
        .iter_mut()
        .find(|existing| existing.site == call.site)
    {
        *existing = call;
        return true;
    }
    false
}

fn frequency_only_timing_info(frequency_hz: Option<u64>) -> TimingInfo {
    let frequency_domains = frequency_hz
        .map(|hz| {
            vec![FrequencyDomain {
                id: FrequencyDomainId::new(CORE_DOMAIN),
                name: "core".to_owned(),
                hz,
                source: FrequencySource::Cli,
                confidence: Confidence::High,
            }]
        })
        .unwrap_or_default();
    TimingInfo {
        models: Vec::new(),
        frequency_domains,
        default_frequency_domain: frequency_hz.map(|_| FrequencyDomainId::new(CORE_DOMAIN)),
        caveats: vec![
            "No instruction timing model is available for this architecture in M0.".to_owned(),
        ],
    }
}

fn function_id(address: u64) -> FunctionId {
    FunctionId::new(format!("fn:0x{address:x}"))
}

fn block_id(address: u64) -> BlockId {
    BlockId::new(format!("bb:0x{address:x}"))
}

fn insn_text(insn: &DecodedInsn) -> String {
    if insn.operands.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} {}", insn.mnemonic, insn.operands)
    }
}

fn sum_costs(model: TimingModel, instructions: &[DecodedInsn]) -> elf2tdg_schema::CostRange {
    let mut min = 0.0_f64;
    let mut max = 0.0_f64;
    for instruction in instructions {
        let cost = model.instruction_cost(instruction);
        min += cost.min;
        max += cost.max;
    }
    elf2tdg_schema::CostRange::new(min, max)
}

#[derive(Clone)]
struct NameChoice {
    display: String,
    demangled: Option<String>,
    language: Language,
}

/// Returns whether any symbol alias at `address` marks a runtime default
/// handler. Cortex-M runtimes commonly alias unused vectors to a shared
/// `DefaultHandler`, but may also expose a weaker name such as `PendSV` for
/// the same address. Looking only at the chosen display name then creates one
/// ISR context per unused vector.
fn has_default_handler_alias(image: &Image, address: u64) -> bool {
    image
        .symbols
        .iter()
        .filter(|symbol| symbol.canonical_address == address)
        .any(|symbol| {
            let name = symbol.name.to_ascii_lowercase();
            name.contains("default_handler") || name.contains("defaulthandler")
        })
}

fn choose_name(names: &[String]) -> NameChoice {
    #[derive(Clone)]
    struct Candidate {
        score: u8,
        display: String,
        demangled: Option<String>,
        language: Language,
    }
    let mut candidates = Vec::new();
    for name in names {
        if let Ok(demangled) = rustc_demangle::try_demangle(name) {
            let display = demangled.to_string();
            candidates.push(Candidate {
                score: 0,
                display: display.clone(),
                demangled: Some(display),
                language: Language::Rust,
            });
        } else if name.starts_with("_Z") {
            candidates.push(Candidate {
                score: 1,
                display: name.clone(),
                demangled: None,
                language: Language::Cpp,
            });
        } else {
            let lower = name.to_ascii_lowercase();
            let default_handler =
                lower.contains("default_handler") || lower.contains("defaulthandler");
            candidates.push(Candidate {
                score: if default_handler {
                    0
                } else if name.starts_with('_') {
                    3
                } else {
                    2
                },
                display: name.clone(),
                demangled: None,
                language: Language::C,
            });
        }
    }
    candidates.sort_by(|left, right| {
        (left.score, left.display.len(), &left.display).cmp(&(
            right.score,
            right.display.len(),
            &right.display,
        ))
    });
    if let Some(candidate) = candidates.into_iter().next() {
        NameChoice {
            display: candidate.display,
            demangled: candidate.demangled,
            language: candidate.language,
        }
    } else {
        NameChoice {
            display: String::new(),
            demangled: None,
            language: Language::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisOptions, analyze, analyze_with_cfg};
    use crate::loader::{ArchKind, ByteOrder, ElfKind, Image, ImageSymbol, Section};
    use elf2tdg_schema::FunctionKind;
    use object::SymbolKind;

    fn image_with_code(code: Vec<u8>, symbols: Vec<(&str, u64, u64)>) -> Image {
        image_with_arch(ArchKind::X86_64, code, symbols)
    }

    fn image_with_arch(arch: ArchKind, code: Vec<u8>, symbols: Vec<(&str, u64, u64)>) -> Image {
        let symbols = symbols
            .into_iter()
            .map(|(name, address, size)| ImageSymbol {
                name: name.to_owned(),
                address,
                canonical_address: address & !1,
                size,
                kind: SymbolKind::Text,
                section: Some(".text".to_owned()),
                thumb: false,
            })
            .collect();
        Image {
            path: "synthetic.elf".into(),
            arch,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
            imported_slots: std::collections::BTreeMap::default(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".text".to_owned(),
                address: 0x1000,
                size: code.len() as u64,
                data: code,
                executable: true,
                writable: false,
                alloc: true,
            }],
            symbols,
            has_symbols: true,
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
    fn builds_call_graph_and_blocks() {
        // 0x1000: call 0x1010
        // 0x1005: ret
        // 0x1010: ret
        let image = image_with_code(
            vec![
                0xe8, 0x0b, 0x00, 0x00, 0x00, // call 0x1010
                0xc3, // ret
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0xc3, // ret at 0x1010
            ],
            vec![("main", 0x1000, 6), ("callee", 0x1010, 1)],
        );
        let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        assert_eq!(tdg.functions.len(), 2);
        assert!(tdg.functions.iter().any(|function| {
            function.primary_name == "main" && function.kind == FunctionKind::Entry
        }));
        let call = tdg
            .edges
            .iter()
            .find(|edge| matches!(edge, elf2tdg_schema::Edge::Call { .. }))
            .expect("call edge");
        match call {
            elf2tdg_schema::Edge::Call { caller, callee, .. } => {
                assert_eq!(caller.as_str(), "fn:0x1000");
                assert_eq!(callee.as_str(), "fn:0x1010");
            }
            _ => unreachable!(),
        }
        tdg.ensure_valid().expect("TDG must validate");
    }

    #[test]
    fn recovers_gap_call_after_unresolved_indirect_jump() {
        // jmp rax; padding with a direct call to 0x1020; ret.
        let mut code = vec![0xff, 0xe0];
        code.resize(0x10, 0x90);
        code.extend_from_slice(&[0xe8, 0x0b, 0x00, 0x00, 0x00]);
        code.push(0xc3);
        code.resize(0x20, 0x90);
        code.push(0xc3);
        let image = image_with_code(code, vec![("main", 0x1000, 0x20), ("callee", 0x1020, 1)]);
        let analysis =
            analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        let main = analysis
            .cfg
            .function(&elf2tdg_schema::FunctionId::new("fn:0x1000"))
            .expect("main CFG");
        assert!(
            main.cfg
                .recovered_calls
                .iter()
                .any(|call| { call.target == Some(0x1020) && call.heuristic && !call.unresolved })
        );
    }

    #[test]
    fn recovers_unresolved_indirect_call_as_diagnostic() {
        // call rax; ret
        let image = image_with_code(vec![0xff, 0xd0, 0xc3], vec![("main", 0x1000, 3)]);
        let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        assert!(
            tdg.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unresolved-indirect-call")
        );
    }

    #[test]
    fn aarch64_direct_call_is_recovered() {
        let image = image_with_arch(
            ArchKind::Aarch64,
            vec![
                0x02, 0x00, 0x00, 0x94, // bl 0x1008
                0xc0, 0x03, 0x5f, 0xd6, // ret
                0xc0, 0x03, 0x5f, 0xd6, // ret at 0x1008
            ],
            vec![("main", 0x1000, 8), ("callee", 0x1008, 4)],
        );
        let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        assert!(tdg.edges.iter().any(|edge| matches!(
            edge,
            elf2tdg_schema::Edge::Call { caller, callee, .. }
                if caller.as_str() == "fn:0x1000" && callee.as_str() == "fn:0x1008"
        )));
        assert!(
            tdg.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "timing-model-unavailable")
        );
    }

    #[test]
    fn riscv_direct_call_and_timing_are_recovered() {
        let image = image_with_arch(
            ArchKind::Riscv32,
            vec![
                0xef, 0x00, 0x80, 0x00, // jal ra, 0x1008
                0x67, 0x80, 0x00, 0x00, // ret
                0x67, 0x80, 0x00, 0x00, // ret at 0x1008
            ],
            vec![("main", 0x1000, 8), ("callee", 0x1008, 4)],
        );
        let options = AnalysisOptions {
            frequency_hz: Some(32_000_000),
            ..AnalysisOptions::default()
        };
        let tdg = analyze(&image, &options).expect("analysis succeeds");
        assert_eq!(
            tdg.timing.models.first().map(|model| model.id.as_str()),
            Some("riscv32-generic")
        );
        assert!(tdg.edges.iter().any(|edge| matches!(
            edge,
            elf2tdg_schema::Edge::Call { caller, callee, .. }
                if caller.as_str() == "fn:0x1000" && callee.as_str() == "fn:0x1008"
        )));
        assert!(tdg.functions.iter().any(|function| {
            function.id.as_str() == "fn:0x1000"
                && function
                    .blocks
                    .first()
                    .and_then(|block| block.timing.as_ref())
                    .and_then(|timing| timing.time_ns)
                    .is_some()
        }));
    }

    #[test]
    fn prefers_default_handler_alias_over_vector_weak_names() {
        let choice = super::choose_name(&[
            "PendSV".to_owned(),
            "DefaultHandler".to_owned(),
            "DefaultHandler_".to_owned(),
        ]);
        assert_eq!(choice.display, "DefaultHandler");
    }

    #[test]
    fn detects_c_runtime_spawn_as_opaque_edge() {
        // main: call pthread_create; ret
        // pthread_create: ret
        let image = image_with_code(
            vec![
                0xe8, 0x0b, 0x00, 0x00, 0x00, // call 0x1010
                0xc3, // ret
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0xc3, // ret at 0x1010
            ],
            vec![("main", 0x1000, 6), ("pthread_create", 0x1010, 1)],
        );
        let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        let spawn = tdg
            .edges
            .iter()
            .find_map(|edge| match edge {
                elf2tdg_schema::Edge::Spawn {
                    runtime,
                    target: elf2tdg_schema::SpawnTarget::Opaque { .. },
                    ..
                } => Some(runtime),
                _ => None,
            })
            .expect("pthread spawn edge");
        assert_eq!(spawn.as_str(), "pthread");
    }

    #[test]
    fn exposes_logical_embassy_task_in_program_cfg() {
        let spawn_name = "<embassy_executor::spawner::Spawner>::spawn::<app::task>";
        let image = image_with_code(
            vec![
                0xe8, 0x0b, 0x00, 0x00, 0x00, // call 0x1010
                0xc3, // ret
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0xc3, // ret at 0x1010
            ],
            vec![("main", 0x1000, 6), (spawn_name, 0x1010, 1)],
        );
        let analysis =
            analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        let logical = analysis
            .tdg
            .functions
            .iter()
            .find(|function| {
                function.kind == FunctionKind::TaskEntry
                    && function
                        .ext
                        .get("elf2tdg.logical_task")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
            })
            .expect("logical task entry");
        let cfg_function = analysis
            .cfg
            .function(&logical.id)
            .expect("logical CFG function");
        assert!(cfg_function.cfg.blocks_by_address.is_empty());
        assert_eq!(cfg_function.kind, FunctionKind::TaskEntry);

        let selected = analysis
            .cfg
            .select_with_tdg(&analysis.tdg, Some("app::task"))
            .expect("logical selector");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, logical.id);

        let json = crate::cfg::render_json(&analysis.cfg, &analysis.tdg, Some("app::task"), false)
            .expect("logical CFG JSON");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["functions"][0]["kind"], "task-entry");
        assert_eq!(value["functions"][0]["no_code"]["reason"], "logical");
        assert_eq!(
            value["functions"][0]["blocks"].as_array().map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn resolves_pthread_create_entry_argument() {
        // 0x1000: lea rdx, [rip + 9]  -> 0x1010
        // 0x1007: call 0x1020          (pthread_create)
        // 0x100c: ret
        // 0x1010: ret                  (task)
        // 0x1020: ret                  (pthread_create)
        let mut code = vec![
            0x48, 0x8d, 0x15, 0x09, 0x00, 0x00, 0x00, // lea rdx, [rip + 9]
            0xe8, 0x14, 0x00, 0x00, 0x00, // call 0x1020
            0xc3, // ret
        ];
        code.resize(0x10, 0x90);
        code.push(0xc3); // task at 0x1010
        code.resize(0x20, 0x90);
        code.push(0xc3); // pthread_create at 0x1020
        let image = image_with_code(
            code,
            vec![
                ("main", 0x1000, 13),
                ("task", 0x1010, 1),
                ("pthread_create", 0x1020, 1),
            ],
        );
        let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        tdg.ensure_valid().expect("TDG must validate");
        let (context, entry) = tdg
            .edges
            .iter()
            .find_map(|edge| match edge {
                elf2tdg_schema::Edge::Spawn {
                    runtime,
                    target: elf2tdg_schema::SpawnTarget::Context { context, entry, .. },
                    ..
                } if runtime.as_str() == "pthread" => Some((context, entry)),
                _ => None,
            })
            .expect("resolved pthread spawn");
        assert_eq!(entry.as_str(), "fn:0x1010");
        let context = tdg
            .contexts
            .iter()
            .find(|candidate| &candidate.id == context)
            .expect("thread context");
        assert_eq!(context.kind, elf2tdg_schema::ContextKind::Thread);
        assert_eq!(context.entry.as_str(), "fn:0x1010");
    }

    #[test]
    fn creates_synthetic_callee_without_symbol() {
        // call 0x1008; ret; ret
        let image = image_with_code(
            vec![
                0xe8, 0x03, 0x00, 0x00, 0x00, // call 0x1008
                0xc3, // ret
                0x90, 0x90, // padding
                0xc3, // ret at 0x1008
            ],
            vec![("main", 0x1000, 6)],
        );
        let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis succeeds");
        assert!(
            tdg.functions
                .iter()
                .any(|function| function.id.as_str() == "fn:0x1008")
        );
        assert!(
            tdg.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "synthetic-function")
        );
    }
}
