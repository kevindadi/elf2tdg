//! Instruction timing models.
//!
//! The tables intentionally produce bounded or statistical cycle estimates
//! rather than pretending to be a WCET proof. Cortex-M and generic RISC-V
//! models are selected automatically. Generic `AArch64` and `x86-64` models are
//! statistical throughput tables and must be selected explicitly with
//! `--cpu aarch64` or `--cpu x86-64`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use elf2tdg_schema::{
    BlockTiming, CacheParams, Confidence, CostRange, Determinism, FrequencyDomain,
    FrequencyDomainId, FrequencySource, TimingInfo, TimingModelId, TimingModelInfo, TimingParams,
};
use serde::Deserialize;

use crate::arch::{DecodedInsn, MemoryAccess, MemoryAccessKind};
use crate::board_profile::{BoardProfile, BranchPredictionModel, UnknownInstructionPolicy};
use crate::error::{Error, Result};
use crate::loader::{ArchKind, Image};

/// Core clock domain ID used by M0.
pub const CORE_DOMAIN: &str = "clk:core";

/// A concrete instruction timing model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingModel {
    /// Cortex-M0.
    CortexM0,
    /// Cortex-M0+.
    CortexM0Plus,
    /// Cortex-M3.
    CortexM3,
    /// Cortex-M4.
    CortexM4,
    /// Cortex-M7.
    CortexM7,
    /// Cortex-M33.
    CortexM33,
    /// Generic in-order RV32 throughput model.
    RiscV32,
    /// Generic in-order RV64 throughput model.
    RiscV64,
    /// Abstract single-issue in-order RV32 bounded model.
    RiscV32Bounded,
    /// Abstract single-issue in-order RV64 bounded model.
    RiscV64Bounded,
    /// Generic out-of-order `AArch64` throughput model.
    Aarch64Generic,
    /// Abstract single-issue in-order `AArch64` bounded model.
    Aarch64Bounded,
    /// Generic out-of-order `x86-64` throughput model.
    X86_64Generic,
}

impl TimingModel {
    /// Parses a CLI CPU/timing-model name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let normalized = name.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "cortex-m0" | "m0" => Some(Self::CortexM0),
            "cortex-m0plus" | "cortex-m0+" | "m0plus" | "m0+" => Some(Self::CortexM0Plus),
            "cortex-m3" | "m3" => Some(Self::CortexM3),
            "cortex-m4" | "m4" => Some(Self::CortexM4),
            "cortex-m7" | "m7" => Some(Self::CortexM7),
            "cortex-m33" | "m33" => Some(Self::CortexM33),
            "riscv32" | "riscv32-generic" | "rv32" => Some(Self::RiscV32),
            "riscv64" | "riscv64-generic" | "rv64" => Some(Self::RiscV64),
            "riscv32-bounded" | "rv32-bounded" | "riscv32-inorder" | "rv32-inorder" => {
                Some(Self::RiscV32Bounded)
            }
            "riscv64-bounded" | "rv64-bounded" | "riscv64-inorder" | "rv64-inorder" => {
                Some(Self::RiscV64Bounded)
            }
            "aarch64" | "aarch64-generic" | "arm64" | "cortex-a53" | "cortex-a55"
            | "cortex-a72" | "cortex-a76" | "neoverse-n1" => Some(Self::Aarch64Generic),
            "aarch64-bounded" | "aarch64-inorder" | "aarch64-in-order" => {
                Some(Self::Aarch64Bounded)
            }
            "x86-64" | "x86-64-generic" | "amd64" | "x86-64-v2" | "x86-64-v3" => {
                Some(Self::X86_64Generic)
            }
            _ => None,
        }
    }

    /// Auto-detects a model from the image. Returns `None` when M0 has no
    /// timing table for the architecture/CPU.
    #[must_use]
    pub fn auto(image: &Image) -> Option<Self> {
        match image.arch {
            ArchKind::Thumb => image.arm_cpu.as_deref().and_then(Self::from_arm_cpu_name),
            ArchKind::Riscv32 => Some(Self::RiscV32),
            ArchKind::Riscv64 => Some(Self::RiscV64),
            // A generic out-of-order throughput table is not a safe default
            // for every AArch64/x86-64 core. Require an explicit --cpu choice.
            ArchKind::Arm | ArchKind::Aarch64 | ArchKind::X86_64 => None,
        }
    }

    fn from_arm_cpu_name(name: &str) -> Option<Self> {
        let normalized = name.trim().to_ascii_lowercase();
        if normalized.starts_with("cortex-m0+") {
            Some(Self::CortexM0Plus)
        } else if normalized.starts_with("cortex-m0") {
            Some(Self::CortexM0)
        } else if normalized.starts_with("cortex-m3") {
            Some(Self::CortexM3)
        } else if normalized.starts_with("cortex-m4") {
            Some(Self::CortexM4)
        } else if normalized.starts_with("cortex-m7") {
            Some(Self::CortexM7)
        } else if normalized.starts_with("cortex-m33") {
            Some(Self::CortexM33)
        } else {
            None
        }
    }

    /// Selects the timing model for an image.
    ///
    /// An explicit CPU name must be compatible with the ELF architecture.
    /// Generic AArch64/x86-64 throughput models are opt-in because their
    /// results are statistical and vary substantially across real cores.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for an unknown or incompatible `--cpu`.
    pub fn select(explicit: Option<&str>, image: &Image) -> Result<Option<Self>> {
        let Some(name) = explicit else {
            return Ok(Self::auto(image));
        };
        let Some(model) = Self::from_name(name) else {
            return Err(Error::Config(format!(
                "unknown CPU/timing model {name:?}; use cortex-m0, cortex-m0plus, cortex-m3, cortex-m4, cortex-m7, cortex-m33, riscv32, riscv64, riscv32-bounded, riscv64-bounded, aarch64, aarch64-bounded or x86-64"
            )));
        };
        if !model.matches_arch(image.arch) {
            return Err(Error::Config(format!(
                "timing model {} is not compatible with ELF architecture {}",
                model.id(),
                image.arch.schema_name()
            )));
        }
        Ok(Some(model))
    }

    fn matches_arch(self, arch: ArchKind) -> bool {
        match self {
            Self::CortexM0
            | Self::CortexM0Plus
            | Self::CortexM3
            | Self::CortexM4
            | Self::CortexM7
            | Self::CortexM33 => arch == ArchKind::Thumb,
            Self::RiscV32 | Self::RiscV32Bounded => arch == ArchKind::Riscv32,
            Self::RiscV64 | Self::RiscV64Bounded => arch == ArchKind::Riscv64,
            Self::Aarch64Generic | Self::Aarch64Bounded => arch == ArchKind::Aarch64,
            Self::X86_64Generic => arch == ArchKind::X86_64,
        }
    }

    /// Stable model ID.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::CortexM0 => "cortex-m0",
            Self::CortexM0Plus => "cortex-m0plus",
            Self::CortexM3 => "cortex-m3",
            Self::CortexM4 => "cortex-m4",
            Self::CortexM7 => "cortex-m7",
            Self::CortexM33 => "cortex-m33",
            Self::RiscV32 => "riscv32-generic",
            Self::RiscV64 => "riscv64-generic",
            Self::RiscV32Bounded => "riscv32-bounded",
            Self::RiscV64Bounded => "riscv64-bounded",
            Self::Aarch64Generic => "aarch64-generic",
            Self::Aarch64Bounded => "aarch64-bounded",
            Self::X86_64Generic => "x86-64-generic",
        }
    }

    /// Timing model architecture string.
    #[must_use]
    pub fn arch(self) -> &'static str {
        match self {
            Self::CortexM0
            | Self::CortexM0Plus
            | Self::CortexM3
            | Self::CortexM4
            | Self::CortexM7
            | Self::CortexM33 => "thumb",
            Self::RiscV32 | Self::RiscV32Bounded => "riscv32",
            Self::RiscV64 | Self::RiscV64Bounded => "riscv64",
            Self::Aarch64Generic | Self::Aarch64Bounded => "aarch64",
            Self::X86_64Generic => "x86-64",
        }
    }

    /// Human-readable core name.
    #[must_use]
    pub fn core(self) -> &'static str {
        match self {
            Self::CortexM0 => "Cortex-M0",
            Self::CortexM0Plus => "Cortex-M0+",
            Self::CortexM3 => "Cortex-M3",
            Self::CortexM4 => "Cortex-M4",
            Self::CortexM7 => "Cortex-M7",
            Self::CortexM33 => "Cortex-M33",
            Self::RiscV32 => "generic in-order RV32",
            Self::RiscV64 => "generic in-order RV64",
            Self::RiscV32Bounded => "bounded single-issue in-order RV32",
            Self::RiscV64Bounded => "bounded single-issue in-order RV64",
            Self::Aarch64Generic => "generic AArch64",
            Self::Aarch64Bounded => "bounded single-issue in-order AArch64",
            Self::X86_64Generic => "generic x86-64",
        }
    }

    /// Whether this is an explicit abstract bounded model.
    #[must_use]
    pub fn is_bounded_abstract(self) -> bool {
        matches!(
            self,
            Self::RiscV32Bounded | Self::RiscV64Bounded | Self::Aarch64Bounded
        )
    }

    /// Whether the board-profile in-order resource/dependency pipeline model
    /// can be selected for this timing model.
    #[must_use]
    pub(crate) fn supports_pipeline_model(self) -> bool {
        matches!(
            self,
            Self::CortexM4
                | Self::RiscV32
                | Self::RiscV64
                | Self::RiscV32Bounded
                | Self::RiscV64Bounded
                | Self::Aarch64Generic
                | Self::Aarch64Bounded
        )
    }

    /// Version of the cost table.
    #[must_use]
    pub fn table_version(self) -> &'static str {
        if self.is_bounded_abstract() {
            "0.3.0-bounded"
        } else {
            "0.2.0-m3"
        }
    }

    /// Determinism class of the model.
    #[must_use]
    pub fn determinism(self) -> Determinism {
        match self {
            Self::CortexM0
            | Self::CortexM0Plus
            | Self::CortexM3
            | Self::CortexM4
            | Self::CortexM33
            | Self::RiscV32Bounded
            | Self::RiscV64Bounded
            | Self::Aarch64Bounded => Determinism::Bounded,
            Self::CortexM7
            | Self::RiscV32
            | Self::RiscV64
            | Self::Aarch64Generic
            | Self::X86_64Generic => Determinism::Statistical,
        }
    }

    /// Confidence in a block estimate from this model.
    #[must_use]
    pub fn confidence(self) -> Confidence {
        match self {
            Self::CortexM0
            | Self::CortexM0Plus
            | Self::CortexM3
            | Self::CortexM4
            | Self::CortexM33 => Confidence::Medium,
            Self::CortexM7
            | Self::RiscV32
            | Self::RiscV64
            | Self::RiscV32Bounded
            | Self::RiscV64Bounded
            | Self::Aarch64Generic
            | Self::Aarch64Bounded
            | Self::X86_64Generic => Confidence::Low,
        }
    }

    /// Model caveats.
    #[must_use]
    pub fn caveats(self) -> Vec<String> {
        let mut caveats = vec![
            "Core-cycle estimate excludes flash wait states, bus contention, interrupts and caches."
                .to_owned(),
        ];
        match self {
            Self::CortexM0 | Self::CortexM0Plus => caveats.push(
                "Cortex-M0/M0+ modeled as a single-issue in-order pipeline.".to_owned(),
            ),
            Self::CortexM3 | Self::CortexM4 | Self::CortexM33 => caveats.push(
                "Load/store and branch penalties are table-based; cache/TCM configuration is not modeled."
                    .to_owned(),
            ),
            Self::CortexM7 => caveats.push(
                "Cortex-M7 branch prediction, caches and dual-issue are not modeled; treat as a rough estimate."
                    .to_owned(),
            ),
            Self::RiscV32 | Self::RiscV64 => caveats.push(
                "Generic in-order RISC-V throughput model; a specific core's pipeline and memory system may differ substantially."
                    .to_owned(),
            ),
            Self::RiscV32Bounded | Self::RiscV64Bounded => caveats.push(
                "Bounded abstract RISC-V model: additive per-instruction upper bounds for a single-issue in-order core. Base costs assume single-cycle instruction/data memory and include a branch/call/return allowance; caches, memory latency, multicore interference and exceptions require a board profile or are unmodeled."
                    .to_owned(),
            ),
            Self::Aarch64Generic => caveats.push(
                "Generic AArch64 throughput model: out-of-order issue, caches, branch prediction and memory latency are not modeled; this is not a bound."
                    .to_owned(),
            ),
            Self::Aarch64Bounded => caveats.push(
                "Bounded abstract AArch64 model: additive per-instruction upper bounds for a single-issue in-order core. Base costs assume single-cycle instruction/data memory and include a branch/call/return allowance; caches, memory latency, multicore interference and exceptions require a board profile or are unmodeled."
                    .to_owned(),
            ),
            Self::X86_64Generic => caveats.push(
                "Generic x86-64 throughput model: pipeline width, caches, branch misprediction and memory latency are not modeled; this is not a bound."
                    .to_owned(),
            ),
        }
        caveats
    }

    /// Model parameters recorded in the CFG timing metadata.
    #[must_use]
    pub fn params(self) -> TimingParams {
        match self {
            Self::RiscV32Bounded | Self::RiscV64Bounded | Self::Aarch64Bounded => {
                let mut extras = BTreeMap::new();
                extras.insert(
                    "bounded_semantics".to_owned(),
                    "abstract-single-issue-in-order".to_owned(),
                );
                extras.insert("base_memory_model".to_owned(), "single-cycle".to_owned());
                extras.insert("pipeline_overlap".to_owned(), "none".to_owned());
                extras.insert(
                    "branch_allowance".to_owned(),
                    "included-in-class-upper-bounds".to_owned(),
                );
                TimingParams {
                    extras,
                    ..TimingParams::default()
                }
            }
            Self::CortexM7 | Self::Aarch64Generic | Self::X86_64Generic => TimingParams {
                caches: Some(CacheParams {
                    icache: true,
                    dcache: true,
                    line_bytes: None,
                }),
                branch_prediction: Some(true),
                ..TimingParams::default()
            },
            _ => TimingParams::default(),
        }
    }

    /// Modeled cycle cost of one instruction.
    #[must_use]
    pub fn instruction_cost(self, insn: &DecodedInsn) -> CostRange {
        let class = classify(insn).class;
        match self {
            Self::CortexM0 | Self::CortexM0Plus => cortex_m0_cost(class),
            Self::CortexM3 | Self::CortexM4 | Self::CortexM33 => cortex_m3_cost(class),
            Self::CortexM7 => cortex_m7_cost(class),
            Self::RiscV32 | Self::RiscV64 => riscv_cost(class),
            Self::RiscV32Bounded => riscv_bounded_cost(class, 64),
            Self::RiscV64Bounded => riscv_bounded_cost(class, 128),
            Self::Aarch64Generic => aarch64_cost(class),
            Self::Aarch64Bounded => aarch64_bounded_cost(class),
            Self::X86_64Generic => x86_64_cost(class),
        }
    }

    /// Builds CFG timing metadata.
    #[must_use]
    pub fn timing_info(self, frequency_hz: Option<u64>) -> TimingInfo {
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
            models: vec![TimingModelInfo {
                id: TimingModelId::new(self.id()),
                arch: self.arch().to_owned(),
                core: Some(self.core().to_owned()),
                determinism: self.determinism(),
                table_version: self.table_version().to_owned(),
                params: self.params(),
                caveats: self.caveats(),
            }],
            frequency_domains,
            default_frequency_domain: frequency_hz.map(|_| FrequencyDomainId::new(CORE_DOMAIN)),
            caveats: vec![
                "Static timing estimates are not WCET bounds; loop bounds and execution counts are not proven by the timing table."
                    .to_owned(),
            ],
        }
    }

    /// Builds a block timing record.
    #[must_use]
    pub fn block_timing(self, cycles: CostRange, frequency_hz: Option<u64>) -> BlockTiming {
        BlockTiming {
            model: Some(TimingModelId::new(self.id())),
            cycles,
            time_ns: frequency_hz.and_then(|hz| cycles.time_ns(hz)),
            frequency_domain: frequency_hz.map(|_| FrequencyDomainId::new(CORE_DOMAIN)),
            confidence: self.confidence(),
            caveats: self.caveats(),
        }
    }
}

/// A selected base timing model plus an optional board profile.
#[derive(Clone, Debug)]
pub struct TimingCostModel {
    model: TimingModel,
    profile: Option<BoardProfile>,
}

/// Cost of one instruction after applying the base table, profile overrides and
/// profile fetch wait states.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InstructionCost {
    /// Modeled cycle range for the instruction.
    pub cycles: CostRange,
    /// Whether the mnemonic was not recognized by the base classifier and had
    /// no profile override. The fallback class cost was used.
    pub unknown: bool,
}

/// Pipeline resource availability and register readiness.
///
/// Each resource maps to the sorted free times of its busy units. A resource
/// with configured capacity `n` never stores more than `n` entries; a missing
/// unit is free at time zero. Entries at or before the normalized elapsed time
/// are removed, so `PipelineState::default()` is the all-ready state.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PipelineState {
    resource_free: BTreeMap<String, Vec<u32>>,
    register_ready: BTreeMap<capstone::RegId, u32>,
}

impl PipelineState {
    fn normalize(&mut self, elapsed: u32) {
        self.resource_free.retain(|_, times| {
            for time in times.iter_mut() {
                *time = time.saturating_sub(elapsed);
            }
            times.retain(|time| *time > 0);
            !times.is_empty()
        });
        self.register_ready.retain(|_, time| {
            *time = time.saturating_sub(elapsed);
            *time > 0
        });
    }
}

struct PipelineSchedule {
    cost: CostRange,
    exit_state: PipelineState,
    unknown: Vec<(String, u64)>,
}

/// Precomputed cost and exit state for one pipeline entry state.
#[derive(Clone, Debug)]
pub(crate) struct PipelineStateTransition {
    cost_max: f64,
    exit: PipelineState,
}

/// Precomputed pipeline states for one basic block.
#[derive(Clone, Debug)]
pub(crate) struct PipelineBlockModel {
    default_cost: f64,
    states: BTreeMap<PipelineState, PipelineStateTransition>,
}

/// Full inter-block pipeline state table for one function.
#[derive(Clone, Debug)]
pub(crate) struct PipelineFunctionModel {
    entry_state: PipelineState,
    blocks: BTreeMap<u64, PipelineBlockModel>,
}

impl PipelineFunctionModel {
    /// Pipeline state at function entry.
    pub(crate) fn entry_state(&self) -> &PipelineState {
        &self.entry_state
    }

    /// Ready-entry cost of a block, before cache/branch/data-memory extras.
    pub(crate) fn default_cost(&self, address: u64) -> Option<f64> {
        self.blocks.get(&address).map(|block| block.default_cost)
    }

    /// Cost and exit state of `address` entered from `state`.
    pub(crate) fn transition(
        &self,
        address: u64,
        state: &PipelineState,
    ) -> Option<(f64, PipelineState)> {
        let transition = self.blocks.get(&address)?.states.get(state)?;
        Some((transition.cost_max, transition.exit.clone()))
    }
}

/// Symbolic address used by the block-local store buffer. Only an absolute
/// address or a base register plus displacement is tracked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoreAddress {
    Absolute(u64),
    Base {
        register: capstone::RegId,
        disp: i64,
    },
}

impl StoreAddress {
    fn uses_register(self, register: capstone::RegId) -> bool {
        matches!(self, Self::Base { register: base, .. } if base == register)
    }
}

fn address_range(start: i128, width: u8) -> Option<(i128, i128)> {
    if width == 0 {
        return None;
    }
    Some((start, start.saturating_add(i128::from(width))))
}

fn ranges_overlap(left: (i128, i128), right: (i128, i128)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

#[derive(Clone, Copy, Debug)]
struct StoreBufferEntry {
    address: StoreAddress,
    width: u8,
    issue: u32,
}

impl StoreBufferEntry {
    /// Whether this store and a load can touch at least one common byte. Only
    /// the same base register or two absolute addresses are compared; distinct
    /// symbolic expressions are assumed not to alias.
    fn overlaps(&self, address: StoreAddress, width: u8) -> bool {
        match (self.address, address) {
            (StoreAddress::Absolute(left), StoreAddress::Absolute(right)) => {
                address_range(i128::from(left), self.width)
                    .zip(address_range(i128::from(right), width))
                    .is_some_and(|(left, right)| ranges_overlap(left, right))
            }
            (
                StoreAddress::Base {
                    register: left,
                    disp: left_disp,
                },
                StoreAddress::Base {
                    register: right,
                    disp: right_disp,
                },
            ) if left == right => address_range(i128::from(left_disp), self.width)
                .zip(address_range(i128::from(right_disp), width))
                .is_some_and(|(left, right)| ranges_overlap(left, right)),
            _ => false,
        }
    }
}

/// Block-local FIFO store buffer used for store-to-load forwarding.
struct StoreBuffer {
    capacity: usize,
    entries: VecDeque<StoreBufferEntry>,
}

impl StoreBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::new(),
        }
    }

    fn push(&mut self, address: StoreAddress, width: u8, issue: u32) {
        while self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(StoreBufferEntry {
            address,
            width,
            issue,
        });
    }

    fn clear(&mut self) {
        self.entries.clear();
    }

    fn invalidate_register(&mut self, register: capstone::RegId) {
        self.entries
            .retain(|entry| !entry.address.uses_register(register));
    }

    /// Whether a load can take its value from the newest overlapping store.
    /// A newer partial-overlap store blocks forwarding from an older exact
    /// match, and the matching store must be older than the load's issue.
    fn can_forward(&self, address: StoreAddress, width: u8, load_issue: u32) -> bool {
        for entry in self.entries.iter().rev() {
            if !entry.overlaps(address, width) {
                continue;
            }
            return entry.address == address && entry.width == width && entry.issue < load_issue;
        }
        false
    }
}

fn simple_memory_address(access: &MemoryAccess) -> Option<(StoreAddress, u8)> {
    if access.width == 0 || access.index.is_some() {
        return None;
    }
    if let Some(address) = access.absolute {
        return Some((StoreAddress::Absolute(address), access.width));
    }
    access.base.map(|register| {
        (
            StoreAddress::Base {
                register,
                disp: access.disp,
            },
            access.width,
        )
    })
}

/// Upper bound on per-function pipeline state entries.
const MAX_PIPELINE_STATES: usize = 100_000;

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
fn pipeline_schedule(
    profile: &BoardProfile,
    model: TimingModel,
    pipeline: &crate::board_profile::PipelineProfile,
    instructions: &[&DecodedInsn],
    entry: &PipelineState,
) -> PipelineSchedule {
    let mut resource_free = entry.resource_free.clone();
    let mut register_ready = entry.register_ready.clone();
    let issue_width = pipeline.issue_width().max(1);
    let read_ports = pipeline
        .register_file()
        .map_or(u32::MAX, |register_file| register_file.read_ports().max(1));
    let write_ports = pipeline
        .register_file()
        .map_or(u32::MAX, |register_file| register_file.write_ports().max(1));
    let mut issue_floor = 0_u32;
    let mut current_cycle: Option<u32> = None;
    let mut issued_in_cycle = 0_u32;
    let mut reads_in_cycle = 0_u32;
    let mut writes_in_cycle = 0_u32;
    let mut port_end = 0_u32;
    let store_forwarding = pipeline.store_forwarding();
    let mut store_buffer = store_forwarding
        .map(|profile| StoreBuffer::new(usize::try_from(profile.entries()).unwrap_or(usize::MAX)));
    let mut completion = 0_u32;
    let mut fetch_cycles = 0_u32;
    let mut unknown = Vec::new();
    for instruction in instructions {
        let classification = classify(instruction);
        let mnemonic = canonical_mnemonic(&instruction.mnemonic);
        let (resources, latency, occupancy, forwarding_override, is_unknown) =
            if let Some(spec) = pipeline.instruction_for(classification.class, mnemonic) {
                (
                    spec.resources()
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    spec.latency(),
                    spec.occupancy(),
                    spec.forwarding_latency(),
                    false,
                )
            } else {
                let (resources, latency, occupancy) =
                    pipeline_class_default(model, classification.class);
                (
                    resources.to_vec(),
                    latency,
                    occupancy,
                    None,
                    !classification.known,
                )
            };
        let accesses = instruction.memory_accesses.as_slice();
        let single_read = accesses.len() == 1 && accesses[0].kind == MemoryAccessKind::Read;
        let single_write = accesses.len() == 1 && accesses[0].kind == MemoryAccessKind::Write;
        let has_memory_write = accesses.iter().any(|access| {
            matches!(
                access.kind,
                MemoryAccessKind::Write | MemoryAccessKind::ReadWrite
            )
        }) || instruction.memory_write.is_some()
            || classification.class == InstructionClass::Store;
        let load_candidate = (single_read && !has_memory_write)
            .then(|| simple_memory_address(&accesses[0]))
            .flatten();
        let store_candidate = single_write
            .then(|| simple_memory_address(&accesses[0]))
            .flatten();
        let clears_store_buffer = has_memory_write && store_candidate.is_none();
        let store_barrier = classification.class == InstructionClass::Barrier;
        let operand_ready = instruction
            .regs_read
            .iter()
            .filter_map(|register| register_ready.get(register))
            .copied()
            .max()
            .unwrap_or(0);
        let resource_ready = resources
            .iter()
            .map(|resource| {
                let capacity = pipeline.resource_units(resource);
                resource_free.get(*resource).map_or(0, |times| {
                    if times.len() < capacity {
                        0
                    } else {
                        times.first().copied().unwrap_or(0)
                    }
                })
            })
            .max()
            .unwrap_or(0);
        let reads = u32::try_from(instruction.regs_read.len()).unwrap_or(u32::MAX);
        let writes = u32::try_from(instruction.regs_write.len()).unwrap_or(u32::MAX);
        let oversized = reads > read_ports || writes > write_ports;
        let port_cycles = reads
            .div_ceil(read_ports)
            .max(writes.div_ceil(write_ports))
            .max(1);
        let forwarding_latency = pipeline.forwarding().map_or(latency, |forwarding| {
            forwarding_override
                .or(forwarding.default_latency())
                .unwrap_or_else(|| pipeline_class_forwarding_default(model, classification.class))
                .min(latency)
                .max(1)
        });
        let mut start = issue_floor.max(operand_ready).max(resource_ready);
        if oversized {
            if current_cycle == Some(start) {
                start = start.saturating_add(1);
            }
            issue_floor = start.saturating_add(port_cycles);
            port_end = port_end.max(issue_floor);
            current_cycle = None;
            issued_in_cycle = 0;
            reads_in_cycle = 0;
            writes_in_cycle = 0;
        } else {
            if current_cycle != Some(start) {
                current_cycle = Some(start);
                issued_in_cycle = 0;
                reads_in_cycle = 0;
                writes_in_cycle = 0;
            }
            if issued_in_cycle >= issue_width
                || reads_in_cycle.saturating_add(reads) > read_ports
                || writes_in_cycle.saturating_add(writes) > write_ports
            {
                start = start.saturating_add(1);
                current_cycle = Some(start);
                issued_in_cycle = 0;
                reads_in_cycle = 0;
                writes_in_cycle = 0;
            }
            issued_in_cycle = issued_in_cycle.saturating_add(1);
            reads_in_cycle = reads_in_cycle.saturating_add(reads);
            writes_in_cycle = writes_in_cycle.saturating_add(writes);
            issue_floor = start;
            port_end = port_end.max(start.saturating_add(port_cycles));
        }
        let store_forwarded = store_forwarding.is_some()
            && load_candidate.is_some_and(|(address, width)| {
                store_buffer
                    .as_ref()
                    .is_some_and(|buffer| buffer.can_forward(address, width, start))
            });
        let effective_latency = if store_forwarded {
            store_forwarding.map_or(latency, |profile| profile.latency().max(1).min(latency))
        } else {
            latency
        };
        for resource in &resources {
            let capacity = pipeline.resource_units(resource);
            let times = resource_free.entry((*resource).to_owned()).or_default();
            if times.len() >= capacity {
                times.remove(0);
            }
            times.push(start.saturating_add(occupancy));
            times.sort_unstable();
        }
        let result_ready = start.saturating_add(effective_latency);
        let forwarding_after_store = if store_forwarded {
            forwarding_latency.min(effective_latency)
        } else {
            forwarding_latency
        };
        let source_ready = start.saturating_add(forwarding_after_store.max(port_cycles));
        for register in &instruction.regs_write {
            register_ready
                .entry(*register)
                .and_modify(|current| *current = (*current).max(source_ready))
                .or_insert(source_ready);
        }
        completion = completion.max(result_ready);
        if let Some(buffer) = &mut store_buffer {
            if store_barrier || clears_store_buffer {
                buffer.clear();
            } else if let Some((address, width)) = store_candidate {
                buffer.push(address, width, start);
            }
            for register in &instruction.regs_write {
                buffer.invalidate_register(*register);
            }
        }
        fetch_cycles = fetch_cycles
            .saturating_add(profile.fetch_wait_cycles(instruction.address, instruction.size));
        if is_unknown {
            unknown.push((instruction.mnemonic.clone(), instruction.address));
        }
    }
    let base = port_end.max(completion).saturating_add(fetch_cycles);
    let branch_penalty = pipeline.branch_penalty();
    let ends_in_transfer = instructions
        .last()
        .is_some_and(|last| last.is_jump || last.is_call || last.is_return);
    let min = f64::from(base)
        + if ends_in_transfer {
            branch_penalty.min
        } else {
            0.0
        };
    let max = f64::from(base)
        + if ends_in_transfer {
            branch_penalty.max
        } else {
            0.0
        };
    let elapsed = base.saturating_add(if ends_in_transfer {
        branch_penalty.max.ceil() as u32
    } else {
        0
    });
    let mut exit_state = PipelineState {
        resource_free,
        register_ready,
    };
    exit_state.normalize(elapsed);
    PipelineSchedule {
        cost: CostRange::new(min, max),
        exit_state,
        unknown,
    }
}

impl TimingCostModel {
    /// Selects a timing model and applies an optional board profile.
    ///
    /// A profile pins the CPU model and architecture. An explicit CPU name must
    /// agree with the profile. Without a profile this behaves exactly like
    /// [`TimingModel::select`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for an invalid profile, an unknown or
    /// incompatible CPU, an architecture mismatch, or a profile/CLI CPU
    /// conflict.
    pub fn select(
        explicit: Option<&str>,
        profile: Option<&BoardProfile>,
        image: &Image,
    ) -> Result<Option<Self>> {
        let Some(profile) = profile else {
            return TimingModel::select(explicit, image).map(|selected| {
                selected.map(|model| Self {
                    model,
                    profile: None,
                })
            });
        };
        profile.validate()?;
        let Some(profile_model) = TimingModel::from_name(profile.cpu()) else {
            return Err(Error::Config(format!(
                "board profile {} has unknown CPU/timing model {:?}",
                profile.id(),
                profile.cpu()
            )));
        };
        if !profile_model.matches_arch(image.arch) {
            return Err(Error::Config(format!(
                "board profile {} timing model {} is not compatible with ELF architecture {}",
                profile.id(),
                profile_model.id(),
                image.arch.schema_name()
            )));
        }
        if let Some(explicit) = explicit {
            let Some(explicit_model) = TimingModel::from_name(explicit) else {
                return Err(Error::Config(format!(
                    "unknown CPU/timing model {explicit:?}; use cortex-m0, cortex-m0plus, cortex-m3, cortex-m4, cortex-m7, cortex-m33, riscv32, riscv64, riscv32-bounded, riscv64-bounded, aarch64, aarch64-bounded or x86-64"
                )));
            };
            if explicit_model.id() != profile_model.id() {
                return Err(Error::Config(format!(
                    "CPU/timing model {} conflicts with board profile {} ({})",
                    explicit_model.id(),
                    profile.id(),
                    profile_model.id()
                )));
            }
            if !explicit_model.matches_arch(image.arch) {
                return Err(Error::Config(format!(
                    "timing model {} is not compatible with ELF architecture {}",
                    explicit_model.id(),
                    image.arch.schema_name()
                )));
            }
        }
        Ok(Some(Self {
            model: profile_model,
            profile: Some(profile.clone()),
        }))
    }

    /// Base timing model.
    #[must_use]
    pub fn model(&self) -> TimingModel {
        self.model
    }

    /// Board profile, when one was supplied.
    #[must_use]
    pub fn profile(&self) -> Option<&BoardProfile> {
        self.profile.as_ref()
    }

    /// Stable timing-model ID.
    #[must_use]
    pub fn id(&self) -> &'static str {
        self.model.id()
    }

    /// Human-readable core name.
    #[must_use]
    pub fn core(&self) -> &'static str {
        self.model.core()
    }

    /// Unknown-instruction policy, defaulting to `warn` without a profile.
    #[must_use]
    pub fn unknown_instruction_policy(&self) -> UnknownInstructionPolicy {
        self.profile.as_ref().map_or(
            UnknownInstructionPolicy::Warn,
            BoardProfile::unknown_instruction_policy,
        )
    }

    /// Resolved core frequency: CLI value first, then the profile's core clock.
    #[must_use]
    pub fn core_frequency_hz(&self, cli_frequency_hz: Option<u64>) -> Option<u64> {
        cli_frequency_hz.or_else(|| self.profile.as_ref().and_then(BoardProfile::core_clock_hz))
    }

    /// Costs one instruction using the base table, overrides and fetch model.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn instruction_cost(&self, insn: &DecodedInsn) -> InstructionCost {
        let classification = classify(insn);
        let mnemonic = canonical_mnemonic(&insn.mnemonic);
        let override_ = self
            .profile
            .as_ref()
            .and_then(|profile| profile.override_for(classification.class, mnemonic));
        let mut cycles = override_.as_ref().map_or_else(
            || self.model.instruction_cost(insn),
            |matched| matched.cycles,
        );
        let fetch_cycles = self.profile.as_ref().map_or(0, |profile| {
            profile.fetch_wait_cycles(insn.address, insn.size)
        });
        if fetch_cycles > 0 {
            cycles.min += f64::from(fetch_cycles);
            cycles.max += f64::from(fetch_cycles);
        }
        InstructionCost {
            cycles,
            unknown: !classification.known && override_.is_none(),
        }
    }

    /// Costs a basic block using the additive table or the profile pipeline
    /// model.
    ///
    /// The pipeline model schedules instructions in order using per-class
    /// resources, result latencies and register dependencies. Up to
    /// `issue_width` instructions may issue per cycle, each resource name has
    /// the configured number of units, an optional register-file section
    /// budgets register reads and writes per issue cycle, an optional
    /// forwarding section makes producer results readable before full
    /// latency, and an optional store-forwarding section shortens matching
    /// loads through a block-local store buffer. It models local hazards
    /// within one block; pipeline state at block entry is assumed ready, so
    /// this is a local cost rather than a whole-program WCET bound.
    #[must_use]
    pub fn block_cost(&self, instructions: &[DecodedInsn]) -> (CostRange, Vec<(String, u64)>) {
        if self.model.supports_pipeline_model()
            && let Some(profile) = &self.profile
            && let Some(pipeline) = profile.pipeline()
        {
            return Self::pipeline_block_cost(self.model, profile, pipeline, instructions);
        }
        let mut min = 0.0_f64;
        let mut max = 0.0_f64;
        let mut unknown = Vec::new();
        for instruction in instructions {
            let cost = self.instruction_cost(instruction);
            min += cost.cycles.min;
            max += cost.cycles.max;
            if cost.unknown {
                unknown.push((instruction.mnemonic.clone(), instruction.address));
            }
        }
        (CostRange::new(min, max), unknown)
    }

    fn pipeline_block_cost(
        model: TimingModel,
        profile: &BoardProfile,
        pipeline: &crate::board_profile::PipelineProfile,
        instructions: &[DecodedInsn],
    ) -> (CostRange, Vec<(String, u64)>) {
        let instructions: Vec<&DecodedInsn> = instructions.iter().collect();
        let schedule = pipeline_schedule(
            profile,
            model,
            pipeline,
            &instructions,
            &PipelineState::default(),
        );
        (schedule.cost, schedule.unknown)
    }

    /// Returns the pipeline cost added when a block is entered from each CFG
    /// edge instead of from an all-ready pipeline.
    ///
    /// The state is derived from the source block's local schedule. This is a
    /// first-order predecessor context used as the IPET fallback when the full
    /// inter-block state table is unavailable.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::too_many_lines
    )]
    pub(crate) fn pipeline_edge_stalls(
        &self,
        decoded: &[DecodedInsn],
        blocks: &[crate::cfg::CfgBlockDraft],
        edges: &[crate::cfg::CfgEdgeDraft],
    ) -> Vec<Option<f64>> {
        let Some(profile) = &self.profile else {
            return vec![None; edges.len()];
        };
        let Some(pipeline) = self.active_pipeline() else {
            return vec![None; edges.len()];
        };
        let instructions_by_block: Vec<Vec<&DecodedInsn>> = blocks
            .iter()
            .map(|block| {
                let end = block.address.saturating_add(block.size);
                decoded
                    .iter()
                    .filter(|instruction| {
                        instruction.address >= block.address && instruction.address < end
                    })
                    .collect()
            })
            .collect();
        let mut base = Vec::with_capacity(blocks.len());
        let mut exit_states = Vec::with_capacity(blocks.len());
        for instructions in &instructions_by_block {
            let schedule = pipeline_schedule(
                profile,
                self.model,
                pipeline,
                instructions,
                &PipelineState::default(),
            );
            base.push(schedule.cost.max);
            exit_states.push(schedule.exit_state);
        }
        let index_by_address: BTreeMap<u64, usize> = blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.address, index))
            .collect();
        edges
            .iter()
            .map(|edge| {
                if edge.kind == crate::cfg::CfgEdgeKind::CallReturn {
                    return None;
                }
                let source = *index_by_address.get(&edge.from)?;
                let target = *index_by_address.get(&edge.to)?;
                let schedule = pipeline_schedule(
                    profile,
                    self.model,
                    pipeline,
                    &instructions_by_block[target],
                    &exit_states[source],
                );
                let delta = (schedule.cost.max - base[target]).max(0.0);
                (delta > 1e-9).then_some(delta)
            })
            .collect()
    }

    /// Builds the full inter-block pipeline state table for one function.
    ///
    /// Call-return edges reset the model to the ready state: callee pipeline
    /// state is not available in the caller summary. Returns `None` when the
    /// state table exceeds the configured cap.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::too_many_lines
    )]
    pub(crate) fn pipeline_state_model(
        &self,
        decoded: &[DecodedInsn],
        blocks: &[crate::cfg::CfgBlockDraft],
        edges: &[crate::cfg::CfgEdgeDraft],
        entry: u64,
    ) -> Option<PipelineFunctionModel> {
        let profile = self.profile.as_ref()?;
        let pipeline = self.active_pipeline()?;
        let block_by_address: BTreeMap<u64, &crate::cfg::CfgBlockDraft> =
            blocks.iter().map(|block| (block.address, block)).collect();
        block_by_address.get(&entry)?;
        let instructions_by_block: BTreeMap<u64, Vec<&DecodedInsn>> = blocks
            .iter()
            .map(|block| {
                let end = block.address.saturating_add(block.size);
                (
                    block.address,
                    decoded
                        .iter()
                        .filter(|instruction| {
                            instruction.address >= block.address && instruction.address < end
                        })
                        .collect(),
                )
            })
            .collect();
        let mut outgoing: BTreeMap<u64, Vec<&crate::cfg::CfgEdgeDraft>> = BTreeMap::new();
        for edge in edges {
            if block_by_address.contains_key(&edge.from) && block_by_address.contains_key(&edge.to)
            {
                outgoing.entry(edge.from).or_default().push(edge);
            }
        }
        let mut models: BTreeMap<u64, PipelineBlockModel> = BTreeMap::new();
        for block in blocks {
            let instructions = instructions_by_block
                .get(&block.address)
                .map_or(&[][..], Vec::as_slice);
            let schedule = pipeline_schedule(
                profile,
                self.model,
                pipeline,
                instructions,
                &PipelineState::default(),
            );
            models.insert(
                block.address,
                PipelineBlockModel {
                    default_cost: schedule.cost.max,
                    states: BTreeMap::new(),
                },
            );
        }
        let entry_state = PipelineState::default();
        let mut queue = VecDeque::from([(entry, entry_state.clone())]);
        let mut state_count = 0_usize;
        while let Some((address, state)) = queue.pop_front() {
            let Some(block) = models.get_mut(&address) else {
                continue;
            };
            if block.states.contains_key(&state) {
                continue;
            }
            let instructions = instructions_by_block
                .get(&address)
                .map_or(&[][..], Vec::as_slice);
            let schedule = pipeline_schedule(profile, self.model, pipeline, instructions, &state);
            let exit = schedule.exit_state.clone();
            block.states.insert(
                state,
                PipelineStateTransition {
                    cost_max: schedule.cost.max,
                    exit: exit.clone(),
                },
            );
            state_count = state_count.saturating_add(1);
            if state_count > MAX_PIPELINE_STATES {
                return None;
            }
            if let Some(next_edges) = outgoing.get(&address) {
                for edge in next_edges {
                    let next = if edge.kind == crate::cfg::CfgEdgeKind::CallReturn {
                        PipelineState::default()
                    } else {
                        exit.clone()
                    };
                    queue.push_back((edge.to, next));
                }
            }
        }
        Some(PipelineFunctionModel {
            entry_state,
            blocks: models,
        })
    }

    /// Active board-profile pipeline, if the timing model supports it.
    #[must_use]
    pub(crate) fn active_pipeline(&self) -> Option<&crate::board_profile::PipelineProfile> {
        if !self.model.supports_pipeline_model() {
            return None;
        }
        self.profile.as_ref()?.pipeline()
    }

    /// CFG pipeline metadata name for the selected timing model.
    #[must_use]
    pub(crate) fn pipeline_model_name(&self) -> String {
        format!("{}-resource-dependency-model", self.model.id())
    }

    /// CFG edge-context pipeline metadata name for the selected timing model.
    #[must_use]
    pub(crate) fn pipeline_edge_model_name(&self) -> String {
        format!("{}-edge-context", self.model.id())
    }

    /// Builds CFG timing metadata for the selected model and profile.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn timing_info(
        &self,
        cli_frequency_hz: Option<u64>,
        unknown_mnemonics: &BTreeSet<String>,
    ) -> TimingInfo {
        let frequency_domains = self.frequency_domains(cli_frequency_hz);
        let core_frequency = self.core_frequency_hz(cli_frequency_hz);
        let default_frequency_domain = core_frequency.map(|_| FrequencyDomainId::new(CORE_DOMAIN));
        let mut params = self.model.params();
        let mut caveats = self.model_caveats();
        if let Some(profile) = &self.profile {
            if let Some(wait_states) = profile.max_flash_wait_states() {
                params.flash_wait_states = Some(wait_states);
            }
            params
                .extras
                .insert("board_profile_id".to_owned(), profile.id().to_owned());
            params.extras.insert(
                "board_profile_sha256".to_owned(),
                profile.sha256().unwrap_or("unknown").to_owned(),
            );
            params.extras.insert(
                "board_profile_source".to_owned(),
                profile
                    .source()
                    .map_or_else(|| "<inline>".to_owned(), |path| path.display().to_string()),
            );
            params.extras.insert(
                "board_profile_schema_version".to_owned(),
                profile.schema_version().to_string(),
            );
            params.extras.insert(
                "board_profile_clocks".to_owned(),
                profile.clock_count().to_string(),
            );
            params.extras.insert(
                "board_profile_memory_regions".to_owned(),
                profile.memory_region_count().to_string(),
            );
            if let Some(wait_states) = profile.max_fetch_wait_states() {
                params.extras.insert(
                    "board_profile_max_fetch_wait_states".to_owned(),
                    wait_states.to_string(),
                );
            }
            if let (Some(cli_hz), Some(profile_hz)) = (cli_frequency_hz, profile.core_clock_hz())
                && cli_hz != profile_hz
            {
                caveats.push(
                    "CLI --freq overrides the profile's core clock, but profile fetch wait states are used unchanged."
                        .to_owned(),
                );
            }
            params.extras.insert(
                "board_profile_instruction_cost_overrides".to_owned(),
                profile.instruction_cost_override_count().to_string(),
            );
            if let Some(pipeline) = profile.pipeline() {
                params.extras.insert(
                    "board_profile_pipeline".to_owned(),
                    self.pipeline_model_name(),
                );
                params.extras.insert(
                    "board_profile_pipeline_issue_width".to_owned(),
                    pipeline.issue_width().to_string(),
                );
                params.extras.insert(
                    "board_profile_pipeline_instruction_overrides".to_owned(),
                    pipeline.instruction_override_count().to_string(),
                );
                if !pipeline.resources().is_empty() {
                    params.extras.insert(
                        "board_profile_pipeline_resources".to_owned(),
                        pipeline.resource_summary(),
                    );
                }
                if let Some(register_file) = pipeline.register_file() {
                    params.extras.insert(
                        "board_profile_pipeline_read_ports".to_owned(),
                        register_file.read_ports().to_string(),
                    );
                    params.extras.insert(
                        "board_profile_pipeline_write_ports".to_owned(),
                        register_file.write_ports().to_string(),
                    );
                }
                if let Some(forwarding) = pipeline.forwarding() {
                    params.extras.insert(
                        "board_profile_pipeline_forwarding".to_owned(),
                        if forwarding.default_latency().is_some() {
                            "uniform-default".to_owned()
                        } else {
                            "isa-class-presets".to_owned()
                        },
                    );
                    if let Some(latency) = forwarding.default_latency() {
                        params.extras.insert(
                            "board_profile_pipeline_forwarding_default_latency".to_owned(),
                            latency.to_string(),
                        );
                    }
                    params.extras.insert(
                        "board_profile_pipeline_forwarding_overrides".to_owned(),
                        pipeline.forwarding_override_count().to_string(),
                    );
                }
                if let Some(store_forwarding) = pipeline.store_forwarding() {
                    params.extras.insert(
                        "board_profile_pipeline_store_forwarding".to_owned(),
                        "enabled".to_owned(),
                    );
                    params.extras.insert(
                        "board_profile_pipeline_store_forwarding_latency".to_owned(),
                        store_forwarding.latency().to_string(),
                    );
                    params.extras.insert(
                        "board_profile_pipeline_store_forwarding_entries".to_owned(),
                        store_forwarding.entries().to_string(),
                    );
                }
                params.extras.insert(
                    "board_profile_pipeline_branch_penalty".to_owned(),
                    format!(
                        "{}..{}",
                        pipeline.branch_penalty().min,
                        pipeline.branch_penalty().max
                    ),
                );
                if self.model.is_bounded_abstract() {
                    params.extras.insert(
                        "bounded_cost_table".to_owned(),
                        "replaced-by-pipeline".to_owned(),
                    );
                    params.extras.insert(
                        "pipeline_overlap".to_owned(),
                        "profile-pipeline-schedule".to_owned(),
                    );
                }
            }
            if let Some(cache) = profile.instruction_cache() {
                params.extras.insert(
                    "board_profile_instruction_cache".to_owned(),
                    format!(
                        "{}B/{}B/{}way/{}",
                        cache.size(),
                        cache.line_bytes(),
                        cache.ways(),
                        cache.replacement_name()
                    ),
                );
                params.extras.insert(
                    "board_profile_instruction_cache_miss_penalty".to_owned(),
                    cache.miss_penalty().to_string(),
                );
            }
            if let Some(cache) = profile.data_cache() {
                params.extras.insert(
                    "board_profile_data_cache".to_owned(),
                    format!(
                        "{}B/{}B/{}way/{}",
                        cache.size(),
                        cache.line_bytes(),
                        cache.ways(),
                        cache.replacement_name()
                    ),
                );
                params.extras.insert(
                    "board_profile_data_cache_miss_penalty".to_owned(),
                    cache.miss_penalty().to_string(),
                );
                params.extras.insert(
                    "board_profile_data_cache_write_allocate".to_owned(),
                    cache.write_allocate().to_string(),
                );
                caveats.push(
                    "Data-cache miss penalties model only statically resolved addresses; unresolved stack, indexed and register-dependent accesses are counted but not charged."
                        .to_owned(),
                );
            }
            if let Some(prediction) = profile.branch_prediction() {
                params.extras.insert(
                    "board_profile_branch_prediction".to_owned(),
                    prediction.model_name().to_owned(),
                );
                params.extras.insert(
                    "board_profile_branch_mispredict_penalty".to_owned(),
                    prediction.mispredict_penalty().to_string(),
                );
                params.extras.insert(
                    "board_profile_branch_max_states".to_owned(),
                    prediction.max_states().to_string(),
                );
                if prediction.model() == BranchPredictionModel::Bimodal {
                    params.extras.insert(
                        "board_profile_branch_initial_state".to_owned(),
                        prediction.initial_state_name().to_owned(),
                    );
                }
                caveats.push(
                    "Branch prediction models conditional direction only; indirect/table target prediction, returns and non-modeled history schemes are not part of the direction predictor."
                        .to_owned(),
                );
            }
            if let Some(btb) = profile.branch_target_buffer() {
                params.extras.insert(
                    "board_profile_btb_entries".to_owned(),
                    btb.entries().to_string(),
                );
                params
                    .extras
                    .insert("board_profile_btb_ways".to_owned(), btb.ways().to_string());
                params.extras.insert(
                    "board_profile_btb_miss_penalty".to_owned(),
                    btb.miss_penalty().to_string(),
                );
                caveats.push(
                    "Branch-target-buffer misses model intra-function taken conditional branches and jump edges with set-associative LRU replacement; calls, returns, fallthrough fetches and cross-function replacement are not modeled."
                        .to_owned(),
                );
            }
            if let Some(ras) = profile.return_address_stack() {
                params.extras.insert(
                    "board_profile_ras_entries".to_owned(),
                    ras.entries().to_string(),
                );
                params.extras.insert(
                    "board_profile_ras_miss_penalty".to_owned(),
                    ras.miss_penalty().to_string(),
                );
                caveats.push(
                    "Return-address-stack misses model per-function return blocks with a bounded LIFO stack; recursive nesting, indirect return targets and cross-function stack occupancy are not modeled."
                        .to_owned(),
                );
            }
            if profile.data_memory_enabled() {
                params.extras.insert(
                    "board_profile_data_memory".to_owned(),
                    "region-data-wait-states".to_owned(),
                );
                params.extras.insert(
                    "board_profile_data_memory_regions".to_owned(),
                    profile
                        .data_memory_regions()
                        .iter()
                        .filter(|region| region.has_data_timing())
                        .count()
                        .to_string(),
                );
                caveats.push(
                    "Data-memory wait cycles are region-based; when data-cache analysis is also enabled, cache miss penalties and memory wait cycles are additive."
                        .to_owned(),
                );
            }
            if let Some(wcet) = profile.wcet() {
                params
                    .extras
                    .insert("board_profile_wcet".to_owned(), "configured".to_owned());
                params.extras.insert(
                    "board_profile_wcet_max_states".to_owned(),
                    wcet.max_states().to_string(),
                );
                params.extras.insert(
                    "board_profile_wcet_loop_bounds".to_owned(),
                    wcet.loop_bound_count().to_string(),
                );
                if let Some(bound) = wcet.default_loop_bound() {
                    params.extras.insert(
                        "board_profile_wcet_default_loop_bound".to_owned(),
                        bound.to_string(),
                    );
                }
                params.extras.insert(
                    "board_profile_wcet_bound_nonterminating_loops".to_owned(),
                    wcet.bound_nonterminating_loops().to_string(),
                );
                caveats.push(
                    "WCET analysis is configured by [wcet]; the selected path-analysis backend and its caveats are recorded in the CFG wcet section."
                        .to_owned(),
                );
            }
            if let Some(multicore) = profile.multicore() {
                params.extras.insert(
                    "board_profile_multicore_model".to_owned(),
                    multicore.model().to_owned(),
                );
                params.extras.insert(
                    "board_profile_multicore_cores".to_owned(),
                    multicore.cores().to_string(),
                );
                params.extras.insert(
                    "board_profile_multicore_core_id".to_owned(),
                    multicore.core_id().to_string(),
                );
                params.extras.insert(
                    "board_profile_multicore_data_read_cycles".to_owned(),
                    multicore.data_read_interference_cycles().to_string(),
                );
                params.extras.insert(
                    "board_profile_multicore_data_write_cycles".to_owned(),
                    multicore.data_write_interference_cycles().to_string(),
                );
                params.extras.insert(
                    "board_profile_multicore_fetch_cycles".to_owned(),
                    multicore
                        .instruction_fetch_interference_cycles()
                        .to_string(),
                );
                caveats.push(
                    "Multicore interference uses a per-access/per-fetch budget; arbitration schedules, shared caches, DMA and other cores' workloads are not modeled."
                        .to_owned(),
                );
            }
        }
        if !unknown_mnemonics.is_empty() {
            params.extras.insert(
                "unknown_instruction_mnemonics".to_owned(),
                unknown_mnemonics.len().to_string(),
            );
            caveats.push(format!(
                "{} unrecognized mnemonic(s) used fallback instruction costs; see timing-unknown-instruction diagnostics.",
                unknown_mnemonics.len()
            ));
        }
        let statistical_profile = self.profile.as_ref().is_some_and(|profile| {
            profile.pipeline().is_some()
                || profile.branch_prediction().is_some()
                || profile.branch_target_buffer().is_some()
                || profile.return_address_stack().is_some()
        });
        TimingInfo {
            models: vec![TimingModelInfo {
                id: TimingModelId::new(self.model.id()),
                arch: self.model.arch().to_owned(),
                core: Some(self.model.core().to_owned()),
                determinism: if statistical_profile {
                    Determinism::Statistical
                } else {
                    self.model.determinism()
                },
                table_version: self.model.table_version().to_owned(),
                params,
                caveats,
            }],
            frequency_domains,
            default_frequency_domain,
            caveats: vec![
                "Static timing estimates are not WCET bounds; loop bounds and execution counts are not proven by the timing table."
                    .to_owned(),
            ],
        }
    }

    /// Builds a block timing record.
    #[must_use]
    pub fn block_timing(&self, cycles: CostRange, frequency_hz: Option<u64>) -> BlockTiming {
        BlockTiming {
            model: Some(TimingModelId::new(self.model.id())),
            cycles,
            time_ns: frequency_hz.and_then(|hz| cycles.time_ns(hz)),
            frequency_domain: frequency_hz.map(|_| FrequencyDomainId::new(CORE_DOMAIN)),
            confidence: self
                .profile
                .as_ref()
                .and_then(BoardProfile::confidence)
                .unwrap_or_else(|| self.model.confidence()),
            caveats: self.model_caveats(),
        }
    }

    fn frequency_domains(&self, cli_frequency_hz: Option<u64>) -> Vec<FrequencyDomain> {
        let mut domains = self
            .profile
            .as_ref()
            .map(BoardProfile::frequency_domains)
            .unwrap_or_default();
        if let Some(hz) = cli_frequency_hz {
            if let Some(core) = domains
                .iter_mut()
                .find(|domain| domain.id.as_str() == CORE_DOMAIN)
            {
                core.hz = hz;
                core.source = FrequencySource::Cli;
                core.confidence = Confidence::High;
            } else {
                domains.push(FrequencyDomain {
                    id: FrequencyDomainId::new(CORE_DOMAIN),
                    name: "core".to_owned(),
                    hz,
                    source: FrequencySource::Cli,
                    confidence: Confidence::High,
                });
            }
        }
        domains.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        domains
    }

    fn model_caveats(&self) -> Vec<String> {
        let mut caveats = self.model.caveats();
        if let Some(profile) = &self.profile {
            caveats.extend(profile.caveats().iter().cloned());
            if profile
                .max_fetch_wait_states()
                .is_some_and(|states| states > 0)
            {
                caveats.retain(|caveat| !caveat.contains("excludes flash wait states"));
                caveats.push(
                    "Board-profile fetch wait states are applied per instruction fetch transaction; prefetch, caches, bus contention and exception entry are not modeled."
                        .to_owned(),
                );
            }
            if let Some(pipeline) = profile.pipeline() {
                caveats.retain(|caveat| {
                    !caveat.contains("Load/store and branch penalties are table-based")
                        && !caveat.contains("additive per-instruction upper bounds")
                });
                if self.model.is_bounded_abstract() {
                    caveats.push(
                        "Board-profile pipeline scheduling replaces the additive bounded timing table for block costs. The pipeline-aware result is statistical, is not a safe upper bound, and is rejected by --require-safe."
                            .to_owned(),
                    );
                }
                caveats.push(
                    "Board-profile pipeline block costs use an in-order resource/dependency model. IPET builds a per-function state table from ready registers and resources at function entry and charges the state-dependent block cost; call-return edges reset the modeled state. Memory dependencies, speculative/out-of-order execution, cross-block co-issue and non-IPET inter-block state are not modeled. The model remains statistical."
                        .to_owned(),
                );
                if pipeline.register_file().is_some() {
                    caveats.push(
                        "Register-file ports are budgeted at issue from Capstone's explicit and implicit read/write register sets. An instruction that exceeds one cycle's ports occupies consecutive exclusive issue cycles; port cycles are not added to execution latency. Writeback-cycle contention, banked/FP/vector register files and cross-block port state are not modeled."
                            .to_owned(),
                    );
                } else {
                    caveats.push(
                        "Register-file port limits are not modeled; add [pipeline.register_file] to enable issue-cycle read/write port budgets."
                            .to_owned(),
                    );
                }
                if pipeline.forwarding().is_some() {
                    caveats.push(
                        "Data forwarding is modeled by making a register producer's value readable after its configured forwarding latency while its execution still completes at full latency. Forwarding-network arbitration, partial bypass paths, writeback ordering/WAW effects and cross-block forwarding are not modeled; block boundaries wait for full completion."
                            .to_owned(),
                    );
                } else {
                    caveats.push(
                        "Data forwarding is not modeled; consumers wait for the producer's full result latency. Add [pipeline.forwarding] to enable bypass latencies."
                            .to_owned(),
                    );
                }
                if pipeline.store_forwarding().is_some() {
                    caveats.push(
                        "Store-to-load forwarding is modeled within one basic block for exactly matching base-plus-displacement or absolute addresses and equal access widths. The newest overlapping store must be an exact match, older than the load's issue cycle and still in the configured store buffer; a newer partial-overlap store blocks forwarding. Unknown, indexed or multi-access stores and barriers clear the buffer; writes to address registers invalidate matching entries. Store-buffer drain/age, partial-overlap and distinct-symbolic-alias forwarding, cross-block forwarding and suppression of cache/data-memory penalties are not modeled."
                            .to_owned(),
                    );
                } else {
                    caveats.push(
                        "Store-to-load forwarding is not modeled; loads use their full latency. Add [pipeline.store_forwarding] to enable block-local store-buffer forwarding."
                            .to_owned(),
                    );
                }
                if pipeline.issue_width() > 1 {
                    caveats.push(
                        "Per-instruction fetch wait states are summed and are not reduced by co-issue; fetch bandwidth is not modeled."
                            .to_owned(),
                    );
                }
                if pipeline.issue_width() > 1 && pipeline.resources().is_empty() {
                    caveats.push(
                        "Pipeline issue_width > 1 without [pipeline.resources] only co-issues instructions whose resource names differ; each resource name still has one unit."
                            .to_owned(),
                    );
                }
                if pipeline.instruction_override_count() == 0 {
                    caveats.push(
                        "Pipeline class defaults are generic in-order presets, not verified target-core timings; provide [pipeline.instructions] overrides from the core manual or measurements."
                            .to_owned(),
                    );
                }
                if profile.instruction_cost_override_count() > 0 {
                    caveats.push(
                        "instruction_costs overrides are not added to pipeline block costs; use pipeline.instructions to override latency, occupancy or resources."
                            .to_owned(),
                    );
                }
            }
            if profile.instruction_cache().is_some() {
                caveats.push(
                    "Instruction-cache miss costs assume a cold cache at each function entry and a local CFG simulation; inter-function cache state, prefetch and data caches are not modeled."
                        .to_owned(),
                );
            }
        }
        caveats
    }
}

/// Parses a frequency such as `168MHz`, `16_000_000`, or `1.2GHz`.
///
/// # Errors
///
/// Returns a human-readable error for invalid, non-positive or overflowing
/// values.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn parse_frequency(input: &str) -> std::result::Result<u64, String> {
    let compact = input.trim().replace('_', "");
    if compact.is_empty() {
        return Err("frequency is empty".to_owned());
    }
    let lower = compact.to_ascii_lowercase();
    let (number, multiplier) = if let Some(value) = lower.strip_suffix("ghz") {
        (value, 1_000_000_000.0)
    } else if let Some(value) = lower.strip_suffix("mhz") {
        (value, 1_000_000.0)
    } else if let Some(value) = lower.strip_suffix("khz") {
        (value, 1_000.0)
    } else if let Some(value) = lower.strip_suffix("hz") {
        (value, 1.0)
    } else {
        (lower.as_str(), 1.0)
    };
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|error| format!("invalid frequency {input:?}: {error}"))?;
    if !value.is_finite() || value <= 0.0 {
        return Err(format!("frequency must be positive and finite: {input:?}"));
    }
    let hz = value * multiplier;
    if hz > u64::MAX as f64 {
        return Err(format!("frequency is too large: {input:?}"));
    }
    let hz = hz.round() as u64;
    if hz == 0 {
        return Err(format!("frequency rounds to zero: {input:?}"));
    }
    Ok(hz)
}

/// Coarse instruction class used by the built-in timing tables and by
/// board-profile cost overrides.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum InstructionClass {
    /// Load from memory.
    Load,
    /// Store to memory.
    Store,
    /// Push or pop multiple registers.
    PushPop,
    /// Load/store multiple.
    LdmStm,
    /// Branch or jump.
    Branch,
    /// Call.
    Call,
    /// Return or interrupt return.
    Return,
    /// Integer multiply.
    Multiply,
    /// Integer divide.
    Divide,
    /// Memory barrier.
    Barrier,
    /// No-operation.
    Nop,
    /// Arithmetic, logic, move or comparison.
    Alu,
    /// Other recognized instruction, or an unrecognized fallback.
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Classification {
    class: InstructionClass,
    known: bool,
}

/// Removes common architectural mnemonic suffixes and conditional prefixes.
///
/// This is the canonical form used both by the built-in classifier and by
/// board-profile `mnemonic` selectors.
#[must_use]
pub fn canonical_mnemonic(mnemonic: &str) -> &str {
    let mnemonic = mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
        .unwrap_or(mnemonic);
    mnemonic.strip_prefix("c.").unwrap_or(mnemonic)
}

fn classify(insn: &DecodedInsn) -> Classification {
    if insn.is_return {
        return Classification {
            class: InstructionClass::Return,
            known: true,
        };
    }
    if insn.is_call {
        return Classification {
            class: InstructionClass::Call,
            known: true,
        };
    }
    if insn.is_jump {
        return Classification {
            class: InstructionClass::Branch,
            known: true,
        };
    }
    let mnemonic = canonical_mnemonic(&insn.mnemonic);
    if mnemonic == "nop" {
        return known(InstructionClass::Nop);
    }
    if matches!(mnemonic, "push" | "pop") || mnemonic.starts_with("push.") {
        return known(InstructionClass::PushPop);
    }
    if mnemonic.starts_with("ldm") || mnemonic.starts_with("stm") {
        return known(InstructionClass::LdmStm);
    }
    if is_load(mnemonic) {
        return known(InstructionClass::Load);
    }
    if is_store(mnemonic) {
        return known(InstructionClass::Store);
    }
    if is_multiply(mnemonic) {
        return known(InstructionClass::Multiply);
    }
    if is_divide(mnemonic) {
        return known(InstructionClass::Divide);
    }
    if is_barrier(mnemonic) {
        return known(InstructionClass::Barrier);
    }
    if is_system(mnemonic) {
        return known(InstructionClass::Other);
    }
    if is_alu(mnemonic) {
        return known(InstructionClass::Alu);
    }
    Classification {
        class: InstructionClass::Other,
        known: false,
    }
}

const fn known(class: InstructionClass) -> Classification {
    Classification { class, known: true }
}

fn is_system(mnemonic: &str) -> bool {
    if mnemonic
        .strip_prefix("it")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| matches!(c, 't' | 'e')))
    {
        return true;
    }
    matches!(
        mnemonic,
        "udf"
            | "ud2"
            | "bkpt"
            | "svc"
            | "syscall"
            | "ecall"
            | "ebreak"
            | "int3"
            | "hlt"
            | "mrs"
            | "msr"
            | "cps"
            | "cpsid"
            | "cpsie"
            | "sev"
            | "wfe"
            | "wfi"
            | "yield"
            | "it"
            | "pld"
            | "pli"
            | "clrex"
            | "ssbb"
            | "csdb"
            | "esb"
            | "dcps"
            | "leave"
            | "enter"
            | "endbr64"
            | "endbr32"
            | "pause"
            | "lfence"
            | "sfence"
            | "mfence"
    )
}

fn is_alu(mnemonic: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "adc", "add", "adr", "and", "asr", "aut", "bfc", "bfi", "bfm", "bfx", "bic", "cbz", "cbnz",
        "ccmp", "ccmn", "cinc", "cinv", "clz", "cls", "cmn", "cmp", "cmpxchg", "cneg", "crc32",
        "csel", "cset", "csinc", "csinv", "csneg", "daa", "das", "dec", "eor", "ext", "extr",
        "fabs", "fadd", "fccmp", "fcmp", "fcsel", "fcvt", "fdiv", "fmadd", "fmov", "fmsub", "fmul",
        "fneg", "fnmadd", "fnmsub", "frint", "fsqrt", "fsub", "hint", "idiv", "imul", "inc", "lea",
        "lsl", "lsr", "madd", "mla", "mls", "mneg", "mov", "movk", "movn", "movsx", "movz",
        "movzx", "msub", "mul", "mvn", "neg", "not", "orn", "orr", "pac", "popcnt", "rbit", "rev",
        "ror", "rrx", "rsb", "sadd", "sar", "sbb", "sbc", "sbf", "sbfm", "sbfx", "sel", "set",
        "shadd", "shl", "shr", "shsub", "smmul", "smul", "smull", "ssat", "ssub", "sub", "sxt",
        "teq", "test", "tst", "ubfm", "ubfx", "udiv", "umul", "umull", "usat", "usad", "uxt",
        "vabs", "vadd", "vand", "vdiv", "veor", "vfma", "vfms", "vmov", "vmul", "vneg", "vorn",
        "vorr", "vsub", "xadd", "xchg", "xsub", "lui", "auipc", "addi", "andi", "ori", "xori",
        "slli", "srli", "srai", "slti", "sltiu", "slt", "sltu", "seqz", "snez", "sltz", "sgtz",
        "csrr", "csrw", "csrs", "csrc", "li", "la", "mv",
    ];
    PREFIXES.iter().any(|prefix| mnemonic.starts_with(prefix))
}

fn is_load(mnemonic: &str) -> bool {
    mnemonic.starts_with("ldr")
        || mnemonic.starts_with("vldr")
        || mnemonic.starts_with("ldp")
        || mnemonic.starts_with("ldur")
        || matches!(
            mnemonic,
            "ld" | "lw"
                | "lh"
                | "lb"
                | "lhu"
                | "lbu"
                | "lwu"
                | "lr"
                | "lr.w"
                | "ldsp"
                | "lwsp"
                | "lq"
                | "flw"
                | "fld"
                | "flq"
                | "flwsp"
                | "fldsp"
                | "flqsp"
        )
}

fn is_store(mnemonic: &str) -> bool {
    mnemonic.starts_with("str")
        || mnemonic.starts_with("vstr")
        || mnemonic.starts_with("stp")
        || mnemonic.starts_with("stur")
        || matches!(
            mnemonic,
            "st" | "sw"
                | "sh"
                | "sb"
                | "sc"
                | "sc.w"
                | "sd"
                | "sdsp"
                | "swsp"
                | "sq"
                | "fsw"
                | "fsd"
                | "fsq"
                | "fswsp"
                | "fsdsp"
                | "fsqsp"
                | "amoswap"
                | "amoadd"
        )
}

fn is_multiply(mnemonic: &str) -> bool {
    mnemonic.starts_with("mul")
        || mnemonic.starts_with("mla")
        || mnemonic.starts_with("mls")
        || mnemonic.starts_with("smull")
        || mnemonic.starts_with("umull")
        || mnemonic.starts_with("smlal")
        || mnemonic.starts_with("umlal")
        || mnemonic.starts_with("smul")
        || mnemonic.starts_with("umul")
}

fn is_divide(mnemonic: &str) -> bool {
    mnemonic.starts_with("sdiv")
        || mnemonic.starts_with("udiv")
        || mnemonic.starts_with("div")
        || mnemonic.starts_with("rem")
}

fn is_barrier(mnemonic: &str) -> bool {
    mnemonic.starts_with("dmb")
        || mnemonic.starts_with("dsb")
        || mnemonic.starts_with("isb")
        || mnemonic.starts_with("fence")
        || mnemonic.starts_with("membar")
}

fn cortex_m4_pipeline_default(class: InstructionClass) -> (&'static [&'static str], u32, u32) {
    match class {
        InstructionClass::Load | InstructionClass::PushPop => (&["load_store"], 2, 1),
        InstructionClass::Store => (&["load_store"], 1, 1),
        InstructionClass::LdmStm => (&["load_store"], 2, 2),
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => {
            (&["branch"], 1, 1)
        }
        InstructionClass::Multiply => (&["mul"], 1, 1),
        InstructionClass::Divide => (&["div"], 12, 1),
        InstructionClass::Alu
        | InstructionClass::Nop
        | InstructionClass::Barrier
        | InstructionClass::Other => (&["alu"], 1, 1),
    }
}

/// Generic RISC-V in-order class defaults. These are structural estimates
/// aligned with the generic RISC-V timing table; a concrete core must override
/// them with verified pipeline timings.
fn riscv_pipeline_default(class: InstructionClass) -> (&'static [&'static str], u32, u32) {
    match class {
        InstructionClass::Load | InstructionClass::PushPop => (&["load_store"], 2, 1),
        InstructionClass::Store => (&["load_store"], 1, 1),
        InstructionClass::LdmStm => (&["load_store"], 2, 2),
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => {
            (&["branch"], 1, 1)
        }
        InstructionClass::Multiply => (&["mul"], 3, 1),
        InstructionClass::Divide => (&["div"], 20, 1),
        InstructionClass::Alu
        | InstructionClass::Nop
        | InstructionClass::Barrier
        | InstructionClass::Other => (&["alu"], 1, 1),
    }
}

/// Generic `AArch64` in-order class defaults. These are structural estimates for
/// the scheduler, not a claim about a specific out-of-order `AArch64` core; a
/// concrete core must override them with verified pipeline timings.
fn aarch64_pipeline_default(class: InstructionClass) -> (&'static [&'static str], u32, u32) {
    match class {
        InstructionClass::Load | InstructionClass::PushPop => (&["load_store"], 3, 1),
        InstructionClass::Store => (&["load_store"], 1, 1),
        InstructionClass::LdmStm => (&["load_store"], 3, 2),
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => {
            (&["branch"], 1, 1)
        }
        InstructionClass::Multiply => (&["mul"], 3, 1),
        InstructionClass::Divide => (&["div"], 12, 1),
        InstructionClass::Alu
        | InstructionClass::Nop
        | InstructionClass::Barrier
        | InstructionClass::Other => (&["alu"], 1, 1),
    }
}

#[allow(clippy::match_same_arms)]
fn pipeline_class_default(
    model: TimingModel,
    class: InstructionClass,
) -> (&'static [&'static str], u32, u32) {
    match model {
        TimingModel::CortexM4 => cortex_m4_pipeline_default(class),
        TimingModel::RiscV32
        | TimingModel::RiscV64
        | TimingModel::RiscV32Bounded
        | TimingModel::RiscV64Bounded => riscv_pipeline_default(class),
        TimingModel::Aarch64Generic | TimingModel::Aarch64Bounded => {
            aarch64_pipeline_default(class)
        }
        _ => cortex_m4_pipeline_default(class),
    }
}

/// Generic per-class forwarding latency used by `[pipeline.forwarding]` when
/// no uniform default or instruction override applies. Values equal to the
/// class latency mean the result is not available before writeback, which is
/// the default for loads and divides.
fn pipeline_class_forwarding_default(model: TimingModel, class: InstructionClass) -> u32 {
    match model {
        TimingModel::CortexM4 => match class {
            InstructionClass::Load | InstructionClass::PushPop | InstructionClass::LdmStm => 2,
            InstructionClass::Divide => 12,
            _ => 1,
        },
        TimingModel::RiscV32
        | TimingModel::RiscV64
        | TimingModel::RiscV32Bounded
        | TimingModel::RiscV64Bounded => match class {
            InstructionClass::Load
            | InstructionClass::PushPop
            | InstructionClass::LdmStm
            | InstructionClass::Multiply => 2,
            InstructionClass::Divide => 20,
            _ => 1,
        },
        TimingModel::Aarch64Generic | TimingModel::Aarch64Bounded => match class {
            InstructionClass::Load | InstructionClass::PushPop | InstructionClass::LdmStm => 3,
            InstructionClass::Multiply => 2,
            InstructionClass::Divide => 12,
            _ => 1,
        },
        _ => 1,
    }
}

fn cortex_m0_cost(class: InstructionClass) -> CostRange {
    match class {
        InstructionClass::Alu
        | InstructionClass::Multiply
        | InstructionClass::Nop
        | InstructionClass::Divide
        | InstructionClass::Barrier
        | InstructionClass::Other => CostRange::exact(1.0),
        InstructionClass::Load | InstructionClass::Store => CostRange::exact(2.0),
        InstructionClass::PushPop | InstructionClass::Call | InstructionClass::Return => {
            CostRange::new(2.0, 4.0)
        }
        InstructionClass::LdmStm => CostRange::new(2.0, 6.0),
        InstructionClass::Branch => CostRange::new(1.0, 3.0),
    }
}

fn cortex_m3_cost(class: InstructionClass) -> CostRange {
    match class {
        InstructionClass::Alu
        | InstructionClass::Multiply
        | InstructionClass::Nop
        | InstructionClass::Store
        | InstructionClass::Barrier
        | InstructionClass::Other => CostRange::exact(1.0),
        InstructionClass::Load => CostRange::exact(2.0),
        InstructionClass::PushPop => CostRange::new(1.0, 4.0),
        InstructionClass::LdmStm => CostRange::new(1.0, 6.0),
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => {
            CostRange::new(1.0, 3.0)
        }
        InstructionClass::Divide => CostRange::new(2.0, 12.0),
    }
}

fn cortex_m7_cost(class: InstructionClass) -> CostRange {
    match class {
        InstructionClass::Alu
        | InstructionClass::Multiply
        | InstructionClass::Nop
        | InstructionClass::Load
        | InstructionClass::Store
        | InstructionClass::Branch => CostRange::new(1.0, 2.0),
        InstructionClass::PushPop | InstructionClass::LdmStm => CostRange::new(1.0, 5.0),
        InstructionClass::Call | InstructionClass::Return => CostRange::new(2.0, 4.0),
        InstructionClass::Divide => CostRange::new(2.0, 12.0),
        InstructionClass::Barrier | InstructionClass::Other => CostRange::exact(1.0),
    }
}

fn riscv_cost(class: InstructionClass) -> CostRange {
    match class {
        InstructionClass::Alu
        | InstructionClass::Nop
        | InstructionClass::Store
        | InstructionClass::Barrier
        | InstructionClass::Other => CostRange::exact(1.0),
        InstructionClass::Load => CostRange::exact(2.0),
        InstructionClass::PushPop | InstructionClass::LdmStm | InstructionClass::Multiply => {
            CostRange::new(1.0, 3.0)
        }
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => {
            CostRange::new(1.0, 2.0)
        }
        InstructionClass::Divide => CostRange::new(2.0, 20.0),
    }
}

fn aarch64_cost(class: InstructionClass) -> CostRange {
    match class {
        InstructionClass::Alu | InstructionClass::Nop | InstructionClass::Other => {
            CostRange::new(1.0, 2.0)
        }
        InstructionClass::Load | InstructionClass::Store => CostRange::new(2.0, 5.0),
        InstructionClass::PushPop | InstructionClass::LdmStm | InstructionClass::Multiply => {
            CostRange::new(2.0, 4.0)
        }
        InstructionClass::Branch | InstructionClass::Barrier => CostRange::new(1.0, 4.0),
        InstructionClass::Call | InstructionClass::Return => CostRange::new(1.0, 5.0),
        InstructionClass::Divide => CostRange::new(8.0, 20.0),
    }
}

/// Additive upper bounds for an abstract single-issue in-order RISC-V core.
///
/// The base table assumes single-cycle instruction and data memory. Memory
/// wait states, cache misses and branch-prediction penalties are added by the
/// board-profile analyses. The branch/call/return bound includes a conservative
/// pipeline-restart allowance; divide and barrier bounds cover the common
/// iterative implementations.
fn riscv_bounded_cost(class: InstructionClass, divide_max: u32) -> CostRange {
    let max = match class {
        InstructionClass::Alu | InstructionClass::Nop | InstructionClass::Other => 2.0,
        InstructionClass::Load
        | InstructionClass::Store
        | InstructionClass::PushPop
        | InstructionClass::LdmStm
        | InstructionClass::Multiply => 4.0,
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => 20.0,
        InstructionClass::Divide => f64::from(divide_max),
        InstructionClass::Barrier => 64.0,
    };
    CostRange::new(1.0, max)
}

/// Additive upper bounds for an abstract single-issue in-order `AArch64` core.
fn aarch64_bounded_cost(class: InstructionClass) -> CostRange {
    let max = match class {
        InstructionClass::Alu
        | InstructionClass::Nop
        | InstructionClass::Other
        | InstructionClass::Load
        | InstructionClass::Store
        | InstructionClass::PushPop
        | InstructionClass::LdmStm
        | InstructionClass::Multiply => 4.0,
        InstructionClass::Branch | InstructionClass::Call | InstructionClass::Return => 20.0,
        InstructionClass::Divide | InstructionClass::Barrier => 64.0,
    };
    CostRange::new(1.0, max)
}

fn x86_64_cost(class: InstructionClass) -> CostRange {
    match class {
        InstructionClass::Alu | InstructionClass::Nop | InstructionClass::Store => {
            CostRange::new(1.0, 2.0)
        }
        InstructionClass::Load => CostRange::new(1.0, 5.0),
        InstructionClass::PushPop | InstructionClass::LdmStm | InstructionClass::Other => {
            CostRange::new(1.0, 3.0)
        }
        InstructionClass::Branch => CostRange::new(1.0, 20.0),
        InstructionClass::Call | InstructionClass::Return => CostRange::new(2.0, 10.0),
        InstructionClass::Multiply => CostRange::new(3.0, 5.0),
        InstructionClass::Divide => CostRange::new(20.0, 40.0),
        InstructionClass::Barrier => CostRange::new(1.0, 10.0),
    }
}

#[cfg(test)]
mod tests {
    use super::{TimingCostModel, TimingModel, parse_frequency};
    use crate::arch::{DecodedInsn, MemoryAccess, MemoryAccessKind};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgTerminator};
    use crate::loader::{ArchKind, ByteOrder, ElfKind, Image, Section};
    use elf2tdg_schema::FrequencySource;
    use std::collections::BTreeSet;

    fn image(arch: ArchKind) -> Image {
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
                size: 4,
                data: vec![0; 4],
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
    fn parses_frequency_suffixes() {
        assert_eq!(parse_frequency("168MHz").unwrap(), 168_000_000);
        assert_eq!(parse_frequency("16_000_000").unwrap(), 16_000_000);
        assert_eq!(parse_frequency("1.2GHz").unwrap(), 1_200_000_000);
        assert_eq!(parse_frequency("100 kHz").unwrap(), 100_000);
        assert_eq!(parse_frequency("42hz").unwrap(), 42);
    }

    #[test]
    fn rejects_invalid_frequencies() {
        assert!(parse_frequency("").is_err());
        assert!(parse_frequency("0").is_err());
        assert!(parse_frequency("-1MHz").is_err());
        assert!(parse_frequency("fast").is_err());
        assert!(parse_frequency("NaN").is_err());
    }

    #[test]
    fn model_names_round_trip() {
        assert_eq!(
            TimingModel::from_name("Cortex-M4"),
            Some(TimingModel::CortexM4)
        );
        assert_eq!(
            TimingModel::from_name("cortex_m0plus"),
            Some(TimingModel::CortexM0Plus)
        );
        assert_eq!(TimingModel::from_name("rv32"), Some(TimingModel::RiscV32));
        assert_eq!(
            TimingModel::from_name("Cortex-A53"),
            Some(TimingModel::Aarch64Generic)
        );
        assert_eq!(
            TimingModel::from_name("x86_64"),
            Some(TimingModel::X86_64Generic)
        );
    }

    #[test]
    fn generic_aarch64_and_x86_timing_are_opt_in() {
        assert_eq!(TimingModel::auto(&image(ArchKind::Aarch64)), None);
        assert_eq!(TimingModel::auto(&image(ArchKind::X86_64)), None);
        assert_eq!(
            TimingModel::select(Some("aarch64"), &image(ArchKind::Aarch64)).unwrap(),
            Some(TimingModel::Aarch64Generic)
        );
        assert_eq!(
            TimingModel::select(Some("x86-64"), &image(ArchKind::X86_64)).unwrap(),
            Some(TimingModel::X86_64Generic)
        );
        assert!(TimingModel::select(Some("aarch64"), &image(ArchKind::X86_64)).is_err());
        assert!(TimingModel::select(Some("x86-64"), &image(ArchKind::Aarch64)).is_err());
    }

    #[test]
    fn bounded_aarch64_and_riscv_models_are_explicit() {
        for (name, model, arch) in [
            (
                "aarch64-bounded",
                TimingModel::Aarch64Bounded,
                ArchKind::Aarch64,
            ),
            (
                "riscv32-bounded",
                TimingModel::RiscV32Bounded,
                ArchKind::Riscv32,
            ),
            (
                "riscv64-bounded",
                TimingModel::RiscV64Bounded,
                ArchKind::Riscv64,
            ),
        ] {
            assert_eq!(TimingModel::from_name(name), Some(model));
            assert_eq!(
                TimingModel::select(Some(name), &image(arch)).unwrap(),
                Some(model)
            );
            assert_eq!(model.determinism(), elf2tdg_schema::Determinism::Bounded);
            assert_eq!(model.confidence(), elf2tdg_schema::Confidence::Low);
            assert_eq!(model.table_version(), "0.3.0-bounded");
            assert!(model.is_bounded_abstract());
            assert_eq!(
                model
                    .params()
                    .extras
                    .get("bounded_semantics")
                    .map(String::as_str),
                Some("abstract-single-issue-in-order")
            );
        }
        assert!(TimingModel::select(Some("aarch64-bounded"), &image(ArchKind::X86_64)).is_err());
    }

    #[test]
    fn bounded_model_costs_have_defined_upper_bounds() {
        let mut branch = insn(0x1000, 4, "b");
        branch.is_jump = true;
        let mut call = insn(0x1004, 4, "bl");
        call.is_call = true;

        let aarch64 = TimingModel::Aarch64Bounded;
        assert_eq!(aarch64.instruction_cost(&insn(0x1000, 4, "ldr")).max, 4.0);
        assert_eq!(aarch64.instruction_cost(&branch).max, 20.0);
        assert_eq!(aarch64.instruction_cost(&call).max, 20.0);
        assert_eq!(aarch64.instruction_cost(&insn(0x1000, 4, "sdiv")).max, 64.0);

        let rv32 = TimingModel::RiscV32Bounded;
        assert_eq!(rv32.instruction_cost(&insn(0x1000, 4, "ld")).max, 4.0);
        assert_eq!(rv32.instruction_cost(&branch).max, 20.0);
        assert_eq!(rv32.instruction_cost(&insn(0x1000, 4, "div")).max, 64.0);

        let rv64 = TimingModel::RiscV64Bounded;
        assert_eq!(rv64.instruction_cost(&insn(0x1000, 4, "div")).max, 128.0);
    }

    #[test]
    fn riscv_compressed_loads_and_stores_are_classified() {
        let model = TimingModel::RiscV64Bounded;
        for mnemonic in ["ld", "sd", "c.ldsp", "c.sdsp", "c.lwsp", "c.swsp"] {
            let cost = model.instruction_cost(&insn(0x1000, 4, mnemonic));
            assert_eq!(cost.max, 4.0, "{mnemonic}");
        }
    }

    #[test]
    fn bounded_model_block_cost_is_additive() {
        let model =
            TimingCostModel::select(Some("riscv64-bounded"), None, &image(ArchKind::Riscv64))
                .expect("select")
                .expect("bounded model");
        let instructions = [
            insn(0x1000, 4, "add"),
            insn(0x1004, 4, "ld"),
            insn(0x1008, 4, "add"),
        ];
        let (cycles, unknown) = model.block_cost(&instructions);
        assert_eq!(unknown.len(), 0);
        assert_eq!(cycles.min, 3.0);
        let expected_max: f64 = instructions
            .iter()
            .map(|instruction| model.instruction_cost(instruction).cycles.max)
            .sum();
        assert_eq!(cycles.max, expected_max);

        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0].determinism,
            elf2tdg_schema::Determinism::Bounded
        );
        assert_eq!(info.models[0].table_version, "0.3.0-bounded");
    }

    #[test]
    fn bounded_model_with_profile_stays_bounded() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:bounded-rv64"
arch = "riscv64"
cpu = "riscv64-bounded"

[clocks.core]
hz = 1_000_000_000

[[memory]]
name = "ram"
start = 0x400000
size = 0x100000
kind = "ram"
executable = true
"#,
        )
        .expect("valid profile");
        let model = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("bounded model");
        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0].determinism,
            elf2tdg_schema::Determinism::Bounded
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_memory_regions")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn statistical_models_are_marked_as_such() {
        for model in [TimingModel::Aarch64Generic, TimingModel::X86_64Generic] {
            assert_eq!(
                model.determinism(),
                elf2tdg_schema::Determinism::Statistical
            );
            assert_eq!(model.confidence(), elf2tdg_schema::Confidence::Low);
            assert_eq!(model.params().branch_prediction, Some(true));
            assert!(model.params().caches.is_some());
        }
    }

    #[test]
    fn branch_cost_is_a_range() {
        let model = TimingModel::CortexM4;
        let insn = DecodedInsn {
            address: 0x1000,
            size: 2,
            mnemonic: "bne".to_owned(),
            operands: "#0x1004".to_owned(),
            is_call: false,
            is_jump: true,
            is_return: false,
            is_conditional: true,
            direct_target: Some(0x1004),
            value: None,
            memory_write: None,
            memory_accesses: Vec::new(),
            indirect: None,
            regs_read: Vec::new(),
            regs_write: Vec::new(),
            compare: None,
            branch_registers: None,
            compare_registers: None,
        };
        let cost = model.instruction_cost(&insn);
        assert!(cost.is_valid());
        assert!(cost.min <= cost.max);
    }

    #[test]
    fn time_is_derived_only_with_frequency() {
        let model = TimingModel::CortexM4;
        let cycles = model.instruction_cost(&DecodedInsn {
            address: 0x1000,
            size: 2,
            mnemonic: "ldr".to_owned(),
            operands: "r0, [r1]".to_owned(),
            is_call: false,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            value: None,
            memory_write: None,
            memory_accesses: Vec::new(),
            indirect: None,
            regs_read: Vec::new(),
            regs_write: Vec::new(),
            compare: None,
            branch_registers: None,
            compare_registers: None,
        });
        let timed = model.block_timing(cycles, Some(168_000_000));
        assert!(timed.time_ns.is_some());
        let untimed = model.block_timing(cycles, None);
        assert!(untimed.time_ns.is_none());
    }

    fn insn(address: u64, size: u8, mnemonic: &str) -> DecodedInsn {
        DecodedInsn {
            address,
            size,
            mnemonic: mnemonic.to_owned(),
            operands: String::new(),
            is_call: false,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            value: None,
            memory_write: None,
            memory_accesses: Vec::new(),
            indirect: None,
            regs_read: Vec::new(),
            regs_write: Vec::new(),
            compare: None,
            branch_registers: None,
            compare_registers: None,
        }
    }

    fn insn_with_regs(
        address: u64,
        size: u8,
        mnemonic: &str,
        reads: &[u16],
        writes: &[u16],
    ) -> DecodedInsn {
        let mut instruction = insn(address, size, mnemonic);
        instruction.regs_read = reads.iter().copied().map(capstone::RegId).collect();
        instruction.regs_write = writes.iter().copied().map(capstone::RegId).collect();
        instruction
    }

    fn memory_access(
        kind: MemoryAccessKind,
        width: u8,
        base: Option<u16>,
        index: Option<u16>,
        disp: i64,
        absolute: Option<u64>,
    ) -> MemoryAccess {
        MemoryAccess {
            kind,
            width,
            base: base.map(capstone::RegId),
            index: index.map(capstone::RegId),
            disp,
            absolute,
        }
    }

    fn insn_with_memory(
        address: u64,
        size: u8,
        mnemonic: &str,
        reads: &[u16],
        writes: &[u16],
        accesses: Vec<MemoryAccess>,
    ) -> DecodedInsn {
        let mut instruction = insn_with_regs(address, size, mnemonic, reads, writes);
        instruction.memory_accesses = accesses;
        instruction
    }

    fn store_forwarding_model(latency: u32, entries: u32) -> TimingCostModel {
        let profile = BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:store-forwarding"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 1

[pipeline.store_forwarding]
latency = {latency}
entries = {entries}
"#
        ))
        .expect("valid store-forwarding profile");
        TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model")
    }

    fn store_pair(store_disp: i64, load_disp: i64) -> [DecodedInsn; 2] {
        [
            insn_with_memory(
                0x1000,
                4,
                "sd",
                &[1, 2],
                &[],
                vec![memory_access(
                    MemoryAccessKind::Write,
                    8,
                    Some(1),
                    None,
                    store_disp,
                    None,
                )],
            ),
            insn_with_memory(
                0x1004,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    None,
                    load_disp,
                    None,
                )],
            ),
        ]
    }

    fn board_profile() -> BoardProfile {
        BoardProfile::parse_toml(
            r#"
schema_version = 1
id = "board:test"
arch = "thumb"
cpu = "cortex-m0"
confidence = "high"

[clocks.core]
hz = 48_000_000
confidence = "high"

[[memory]]
name = "flash"
start = 0x1000
size = 0x100
kind = "flash"
executable = true
fetch_wait_states = 1
fetch_width_bytes = 4

[[instruction_costs]]
mnemonic = "ldr"
cycles = 10
"#,
        )
        .expect("valid board profile")
    }

    #[test]
    fn board_profile_applies_overrides_and_fetch_costs() {
        let profile = board_profile();
        let model = TimingCostModel::select(None, Some(&profile), &image(ArchKind::Thumb))
            .expect("profile selects")
            .expect("timing model");
        let ldr = model.instruction_cost(&insn(0x1000, 2, "ldr"));
        assert_eq!(ldr.cycles.min, 11.0);
        assert_eq!(ldr.cycles.max, 11.0);
        assert!(!ldr.unknown);

        let add = model.instruction_cost(&insn(0x1002, 2, "add"));
        assert_eq!(add.cycles.min, 2.0);
        assert_eq!(add.cycles.max, 2.0);
        assert!(!add.unknown);

        let unknown = model.instruction_cost(&insn(0x1004, 2, "vxyz"));
        assert!(unknown.unknown);
        assert_eq!(unknown.cycles.min, 2.0);
        assert_eq!(model.core_frequency_hz(None), Some(48_000_000));
        assert_eq!(model.core_frequency_hz(Some(1_000_000)), Some(1_000_000));
    }

    #[test]
    fn board_profile_metadata_is_recorded() {
        let profile = board_profile();
        let model = TimingCostModel::select(None, Some(&profile), &image(ArchKind::Thumb))
            .expect("profile selects")
            .expect("timing model");
        let unknown = BTreeSet::new();
        let info = model.timing_info(None, &unknown);
        assert_eq!(info.models.len(), 1);
        assert_eq!(
            info.models[0].params.flash_wait_states,
            Some(1),
            "flash wait states are recorded"
        );
        assert_eq!(
            info.models[0].params.extras.get("board_profile_id"),
            Some(&"board:test".to_owned())
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_sha256")
                .map(String::len),
            Some(64)
        );
        assert_eq!(
            info.frequency_domains[0].source,
            FrequencySource::BoardProfile
        );
        assert_eq!(
            info.default_frequency_domain
                .as_ref()
                .map(elf2tdg_schema::FrequencyDomainId::as_str),
            Some("clk:core")
        );

        let overridden = model.timing_info(Some(1_000_000), &unknown);
        let core = overridden
            .frequency_domains
            .iter()
            .find(|domain| domain.id.as_str() == "clk:core")
            .expect("core domain");
        assert_eq!(core.hz, 1_000_000);
        assert_eq!(core.source, FrequencySource::Cli);
        assert_eq!(core.confidence, elf2tdg_schema::Confidence::High);
        assert!(
            overridden.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("used unchanged")),
            "CLI frequency override must not imply rescaled wait states"
        );

        let block = model.block_timing(ldr_cost(), None);
        assert_eq!(block.confidence, elf2tdg_schema::Confidence::High);
    }

    fn ldr_cost() -> elf2tdg_schema::CostRange {
        elf2tdg_schema::CostRange::exact(2.0)
    }

    fn pipeline_profile() -> BoardProfile {
        BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:pipeline"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 168_000_000

[pipeline]
issue_width = 1
branch_penalty = { min = 2, max = 2 }

[[pipeline.instructions]]
mnemonic = "ldr"
resources = ["load_store"]
latency = 2
occupancy = 2
"#,
        )
        .expect("valid pipeline profile")
    }

    #[test]
    fn pipeline_schedules_dependencies_resources_and_branch_penalty() {
        let profile = pipeline_profile();
        let model = TimingCostModel::select(None, Some(&profile), &image(ArchKind::Thumb))
            .expect("profile selects")
            .expect("timing model");

        let independent_loads = [
            insn_with_regs(0x1000, 2, "ldr", &[1], &[0]),
            insn_with_regs(0x1002, 2, "ldr", &[3], &[2]),
        ];
        let (cost, unknown) = model.block_cost(&independent_loads);
        assert_eq!(unknown, Vec::new());
        assert_eq!(cost.min, 4.0);
        assert_eq!(cost.max, 4.0);

        let dependent = [
            insn_with_regs(0x1000, 2, "ldr", &[1], &[0]),
            insn_with_regs(0x1002, 2, "add", &[0], &[2]),
        ];
        let (cost, _) = model.block_cost(&dependent);
        assert_eq!(cost.min, 3.0);
        assert_eq!(cost.max, 3.0);

        let mut branch = insn(0x1004, 2, "b");
        branch.is_jump = true;
        let branch_block = [insn_with_regs(0x1000, 2, "ldr", &[1], &[0]), branch];
        let (cost, _) = model.block_cost(&branch_block);
        assert_eq!(cost.min, 4.0);
        assert_eq!(cost.max, 4.0);

        let (cost, unknown) = model.block_cost(&[insn(0x1000, 2, "vxyz")]);
        assert_eq!(unknown.len(), 1);
        assert_eq!(cost.min, 1.0);

        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0].determinism,
            elf2tdg_schema::Determinism::Statistical
        );
    }

    #[test]
    fn pipeline_edge_stalls_carry_resource_occupancy() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:pipeline-edge"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 168_000_000

[pipeline]
issue_width = 1
branch_penalty = 2

[[pipeline.instructions]]
mnemonic = "ldr"
resources = ["load_store"]
latency = 1
occupancy = 4
"#,
        )
        .expect("valid pipeline edge profile");
        let model = TimingCostModel::select(None, Some(&profile), &image(ArchKind::Thumb))
            .expect("profile selects")
            .expect("timing model");
        let decoded = [
            insn_with_regs(0x1000, 2, "ldr", &[1], &[0]),
            insn_with_regs(0x1002, 2, "ldr", &[2], &[3]),
        ];
        let blocks = [
            CfgBlockDraft {
                address: 0x1000,
                size: 2,
                instructions: Vec::new(),
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Fallthrough,
            },
            CfgBlockDraft {
                address: 0x1002,
                size: 2,
                instructions: Vec::new(),
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Fallthrough,
            },
        ];
        let edges = [CfgEdgeDraft {
            from: 0x1000,
            to: 0x1002,
            kind: CfgEdgeKind::Fallthrough,
            site: 0x1000,
            conditional: false,
        }];
        let stalls = model.pipeline_edge_stalls(&decoded, &blocks, &edges);
        assert_eq!(stalls, vec![Some(3.0)]);

        let call_return = [CfgEdgeDraft {
            from: 0x1000,
            to: 0x1002,
            kind: CfgEdgeKind::CallReturn,
            site: 0x1000,
            conditional: false,
        }];
        assert_eq!(
            model.pipeline_edge_stalls(&decoded, &blocks, &call_return),
            vec![None]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pipeline_state_model_carries_state_across_blocks_and_resets_on_call_return() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:pipeline-state"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 168_000_000

[pipeline]
issue_width = 1
branch_penalty = 2

[[pipeline.instructions]]
mnemonic = "ldr"
resources = ["load_store"]
latency = 1
occupancy = 4
"#,
        )
        .expect("valid pipeline state profile");
        let model = TimingCostModel::select(None, Some(&profile), &image(ArchKind::Thumb))
            .expect("profile selects")
            .expect("timing model");
        let decoded = [
            insn_with_regs(0x1000, 2, "ldr", &[1], &[0]),
            insn_with_regs(0x1002, 2, "ldr", &[2], &[3]),
        ];
        let blocks = [
            CfgBlockDraft {
                address: 0x1000,
                size: 2,
                instructions: Vec::new(),
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Fallthrough,
            },
            CfgBlockDraft {
                address: 0x1002,
                size: 2,
                instructions: Vec::new(),
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Fallthrough,
            },
        ];
        let loop_edges = [
            CfgEdgeDraft {
                from: 0x1000,
                to: 0x1002,
                kind: CfgEdgeKind::Fallthrough,
                site: 0x1000,
                conditional: false,
            },
            CfgEdgeDraft {
                from: 0x1002,
                to: 0x1000,
                kind: CfgEdgeKind::Fallthrough,
                site: 0x1002,
                conditional: false,
            },
        ];
        let function = model
            .pipeline_state_model(&decoded, &blocks, &loop_edges, 0x1000)
            .expect("pipeline state table");
        assert_eq!(function.entry_state(), &super::PipelineState::default());
        assert_eq!(function.default_cost(0x1000), Some(1.0));
        assert_eq!(function.default_cost(0x1002), Some(1.0));
        let (cost, exit) = function
            .transition(0x1000, function.entry_state())
            .expect("entry transition");
        assert_eq!(cost, 1.0);
        assert_ne!(exit, super::PipelineState::default());
        assert_eq!(
            function.transition(0x1002, &exit).map(|(cost, _)| cost),
            Some(4.0)
        );
        assert_eq!(function.blocks[&0x1000].states.len(), 2);
        assert_eq!(function.blocks[&0x1002].states.len(), 1);

        let call_return_edges = [
            CfgEdgeDraft {
                from: 0x1000,
                to: 0x1002,
                kind: CfgEdgeKind::Fallthrough,
                site: 0x1000,
                conditional: false,
            },
            CfgEdgeDraft {
                from: 0x1002,
                to: 0x1000,
                kind: CfgEdgeKind::CallReturn,
                site: 0x1002,
                conditional: false,
            },
        ];
        let reset = model
            .pipeline_state_model(&decoded, &blocks, &call_return_edges, 0x1000)
            .expect("pipeline state table across a call return");
        assert_eq!(reset.blocks[&0x1000].states.len(), 1);
        assert!(
            reset.blocks[&0x1000]
                .states
                .contains_key(&super::PipelineState::default())
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pipeline_model_supports_aarch64_and_riscv_bounded_models() {
        for (cpu, arch, load) in [
            ("aarch64-bounded", ArchKind::Aarch64, "ldr"),
            ("riscv32-bounded", ArchKind::Riscv32, "ld"),
            ("riscv64-bounded", ArchKind::Riscv64, "ld"),
        ] {
            let profile = BoardProfile::parse_toml(&format!(
                r#"
schema_version = 2
id = "board:{cpu}"
arch = "{arch}"
cpu = "{cpu}"

[clocks.core]
hz = 1_000_000_000

[pipeline]
issue_width = 1
branch_penalty = 2
"#,
                arch = match arch {
                    ArchKind::Aarch64 => "aarch64",
                    ArchKind::Riscv32 => "riscv32",
                    _ => "riscv64",
                }
            ))
            .expect("valid pipeline profile");
            let model = TimingCostModel::select(Some(cpu), Some(&profile), &image(arch))
                .expect("select")
                .expect("model");
            assert!(model.active_pipeline().is_some(), "{cpu}");

            let loads = [
                insn_with_regs(0x1000, 4, load, &[1], &[0]),
                insn_with_regs(0x1004, 4, load, &[3], &[2]),
            ];
            let (cost, unknown) = model.block_cost(&loads);
            assert!(unknown.is_empty(), "{cpu}");
            assert!(
                cost.max < 8.0,
                "{cpu} pipeline cost {} should be below the additive bounded table",
                cost.max
            );

            let blocks = [
                CfgBlockDraft {
                    address: 0x1000,
                    size: 4,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: None,
                    terminator: CfgTerminator::Fallthrough,
                },
                CfgBlockDraft {
                    address: 0x1004,
                    size: 4,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: None,
                    terminator: CfgTerminator::Fallthrough,
                },
            ];
            let edges = [CfgEdgeDraft {
                from: 0x1000,
                to: 0x1004,
                kind: CfgEdgeKind::Fallthrough,
                site: 0x1000,
                conditional: false,
            }];
            let decoded = [
                insn_with_regs(0x1000, 4, load, &[1], &[0]),
                insn_with_regs(0x1004, 4, load, &[2], &[3]),
            ];
            assert!(
                model
                    .pipeline_state_model(&decoded, &blocks, &edges, 0x1000)
                    .is_some(),
                "{cpu} state table"
            );
            assert_eq!(
                model.pipeline_edge_stalls(&decoded, &blocks, &edges).len(),
                1
            );

            let info = model.timing_info(None, &BTreeSet::new());
            assert_eq!(
                info.models[0].determinism,
                elf2tdg_schema::Determinism::Statistical,
                "{cpu}"
            );
            assert_eq!(
                info.models[0]
                    .params
                    .extras
                    .get("board_profile_pipeline")
                    .map(String::as_str),
                Some(format!("{cpu}-resource-dependency-model").as_str())
            );
            assert_eq!(
                model.pipeline_edge_model_name(),
                format!("{cpu}-edge-context")
            );
            assert_eq!(
                info.models[0]
                    .params
                    .extras
                    .get("bounded_cost_table")
                    .map(String::as_str),
                Some("replaced-by-pipeline")
            );
            assert!(
                info.models[0]
                    .caveats
                    .iter()
                    .any(|caveat| caveat.contains("not a safe upper bound")),
                "{cpu}"
            );
        }
    }

    #[test]
    fn pipeline_class_defaults_follow_the_target_isa() {
        let aarch64 = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:aarch64-pipeline"
arch = "aarch64"
cpu = "aarch64-bounded"

[pipeline]
issue_width = 1
"#,
        )
        .expect("valid AArch64 pipeline profile");
        let aarch64 = TimingCostModel::select(
            Some("aarch64-bounded"),
            Some(&aarch64),
            &image(ArchKind::Aarch64),
        )
        .expect("select")
        .expect("model");
        let (multiply, _) = aarch64.block_cost(&[insn(0x1000, 4, "mul")]);
        assert_eq!(multiply.max, 3.0);
        let (divide, _) = aarch64.block_cost(&[insn(0x1000, 4, "sdiv")]);
        assert_eq!(divide.max, 12.0);

        let riscv = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:riscv-pipeline"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 1
"#,
        )
        .expect("valid RISC-V pipeline profile");
        let riscv = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&riscv),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model");
        let (multiply, _) = riscv.block_cost(&[insn(0x1000, 4, "mul")]);
        assert_eq!(multiply.max, 3.0);
        let (divide, _) = riscv.block_cost(&[insn(0x1000, 4, "div")]);
        assert_eq!(divide.max, 20.0);
    }

    fn multi_issue_profile(issue_width: u32, alu_units: Option<u32>) -> BoardProfile {
        let resources = alu_units.map_or_else(String::new, |units| {
            format!("[pipeline.resources]\nalu = {units}\n")
        });
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:multi-issue"
arch = "riscv64"
cpu = "riscv64-bounded"

[clocks.core]
hz = 1_000_000_000

[pipeline]
issue_width = {issue_width}
branch_penalty = 1
{resources}
[[pipeline.instructions]]
mnemonic = "add"
resources = ["alu"]
latency = 1
occupancy = 1
"#
        ))
        .expect("valid multi-issue profile")
    }

    fn multi_issue_model(issue_width: u32, alu_units: Option<u32>) -> TimingCostModel {
        let profile = multi_issue_profile(issue_width, alu_units);
        TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model")
    }

    #[test]
    fn multi_issue_co_issues_independent_resources() {
        let model = multi_issue_model(2, None);
        let independent = [
            insn_with_regs(0x1000, 4, "add", &[1, 2], &[3]),
            insn_with_regs(0x1004, 4, "ld", &[5], &[4]),
        ];
        let (cost, unknown) = model.block_cost(&independent);
        assert!(unknown.is_empty(), "unexpected fallback: {unknown:?}");
        assert_eq!(cost.max, 2.0, "add and load should issue together");

        let two_adds = [
            insn_with_regs(0x1000, 4, "add", &[1, 2], &[3]),
            insn_with_regs(0x1004, 4, "add", &[5, 6], &[7]),
        ];
        let (cost, _) = model.block_cost(&two_adds);
        assert_eq!(cost.max, 2.0, "the default ALU has one unit");

        let model = multi_issue_model(2, Some(2));
        let (cost, _) = model.block_cost(&two_adds);
        assert_eq!(cost.max, 1.0, "two ALU units allow co-issue");
    }

    #[test]
    fn multi_issue_caps_issue_slots_per_cycle() {
        let instructions = [
            insn_with_regs(0x1000, 4, "add", &[1, 2], &[3]),
            insn_with_regs(0x1004, 4, "add", &[5, 6], &[7]),
            insn_with_regs(0x1008, 4, "add", &[8, 9], &[10]),
        ];
        let width_three = multi_issue_model(3, Some(3));
        let (cost, _) = width_three.block_cost(&instructions);
        assert_eq!(cost.max, 1.0);

        let width_two = multi_issue_model(2, Some(3));
        let (cost, _) = width_two.block_cost(&instructions);
        assert_eq!(cost.max, 2.0);

        let width_one = multi_issue_model(1, Some(3));
        let (cost, _) = width_one.block_cost(&instructions);
        assert_eq!(cost.max, 3.0);
    }

    #[test]
    fn multi_issue_state_carries_unit_occupancy_across_blocks() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:multi-issue-state"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 2

[pipeline.resources]
alu = 2

[[pipeline.instructions]]
mnemonic = "add"
resources = ["alu"]
latency = 1
occupancy = 3
"#,
        )
        .expect("valid multi-issue state profile");
        let model = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model");
        let decoded = [
            insn_with_regs(0x1000, 4, "add", &[1, 2], &[3]),
            insn_with_regs(0x1004, 4, "add", &[5, 6], &[7]),
            insn_with_regs(0x1008, 4, "add", &[8, 9], &[10]),
        ];
        let blocks = [
            CfgBlockDraft {
                address: 0x1000,
                size: 8,
                instructions: Vec::new(),
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Fallthrough,
            },
            CfgBlockDraft {
                address: 0x1008,
                size: 4,
                instructions: Vec::new(),
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Fallthrough,
            },
        ];
        let edges = [CfgEdgeDraft {
            from: 0x1000,
            to: 0x1008,
            kind: CfgEdgeKind::Fallthrough,
            site: 0x1004,
            conditional: false,
        }];
        let function = model
            .pipeline_state_model(&decoded, &blocks, &edges, 0x1000)
            .expect("multi-issue state table");
        assert_eq!(function.default_cost(0x1000), Some(1.0));
        assert_eq!(function.default_cost(0x1008), Some(1.0));
        let (cost, exit) = function
            .transition(0x1000, function.entry_state())
            .expect("entry transition");
        assert_eq!(cost, 1.0);
        assert_ne!(exit, super::PipelineState::default());
        assert_eq!(
            function.transition(0x1008, &exit).map(|(cost, _)| cost),
            Some(3.0)
        );
        assert_eq!(
            model.pipeline_edge_stalls(&decoded, &blocks, &edges),
            vec![Some(2.0)]
        );
    }

    #[test]
    fn multi_issue_metadata_records_width_and_resource_units() {
        let model = multi_issue_model(2, Some(2));
        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0].determinism,
            elf2tdg_schema::Determinism::Statistical
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_issue_width")
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_resources")
                .map(String::as_str),
            Some("alu=2")
        );
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("cross-block co-issue"))
        );
    }

    fn register_file_model(read_ports: u32, write_ports: u32) -> TimingCostModel {
        let profile = BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:register-file"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 2

[pipeline.resources]
alu = 2

[pipeline.register_file]
read_ports = {read_ports}
write_ports = {write_ports}
"#
        ))
        .expect("valid register-file profile");
        TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model")
    }

    #[test]
    fn register_file_ports_limit_co_issue() {
        let instructions = [
            insn_with_regs(0x1000, 4, "add", &[1], &[2]),
            insn_with_regs(0x1004, 4, "add", &[3], &[4]),
        ];
        for (read_ports, write_ports, expected) in
            [(2, 2, 1.0), (1, 2, 2.0), (2, 1, 2.0), (1, 1, 2.0)]
        {
            let model = register_file_model(read_ports, write_ports);
            let (cost, _) = model.block_cost(&instructions);
            assert_eq!(
                cost.max, expected,
                "read_ports={read_ports}, write_ports={write_ports}"
            );
        }
    }

    #[test]
    fn register_file_oversized_instructions_use_exclusive_issue_cycles() {
        let read_limited = register_file_model(1, 2);
        let instructions = [
            insn_with_regs(0x1000, 4, "add", &[1, 2], &[3]),
            insn_with_regs(0x1004, 4, "add", &[4], &[5]),
        ];
        let (cost, _) = read_limited.block_cost(&instructions);
        assert_eq!(cost.max, 3.0, "two reads need two exclusive cycles");

        let write_limited = register_file_model(2, 1);
        let instructions = [
            insn_with_regs(0x1000, 4, "add", &[1], &[2, 3, 4]),
            insn_with_regs(0x1004, 4, "add", &[5], &[6]),
        ];
        let (cost, _) = write_limited.block_cost(&instructions);
        assert_eq!(cost.max, 4.0, "three writes need three exclusive cycles");

        let unlimited = multi_issue_model(2, Some(2));
        let instructions = [
            insn_with_regs(0x1000, 4, "add", &[1, 2], &[3]),
            insn_with_regs(0x1004, 4, "add", &[4], &[5]),
        ];
        let (cost, _) = unlimited.block_cost(&instructions);
        assert_eq!(
            cost.max, 1.0,
            "without the section both instructions co-issue"
        );
    }

    #[test]
    fn register_file_metadata_records_port_counts() {
        let model = register_file_model(4, 2);
        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_read_ports")
                .map(String::as_str),
            Some("4")
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_write_ports")
                .map(String::as_str),
            Some("2")
        );
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("Register-file ports are budgeted"))
        );
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("consecutive exclusive issue cycles"))
        );

        let unlimited = multi_issue_model(2, Some(2));
        let info = unlimited.timing_info(None, &BTreeSet::new());
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("Register-file port limits are not modeled"))
        );
    }

    #[allow(clippy::option_option)]
    fn forwarding_add_model(
        forwarding: Option<Option<u32>>,
        latency: u32,
        forwarding_latency: Option<u32>,
    ) -> TimingCostModel {
        let forwarding_section = forwarding.map_or_else(String::new, |default_latency| {
            default_latency.map_or_else(
                || "[pipeline.forwarding]\n".to_owned(),
                |latency| format!("[pipeline.forwarding]\ndefault_latency = {latency}\n"),
            )
        });
        let forwarding_line = forwarding_latency.map_or_else(String::new, |latency| {
            format!("forwarding_latency = {latency}\n")
        });
        let profile = BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:forwarding"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 1
{forwarding_section}
[[pipeline.instructions]]
mnemonic = "add"
resources = ["alu"]
latency = {latency}
{forwarding_line}"#
        ))
        .expect("valid forwarding profile");
        TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model")
    }

    fn dependent_adds() -> [DecodedInsn; 2] {
        [
            insn_with_regs(0x1000, 4, "add", &[1], &[2]),
            insn_with_regs(0x1004, 4, "add", &[2], &[3]),
        ]
    }

    #[test]
    fn forwarding_class_preset_reduces_raw_stalls() {
        let baseline = forwarding_add_model(None, 4, None);
        let (cost, _) = baseline.block_cost(&dependent_adds());
        assert_eq!(cost.max, 8.0);

        let forwarded = forwarding_add_model(Some(None), 4, None);
        let (cost, _) = forwarded.block_cost(&dependent_adds());
        assert_eq!(cost.max, 5.0);
    }

    #[test]
    fn forwarding_default_and_instruction_override_are_applied() {
        let uniform = forwarding_add_model(Some(Some(2)), 4, None);
        let (cost, _) = uniform.block_cost(&dependent_adds());
        assert_eq!(cost.max, 6.0);

        let overridden = forwarding_add_model(Some(Some(2)), 4, Some(3));
        let (cost, _) = overridden.block_cost(&dependent_adds());
        assert_eq!(cost.max, 7.0);
    }

    #[test]
    fn forwarding_does_not_reduce_completion_latency() {
        let model = forwarding_add_model(Some(None), 5, None);
        let (cost, _) = model.block_cost(&[insn_with_regs(0x1000, 4, "add", &[1], &[2])]);
        assert_eq!(cost.max, 5.0);
    }

    #[test]
    fn forwarding_default_is_clamped_to_instruction_latency() {
        let model = forwarding_add_model(Some(Some(10)), 4, None);
        let (cost, _) = model.block_cost(&dependent_adds());
        assert_eq!(cost.max, 8.0);
    }

    #[test]
    fn forwarding_keeps_the_default_load_use_stall() {
        let toml = r#"
schema_version = 2
id = "board:forwarding-load"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 1

[pipeline.forwarding]
"#;
        let profile = BoardProfile::parse_toml(toml).expect("valid load forwarding profile");
        let model = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model");
        let instructions = [
            insn_with_regs(0x1000, 4, "ld", &[1], &[2]),
            insn_with_regs(0x1004, 4, "add", &[2], &[3]),
        ];
        let (cost, _) = model.block_cost(&instructions);
        assert_eq!(cost.max, 3.0, "load-use waits for the full load latency");

        let uniform = toml.replace(
            "[pipeline.forwarding]",
            "[pipeline.forwarding]\ndefault_latency = 1",
        );
        let profile = BoardProfile::parse_toml(&uniform).expect("valid uniform load forwarding");
        let model = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model");
        let (cost, _) = model.block_cost(&instructions);
        assert_eq!(
            cost.max, 2.0,
            "a uniform bypass latency can override load-use"
        );
    }

    #[test]
    fn forwarding_class_presets_cover_multiply() {
        for (cpu, arch) in [
            ("aarch64-bounded", ArchKind::Aarch64),
            ("riscv64-bounded", ArchKind::Riscv64),
        ] {
            let arch_name = if arch == ArchKind::Aarch64 {
                "aarch64"
            } else {
                "riscv64"
            };
            let profile = BoardProfile::parse_toml(&format!(
                r#"
schema_version = 2
id = "board:forwarding-multiply"
arch = "{arch_name}"
cpu = "{cpu}"

[pipeline]
issue_width = 1

[pipeline.forwarding]
"#
            ))
            .expect("valid multiply forwarding profile");
            let model = TimingCostModel::select(Some(cpu), Some(&profile), &image(arch))
                .expect("select")
                .expect("model");
            let instructions = [
                insn_with_regs(0x1000, 4, "mul", &[1, 2], &[3]),
                insn_with_regs(0x1004, 4, "add", &[3], &[4]),
            ];
            let (cost, _) = model.block_cost(&instructions);
            assert_eq!(cost.max, 3.0, "{cpu} multiply forwards one cycle early");
        }
    }

    #[test]
    fn forwarding_metadata_records_model_and_overrides() {
        let model = forwarding_add_model(Some(None), 4, Some(2));
        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_forwarding")
                .map(String::as_str),
            Some("isa-class-presets")
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_forwarding_overrides")
                .map(String::as_str),
            Some("1")
        );
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("Data forwarding is modeled"))
        );

        let uniform = forwarding_add_model(Some(Some(3)), 4, None);
        let info = uniform.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_forwarding")
                .map(String::as_str),
            Some("uniform-default")
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_forwarding_default_latency")
                .map(String::as_str),
            Some("3")
        );

        let baseline = forwarding_add_model(None, 4, None);
        let info = baseline.timing_info(None, &BTreeSet::new());
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("Data forwarding is not modeled"))
        );
    }

    #[test]
    fn store_forwarding_reduces_matching_load_latency() {
        let model = store_forwarding_model(1, 4);
        let (cost, _) = model.block_cost(&store_pair(0, 0));
        assert_eq!(cost.max, 2.0);

        let (cost, _) = model.block_cost(&store_pair(0, 8));
        assert_eq!(cost.max, 3.0, "different displacement must not forward");

        let width_mismatch = [
            insn_with_memory(
                0x1000,
                4,
                "sd",
                &[1, 2],
                &[],
                vec![memory_access(
                    MemoryAccessKind::Write,
                    4,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
            insn_with_memory(
                0x1004,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&width_mismatch);
        assert_eq!(cost.max, 3.0, "different widths must not forward");

        let indexed_load = [
            store_pair(0, 0)[0].clone(),
            insn_with_memory(
                0x1004,
                4,
                "ld",
                &[1, 2],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    Some(2),
                    0,
                    None,
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&indexed_load);
        assert_eq!(cost.max, 3.0, "indexed loads are not forwarded");

        let absolute_pair = [
            insn_with_memory(
                0x1000,
                4,
                "sd",
                &[1, 2],
                &[],
                vec![memory_access(
                    MemoryAccessKind::Write,
                    8,
                    None,
                    None,
                    0,
                    Some(0x2000),
                )],
            ),
            insn_with_memory(
                0x1004,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    None,
                    None,
                    0,
                    Some(0x2000),
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&absolute_pair);
        assert_eq!(cost.max, 2.0);
    }

    #[test]
    fn store_forwarding_invalidates_after_address_register_write() {
        let model = store_forwarding_model(1, 4);
        let instructions = [
            store_pair(0, 0)[0].clone(),
            insn_with_regs(0x1004, 4, "add", &[1, 2], &[1]),
            insn_with_memory(
                0x1008,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&instructions);
        assert_eq!(cost.max, 4.0);
    }

    #[test]
    fn store_forwarding_blocks_partial_overlap() {
        let model = store_forwarding_model(1, 4);
        let instructions = [
            insn_with_memory(
                0x1000,
                4,
                "sd",
                &[1, 2],
                &[],
                vec![memory_access(
                    MemoryAccessKind::Write,
                    8,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
            insn_with_memory(
                0x1004,
                4,
                "sw",
                &[1, 2],
                &[],
                vec![memory_access(
                    MemoryAccessKind::Write,
                    4,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
            insn_with_memory(
                0x1008,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&instructions);
        assert_eq!(cost.max, 4.0, "a newer partial store blocks forwarding");
    }

    #[test]
    fn store_forwarding_respects_store_buffer_capacity() {
        let sequence = |entries| {
            let model = store_forwarding_model(1, entries);
            let instructions = [
                store_pair(0, 0)[0].clone(),
                insn_with_memory(
                    0x1004,
                    4,
                    "sd",
                    &[1, 2],
                    &[],
                    vec![memory_access(
                        MemoryAccessKind::Write,
                        8,
                        Some(1),
                        None,
                        8,
                        None,
                    )],
                ),
                insn_with_memory(
                    0x1008,
                    4,
                    "ld",
                    &[1],
                    &[3],
                    vec![memory_access(
                        MemoryAccessKind::Read,
                        8,
                        Some(1),
                        None,
                        0,
                        None,
                    )],
                ),
            ];
            model.block_cost(&instructions).0.max
        };
        assert_eq!(sequence(1), 4.0, "the first store was evicted");
        assert_eq!(sequence(2), 3.0, "both stores fit in the buffer");
    }

    #[test]
    fn store_forwarding_clears_on_unknown_store_and_barrier() {
        let model = store_forwarding_model(1, 4);
        let unknown_store = [
            store_pair(0, 0)[0].clone(),
            insn_with_memory(
                0x1004,
                4,
                "sd",
                &[1, 2],
                &[],
                vec![memory_access(
                    MemoryAccessKind::Write,
                    8,
                    Some(1),
                    Some(2),
                    0,
                    None,
                )],
            ),
            insn_with_memory(
                0x1008,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&unknown_store);
        assert_eq!(cost.max, 4.0, "unknown store clears the buffer");

        let barrier = [
            store_pair(0, 0)[0].clone(),
            insn(0x1004, 4, "dmb"),
            insn_with_memory(
                0x1008,
                4,
                "ld",
                &[1],
                &[3],
                vec![memory_access(
                    MemoryAccessKind::Read,
                    8,
                    Some(1),
                    None,
                    0,
                    None,
                )],
            ),
        ];
        let (cost, _) = model.block_cost(&barrier);
        assert_eq!(cost.max, 4.0, "barrier clears the buffer");
    }

    #[test]
    fn store_forwarding_requires_an_older_store() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:store-forwarding-coissue"
arch = "riscv64"
cpu = "riscv64-bounded"

[pipeline]
issue_width = 2

[pipeline.resources]
load_store = 2

[pipeline.store_forwarding]
latency = 1
entries = 4
"#,
        )
        .expect("valid co-issue store-forwarding profile");
        let model = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model");
        let (cost, _) = model.block_cost(&store_pair(0, 0));
        assert_eq!(cost.max, 2.0, "a same-cycle store cannot be forwarded");
    }

    #[test]
    fn store_forwarding_metadata_records_parameters() {
        let model = store_forwarding_model(1, 4);
        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_store_forwarding")
                .map(String::as_str),
            Some("enabled")
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_store_forwarding_latency")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            info.models[0]
                .params
                .extras
                .get("board_profile_pipeline_store_forwarding_entries")
                .map(String::as_str),
            Some("4")
        );
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("Store-to-load forwarding is modeled"))
        );

        let baseline = multi_issue_model(2, Some(2));
        let info = baseline.timing_info(None, &BTreeSet::new());
        assert!(
            info.models[0]
                .caveats
                .iter()
                .any(|caveat| caveat.contains("Store-to-load forwarding is not modeled"))
        );
    }

    #[test]
    fn statistical_profile_overrides_bounded_determinism() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:bounded-branch"
arch = "riscv64"
cpu = "riscv64-bounded"

[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
"#,
        )
        .expect("valid branch profile");
        let model = TimingCostModel::select(
            Some("riscv64-bounded"),
            Some(&profile),
            &image(ArchKind::Riscv64),
        )
        .expect("select")
        .expect("model");
        let info = model.timing_info(None, &BTreeSet::new());
        assert_eq!(
            info.models[0].determinism,
            elf2tdg_schema::Determinism::Statistical
        );
    }

    #[test]
    fn explicit_cpu_must_agree_with_profile() {
        let profile = board_profile();
        assert!(
            TimingCostModel::select(Some("cortex-m4"), Some(&profile), &image(ArchKind::Thumb))
                .is_err()
        );
        assert!(TimingCostModel::select(None, Some(&profile), &image(ArchKind::Aarch64)).is_err());
    }
}
