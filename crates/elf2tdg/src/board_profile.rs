//! Board-specific timing profiles.
//!
//! A profile is a declarative, versioned description of a concrete board:
//! clock domains, executable memory regions and their fetch costs, and
//! instruction-cost overrides on top of a built-in core timing table. Loading a
//! profile never changes the default analysis; the caller opts in explicitly.
//!
//! Profiles are written as TOML (the default) or JSON. Every profile records
//! the SHA-256 of the loaded file so the CFG can name the exact timing input that
//! produced its cycle estimates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use elf2tdg_schema::{Confidence, CostRange, FrequencyDomain, FrequencyDomainId, FrequencySource};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::timing::{InstructionClass, TimingModel};

/// Current board-profile schema version.
pub const BOARD_PROFILE_SCHEMA_VERSION: u32 = 2;

/// Oldest board-profile schema version still accepted.
pub const MIN_BOARD_PROFILE_SCHEMA_VERSION: u32 = 1;

const DEFAULT_FETCH_WIDTH_BYTES: u32 = 4;

const fn default_profile_schema_version() -> u32 {
    BOARD_PROFILE_SCHEMA_VERSION
}

fn default_profile_id() -> String {
    "board:default".to_owned()
}

const fn default_fetch_width() -> u32 {
    DEFAULT_FETCH_WIDTH_BYTES
}

const fn default_issue_width() -> u32 {
    1
}

const fn default_occupancy() -> u32 {
    1
}

const fn default_true() -> bool {
    true
}

const fn default_max_cache_states() -> usize {
    128
}

const fn default_max_branch_states() -> usize {
    128
}

const fn default_wcet_max_states() -> usize {
    100_000
}

const fn default_link_count() -> u32 {
    1
}

fn default_multicore_model() -> String {
    "access-budget".to_owned()
}

const DEFAULT_PROFILE_TEMPLATE: &str = r#"# elf2tdg board profile template for __CPU__ (__ARCH__).
#
# Only `cpu` is required. Omitted optional models are disabled by default.
# Board-specific clock, memory, cache and pipeline values are never guessed:
# uncomment a section and replace the example values with verified board data.
# See docs/board-profile.md for field semantics and safety notes.
schema_version = 2
id = "board:__ID__"
name = "Default profile for __CPU__"
arch = "__ARCH__"
cpu = "__CPU__"
# confidence = "medium"
# unknown_instructions = "warn"
# caveats = ["Replace example values with verified board data."]

# Clock domains. Required for wall-clock nanoseconds and frequency metadata.
# [clocks.core]
# hz = 100_000_000
# confidence = "high"

# Memory regions. Required to charge fetch and data wait states.
# [[memory]]
# name = "flash"
# start = 0x0800_0000
# size = 0x0010_0000
# kind = "flash"                     # flash, ram, peripheral or other
# executable = true
# fetch_wait_states = 0
# fetch_width_bytes = 4
# data_width_bytes = 4
# data_read_wait_states = 0
# data_write_wait_states = 0

# Per-instruction timing overrides on top of the built-in CPU table.
# [[instruction_costs]]
# class = "load"                     # class and/or mnemonic
# mnemonic = "ldr"
# cycles = { min = 2, max = 3 }      # or a single number
# note = "measured on target"

# Cortex-M4 in-order resource/dependency pipeline; currently Cortex-M4 only.
# [pipeline]
# issue_width = 1
# branch_penalty = { min = 1, max = 3 }
# [[pipeline.instructions]]
# mnemonic = "ldr"
# resources = ["load_store"]
# latency = 2
# occupancy = 2

# Instruction cache.
# [instruction_cache]
# size = 32768
# line_bytes = 32
# ways = 4
# replacement = "lru"
# miss_penalty = 10
# invalidate_on_call = true
# max_states = 128

# Data cache.
# [data_cache]
# size = 32768
# line_bytes = 32
# ways = 4
# replacement = "lru"
# miss_penalty = 10
# write_allocate = true
# invalidate_on_call = true
# max_states = 128

# Branch prediction.
# [branch_prediction]
# model = "bimodal"                  # static-not-taken, static-taken, btfn, bimodal
# mispredict_penalty = 3
# initial_state = "weakly-not-taken"
# max_states = 128

# Multicore contention budget.
# [multicore]
# model = "access-budget"
# cores = 2
# core_id = 0
# data_read_interference_cycles = 0
# data_write_interference_cycles = 0
# instruction_fetch_interference_cycles = 0
# confidence = "medium"
# caveats = []

# WCET analysis configuration.
# [wcet]
# default_loop_bound = 4
# max_states = 100_000
# bound_nonterminating_loops = false
# [[wcet.loop_bounds]]
# header = 0x0800_0100
# bound = 4

# Scheduler/system model sections ([system]) are documented in
# docs/board-profile.md and docs/layered-model.md.
"#;

/// Multicore interference budget for one core.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MulticoreProfile {
    #[serde(default = "default_multicore_model")]
    model: String,
    cores: u32,
    #[serde(default)]
    core_id: u32,
    #[serde(default)]
    data_read_interference_cycles: u32,
    #[serde(default)]
    data_write_interference_cycles: u32,
    #[serde(default)]
    instruction_fetch_interference_cycles: u32,
    #[serde(default)]
    confidence: Option<Confidence>,
    #[serde(default)]
    caveats: Vec<String>,
}

impl MulticoreProfile {
    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    pub(crate) fn cores(&self) -> u32 {
        self.cores
    }

    pub(crate) fn core_id(&self) -> u32 {
        self.core_id
    }

    pub(crate) fn data_read_interference_cycles(&self) -> u32 {
        self.data_read_interference_cycles
    }

    pub(crate) fn data_write_interference_cycles(&self) -> u32 {
        self.data_write_interference_cycles
    }

    pub(crate) fn instruction_fetch_interference_cycles(&self) -> u32 {
        self.instruction_fetch_interference_cycles
    }

    pub(crate) fn confidence(&self) -> Option<Confidence> {
        self.confidence
    }

    pub(crate) fn caveats(&self) -> &[String] {
        &self.caveats
    }
}

/// Task activation bounds and cumulative resource budgets for the layered
/// system model.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemProfile {
    #[serde(default)]
    tasks: Vec<SystemTaskProfile>,
    #[serde(default)]
    resources: Vec<SystemResourceProfile>,
    #[serde(default)]
    locks: Vec<SystemLockProfile>,
    #[serde(default)]
    links: Vec<SystemLinkProfile>,
    #[serde(default)]
    blocking_model: Option<SystemBlockingModel>,
    #[serde(default)]
    horizon_ns: Option<u64>,
    #[serde(default)]
    slot_ns: Option<u64>,
}

impl SystemProfile {
    pub(crate) fn tasks(&self) -> &[SystemTaskProfile] {
        &self.tasks
    }

    pub(crate) fn resources(&self) -> &[SystemResourceProfile] {
        &self.resources
    }

    pub(crate) fn locks(&self) -> &[SystemLockProfile] {
        &self.locks
    }

    pub(crate) fn blocking_model(&self) -> Option<SystemBlockingModel> {
        self.blocking_model
    }

    pub(crate) fn links(&self) -> &[SystemLinkProfile] {
        &self.links
    }

    pub(crate) fn horizon_ns(&self) -> Option<u64> {
        self.horizon_ns
    }

    pub(crate) fn slot_ns(&self) -> Option<u64> {
        self.slot_ns
    }
}

/// One execution root in a `[system]` profile.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemTaskProfile {
    target: String,
    #[serde(default)]
    priority: Option<u32>,
    #[serde(default)]
    activations: Option<u32>,
    #[serde(default)]
    period_ns: Option<u64>,
    #[serde(default)]
    release_offset_ns: Option<u64>,
    #[serde(default)]
    release_jitter_ns: Option<u64>,
    #[serde(default)]
    deadline_ns: Option<u64>,
    #[serde(default)]
    resources: BTreeMap<String, u32>,
    #[serde(default)]
    locks: BTreeMap<String, u64>,
}

impl SystemTaskProfile {
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    pub(crate) fn priority(&self) -> Option<u32> {
        self.priority
    }

    pub(crate) fn activations(&self) -> Option<u32> {
        self.activations
    }

    pub(crate) fn period_ns(&self) -> Option<u64> {
        self.period_ns
    }

    pub(crate) fn release_offset_ns(&self) -> Option<u64> {
        self.release_offset_ns
    }

    pub(crate) fn release_jitter_ns(&self) -> Option<u64> {
        self.release_jitter_ns
    }

    pub(crate) fn deadline_ns(&self) -> Option<u64> {
        self.deadline_ns
    }

    pub(crate) fn resources(&self) -> &BTreeMap<String, u32> {
        &self.resources
    }

    pub(crate) fn locks(&self) -> &BTreeMap<String, u64> {
        &self.locks
    }
}

/// Fork/join relation kind in a `[system]` profile.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SystemLinkKind {
    Fork,
    Join,
}

impl SystemLinkKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Fork => "fork",
            Self::Join => "join",
        }
    }
}

/// One explicit fork/join link between two system tasks.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemLinkProfile {
    from: String,
    to: String,
    kind: SystemLinkKind,
    #[serde(default = "default_link_count")]
    count: u32,
}

impl SystemLinkProfile {
    pub(crate) fn from(&self) -> &str {
        &self.from
    }

    pub(crate) fn to(&self) -> &str {
        &self.to
    }

    pub(crate) fn kind(&self) -> SystemLinkKind {
        self.kind
    }

    pub(crate) fn count(&self) -> u32 {
        self.count
    }
}

/// One cumulative resource budget for the layered system model.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemResourceProfile {
    name: String,
    capacity: u32,
}

impl SystemResourceProfile {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn capacity(&self) -> u32 {
        self.capacity
    }
}

/// A mutex-like lock whose critical sections participate in blocking analysis.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemLockProfile {
    name: String,
}

impl SystemLockProfile {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// Supported blocking and priority-inversion protocols.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SystemBlockingModel {
    /// Immediate priority ceiling: at most one lower-priority critical section
    /// can block a task.
    PriorityCeiling,
}

impl SystemBlockingModel {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::PriorityCeiling => "priority-ceiling",
        }
    }
}

/// A versioned description of one board's timing-relevant configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardProfile {
    #[serde(default = "default_profile_schema_version")]
    schema_version: u32,
    #[serde(default = "default_profile_id")]
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arch: String,
    cpu: String,
    #[serde(default)]
    clocks: std::collections::BTreeMap<String, BoardClock>,
    #[serde(default)]
    memory: Vec<MemoryRegion>,
    #[serde(default)]
    instruction_costs: Vec<InstructionCostOverride>,
    #[serde(default)]
    pipeline: Option<PipelineProfile>,
    #[serde(default)]
    instruction_cache: Option<InstructionCacheProfile>,
    #[serde(default)]
    data_cache: Option<DataCacheProfile>,
    #[serde(default)]
    branch_prediction: Option<BranchPredictionProfile>,
    #[serde(default)]
    multicore: Option<MulticoreProfile>,
    #[serde(default)]
    wcet: Option<WcetProfile>,
    #[serde(default)]
    system: Option<SystemProfile>,
    #[serde(default)]
    caveats: Vec<String>,
    #[serde(default)]
    unknown_instructions: UnknownInstructionPolicy,
    #[serde(default)]
    confidence: Option<Confidence>,
    #[serde(skip)]
    source: Option<PathBuf>,
    #[serde(skip)]
    sha256: Option<String>,
}

/// Behavior when an instruction has no recognized timing class.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownInstructionPolicy {
    /// Emit a CFG diagnostic and use the fallback cost class.
    #[default]
    Warn,
    /// Use the fallback cost class without a warning.
    Ignore,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoardClock {
    hz: u64,
    #[serde(default)]
    confidence: Option<Confidence>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum MemoryKind {
    Flash,
    Ram,
    Peripheral,
    #[default]
    Other,
}

impl MemoryKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Flash => "flash",
            Self::Ram => "ram",
            Self::Peripheral => "peripheral",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemoryRegion {
    name: String,
    start: u64,
    size: u64,
    #[serde(default)]
    kind: MemoryKind,
    #[serde(default)]
    executable: bool,
    #[serde(default)]
    fetch_wait_states: u32,
    #[serde(default = "default_fetch_width")]
    fetch_width_bytes: u32,
    #[serde(default)]
    data_width_bytes: Option<u32>,
    #[serde(default)]
    data_read_wait_states: Option<u32>,
    #[serde(default)]
    data_write_wait_states: Option<u32>,
}

impl MemoryRegion {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn kind_name(&self) -> &'static str {
        self.kind.name()
    }

    pub(crate) fn end(&self) -> Option<u64> {
        self.start.checked_add(self.size)
    }

    pub(crate) fn contains(&self, address: u64) -> bool {
        address
            .checked_sub(self.start)
            .is_some_and(|offset| offset < self.size)
    }

    pub(crate) fn has_data_timing(&self) -> bool {
        self.data_width_bytes.is_some()
            || self.data_read_wait_states.is_some()
            || self.data_write_wait_states.is_some()
    }

    pub(crate) fn data_width_bytes(&self) -> u32 {
        self.data_width_bytes
            .unwrap_or(DEFAULT_FETCH_WIDTH_BYTES)
            .max(1)
    }

    pub(crate) fn data_read_wait_states(&self) -> u32 {
        self.data_read_wait_states.unwrap_or(0)
    }

    pub(crate) fn data_write_wait_states(&self) -> u32 {
        self.data_write_wait_states.unwrap_or(0)
    }

    fn fetch_cycles(&self, size: u8) -> u32 {
        if !self.executable || self.fetch_wait_states == 0 || size == 0 {
            return 0;
        }
        let width = u64::from(self.fetch_width_bytes.max(1));
        let transactions = u64::from(size).div_ceil(width);
        let cycles = transactions.saturating_mul(u64::from(self.fetch_wait_states));
        u32::try_from(cycles).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstructionCostOverride {
    #[serde(default)]
    class: Option<InstructionClass>,
    #[serde(default)]
    mnemonic: Option<String>,
    cycles: CostSpec,
    #[serde(default)]
    note: Option<String>,
}

impl InstructionCostOverride {
    fn matches(&self, class: InstructionClass, mnemonic: &str) -> bool {
        let class_matches = self.class.is_none_or(|candidate| candidate == class);
        let mnemonic_matches = self.mnemonic.as_deref().is_none_or(|candidate| {
            crate::timing::canonical_mnemonic(candidate).eq_ignore_ascii_case(mnemonic)
        });
        class_matches && mnemonic_matches
    }

    fn specificity(&self) -> u8 {
        // A mnemonic is more specific than a class, and a selector that names
        // both is more specific than either alone.
        2 * u8::from(self.mnemonic.is_some()) + u8::from(self.class.is_some())
    }

    fn cost_range(&self) -> CostRange {
        self.cycles.cost_range()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CacheReplacement {
    #[default]
    Lru,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstructionCacheProfile {
    size: u64,
    line_bytes: u32,
    ways: u32,
    #[serde(default)]
    replacement: CacheReplacement,
    miss_penalty: u32,
    #[serde(default = "default_true")]
    invalidate_on_call: bool,
    #[serde(default = "default_max_cache_states")]
    max_states: usize,
}

impl InstructionCacheProfile {
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn line_bytes(&self) -> u32 {
        self.line_bytes
    }

    pub(crate) fn ways(&self) -> u32 {
        self.ways
    }

    pub(crate) fn replacement_name(&self) -> &'static str {
        match self.replacement {
            CacheReplacement::Lru => "lru",
        }
    }

    pub(crate) fn miss_penalty(&self) -> u32 {
        self.miss_penalty
    }

    pub(crate) fn invalidate_on_call(&self) -> bool {
        self.invalidate_on_call
    }

    pub(crate) fn max_states(&self) -> usize {
        self.max_states
    }

    pub(crate) fn sets(&self) -> u64 {
        self.size / (u64::from(self.line_bytes) * u64::from(self.ways))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DataCacheProfile {
    size: u64,
    line_bytes: u32,
    ways: u32,
    #[serde(default)]
    replacement: CacheReplacement,
    miss_penalty: u32,
    #[serde(default = "default_true")]
    write_allocate: bool,
    #[serde(default = "default_true")]
    invalidate_on_call: bool,
    #[serde(default = "default_max_cache_states")]
    max_states: usize,
}

impl DataCacheProfile {
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn line_bytes(&self) -> u32 {
        self.line_bytes
    }

    pub(crate) fn ways(&self) -> u32 {
        self.ways
    }

    pub(crate) fn replacement_name(&self) -> &'static str {
        match self.replacement {
            CacheReplacement::Lru => "lru",
        }
    }

    pub(crate) fn miss_penalty(&self) -> u32 {
        self.miss_penalty
    }

    pub(crate) fn write_allocate(&self) -> bool {
        self.write_allocate
    }

    pub(crate) fn invalidate_on_call(&self) -> bool {
        self.invalidate_on_call
    }

    pub(crate) fn max_states(&self) -> usize {
        self.max_states
    }

    pub(crate) fn sets(&self) -> u64 {
        self.size / (u64::from(self.line_bytes) * u64::from(self.ways))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BranchPredictionModel {
    /// Predict every conditional branch as not taken.
    #[default]
    StaticNotTaken,
    /// Predict every conditional branch as taken.
    StaticTaken,
    /// Predict backward branches taken and forward branches not taken.
    #[serde(alias = "backward-taken-forward-not-taken")]
    Btfn,
    /// Two-bit local saturating counter per branch site.
    #[serde(alias = "two-bit")]
    Bimodal,
}

impl BranchPredictionModel {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::StaticNotTaken => "static-not-taken",
            Self::StaticTaken => "static-taken",
            Self::Btfn => "btfn",
            Self::Bimodal => "bimodal",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)]
pub(crate) enum BranchPredictionState {
    /// Two-bit counter value 0.
    StronglyNotTaken,
    /// Two-bit counter value 1.
    #[default]
    WeaklyNotTaken,
    /// Two-bit counter value 2.
    WeaklyTaken,
    /// Two-bit counter value 3.
    StronglyTaken,
}

impl BranchPredictionState {
    pub(crate) const fn counter(self) -> u8 {
        match self {
            Self::StronglyNotTaken => 0,
            Self::WeaklyNotTaken => 1,
            Self::WeaklyTaken => 2,
            Self::StronglyTaken => 3,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::StronglyNotTaken => "strongly-not-taken",
            Self::WeaklyNotTaken => "weakly-not-taken",
            Self::WeaklyTaken => "weakly-taken",
            Self::StronglyTaken => "strongly-taken",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BranchPredictionProfile {
    model: BranchPredictionModel,
    mispredict_penalty: u32,
    #[serde(default)]
    initial_state: BranchPredictionState,
    #[serde(default = "default_max_branch_states")]
    max_states: usize,
}

impl BranchPredictionProfile {
    pub(crate) fn model(&self) -> BranchPredictionModel {
        self.model
    }

    pub(crate) fn model_name(&self) -> &'static str {
        self.model.name()
    }

    pub(crate) fn mispredict_penalty(&self) -> u32 {
        self.mispredict_penalty
    }

    pub(crate) fn initial_state_name(&self) -> &'static str {
        self.initial_state.name()
    }

    pub(crate) fn initial_counter(&self) -> u8 {
        self.initial_state.counter()
    }

    pub(crate) fn max_states(&self) -> usize {
        self.max_states
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WcetProfile {
    #[serde(default)]
    default_loop_bound: Option<u32>,
    #[serde(default = "default_wcet_max_states")]
    max_states: usize,
    #[serde(default)]
    bound_nonterminating_loops: bool,
    #[serde(default)]
    loop_bounds: Vec<WcetLoopBound>,
}

impl WcetProfile {
    pub(crate) fn default_loop_bound(&self) -> Option<u32> {
        self.default_loop_bound
    }

    pub(crate) fn max_states(&self) -> usize {
        self.max_states
    }

    pub(crate) fn loop_bounds(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.loop_bounds
            .iter()
            .map(|entry| (entry.header, entry.bound))
    }

    pub(crate) fn loop_bound_count(&self) -> usize {
        self.loop_bounds.len()
    }

    pub(crate) fn bound_nonterminating_loops(&self) -> bool {
        self.bound_nonterminating_loops
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WcetLoopBound {
    header: u64,
    bound: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PipelineProfile {
    #[serde(default = "default_issue_width")]
    issue_width: u32,
    #[serde(default)]
    branch_penalty: Option<CostSpec>,
    #[serde(default)]
    instructions: Vec<PipelineInstruction>,
}

impl PipelineProfile {
    pub(crate) fn issue_width(&self) -> u32 {
        self.issue_width
    }

    pub(crate) fn branch_penalty(&self) -> CostRange {
        self.branch_penalty
            .as_ref()
            .map_or_else(|| CostRange::new(1.0, 3.0), CostSpec::cost_range)
    }

    pub(crate) fn instruction_for(
        &self,
        class: InstructionClass,
        mnemonic: &str,
    ) -> Option<&PipelineInstruction> {
        let mut best: Option<(&PipelineInstruction, u8)> = None;
        for instruction in &self.instructions {
            if !instruction.matches(class, mnemonic) {
                continue;
            }
            let specificity = instruction.specificity();
            if best.is_none_or(|(_, current)| specificity > current) {
                best = Some((instruction, specificity));
            }
        }
        best.map(|(instruction, _)| instruction)
    }

    pub(crate) fn instruction_override_count(&self) -> usize {
        self.instructions.len()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PipelineInstruction {
    #[serde(default)]
    class: Option<InstructionClass>,
    #[serde(default)]
    mnemonic: Option<String>,
    resources: Vec<String>,
    latency: u32,
    #[serde(default = "default_occupancy")]
    occupancy: u32,
}

impl PipelineInstruction {
    fn matches(&self, class: InstructionClass, mnemonic: &str) -> bool {
        let class_matches = self.class.is_none_or(|candidate| candidate == class);
        let mnemonic_matches = self.mnemonic.as_deref().is_none_or(|candidate| {
            crate::timing::canonical_mnemonic(candidate).eq_ignore_ascii_case(mnemonic)
        });
        class_matches && mnemonic_matches
    }

    fn specificity(&self) -> u8 {
        2 * u8::from(self.mnemonic.is_some()) + u8::from(self.class.is_some())
    }

    pub(crate) fn latency(&self) -> u32 {
        self.latency
    }

    pub(crate) fn occupancy(&self) -> u32 {
        self.occupancy
    }

    pub(crate) fn resources(&self) -> &[String] {
        &self.resources
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum CostSpec {
    Exact(f64),
    Range(CostRangeSpec),
}

impl CostSpec {
    fn cost_range(&self) -> CostRange {
        match self {
            Self::Exact(value) => CostRange::exact(*value),
            Self::Range(range) => CostRange::new(range.min, range.max),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CostRangeSpec {
    min: f64,
    max: f64,
}

/// The effective instruction-cost override selected for one instruction.
pub(crate) struct MatchedCost {
    pub cycles: CostRange,
}

impl BoardProfile {
    /// Loads and validates a TOML or JSON profile from `path`.
    ///
    /// Files ending in `.json` are parsed as JSON; every other extension is
    /// parsed as TOML.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadFile`] for I/O failures and [`Error::Config`] for
    /// invalid syntax, unknown fields or inconsistent profile data.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| Error::Config(format!("board profile is not UTF-8: {error}")))?;
        let is_json = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
        let mut profile = if is_json {
            Self::parse_json(text)?
        } else {
            Self::parse_toml(text)?
        };
        profile.source = Some(path.to_path_buf());
        profile.sha256 = Some(sha256_hex(&bytes));
        Ok(profile)
    }

    /// Returns a complete, safe-default TOML profile template for `cpu`.
    ///
    /// Only `cpu` is active. Board-specific models are included as commented
    /// examples because guessing them would make a WCET bound unsound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when `cpu` is not a known timing model.
    pub fn default_profile_template(cpu: &str) -> Result<String> {
        let model = TimingModel::from_name(cpu).ok_or_else(|| {
            Error::Config(format!(
                "board profile CPU {cpu:?} is not a known timing model"
            ))
        })?;
        Ok(DEFAULT_PROFILE_TEMPLATE
            .replace("__CPU__", model.id())
            .replace("__ARCH__", model.arch())
            .replace("__ID__", model.id()))
    }

    /// Parses and validates a TOML profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for invalid syntax or inconsistent data.
    pub fn parse_toml(text: &str) -> Result<Self> {
        let mut profile: Self = toml::from_str(text)
            .map_err(|error| Error::Config(format!("invalid board profile TOML: {error}")))?;
        profile.resolve_defaults()?;
        profile.sha256 = Some(sha256_hex(text.as_bytes()));
        profile.validate()?;
        Ok(profile)
    }

    /// Parses and validates a JSON profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for invalid syntax or inconsistent data.
    pub fn parse_json(text: &str) -> Result<Self> {
        let mut profile: Self = serde_json::from_str(text)
            .map_err(|error| Error::Config(format!("invalid board profile JSON: {error}")))?;
        profile.resolve_defaults()?;
        profile.sha256 = Some(sha256_hex(text.as_bytes()));
        profile.validate()?;
        Ok(profile)
    }

    fn resolve_defaults(&mut self) -> Result<()> {
        if self.arch.trim().is_empty() {
            let Some(model) = TimingModel::from_name(&self.cpu) else {
                return Err(Error::Config(format!(
                    "board profile CPU {:?} is not a known timing model",
                    self.cpu
                )));
            };
            model.arch().clone_into(&mut self.arch);
        }
        Ok(())
    }

    /// Validates profile structure and cross-field invariants.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] describing the first invalid field or
    /// relationship.
    pub fn validate(&self) -> Result<()> {
        self.validate_identity()?;
        self.validate_clocks()?;
        self.validate_memory()?;
        self.validate_instruction_costs()?;
        self.validate_pipeline()?;
        self.validate_instruction_cache()?;
        self.validate_data_cache()?;
        self.validate_branch_prediction()?;
        self.validate_multicore()?;
        self.validate_wcet()?;
        self.validate_system()?;
        for caveat in &self.caveats {
            validate_text("caveats", caveat)?;
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<()> {
        if !(MIN_BOARD_PROFILE_SCHEMA_VERSION..=BOARD_PROFILE_SCHEMA_VERSION)
            .contains(&self.schema_version)
        {
            return Err(Error::Config(format!(
                "unsupported board profile schema_version {}; expected {}..={}",
                self.schema_version, MIN_BOARD_PROFILE_SCHEMA_VERSION, BOARD_PROFILE_SCHEMA_VERSION
            )));
        }
        validate_text("id", &self.id)?;
        if let Some(name) = &self.name {
            validate_text("name", name)?;
        }
        validate_text("arch", &self.arch)?;
        validate_text("cpu", &self.cpu)?;
        let Some(model) = TimingModel::from_name(&self.cpu) else {
            return Err(Error::Config(format!(
                "board profile CPU {:?} is not a known timing model",
                self.cpu
            )));
        };
        if !arch_matches(&self.arch, model.arch()) {
            return Err(Error::Config(format!(
                "board profile arch {:?} does not match CPU model {} ({})",
                self.arch,
                model.id(),
                model.arch()
            )));
        }
        Ok(())
    }

    fn validate_clocks(&self) -> Result<()> {
        for (name, clock) in &self.clocks {
            if !valid_domain_name(name) {
                return Err(Error::Config(format!(
                    "board profile clock name {name:?} must contain only ASCII letters, digits, '_' or '-'"
                )));
            }
            if clock.hz == 0 {
                return Err(Error::Config(format!(
                    "board profile clock {name:?} must have a positive frequency"
                )));
            }
        }
        Ok(())
    }

    fn validate_memory(&self) -> Result<()> {
        let mut region_names = BTreeSet::new();
        for region in &self.memory {
            validate_text("memory.name", &region.name)?;
            if !region_names.insert(region.name.as_str()) {
                return Err(Error::Config(format!(
                    "board profile memory region {:?} is declared twice",
                    region.name
                )));
            }
            if region.size == 0 {
                return Err(Error::Config(format!(
                    "board profile memory region {:?} must have a non-zero size",
                    region.name
                )));
            }
            if region.end().is_none() {
                return Err(Error::Config(format!(
                    "board profile memory region {:?} overflows the address space",
                    region.name
                )));
            }
            if region.fetch_width_bytes == 0 {
                return Err(Error::Config(format!(
                    "board profile memory region {:?} fetch_width_bytes must be positive",
                    region.name
                )));
            }
            if region.data_width_bytes == Some(0) {
                return Err(Error::Config(format!(
                    "board profile memory region {:?} data_width_bytes must be positive",
                    region.name
                )));
            }
            if region.has_data_timing() && self.schema_version < 2 {
                return Err(Error::Config(
                    "board profile data-memory timing requires schema_version 2".to_owned(),
                ));
            }
        }
        let mut sorted: Vec<&MemoryRegion> = self.memory.iter().collect();
        sorted.sort_by_key(|region| region.start);
        for pair in sorted.windows(2) {
            let [left, right] = pair else {
                continue;
            };
            if left.end().is_some_and(|end| end > right.start) {
                return Err(Error::Config(format!(
                    "board profile memory regions {:?} and {:?} overlap",
                    left.name, right.name
                )));
            }
        }
        Ok(())
    }

    fn validate_pipeline(&self) -> Result<()> {
        let Some(pipeline) = &self.pipeline else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile pipeline requires schema_version 2".to_owned(),
            ));
        }
        let Some(model) = TimingModel::from_name(&self.cpu) else {
            return Err(Error::Config(format!(
                "board profile CPU {:?} is not a known timing model",
                self.cpu
            )));
        };
        if model.id() != "cortex-m4" {
            return Err(Error::Config(format!(
                "board profile pipeline model currently supports only cortex-m4, not {}",
                model.id()
            )));
        }
        if pipeline.issue_width != 1 {
            return Err(Error::Config(
                "board profile pipeline.issue_width other than 1 is not supported yet".to_owned(),
            ));
        }
        if let Some(branch_penalty) = &pipeline.branch_penalty
            && !branch_penalty.cost_range().is_valid()
        {
            return Err(Error::Config(
                "board profile pipeline.branch_penalty has an invalid cycle range".to_owned(),
            ));
        }
        let mut selectors = BTreeSet::new();
        for (index, instruction) in pipeline.instructions.iter().enumerate() {
            if instruction.class.is_none() && instruction.mnemonic.is_none() {
                return Err(Error::Config(format!(
                    "board profile pipeline.instructions[{index}] needs class or mnemonic"
                )));
            }
            let mnemonic = instruction.mnemonic.as_deref().map(|value| {
                let canonical = crate::timing::canonical_mnemonic(value);
                if canonical.is_empty()
                    || canonical
                        .chars()
                        .any(|character| character.is_whitespace() || character.is_control())
                {
                    return Err(Error::Config(format!(
                        "board profile pipeline.instructions[{index}] has invalid mnemonic {value:?}"
                    )));
                }
                Ok(canonical.to_ascii_lowercase())
            });
            let mnemonic = mnemonic.transpose()?;
            if instruction.resources.is_empty() {
                return Err(Error::Config(format!(
                    "board profile pipeline.instructions[{index}] needs at least one resource"
                )));
            }
            let mut resources = BTreeSet::new();
            for resource in &instruction.resources {
                if resource.is_empty()
                    || resource.len() > 64
                    || resource
                        .chars()
                        .any(|character| character.is_whitespace() || character.is_control())
                {
                    return Err(Error::Config(format!(
                        "board profile pipeline.instructions[{index}] has invalid resource {resource:?}"
                    )));
                }
                if !resources.insert(resource.as_str()) {
                    return Err(Error::Config(format!(
                        "board profile pipeline.instructions[{index}] repeats resource {resource:?}"
                    )));
                }
            }
            if instruction.latency == 0 || instruction.occupancy == 0 {
                return Err(Error::Config(format!(
                    "board profile pipeline.instructions[{index}] latency and occupancy must be positive"
                )));
            }
            if !selectors.insert((instruction.class, mnemonic)) {
                return Err(Error::Config(format!(
                    "board profile pipeline.instructions[{index}] duplicates an earlier selector"
                )));
            }
        }
        Ok(())
    }

    fn validate_instruction_cache(&self) -> Result<()> {
        let Some(cache) = &self.instruction_cache else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile instruction_cache requires schema_version 2".to_owned(),
            ));
        }
        if cache.size == 0 {
            return Err(Error::Config(
                "board profile instruction_cache.size must be positive".to_owned(),
            ));
        }
        if cache.line_bytes == 0 || !cache.line_bytes.is_power_of_two() {
            return Err(Error::Config(
                "board profile instruction_cache.line_bytes must be a positive power of two"
                    .to_owned(),
            ));
        }
        if cache.ways == 0 {
            return Err(Error::Config(
                "board profile instruction_cache.ways must be positive".to_owned(),
            ));
        }
        let line_total = u64::from(cache.line_bytes) * u64::from(cache.ways);
        if cache.size % line_total != 0 {
            return Err(Error::Config(
                "board profile instruction_cache.size must be divisible by line_bytes * ways"
                    .to_owned(),
            ));
        }
        if cache.miss_penalty == 0 {
            return Err(Error::Config(
                "board profile instruction_cache.miss_penalty must be positive".to_owned(),
            ));
        }
        if cache.max_states == 0 {
            return Err(Error::Config(
                "board profile instruction_cache.max_states must be positive".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_data_cache(&self) -> Result<()> {
        let Some(cache) = &self.data_cache else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile data_cache requires schema_version 2".to_owned(),
            ));
        }
        if cache.size == 0 {
            return Err(Error::Config(
                "board profile data_cache.size must be positive".to_owned(),
            ));
        }
        if cache.line_bytes == 0 || !cache.line_bytes.is_power_of_two() {
            return Err(Error::Config(
                "board profile data_cache.line_bytes must be a positive power of two".to_owned(),
            ));
        }
        if cache.ways == 0 {
            return Err(Error::Config(
                "board profile data_cache.ways must be positive".to_owned(),
            ));
        }
        let line_total = u64::from(cache.line_bytes) * u64::from(cache.ways);
        if cache.size % line_total != 0 {
            return Err(Error::Config(
                "board profile data_cache.size must be divisible by line_bytes * ways".to_owned(),
            ));
        }
        if cache.miss_penalty == 0 {
            return Err(Error::Config(
                "board profile data_cache.miss_penalty must be positive".to_owned(),
            ));
        }
        if cache.max_states == 0 {
            return Err(Error::Config(
                "board profile data_cache.max_states must be positive".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_branch_prediction(&self) -> Result<()> {
        let Some(prediction) = &self.branch_prediction else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile branch_prediction requires schema_version 2".to_owned(),
            ));
        }
        if prediction.mispredict_penalty == 0 {
            return Err(Error::Config(
                "board profile branch_prediction.mispredict_penalty must be positive".to_owned(),
            ));
        }
        if prediction.max_states == 0 {
            return Err(Error::Config(
                "board profile branch_prediction.max_states must be positive".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_multicore(&self) -> Result<()> {
        let Some(multicore) = &self.multicore else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile multicore requires schema_version 2".to_owned(),
            ));
        }
        if multicore.model != "access-budget" {
            return Err(Error::Config(format!(
                "board profile multicore.model must be \"access-budget\", not {:?}",
                multicore.model
            )));
        }
        if multicore.cores < 2 {
            return Err(Error::Config(
                "board profile multicore.cores must be at least 2".to_owned(),
            ));
        }
        if multicore.core_id >= multicore.cores {
            return Err(Error::Config(format!(
                "board profile multicore.core_id {} is outside 0..{}",
                multicore.core_id, multicore.cores
            )));
        }
        for caveat in &multicore.caveats {
            validate_text("multicore.caveats", caveat)?;
        }
        Ok(())
    }

    fn validate_wcet(&self) -> Result<()> {
        let Some(wcet) = &self.wcet else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile wcet requires schema_version 2".to_owned(),
            ));
        }
        if wcet.default_loop_bound == Some(0) {
            return Err(Error::Config(
                "board profile wcet.default_loop_bound must be positive".to_owned(),
            ));
        }
        if wcet.max_states == 0 {
            return Err(Error::Config(
                "board profile wcet.max_states must be positive".to_owned(),
            ));
        }
        let mut headers = BTreeSet::new();
        for (index, entry) in wcet.loop_bounds.iter().enumerate() {
            if entry.bound == 0 {
                return Err(Error::Config(format!(
                    "board profile wcet.loop_bounds[{index}].bound must be positive"
                )));
            }
            if !headers.insert(entry.header) {
                return Err(Error::Config(format!(
                    "board profile wcet loop header 0x{:x} is declared twice",
                    entry.header
                )));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_system(&self) -> Result<()> {
        let Some(system) = &self.system else {
            return Ok(());
        };
        if self.schema_version < 2 {
            return Err(Error::Config(
                "board profile system requires schema_version 2".to_owned(),
            ));
        }
        if self.wcet.is_none() {
            return Err(Error::Config(
                "board profile system requires a [wcet] section".to_owned(),
            ));
        }
        let mut resources = BTreeMap::new();
        for (index, resource) in system.resources.iter().enumerate() {
            validate_text("system.resources.name", &resource.name)?;
            if resource.capacity == 0 {
                return Err(Error::Config(format!(
                    "board profile system.resources[{index}].capacity must be positive"
                )));
            }
            if resources
                .insert(resource.name.as_str(), resource.capacity)
                .is_some()
            {
                return Err(Error::Config(format!(
                    "board profile system resource {:?} is declared twice",
                    resource.name
                )));
            }
        }
        let mut locks = BTreeSet::new();
        for lock in &system.locks {
            validate_text("system.locks.name", &lock.name)?;
            if !locks.insert(lock.name.as_str()) {
                return Err(Error::Config(format!(
                    "board profile system lock {:?} is declared twice",
                    lock.name
                )));
            }
        }
        let has_task_locks = system.tasks.iter().any(|task| !task.locks.is_empty());
        if system.blocking_model.is_none() && (!system.locks.is_empty() || has_task_locks) {
            return Err(Error::Config(
                "board profile system locks require blocking_model = \"priority-ceiling\""
                    .to_owned(),
            ));
        }
        if system.horizon_ns == Some(0) {
            return Err(Error::Config(
                "board profile system.horizon_ns must be positive".to_owned(),
            ));
        }
        if system.slot_ns == Some(0) {
            return Err(Error::Config(
                "board profile system.slot_ns must be positive".to_owned(),
            ));
        }
        if system.slot_ns.is_some() && system.horizon_ns.is_none() {
            return Err(Error::Config(
                "board profile system.slot_ns requires system.horizon_ns".to_owned(),
            ));
        }
        let mut has_period = false;
        let mut targets = BTreeSet::new();
        for (index, task) in system.tasks.iter().enumerate() {
            validate_text("system.tasks.target", &task.target)?;
            if task.activations == Some(0) {
                return Err(Error::Config(format!(
                    "board profile system.tasks[{index}].activations must be positive"
                )));
            }
            if task.deadline_ns == Some(0) {
                return Err(Error::Config(format!(
                    "board profile system.tasks[{index}].deadline_ns must be positive"
                )));
            }
            if let Some(period) = task.period_ns {
                if period == 0 {
                    return Err(Error::Config(format!(
                        "board profile system.tasks[{index}].period_ns must be positive"
                    )));
                }
                has_period = true;
            } else if task.release_offset_ns.is_some() || task.release_jitter_ns.is_some() {
                return Err(Error::Config(format!(
                    "board profile system.tasks[{index}] sets release offset/jitter without period_ns"
                )));
            }
            if !targets.insert(task.target.as_str()) {
                return Err(Error::Config(format!(
                    "board profile system task target {:?} is declared twice",
                    task.target
                )));
            }
            for (resource, units) in &task.resources {
                let Some(capacity) = resources.get(resource.as_str()) else {
                    return Err(Error::Config(format!(
                        "board profile system task {:?} uses undeclared resource {:?}",
                        task.target, resource
                    )));
                };
                if *units == 0 {
                    return Err(Error::Config(format!(
                        "board profile system task {:?} resource {:?} units must be positive",
                        task.target, resource
                    )));
                }
                if units > capacity {
                    return Err(Error::Config(format!(
                        "board profile system task {:?} needs {units} unit(s) of resource {:?}, capacity is {capacity}",
                        task.target, resource
                    )));
                }
            }
            for (lock, hold_ns) in &task.locks {
                if !locks.contains(lock.as_str()) {
                    return Err(Error::Config(format!(
                        "board profile system task {:?} uses undeclared lock {:?}",
                        task.target, lock
                    )));
                }
                if *hold_ns == 0 {
                    return Err(Error::Config(format!(
                        "board profile system task {:?} lock {:?} hold_ns must be positive",
                        task.target, lock
                    )));
                }
            }
        }
        if has_period && system.horizon_ns.is_none() {
            return Err(Error::Config(
                "board profile system tasks with period_ns require system.horizon_ns".to_owned(),
            ));
        }
        let mut links = BTreeSet::new();
        for (index, link) in system.links.iter().enumerate() {
            validate_text("system.links.from", &link.from)?;
            validate_text("system.links.to", &link.to)?;
            if link.from == link.to {
                return Err(Error::Config(format!(
                    "board profile system.links[{index}] cannot link a task to itself"
                )));
            }
            if link.count == 0 {
                return Err(Error::Config(format!(
                    "board profile system.links[{index}].count must be positive"
                )));
            }
            if !links.insert((link.from.as_str(), link.to.as_str(), link.kind)) {
                return Err(Error::Config(format!(
                    "board profile system link {:?} -> {:?} ({}) is declared twice",
                    link.from,
                    link.to,
                    link.kind.name()
                )));
            }
        }
        Ok(())
    }

    fn validate_instruction_costs(&self) -> Result<()> {
        let mut selectors = BTreeSet::new();
        for (index, override_) in self.instruction_costs.iter().enumerate() {
            if override_.class.is_none() && override_.mnemonic.is_none() {
                return Err(Error::Config(format!(
                    "board profile instruction_costs[{index}] needs class or mnemonic"
                )));
            }
            let mnemonic = override_.mnemonic.as_deref().map(|value| {
                let canonical = crate::timing::canonical_mnemonic(value);
                if canonical.is_empty()
                    || canonical
                        .chars()
                        .any(|character| character.is_whitespace() || character.is_control())
                {
                    return Err(Error::Config(format!(
                        "board profile instruction_costs[{index}] has invalid mnemonic {value:?}"
                    )));
                }
                Ok(canonical.to_ascii_lowercase())
            });
            let mnemonic = mnemonic.transpose()?;
            if !override_.cost_range().is_valid() {
                return Err(Error::Config(format!(
                    "board profile instruction_costs[{index}] has an invalid cycle range"
                )));
            }
            if let Some(note) = &override_.note {
                validate_text("instruction_costs.note", note)?;
            }
            if !selectors.insert((override_.class, mnemonic)) {
                return Err(Error::Config(format!(
                    "board profile instruction_costs[{index}] duplicates an earlier selector"
                )));
            }
        }
        Ok(())
    }

    /// Profile schema version.
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Stable profile ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable profile name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Architecture string from the profile.
    #[must_use]
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// CPU/timing-model name from the profile.
    #[must_use]
    pub fn cpu(&self) -> &str {
        &self.cpu
    }

    /// Path the profile was loaded from, when it was loaded from a file.
    #[must_use]
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// SHA-256 of the loaded profile file or parsed text.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    /// Extra caveats supplied by the profile author.
    #[must_use]
    pub fn caveats(&self) -> &[String] {
        &self.caveats
    }

    /// Profile-wide confidence override for block timing.
    #[must_use]
    pub fn confidence(&self) -> Option<Confidence> {
        self.confidence
    }

    /// Unknown-instruction diagnostic policy.
    #[must_use]
    pub fn unknown_instruction_policy(&self) -> UnknownInstructionPolicy {
        self.unknown_instructions
    }

    /// Core clock frequency from the profile.
    #[must_use]
    pub fn core_clock_hz(&self) -> Option<u64> {
        self.clocks.get("core").map(|clock| clock.hz)
    }

    /// Number of clock domains declared by the profile.
    #[must_use]
    pub fn clock_count(&self) -> usize {
        self.clocks.len()
    }

    /// Number of memory regions declared by the profile.
    #[must_use]
    pub fn memory_region_count(&self) -> usize {
        self.memory.len()
    }

    /// Memory regions used for data-memory latency analysis.
    #[must_use]
    pub(crate) fn data_memory_regions(&self) -> &[MemoryRegion] {
        &self.memory
    }

    /// Whether any memory region declares data-access timing.
    #[must_use]
    pub(crate) fn data_memory_enabled(&self) -> bool {
        self.memory.iter().any(MemoryRegion::has_data_timing)
    }

    /// Number of instruction-cost overrides declared by the profile.
    #[must_use]
    pub fn instruction_cost_override_count(&self) -> usize {
        self.instruction_costs.len()
    }

    /// Optional in-order pipeline/resource model.
    #[must_use]
    pub(crate) fn pipeline(&self) -> Option<&PipelineProfile> {
        self.pipeline.as_ref()
    }

    /// Optional instruction-cache model.
    #[must_use]
    pub(crate) fn instruction_cache(&self) -> Option<&InstructionCacheProfile> {
        self.instruction_cache.as_ref()
    }

    /// Optional data-cache model.
    #[must_use]
    pub(crate) fn data_cache(&self) -> Option<&DataCacheProfile> {
        self.data_cache.as_ref()
    }

    /// Optional branch-prediction model.
    #[must_use]
    pub(crate) fn branch_prediction(&self) -> Option<&BranchPredictionProfile> {
        self.branch_prediction.as_ref()
    }

    /// Optional WCET analysis configuration.
    #[must_use]
    pub(crate) fn multicore(&self) -> Option<&MulticoreProfile> {
        self.multicore.as_ref()
    }

    pub(crate) fn wcet(&self) -> Option<&WcetProfile> {
        self.wcet.as_ref()
    }

    /// Optional layered system-model activation and resource configuration.
    pub(crate) fn system(&self) -> Option<&SystemProfile> {
        self.system.as_ref()
    }

    /// Largest fetch wait-state count on an executable Flash region.
    #[must_use]
    pub fn max_flash_wait_states(&self) -> Option<u32> {
        self.memory
            .iter()
            .filter(|region| region.executable && region.kind == MemoryKind::Flash)
            .map(|region| region.fetch_wait_states)
            .max()
    }

    /// Largest fetch wait-state count on any executable region.
    #[must_use]
    pub fn max_fetch_wait_states(&self) -> Option<u32> {
        self.memory
            .iter()
            .filter(|region| region.executable)
            .map(|region| region.fetch_wait_states)
            .max()
    }

    /// Builds schema frequency domains for every profile clock.
    #[must_use]
    pub fn frequency_domains(&self) -> Vec<FrequencyDomain> {
        self.clocks
            .iter()
            .map(|(name, clock)| FrequencyDomain {
                id: FrequencyDomainId::new(format!("clk:{name}")),
                name: name.clone(),
                hz: clock.hz,
                source: FrequencySource::BoardProfile,
                confidence: clock.confidence.unwrap_or(Confidence::Medium),
            })
            .collect()
    }

    /// Selects the most specific override matching `class` and `mnemonic`.
    #[must_use]
    pub(crate) fn override_for(
        &self,
        class: InstructionClass,
        mnemonic: &str,
    ) -> Option<MatchedCost> {
        let mut best: Option<(&InstructionCostOverride, u8)> = None;
        for override_ in &self.instruction_costs {
            if !override_.matches(class, mnemonic) {
                continue;
            }
            let specificity = override_.specificity();
            if best.is_none_or(|(_, current)| specificity > current) {
                best = Some((override_, specificity));
            }
        }
        best.map(|(override_, _)| MatchedCost {
            cycles: override_.cost_range(),
        })
    }

    /// Extra fetch cycles for an instruction at `address`.
    #[must_use]
    pub(crate) fn fetch_wait_cycles(&self, address: u64, size: u8) -> u32 {
        self.memory
            .iter()
            .find(|region| region.executable && region.contains(address))
            .map_or(0, |region| region.fetch_cycles(size))
    }
}

fn validate_text(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Config(format!(
            "board profile {field} must not be empty"
        )));
    }
    if value != value.trim() {
        return Err(Error::Config(format!(
            "board profile {field} must not have leading or trailing whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::Config(format!(
            "board profile {field} must not contain control characters"
        )));
    }
    Ok(())
}

fn valid_domain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn arch_matches(profile: &str, model: &str) -> bool {
    let profile = profile.trim().to_ascii_lowercase().replace('_', "-");
    let model = model.trim().to_ascii_lowercase().replace('_', "-");
    if profile == model {
        return true;
    }
    match model.as_str() {
        "thumb" => profile.starts_with("thumbv"),
        "arm" => profile.starts_with("armv"),
        "aarch64" => profile == "arm64",
        "riscv32" => profile == "rv32" || profile.starts_with("riscv32"),
        "riscv64" => profile == "rv64" || profile.starts_with("riscv64"),
        "x86-64" => profile.starts_with("x86-64"),
        _ => false,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        BOARD_PROFILE_SCHEMA_VERSION, BoardProfile, SystemBlockingModel, UnknownInstructionPolicy,
    };

    const VALID: &str = r#"
schema_version = 1
id = "board:test"
name = "Test board"
arch = "thumb"
cpu = "cortex-m0"

[clocks.core]
hz = 48_000_000
confidence = "high"

[[memory]]
name = "flash"
start = 0x0800_0000
size = 0x2000
kind = "flash"
executable = true
fetch_wait_states = 1
fetch_width_bytes = 4

[[instruction_costs]]
mnemonic = "ldr"
cycles = { min = 2, max = 3 }
note = "board errata"
"#;

    #[test]
    fn parses_and_hashes_a_profile() {
        let profile = BoardProfile::parse_toml(VALID).expect("valid profile");
        assert_eq!(profile.id(), "board:test");
        assert_eq!(profile.core_clock_hz(), Some(48_000_000));
        assert_eq!(profile.confidence(), None);
        assert_eq!(profile.clock_count(), 1);
        assert_eq!(profile.memory_region_count(), 1);
        assert_eq!(profile.instruction_cost_override_count(), 1);
        assert!(profile.sha256().is_some_and(|hash| hash.len() == 64));
        assert_eq!(
            profile.frequency_domains()[0].source,
            elf2tdg_schema::FrequencySource::BoardProfile
        );
        assert_eq!(profile.max_flash_wait_states(), Some(1));
    }

    #[test]
    fn loads_toml_and_json_from_files() {
        let directory =
            std::env::temp_dir().join(format!("elf2tdg-board-profile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("temp directory");
        let toml_path = directory.join("profile.toml");
        std::fs::write(&toml_path, VALID).expect("write TOML profile");
        let toml = BoardProfile::load(&toml_path).expect("load TOML profile");
        assert_eq!(toml.source(), Some(toml_path.as_path()));
        assert_eq!(toml.sha256().map(str::len), Some(64));

        let json_path = directory.join("profile.json");
        std::fs::write(
            &json_path,
            r#"{"schema_version":1,"id":"board:file","arch":"thumb","cpu":"cortex-m0"}"#,
        )
        .expect("write JSON profile");
        let json = BoardProfile::load(&json_path).expect("load JSON profile");
        assert_eq!(json.id(), "board:file");
        assert_eq!(json.source(), Some(json_path.as_path()));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn rejects_unknown_fields_and_duplicate_selectors() {
        let unknown = VALID.replace("id = \"board:test\"", "id = \"board:test\"\nbogus = 1");
        assert!(BoardProfile::parse_toml(&unknown).is_err());

        let duplicate = format!("{VALID}\n[[instruction_costs]]\nmnemonic = \"LDR\"\ncycles = 3\n");
        assert!(BoardProfile::parse_toml(&duplicate).is_err());
    }

    #[test]
    fn rejects_overlapping_memory_and_bad_costs() {
        let overlap = VALID.replace(
            "size = 0x2000",
            "size = 0x2000\n\n[[memory]]\nname = \"alias\"\nstart = 0x0800_1000\nsize = 0x10",
        );
        assert!(BoardProfile::parse_toml(&overlap).is_err());

        let negative = VALID.replace(
            "cycles = { min = 2, max = 3 }",
            "cycles = { min = 3, max = 2 }",
        );
        assert!(BoardProfile::parse_toml(&negative).is_err());
    }

    #[test]
    fn validates_data_memory_timing() {
        let valid = VALID
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "fetch_width_bytes = 4",
                "fetch_width_bytes = 4\ndata_width_bytes = 8\ndata_read_wait_states = 2\ndata_write_wait_states = 1",
            );
        let profile = BoardProfile::parse_toml(&valid).expect("valid data-memory profile");
        assert!(profile.data_memory_enabled());
        let region = &profile.data_memory_regions()[0];
        assert_eq!(region.data_width_bytes(), 8);
        assert_eq!(region.data_read_wait_states(), 2);
        assert_eq!(region.data_write_wait_states(), 1);

        let old_schema = valid.replace("schema_version = 2", "schema_version = 1");
        assert!(BoardProfile::parse_toml(&old_schema).is_err());
        let zero_width = valid.replace("data_width_bytes = 8", "data_width_bytes = 0");
        assert!(BoardProfile::parse_toml(&zero_width).is_err());
    }

    #[test]
    fn validates_multicore_profiles() {
        let valid = format!(
            r#"{}
[multicore]
cores = 4
core_id = 1
data_read_interference_cycles = 8
data_write_interference_cycles = 9
instruction_fetch_interference_cycles = 2
confidence = "low"
"#,
            VALID.replace("schema_version = 1", "schema_version = 2")
        );
        let profile = BoardProfile::parse_toml(&valid).expect("valid multicore profile");
        let multicore = profile.multicore().expect("multicore profile");
        assert_eq!(multicore.model(), "access-budget");
        assert_eq!(multicore.cores(), 4);
        assert_eq!(multicore.core_id(), 1);
        assert_eq!(multicore.data_read_interference_cycles(), 8);
        assert_eq!(multicore.data_write_interference_cycles(), 9);
        assert_eq!(multicore.instruction_fetch_interference_cycles(), 2);

        let old_schema = valid.replace("schema_version = 2", "schema_version = 1");
        assert!(BoardProfile::parse_toml(&old_schema).is_err());
        let one_core = valid.replace("cores = 4", "cores = 1");
        assert!(BoardProfile::parse_toml(&one_core).is_err());
        let bad_core = valid.replace("core_id = 1", "core_id = 4");
        assert!(BoardProfile::parse_toml(&bad_core).is_err());
        let bad_model = valid.replace("[multicore]", "[multicore]\nmodel = \"round-robin\"");
        assert!(BoardProfile::parse_toml(&bad_model).is_err());
    }

    #[test]
    fn defaults_identity_and_emits_safe_profile_template() {
        let minimal = BoardProfile::parse_toml(r#"cpu = "cortex-m7""#).expect("minimal profile");
        assert_eq!(minimal.schema_version(), BOARD_PROFILE_SCHEMA_VERSION);
        assert_eq!(minimal.id(), "board:default");
        assert_eq!(minimal.arch(), "thumb");
        assert_eq!(minimal.cpu(), "cortex-m7");

        let template =
            BoardProfile::default_profile_template("cortex-m4").expect("profile template");
        for marker in [
            "# [clocks.core]",
            "# [[memory]]",
            "# [[instruction_costs]]",
            "# [pipeline]",
            "# [instruction_cache]",
            "# [data_cache]",
            "# [branch_prediction]",
            "# [multicore]",
            "# [wcet]",
        ] {
            assert!(template.contains(marker), "template lacks {marker}");
        }
        let parsed = BoardProfile::parse_toml(&template).expect("template must parse");
        assert_eq!(parsed.cpu(), "cortex-m4");
        assert_eq!(parsed.arch(), "thumb");
        assert_eq!(parsed.id(), "board:cortex-m4");
        assert!(parsed.pipeline().is_none());
        assert!(parsed.instruction_cache().is_none());
        assert!(parsed.data_cache().is_none());
        assert!(parsed.branch_prediction().is_none());
        assert!(parsed.multicore().is_none());
        assert!(parsed.wcet().is_none());

        assert!(BoardProfile::default_profile_template("unknown-cpu").is_err());
    }

    #[test]
    fn validates_system_activation_and_resource_profiles() {
        let valid = VALID.replace("schema_version = 1", "schema_version = 2")
            + r#"
[wcet]
default_loop_bound = 4

[system]

[[system.tasks]]
target = "sensor_task"
priority = 3
activations = 3
resources = { bus = 1 }

[[system.resources]]
name = "bus"
capacity = 4
"#;
        let profile = BoardProfile::parse_toml(&valid).expect("valid system profile");
        let system = profile.system().expect("system profile");
        assert_eq!(system.tasks().len(), 1);
        assert_eq!(system.tasks()[0].target(), "sensor_task");
        assert_eq!(system.tasks()[0].priority(), Some(3));
        assert_eq!(system.tasks()[0].activations(), Some(3));
        assert_eq!(system.tasks()[0].resources().get("bus"), Some(&1));
        assert_eq!(system.resources().len(), 1);
        assert_eq!(system.resources()[0].name(), "bus");
        assert_eq!(system.resources()[0].capacity(), 4);

        let with_links = valid.clone()
            + r#"
[[system.links]]
from = "app_main"
to = "sensor_task"
kind = "fork"
count = 2
"#;
        let profile = BoardProfile::parse_toml(&with_links).expect("valid fork link");
        let system = profile.system().expect("system profile");
        assert_eq!(system.links().len(), 1);
        assert_eq!(system.links()[0].from(), "app_main");
        assert_eq!(system.links()[0].to(), "sensor_task");
        assert_eq!(system.links()[0].kind().name(), "fork");
        assert_eq!(system.links()[0].count(), 2);
        let self_link = with_links.replace("to = \"sensor_task\"", "to = \"app_main\"");
        assert!(BoardProfile::parse_toml(&self_link).is_err());
        let zero_count = with_links.replace("count = 2", "count = 0");
        assert!(BoardProfile::parse_toml(&zero_count).is_err());
        let duplicate_link = format!(
            "{with_links}\n[[system.links]]\nfrom = \"app_main\"\nto = \"sensor_task\"\nkind = \"fork\"\n"
        );
        assert!(BoardProfile::parse_toml(&duplicate_link).is_err());
        let bad_kind = with_links.replace("kind = \"fork\"", "kind = \"barrier\"");
        assert!(BoardProfile::parse_toml(&bad_kind).is_err());

        let periodic = valid
            .replace(
                "[system]",
                "[system]\nhorizon_ns = 5_000_000\nslot_ns = 100_000",
            )
            .replace(
                "activations = 3",
                "period_ns = 1_000_000\nrelease_offset_ns = 0\nrelease_jitter_ns = 100\ndeadline_ns = 2_000_000",
            );
        let profile = BoardProfile::parse_toml(&periodic).expect("valid periodic profile");
        let system = profile.system().expect("system profile");
        assert_eq!(system.horizon_ns(), Some(5_000_000));
        assert_eq!(system.slot_ns(), Some(100_000));
        assert_eq!(system.tasks()[0].period_ns(), Some(1_000_000));
        assert_eq!(system.tasks()[0].deadline_ns(), Some(2_000_000));
        assert_eq!(system.tasks()[0].release_offset_ns(), Some(0));
        assert_eq!(system.tasks()[0].release_jitter_ns(), Some(100));
        assert_eq!(system.tasks()[0].activations(), None);
        let no_horizon = periodic.replace("horizon_ns = 5_000_000\n", "");
        assert!(BoardProfile::parse_toml(&no_horizon).is_err());
        let zero_period = periodic.replace("period_ns = 1_000_000", "period_ns = 0");
        assert!(BoardProfile::parse_toml(&zero_period).is_err());
        let zero_horizon = periodic.replace("horizon_ns = 5_000_000", "horizon_ns = 0");
        assert!(BoardProfile::parse_toml(&zero_horizon).is_err());
        let zero_slot = periodic.replace("slot_ns = 100_000", "slot_ns = 0");
        assert!(BoardProfile::parse_toml(&zero_slot).is_err());
        let slot_without_horizon = periodic.replace("horizon_ns = 5_000_000\n", "");
        assert!(BoardProfile::parse_toml(&slot_without_horizon).is_err());
        let zero_deadline = periodic.replace("deadline_ns = 2_000_000", "deadline_ns = 0");
        assert!(BoardProfile::parse_toml(&zero_deadline).is_err());
        let offset_without_period = valid.replace("activations = 3", "release_offset_ns = 10");
        assert!(BoardProfile::parse_toml(&offset_without_period).is_err());

        let no_wcet = valid.replace("[wcet]\ndefault_loop_bound = 4\n", "");
        assert!(BoardProfile::parse_toml(&no_wcet).is_err());
        let duplicate_resource = valid.replace(
            "[[system.resources]]\nname = \"bus\"",
            "[[system.resources]]\nname = \"bus\"\ncapacity = 2\n\n[[system.resources]]\nname = \"bus\"",
        );
        assert!(BoardProfile::parse_toml(&duplicate_resource).is_err());
        let unknown_resource = valid.replace("resources = { bus = 1 }", "resources = { dma = 1 }");
        assert!(BoardProfile::parse_toml(&unknown_resource).is_err());
        let zero_activation = valid.replace("activations = 3", "activations = 0");
        assert!(BoardProfile::parse_toml(&zero_activation).is_err());
        let too_many_units = valid.replace("resources = { bus = 1 }", "resources = { bus = 5 }");
        assert!(BoardProfile::parse_toml(&too_many_units).is_err());
        let duplicate_target = valid.replace(
            "[[system.resources]]",
            "[[system.tasks]]\ntarget = \"sensor_task\"\nactivations = 2\n\n[[system.resources]]",
        );
        assert!(BoardProfile::parse_toml(&duplicate_target).is_err());
    }

    #[test]
    fn validates_system_lock_and_blocking_profiles() {
        let valid = VALID.replace("schema_version = 1", "schema_version = 2")
            + r#"
[wcet]
default_loop_bound = 4

[system]
blocking_model = "priority-ceiling"

[[system.locks]]
name = "uart"

[[system.tasks]]
target = "sensor_task"
priority = 3
locks = { uart = 500 }
"#;
        let profile = BoardProfile::parse_toml(&valid).expect("valid blocking profile");
        let system = profile.system().expect("system profile");
        assert_eq!(system.tasks()[0].locks().get("uart"), Some(&500));
        assert_eq!(system.locks().len(), 1);
        assert_eq!(system.locks()[0].name(), "uart");
        assert_eq!(
            system.blocking_model().map(SystemBlockingModel::name),
            Some("priority-ceiling")
        );

        let locks_without_model = valid.replace("blocking_model = \"priority-ceiling\"\n", "");
        assert!(BoardProfile::parse_toml(&locks_without_model).is_err());
        let undeclared_lock = valid.replace("locks = { uart = 500 }", "locks = { spi = 500 }");
        assert!(BoardProfile::parse_toml(&undeclared_lock).is_err());
        let zero_hold = valid.replace("uart = 500", "uart = 0");
        assert!(BoardProfile::parse_toml(&zero_hold).is_err());
        let duplicate_lock = valid.replace(
            "[[system.locks]]\nname = \"uart\"",
            "[[system.locks]]\nname = \"uart\"\n\n[[system.locks]]\nname = \"uart\"",
        );
        assert!(BoardProfile::parse_toml(&duplicate_lock).is_err());
        let unsupported_protocol = valid.replace("priority-ceiling", "priority-inheritance");
        assert!(BoardProfile::parse_toml(&unsupported_protocol).is_err());
    }

    #[test]
    fn parses_json_profiles() {
        let profile = BoardProfile::parse_json(
            r#"{
                "schema_version": 1,
                "id": "board:json",
                "arch": "thumbv7em",
                "cpu": "cortex-m4",
                "clocks": {"core": {"hz": 1000000, "confidence": "high"}},
                "instruction_costs": [{"mnemonic": "ldr", "cycles": 2}]
            }"#,
        )
        .expect("valid JSON profile");
        assert_eq!(profile.id(), "board:json");
        assert_eq!(profile.core_clock_hz(), Some(1_000_000));
        assert_eq!(profile.instruction_cost_override_count(), 1);
        assert!(profile.sha256().is_some());
    }

    #[test]
    fn validates_pipeline_profiles() {
        let valid = VALID
            .replace("schema_version = 1", "schema_version = 2")
            .replace("cpu = \"cortex-m0\"", "cpu = \"cortex-m4\"")
            + r#"
[pipeline]
issue_width = 1
branch_penalty = { min = 1, max = 3 }

[[pipeline.instructions]]
class = "load"
resources = ["load_store"]
latency = 2
occupancy = 1
"#;
        let profile = BoardProfile::parse_toml(&valid).expect("valid pipeline profile");
        assert!(profile.pipeline().is_some());

        let legacy = valid.replace("schema_version = 2", "schema_version = 1");
        assert!(BoardProfile::parse_toml(&legacy).is_err());

        let m0 = valid.replace("cpu = \"cortex-m4\"", "cpu = \"cortex-m0\"");
        assert!(BoardProfile::parse_toml(&m0).is_err());

        let multi_issue = valid.replace("issue_width = 1", "issue_width = 2");
        assert!(BoardProfile::parse_toml(&multi_issue).is_err());

        let no_resources = valid.replace("resources = [\"load_store\"]", "resources = []");
        assert!(BoardProfile::parse_toml(&no_resources).is_err());
    }

    #[test]
    fn validates_instruction_cache_profiles() {
        let valid = format!(
            "{}\n[instruction_cache]\nsize = 4096\nline_bytes = 32\nways = 4\nmiss_penalty = 10\n",
            VALID.replace("schema_version = 1", "schema_version = 2")
        );
        let profile = BoardProfile::parse_toml(&valid).expect("valid cache profile");
        let cache = profile.instruction_cache().expect("cache profile");
        assert_eq!(cache.sets(), 32);
        assert!(
            BoardProfile::parse_toml(&valid.replace("schema_version = 2", "schema_version = 1"))
                .is_err()
        );
        assert_eq!(cache.replacement_name(), "lru");
        assert!(cache.invalidate_on_call());

        let bad_size = valid.replace("size = 4096", "size = 4097");
        assert!(BoardProfile::parse_toml(&bad_size).is_err());
        let zero_ways = valid.replace("ways = 4", "ways = 0");
        assert!(BoardProfile::parse_toml(&zero_ways).is_err());
        let zero_penalty = valid.replace("miss_penalty = 10", "miss_penalty = 0");
        assert!(BoardProfile::parse_toml(&zero_penalty).is_err());
    }

    #[test]
    fn validates_data_cache_profiles() {
        let valid = format!(
            "{}\n[data_cache]\nsize = 8192\nline_bytes = 32\nways = 4\nmiss_penalty = 12\nwrite_allocate = false\n",
            VALID.replace("schema_version = 1", "schema_version = 2")
        );
        let profile = BoardProfile::parse_toml(&valid).expect("valid data-cache profile");
        let cache = profile.data_cache().expect("data-cache profile");
        assert_eq!(cache.sets(), 64);
        assert!(!cache.write_allocate());
        assert!(cache.invalidate_on_call());
        assert!(
            BoardProfile::parse_toml(&valid.replace("schema_version = 2", "schema_version = 1"))
                .is_err()
        );

        let bad_size = valid.replace("size = 8192", "size = 8193");
        assert!(BoardProfile::parse_toml(&bad_size).is_err());
        let zero_ways = valid.replace("ways = 4", "ways = 0");
        assert!(BoardProfile::parse_toml(&zero_ways).is_err());
        let zero_penalty = valid.replace("miss_penalty = 12", "miss_penalty = 0");
        assert!(BoardProfile::parse_toml(&zero_penalty).is_err());
    }

    #[test]
    fn validates_branch_prediction_profiles() {
        let valid = format!(
            r#"{}
[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
initial_state = "weakly-taken"
max_states = 32
"#,
            VALID.replace("schema_version = 1", "schema_version = 2")
        );
        let profile = BoardProfile::parse_toml(&valid).expect("valid branch-prediction profile");
        let prediction = profile
            .branch_prediction()
            .expect("branch-prediction profile");
        assert_eq!(prediction.model_name(), "bimodal");
        assert_eq!(prediction.initial_state_name(), "weakly-taken");
        assert_eq!(prediction.initial_counter(), 2);
        assert_eq!(prediction.max_states(), 32);
        assert!(
            BoardProfile::parse_toml(&valid.replace("schema_version = 2", "schema_version = 1"))
                .is_err()
        );

        let zero_penalty = valid.replace("mispredict_penalty = 3", "mispredict_penalty = 0");
        assert!(BoardProfile::parse_toml(&zero_penalty).is_err());
        let zero_states = valid.replace("max_states = 32", "max_states = 0");
        assert!(BoardProfile::parse_toml(&zero_states).is_err());
        let bad_model = valid.replace("model = \"bimodal\"", "model = \"unknown\"");
        assert!(BoardProfile::parse_toml(&bad_model).is_err());
    }

    #[test]
    fn validates_wcet_profiles() {
        let valid = format!(
            r"{}
[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true
max_states = 1024

[[wcet.loop_bounds]]
header = 0x800_0100
bound = 12
",
            VALID.replace("schema_version = 1", "schema_version = 2")
        );
        let profile = BoardProfile::parse_toml(&valid).expect("valid WCET profile");
        let wcet = profile.wcet().expect("WCET profile");
        assert_eq!(wcet.default_loop_bound(), Some(4));
        assert_eq!(wcet.max_states(), 1024);
        assert!(wcet.bound_nonterminating_loops());
        assert_eq!(
            wcet.loop_bounds().collect::<Vec<_>>(),
            vec![(0x800_0100, 12)]
        );
        assert_eq!(wcet.loop_bound_count(), 1);
        assert!(
            BoardProfile::parse_toml(&valid.replace("schema_version = 2", "schema_version = 1"))
                .is_err()
        );
        assert!(
            BoardProfile::parse_toml(
                &valid.replace("default_loop_bound = 4", "default_loop_bound = 0")
            )
            .is_err()
        );
        assert!(BoardProfile::parse_toml(&valid.replace("bound = 12", "bound = 0")).is_err());
        assert!(
            BoardProfile::parse_toml(&valid.replace("max_states = 1024", "max_states = 0"))
                .is_err()
        );
        let duplicate = format!("{valid}\n[[wcet.loop_bounds]]\nheader = 0x8000100\nbound = 2\n");
        assert!(BoardProfile::parse_toml(&duplicate).is_err());
    }

    #[test]
    fn rejects_arch_cpu_mismatch() {
        let profile = VALID.replace("arch = \"thumb\"", "arch = \"riscv32\"");
        assert!(BoardProfile::parse_toml(&profile).is_err());
    }

    #[test]
    fn unknown_instruction_policy_defaults_to_warn() {
        let profile = BoardProfile::parse_toml(VALID).expect("valid profile");
        assert_eq!(
            profile.unknown_instruction_policy(),
            UnknownInstructionPolicy::Warn
        );
        let ignored = VALID.replace(
            "cpu = \"cortex-m0\"",
            "cpu = \"cortex-m0\"\nunknown_instructions = \"ignore\"",
        );
        let profile = BoardProfile::parse_toml(&ignored).expect("valid profile");
        assert_eq!(
            profile.unknown_instruction_policy(),
            UnknownInstructionPolicy::Ignore
        );
        assert_eq!(profile.confidence(), None);
    }
}
