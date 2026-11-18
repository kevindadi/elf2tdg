//! Instruction timing models.
//!
//! The tables intentionally produce bounded or statistical cycle estimates
//! rather than pretending to be a WCET proof. Cortex-M and generic RISC-V
//! models are selected automatically. Generic `AArch64` and `x86-64` models are
//! statistical throughput tables and must be selected explicitly with
//! `--cpu aarch64` or `--cpu x86-64`.

use std::collections::{BTreeMap, BTreeSet};

use elf2tdg_schema::{
    BlockTiming, CacheParams, Confidence, CostRange, Determinism, FrequencyDomain,
    FrequencyDomainId, FrequencySource, TimingInfo, TimingModelId, TimingModelInfo, TimingParams,
};
use serde::Deserialize;

use crate::arch::DecodedInsn;
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
    /// Generic in-order RV32.
    RiscV32,
    /// Generic in-order RV64.
    RiscV64,
    /// Generic out-of-order `AArch64` throughput model.
    Aarch64Generic,
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
            "aarch64" | "aarch64-generic" | "arm64" | "cortex-a53" | "cortex-a55"
            | "cortex-a72" | "cortex-a76" | "neoverse-n1" => Some(Self::Aarch64Generic),
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
                "unknown CPU/timing model {name:?}; use cortex-m0, cortex-m0plus, cortex-m3, cortex-m4, cortex-m7, cortex-m33, riscv32, riscv64, aarch64 or x86-64"
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
            Self::RiscV32 => arch == ArchKind::Riscv32,
            Self::RiscV64 => arch == ArchKind::Riscv64,
            Self::Aarch64Generic => arch == ArchKind::Aarch64,
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
            Self::Aarch64Generic => "aarch64-generic",
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
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::Aarch64Generic => "aarch64",
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
            Self::Aarch64Generic => "generic AArch64",
            Self::X86_64Generic => "generic x86-64",
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
            | Self::CortexM33 => Determinism::Bounded,
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
            | Self::Aarch64Generic
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
                "Generic in-order RISC-V model; a specific core's pipeline and memory system may differ substantially."
                    .to_owned(),
            ),
            Self::Aarch64Generic => caveats.push(
                "Generic AArch64 throughput model: out-of-order issue, caches, branch prediction and memory latency are not modeled; this is not a bound."
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
            Self::Aarch64Generic => aarch64_cost(class),
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
                table_version: "0.2.0-m3".to_owned(),
                params: self.params(),
                caveats: self.caveats(),
            }],
            frequency_domains,
            default_frequency_domain: frequency_hz.map(|_| FrequencyDomainId::new(CORE_DOMAIN)),
            caveats: vec![
                "Static timing estimates are not WCET bounds; loop bounds and execution counts are not inferred."
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
                    "unknown CPU/timing model {explicit:?}; use cortex-m0, cortex-m0plus, cortex-m3, cortex-m4, cortex-m7, cortex-m33, riscv32, riscv64, aarch64 or x86-64"
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
    /// resources, result latencies and register dependencies. It models local
    /// hazards within one block; pipeline state at block entry is assumed
    /// ready, so this is a local cost rather than a whole-program WCET bound.
    #[must_use]
    pub fn block_cost(&self, instructions: &[DecodedInsn]) -> (CostRange, Vec<(String, u64)>) {
        if let Some(profile) = &self.profile
            && let Some(pipeline) = profile.pipeline()
        {
            return Self::pipeline_block_cost(profile, pipeline, instructions);
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

    #[allow(clippy::cast_precision_loss)]
    fn pipeline_block_cost(
        profile: &BoardProfile,
        pipeline: &crate::board_profile::PipelineProfile,
        instructions: &[DecodedInsn],
    ) -> (CostRange, Vec<(String, u64)>) {
        let mut resource_free: BTreeMap<&str, u32> = BTreeMap::new();
        let mut register_ready: BTreeMap<capstone::RegId, u32> = BTreeMap::new();
        let mut issue_start = 0_u32;
        let mut completion = 0_u32;
        let mut fetch_cycles = 0_u32;
        let mut unknown = Vec::new();
        for instruction in instructions {
            let classification = classify(instruction);
            let mnemonic = canonical_mnemonic(&instruction.mnemonic);
            let (resources, latency, occupancy, is_unknown) =
                if let Some(spec) = pipeline.instruction_for(classification.class, mnemonic) {
                    (
                        spec.resources()
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                        spec.latency(),
                        spec.occupancy(),
                        false,
                    )
                } else {
                    let (resources, latency, occupancy) =
                        cortex_m4_pipeline_default(classification.class);
                    (
                        resources.to_vec(),
                        latency,
                        occupancy,
                        !classification.known,
                    )
                };
            let operand_ready = instruction
                .regs_read
                .iter()
                .filter_map(|register| register_ready.get(register))
                .copied()
                .max()
                .unwrap_or(0);
            let resource_ready = resources
                .iter()
                .filter_map(|resource| resource_free.get(resource))
                .copied()
                .max()
                .unwrap_or(0);
            let start = issue_start.max(operand_ready).max(resource_ready);
            issue_start = start.saturating_add(1);
            for resource in &resources {
                let free = start.saturating_add(occupancy);
                resource_free
                    .entry(resource)
                    .and_modify(|current| *current = (*current).max(free))
                    .or_insert(free);
            }
            let ready = start.saturating_add(latency);
            for register in &instruction.regs_write {
                register_ready
                    .entry(*register)
                    .and_modify(|current| *current = (*current).max(ready))
                    .or_insert(ready);
            }
            completion = completion.max(ready);
            fetch_cycles = fetch_cycles
                .saturating_add(profile.fetch_wait_cycles(instruction.address, instruction.size));
            if is_unknown {
                unknown.push((instruction.mnemonic.clone(), instruction.address));
            }
        }
        let base = issue_start.max(completion).saturating_add(fetch_cycles);
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
        (CostRange::new(min, max), unknown)
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
                    "cortex-m4-resource-dependency-model".to_owned(),
                );
                params.extras.insert(
                    "board_profile_pipeline_issue_width".to_owned(),
                    pipeline.issue_width().to_string(),
                );
                params.extras.insert(
                    "board_profile_pipeline_instruction_overrides".to_owned(),
                    pipeline.instruction_override_count().to_string(),
                );
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
                    "Branch prediction models conditional direction only; indirect/table target prediction, returns, branch-target buffers and global history are not modeled."
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
                params.extras.insert(
                    "board_profile_wcet".to_owned(),
                    "cfg-longest-path".to_owned(),
                );
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
                    "WCET results are CFG longest-path estimates over modeled block bounds; they are not a hardware proof."
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
        TimingInfo {
            models: vec![TimingModelInfo {
                id: TimingModelId::new(self.model.id()),
                arch: self.model.arch().to_owned(),
                core: Some(self.model.core().to_owned()),
                determinism: if self
                    .profile
                    .as_ref()
                    .is_some_and(|profile| profile.pipeline().is_some())
                {
                    Determinism::Statistical
                } else {
                    self.model.determinism()
                },
                table_version: "0.2.0-m3".to_owned(),
                params,
                caveats,
            }],
            frequency_domains,
            default_frequency_domain,
            caveats: vec![
                "Static timing estimates are not WCET bounds; loop bounds and execution counts are not inferred."
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
            if profile.pipeline().is_some() {
                caveats.retain(|caveat| {
                    !caveat.contains("Load/store and branch penalties are table-based")
                });
                caveats.push(
                    "Board-profile pipeline costs use an in-order resource/dependency model. Registers are assumed ready at block entry; memory dependencies, inter-block pipeline state, caches, branch prediction and exception entry are not modeled."
                        .to_owned(),
                );
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
            "ld" | "lw" | "lh" | "lb" | "lhu" | "lbu" | "lwu" | "lr" | "lr.w"
        )
}

fn is_store(mnemonic: &str) -> bool {
    mnemonic.starts_with("str")
        || mnemonic.starts_with("vstr")
        || mnemonic.starts_with("stp")
        || mnemonic.starts_with("stur")
        || matches!(
            mnemonic,
            "st" | "sw" | "sh" | "sb" | "sc" | "sc.w" | "amoswap" | "amoadd"
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
    use crate::arch::DecodedInsn;
    use crate::board_profile::BoardProfile;
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
    fn explicit_cpu_must_agree_with_profile() {
        let profile = board_profile();
        assert!(
            TimingCostModel::select(Some("cortex-m4"), Some(&profile), &image(ArchKind::Thumb))
                .is_err()
        );
        assert!(TimingCostModel::select(None, Some(&profile), &image(ArchKind::Aarch64)).is_err());
    }
}
