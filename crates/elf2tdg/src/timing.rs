//! Instruction timing models.
//!
//! The tables intentionally produce bounded or statistical cycle estimates
//! rather than pretending to be a WCET proof. Cortex-M and generic RISC-V
//! models are selected automatically. Generic `AArch64` and `x86-64` models are
//! statistical throughput tables and must be selected explicitly with
//! `--cpu aarch64` or `--cpu x86-64`.

use elf2tdg_schema::{
    BlockTiming, CacheParams, Confidence, CostRange, Determinism, FrequencyDomain,
    FrequencyDomainId, FrequencySource, TimingInfo, TimingModelId, TimingModelInfo, TimingParams,
};

use crate::arch::DecodedInsn;
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

    /// Model parameters recorded in the TDG.
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
        let class = classify(insn);
        match self {
            Self::CortexM0 | Self::CortexM0Plus => cortex_m0_cost(class),
            Self::CortexM3 | Self::CortexM4 | Self::CortexM33 => cortex_m3_cost(class),
            Self::CortexM7 => cortex_m7_cost(class),
            Self::RiscV32 | Self::RiscV64 => riscv_cost(class),
            Self::Aarch64Generic => aarch64_cost(class),
            Self::X86_64Generic => x86_64_cost(class),
        }
    }

    /// Builds the TDG timing metadata.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InsnClass {
    Load,
    Store,
    PushPop,
    LdmStm,
    Branch,
    Call,
    Return,
    Multiply,
    Divide,
    Barrier,
    Nop,
    Alu,
    Other,
}

fn classify(insn: &DecodedInsn) -> InsnClass {
    if insn.is_return {
        return InsnClass::Return;
    }
    if insn.is_call {
        return InsnClass::Call;
    }
    if insn.is_jump {
        return InsnClass::Branch;
    }
    let mnemonic = insn
        .mnemonic
        .strip_suffix(".w")
        .or_else(|| insn.mnemonic.strip_suffix(".n"))
        .unwrap_or(insn.mnemonic.as_str());
    let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
    if mnemonic == "nop" {
        return InsnClass::Nop;
    }
    if matches!(mnemonic, "push" | "pop") || mnemonic.starts_with("push.") {
        return InsnClass::PushPop;
    }
    if mnemonic.starts_with("ldm") || mnemonic.starts_with("stm") {
        return InsnClass::LdmStm;
    }
    if is_load(mnemonic) {
        return InsnClass::Load;
    }
    if is_store(mnemonic) {
        return InsnClass::Store;
    }
    if is_multiply(mnemonic) {
        return InsnClass::Multiply;
    }
    if is_divide(mnemonic) {
        return InsnClass::Divide;
    }
    if is_barrier(mnemonic) {
        return InsnClass::Barrier;
    }
    if matches!(
        mnemonic,
        "udf" | "bkpt" | "svc" | "syscall" | "ecall" | "ebreak"
    ) {
        return InsnClass::Other;
    }
    InsnClass::Alu
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

fn cortex_m0_cost(class: InsnClass) -> CostRange {
    match class {
        InsnClass::Alu
        | InsnClass::Multiply
        | InsnClass::Nop
        | InsnClass::Divide
        | InsnClass::Barrier
        | InsnClass::Other => CostRange::exact(1.0),
        InsnClass::Load | InsnClass::Store => CostRange::exact(2.0),
        InsnClass::PushPop | InsnClass::Call | InsnClass::Return => CostRange::new(2.0, 4.0),
        InsnClass::LdmStm => CostRange::new(2.0, 6.0),
        InsnClass::Branch => CostRange::new(1.0, 3.0),
    }
}

fn cortex_m3_cost(class: InsnClass) -> CostRange {
    match class {
        InsnClass::Alu
        | InsnClass::Multiply
        | InsnClass::Nop
        | InsnClass::Store
        | InsnClass::Barrier
        | InsnClass::Other => CostRange::exact(1.0),
        InsnClass::Load => CostRange::exact(2.0),
        InsnClass::PushPop => CostRange::new(1.0, 4.0),
        InsnClass::LdmStm => CostRange::new(1.0, 6.0),
        InsnClass::Branch | InsnClass::Call | InsnClass::Return => CostRange::new(1.0, 3.0),
        InsnClass::Divide => CostRange::new(2.0, 12.0),
    }
}

fn cortex_m7_cost(class: InsnClass) -> CostRange {
    match class {
        InsnClass::Alu
        | InsnClass::Multiply
        | InsnClass::Nop
        | InsnClass::Load
        | InsnClass::Store
        | InsnClass::Branch => CostRange::new(1.0, 2.0),
        InsnClass::PushPop | InsnClass::LdmStm => CostRange::new(1.0, 5.0),
        InsnClass::Call | InsnClass::Return => CostRange::new(2.0, 4.0),
        InsnClass::Divide => CostRange::new(2.0, 12.0),
        InsnClass::Barrier | InsnClass::Other => CostRange::exact(1.0),
    }
}

fn riscv_cost(class: InsnClass) -> CostRange {
    match class {
        InsnClass::Alu
        | InsnClass::Nop
        | InsnClass::Store
        | InsnClass::Barrier
        | InsnClass::Other => CostRange::exact(1.0),
        InsnClass::Load => CostRange::exact(2.0),
        InsnClass::PushPop | InsnClass::LdmStm | InsnClass::Multiply => CostRange::new(1.0, 3.0),
        InsnClass::Branch | InsnClass::Call | InsnClass::Return => CostRange::new(1.0, 2.0),
        InsnClass::Divide => CostRange::new(2.0, 20.0),
    }
}

fn aarch64_cost(class: InsnClass) -> CostRange {
    match class {
        InsnClass::Alu | InsnClass::Nop | InsnClass::Other => CostRange::new(1.0, 2.0),
        InsnClass::Load | InsnClass::Store => CostRange::new(2.0, 5.0),
        InsnClass::PushPop | InsnClass::LdmStm | InsnClass::Multiply => CostRange::new(2.0, 4.0),
        InsnClass::Branch | InsnClass::Barrier => CostRange::new(1.0, 4.0),
        InsnClass::Call | InsnClass::Return => CostRange::new(1.0, 5.0),
        InsnClass::Divide => CostRange::new(8.0, 20.0),
    }
}

fn x86_64_cost(class: InsnClass) -> CostRange {
    match class {
        InsnClass::Alu | InsnClass::Nop | InsnClass::Store => CostRange::new(1.0, 2.0),
        InsnClass::Load => CostRange::new(1.0, 5.0),
        InsnClass::PushPop | InsnClass::LdmStm | InsnClass::Other => CostRange::new(1.0, 3.0),
        InsnClass::Branch => CostRange::new(1.0, 20.0),
        InsnClass::Call | InsnClass::Return => CostRange::new(2.0, 10.0),
        InsnClass::Multiply => CostRange::new(3.0, 5.0),
        InsnClass::Divide => CostRange::new(20.0, 40.0),
        InsnClass::Barrier => CostRange::new(1.0, 10.0),
    }
}

#[cfg(test)]
mod tests {
    use super::{TimingModel, parse_frequency};
    use crate::arch::DecodedInsn;
    use crate::loader::{ArchKind, ByteOrder, ElfKind, Image, Section};

    fn image(arch: ArchKind) -> Image {
        Image {
            path: "synthetic.elf".into(),
            arch,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::default(),
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
            indirect: None,
            compare: None,
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
            indirect: None,
            compare: None,
        });
        let timed = model.block_timing(cycles, Some(168_000_000));
        assert!(timed.time_ns.is_some());
        let untimed = model.block_timing(cycles, None);
        assert!(untimed.time_ns.is_none());
    }
}
