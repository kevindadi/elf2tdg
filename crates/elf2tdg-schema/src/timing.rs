//! Static timing metadata.
//!
//! The schema deliberately separates three things:
//!
//! 1. **cycles** — a model result, attached to basic blocks and optionally to
//!    individual instructions;
//! 2. **frequency domains** — wall-clock frequencies supplied by the user, a
//!    board profile, or recovered from the image;
//! 3. **time** — derived as `cycles / frequency`, never treated as a WCET
//!    bound.
//!
//! A timing model may be deterministic (simple in-order MCU), bounded
//! (pipeline/cache aware), or statistical (out-of-order cores). Consumers must
//! read [`Determinism`] before using cycle estimates for scheduling analysis.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::addr::Addr;
use crate::id::{FrequencyDomainId, TimingModelId};
use crate::model::Confidence;

/// All timing information attached to a program CFG.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimingInfo {
    /// Timing models used by at least one block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<TimingModelInfo>,
    /// Clock domains referenced by contexts and blocks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frequency_domains: Vec<FrequencyDomain>,
    /// Domain used when a block does not name one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_frequency_domain: Option<FrequencyDomainId>,
    /// Global limitations of the timing results (for example "no cache
    /// model").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

impl TimingInfo {
    /// Looks up a frequency domain by ID.
    #[must_use]
    pub fn frequency_domain(&self, id: &FrequencyDomainId) -> Option<&FrequencyDomain> {
        self.frequency_domains
            .iter()
            .find(|domain| &domain.id == id)
    }
}

/// Describes one timing model/table used by the analyzer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimingModelInfo {
    /// Stable model ID, for example `cortex-m4`.
    pub id: TimingModelId,
    /// ELF architecture string, for example `thumbv7em`.
    pub arch: String,
    /// Human-readable core name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<String>,
    /// How trustworthy a cycle count from this model is.
    pub determinism: Determinism,
    /// Version of the instruction-cost table.
    pub table_version: String,
    /// Configuration that influenced the model.
    #[serde(default)]
    pub params: TimingParams,
    /// Model-specific caveats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

/// Behavioral class of a timing model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Determinism {
    /// Exact for the modeled core and memory configuration, assuming the
    /// documented pipeline rules hold.
    Deterministic,
    /// A sound min/max range for the modeled configuration; not a WCET proof.
    Bounded,
    /// A throughput estimate for an out-of-order or otherwise unpredictable
    /// core. Not a bound.
    Statistical,
    /// No reliable model is available.
    Unknown,
}

/// Parameters that change instruction timing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimingParams {
    /// Flash wait states applied to instruction fetches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flash_wait_states: Option<u32>,
    /// Whether branch prediction is modeled/enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_prediction: Option<bool>,
    /// Cache configuration, when modeled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caches: Option<CacheParams>,
    /// Whether the core can dual-issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dual_issue: Option<bool>,
    /// Free-form model parameters for reproducibility.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extras: BTreeMap<String, String>,
}

/// Cache parameters used by a timing model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CacheParams {
    /// Instruction cache enabled.
    pub icache: bool,
    /// Data cache enabled.
    pub dcache: bool,
    /// Cache line size in bytes, when modeled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_bytes: Option<u32>,
}

/// A clock domain. Time is `cycles / hz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FrequencyDomain {
    /// Stable domain ID (`clk:...`).
    pub id: FrequencyDomainId,
    /// Human-readable name, for example `core` or `timer2`.
    pub name: String,
    /// Frequency in hertz. Must be greater than zero.
    pub hz: u64,
    /// Where the value came from.
    pub source: FrequencySource,
    /// Confidence in the value.
    pub confidence: Confidence,
}

/// Provenance of a frequency value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FrequencySource {
    /// Supplied on the command line.
    Cli,
    /// Supplied by a board/profile file.
    BoardProfile,
    /// Recovered from an ELF symbol with a known meaning.
    ElfSymbol,
    /// Recovered by matching clock-configuration code.
    CodePattern,
    /// Built-in default (usually only for tests).
    Default,
    /// Source is unknown.
    Unknown,
}

/// A closed interval of modeled cycle counts or nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CostRange {
    /// Lower bound, non-negative and finite.
    pub min: f64,
    /// Upper bound, non-negative and finite.
    pub max: f64,
}

impl CostRange {
    /// Creates a range without validating it. Use [`Self::is_valid`].
    #[must_use]
    pub fn new(min: f64, max: f64) -> Self {
        Self { min, max }
    }

    /// Creates an exact cost.
    #[must_use]
    pub fn exact(value: f64) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    /// Returns `true` when both bounds are finite, non-negative and ordered.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.min.is_finite()
            && self.max.is_finite()
            && self.min >= 0.0
            && self.max >= 0.0
            && self.min <= self.max
    }

    /// Converts cycles to nanoseconds at `hz`, returning `None` for an invalid
    /// frequency or an overflowing result.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // CPU frequencies are far below 2^53 Hz.
    pub fn time_ns(self, hz: u64) -> Option<Self> {
        if hz == 0 {
            return None;
        }
        let scale = 1_000_000_000.0 / hz as f64;
        let result = Self {
            min: self.min * scale,
            max: self.max * scale,
        };
        result.is_valid().then_some(result)
    }
}

/// Timing attached to a basic block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BlockTiming {
    /// Timing model ID. Must match a [`TimingModelInfo::id`] when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<TimingModelId>,
    /// Modeled cycle count for the block.
    pub cycles: CostRange,
    /// Derived wall-clock time, when a frequency is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<CostRange>,
    /// Frequency domain used to derive `time_ns`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency_domain: Option<FrequencyDomainId>,
    /// Confidence in the cycle/time estimate.
    pub confidence: Confidence,
    /// Assumptions and limitations specific to this block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

impl BlockTiming {
    /// Derives the block time at `hz`.
    #[must_use]
    pub fn time_ns_at(self, hz: u64) -> Option<CostRange> {
        self.cycles.time_ns(hz)
    }
}

/// Optional per-instruction timing detail. Producers may omit instructions to
/// keep documents small; block-level timing is always sufficient for
/// downstream aggregation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InstructionTiming {
    /// Instruction address.
    pub address: Addr,
    /// Instruction width in bytes.
    pub size: u8,
    /// Mnemonic as decoded, for example `ldr`.
    pub mnemonic: String,
    /// Disassembly text, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Modeled cost of this instruction.
    pub cycles: CostRange,
    /// Instruction-specific timing note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl InstructionTiming {
    /// Returns the address just past the instruction.
    #[must_use]
    pub fn end(&self) -> Option<Addr> {
        self.address.checked_add(u64::from(self.size))
    }
}

/// Aggregate, clearly non-execution-time cost of a function.
///
/// This is the sum of the static cost of the function's unique basic blocks. It
/// is useful for triage and visualization, but it is **not** a path time and
/// **not** a WCET estimate. Loops and shared blocks make the sum meaningless as
/// an execution time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionTiming {
    /// Sum of the modeled cost of all blocks in the function.
    pub static_block_sum_cycles: CostRange,
    /// Number of blocks that carry a timing estimate.
    pub modeled_blocks: u32,
    /// Number of blocks without a timing estimate.
    pub unmodeled_blocks: u32,
    /// Caveats that apply to the aggregate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::CostRange;

    #[test]
    fn converts_cycles_to_nanoseconds() {
        let time = CostRange::exact(10.0)
            .time_ns(100_000_000)
            .expect("valid conversion");
        assert!((time.min - 100.0).abs() < 1e-9);
        assert!((time.max - 100.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_zero_frequency() {
        assert!(CostRange::exact(1.0).time_ns(0).is_none());
    }

    #[test]
    fn rejects_invalid_ranges() {
        assert!(!CostRange::new(2.0, 1.0).is_valid());
        assert!(!CostRange::new(-1.0, 1.0).is_valid());
        assert!(!CostRange::new(f64::NAN, 1.0).is_valid());
        assert!(!CostRange::new(0.0, f64::INFINITY).is_valid());
        assert!(CostRange::new(1.0, 2.0).is_valid());
    }
}
