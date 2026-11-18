//! Board-specific timing profiles.
//!
//! A profile is a declarative, versioned description of a concrete board:
//! clock domains, executable memory regions and their fetch costs, and
//! instruction-cost overrides on top of a built-in core timing table. Loading a
//! profile never changes the default analysis; the caller opts in explicitly.
//!
//! Profiles are written as TOML (the default) or JSON. Every profile records
//! the SHA-256 of the loaded file so a TDG can name the exact timing input that
//! produced its cycle estimates.

use std::collections::BTreeSet;
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

const fn default_fetch_width() -> u32 {
    DEFAULT_FETCH_WIDTH_BYTES
}

const fn default_issue_width() -> u32 {
    1
}

const fn default_occupancy() -> u32 {
    1
}

/// A versioned description of one board's timing-relevant configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardProfile {
    schema_version: u32,
    id: String,
    #[serde(default)]
    name: Option<String>,
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
    /// Emit a TDG warning and use the fallback cost class.
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryRegion {
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
}

impl MemoryRegion {
    fn end(&self) -> Option<u64> {
        self.start.checked_add(self.size)
    }

    fn contains(&self, address: u64) -> bool {
        address
            .checked_sub(self.start)
            .is_some_and(|offset| offset < self.size)
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

    /// Parses and validates a TOML profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for invalid syntax or inconsistent data.
    pub fn parse_toml(text: &str) -> Result<Self> {
        let mut profile: Self = toml::from_str(text)
            .map_err(|error| Error::Config(format!("invalid board profile TOML: {error}")))?;
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
        profile.sha256 = Some(sha256_hex(text.as_bytes()));
        profile.validate()?;
        Ok(profile)
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
    use super::{BoardProfile, UnknownInstructionPolicy};

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
