//! Compile-time analysis pass catalog and planning.
//!
//! `elf2tdg` deliberately uses a compile-time pass registry rather than a
//! runtime dynamic-library ABI. A pass declares its stable identifier, its
//! dependencies, the facts it provides and the strength of its correctness
//! claim. The CLI exposes this plan through `--list-passes`, and the text
//! report uses the same vocabulary.
//!
//! The catalog is intentionally descriptive for now: the existing analyses are
//! still invoked directly by the analyzer. As passes are migrated behind the
//! registry, this metadata becomes the scheduler input without changing the
//! public identifiers.

use std::fmt::Write as _;

use crate::analysis::PathAnalysis;
use crate::board_profile::BoardProfile;

/// Role of an analysis pass in the pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassKind {
    /// Builds the program IR or CFG.
    Frontend,
    /// Produces instruction, block or pipeline costs.
    Timing,
    /// Produces a microarchitectural fact such as cache or branch state.
    Analysis,
    /// Computes a path bound from costs and flow facts.
    PathAnalysis,
    /// Renders an analysis result.
    Report,
}

impl PassKind {
    /// Returns the stable display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frontend => "frontend",
            Self::Timing => "timing",
            Self::Analysis => "analysis",
            Self::PathAnalysis => "path-analysis",
            Self::Report => "report",
        }
    }
}

/// Strength of the correctness claim made by a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Soundness {
    /// The pass does not compute a timing bound.
    NotApplicable,
    /// The pass builds the program model but does not claim a bound.
    ModelOnly,
    /// The result is safe only under the configured model and assumptions.
    ModelDependent,
    /// The result is a conservative upper bound under documented assumptions.
    SafeUpperBound,
    /// The result is an estimate and may not be a sound upper bound.
    Estimate,
    /// The pass is planned but not implemented in this build.
    Planned,
}

impl Soundness {
    /// Returns the stable display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::ModelOnly => "model-only",
            Self::ModelDependent => "model-dependent",
            Self::SafeUpperBound => "safe-upper-bound",
            Self::Estimate => "estimate",
            Self::Planned => "planned",
        }
    }
}

/// Availability of a pass in the current build and profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassStatus {
    /// The pass is enabled by the current build/profile.
    Enabled,
    /// The pass is not enabled by the current build/profile.
    Disabled,
}

impl PassStatus {
    /// Returns the stable display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// Static metadata for one analysis pass.
#[derive(Clone, Copy, Debug)]
pub struct PassInfo {
    /// Stable pass identifier.
    pub id: &'static str,
    /// Human-readable title.
    pub title: &'static str,
    /// Pipeline role.
    pub kind: PassKind,
    /// Fact identifiers this pass consumes.
    pub requires: &'static [&'static str],
    /// Fact identifiers this pass produces.
    pub provides: &'static [&'static str],
    /// Correctness claim of this pass.
    pub soundness: Soundness,
}

/// A pass together with its current availability.
#[derive(Clone, Copy, Debug)]
pub struct PlannedPass {
    /// Static pass metadata.
    pub info: PassInfo,
    /// Current availability.
    pub status: PassStatus,
    /// Why the pass is enabled or disabled.
    pub reason: &'static str,
}

/// Built-in pass catalog, in scheduling order.
pub const BUILTIN_PASSES: &[PassInfo] = &[
    PassInfo {
        id: "frontend.cfg-recovery",
        title: "ELF loading, function discovery and CFG recovery",
        kind: PassKind::Frontend,
        requires: &[],
        provides: &["ir.functions", "ir.cfg", "ir.roots", "ir.calls"],
        soundness: Soundness::ModelOnly,
    },
    PassInfo {
        id: "timing.instruction-cost",
        title: "Instruction and basic-block cost model",
        kind: PassKind::Timing,
        requires: &["ir.functions", "ir.cfg"],
        provides: &["timing.instruction-costs", "timing.block-costs"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "analysis.instruction-cache",
        title: "LRU instruction-cache state analysis",
        kind: PassKind::Analysis,
        requires: &["ir.cfg", "timing.block-costs"],
        provides: &["analysis.icache"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "analysis.data-cache",
        title: "LRU data-cache state analysis",
        kind: PassKind::Analysis,
        requires: &["ir.cfg", "timing.block-costs"],
        provides: &["analysis.dcache"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "analysis.branch-prediction",
        title: "Branch-prediction penalty analysis",
        kind: PassKind::Analysis,
        requires: &["ir.cfg", "timing.block-costs"],
        provides: &["analysis.branch-prediction"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "analysis.data-memory",
        title: "Region-based data-memory wait-state analysis",
        kind: PassKind::Analysis,
        requires: &["ir.cfg", "timing.block-costs"],
        provides: &["analysis.data-memory"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "analysis.multicore",
        title: "Multicore access-budget interference",
        kind: PassKind::Analysis,
        requires: &["ir.cfg", "timing.block-costs"],
        provides: &["analysis.multicore"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "flow.facts",
        title: "Loop bounds, inferred counts and context-sensitive flow facts",
        kind: PassKind::Analysis,
        requires: &["ir.cfg"],
        provides: &["flow.facts"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "flow.auto-loop-bounds",
        title: "Conservative counted-loop bound inference",
        kind: PassKind::Analysis,
        requires: &["ir.cfg", "ir.instructions"],
        provides: &["flow.facts"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "wcet.longest-path",
        title: "CFG longest-path WCET summary",
        kind: PassKind::PathAnalysis,
        requires: &["ir.cfg", "ir.calls", "timing.block-costs", "flow.facts"],
        provides: &["wcet.function", "wcet.root"],
        soundness: Soundness::Estimate,
    },
    PassInfo {
        id: "wcet.ipet",
        title: "IPET/ILP WCET analysis with flow facts",
        kind: PassKind::PathAnalysis,
        requires: &[
            "ir.cfg",
            "ir.calls",
            "timing.block-costs",
            "flow.facts",
            "analysis.constraints",
        ],
        provides: &["wcet.function", "wcet.root", "wcet.ilp-model"],
        soundness: Soundness::SafeUpperBound,
    },
    PassInfo {
        id: "system.layered-model",
        title: "Layered task/resource model and coarse system bound",
        kind: PassKind::Analysis,
        requires: &["ir.roots", "wcet.function", "wcet.root"],
        provides: &["system.model", "system.petri", "system.bound"],
        soundness: Soundness::ModelDependent,
    },
    PassInfo {
        id: "report.text",
        title: "Human-readable CFG and WCET report",
        kind: PassKind::Report,
        requires: &["ir.cfg"],
        provides: &["report.text"],
        soundness: Soundness::NotApplicable,
    },
];

/// Builds the pass plan for the current build, board profile and selected
/// WCET path-analysis backend.
///
/// Optional microarchitectural passes are enabled only when the profile
/// contains the corresponding section. Exactly one of `wcet.longest-path` and
/// `wcet.ipet` is enabled when the profile contains `[wcet]`.
#[must_use]
pub fn plan(profile: Option<&BoardProfile>, path_analysis: PathAnalysis) -> Vec<PlannedPass> {
    BUILTIN_PASSES
        .iter()
        .map(|info| {
            let (status, reason) = match info.id {
                "analysis.instruction-cache" => optional(
                    profile.is_some_and(|profile| profile.instruction_cache().is_some()),
                    "no [instruction_cache] section in the board profile",
                    "[instruction_cache] is present in the board profile",
                ),
                "analysis.data-cache" => optional(
                    profile.is_some_and(|profile| profile.data_cache().is_some()),
                    "no [data_cache] section in the board profile",
                    "[data_cache] is present in the board profile",
                ),
                "analysis.branch-prediction" => optional(
                    profile.is_some_and(|profile| profile.branch_prediction().is_some()),
                    "no [branch_prediction] section in the board profile",
                    "[branch_prediction] is present in the board profile",
                ),
                "analysis.data-memory" => optional(
                    profile.is_some_and(BoardProfile::data_memory_enabled),
                    "no memory region declares data wait states",
                    "a memory region declares data wait states",
                ),
                "analysis.multicore" => optional(
                    profile.is_some_and(|profile| profile.multicore().is_some()),
                    "no [multicore] section in the board profile",
                    "[multicore] is present in the board profile",
                ),
                "flow.facts" => optional(
                    profile.is_some_and(|profile| profile.wcet().is_some()),
                    "no [wcet] section in the board profile",
                    "[wcet] is present; --flowfacts files are merged at analysis time",
                ),
                "flow.auto-loop-bounds" => optional(
                    profile
                        .and_then(BoardProfile::wcet)
                        .is_some_and(crate::board_profile::WcetProfile::auto_loop_bounds),
                    "no [wcet] section with auto_loop_bounds enabled",
                    "[wcet] enables conservative counted-loop inference",
                ),
                "wcet.longest-path" => path_analysis_pass(
                    profile,
                    path_analysis,
                    PathAnalysis::LongestPath,
                    "select --path-analysis longest-path",
                ),
                "wcet.ipet" => path_analysis_pass(
                    profile,
                    path_analysis,
                    PathAnalysis::Ipet,
                    "select --path-analysis ipet",
                ),
                "system.layered-model" => optional(
                    profile.is_some_and(|profile| profile.wcet().is_some()),
                    "no [wcet] section in the board profile",
                    "[wcet] is present; the model is built after per-root WCET",
                ),
                "report.text" => (PassStatus::Enabled, "always available"),
                _ => (PassStatus::Enabled, "built in"),
            };
            PlannedPass {
                info: *info,
                status,
                reason,
            }
        })
        .collect()
}

fn optional(
    enabled: bool,
    disabled_reason: &'static str,
    enabled_reason: &'static str,
) -> (PassStatus, &'static str) {
    if enabled {
        (PassStatus::Enabled, enabled_reason)
    } else {
        (PassStatus::Disabled, disabled_reason)
    }
}

fn path_analysis_pass(
    profile: Option<&BoardProfile>,
    selected: PathAnalysis,
    wanted: PathAnalysis,
    other_selected: &'static str,
) -> (PassStatus, &'static str) {
    if profile.is_none_or(|profile| profile.wcet().is_none()) {
        return (
            PassStatus::Disabled,
            "no [wcet] section in the board profile",
        );
    }
    if selected == wanted {
        let reason = match wanted {
            PathAnalysis::LongestPath => "selected --path-analysis longest-path",
            PathAnalysis::Ipet => "selected --path-analysis ipet",
        };
        (PassStatus::Enabled, reason)
    } else {
        (PassStatus::Disabled, other_selected)
    }
}

/// Renders the pass plan as a human-readable report.
#[must_use]
pub fn render_plan(plan: &[PlannedPass]) -> String {
    let mut out = String::from("ANALYSIS PASS PLAN\n==================\n\n");
    let _ = writeln!(
        out,
        "Compile-time pass catalog; enabled passes depend on the selected board profile.\n"
    );
    for pass in plan {
        let _ = writeln!(out, "* {}  [{}]", pass.info.id, pass.status.as_str());
        let _ = writeln!(out, "  title:      {}", pass.info.title);
        let _ = writeln!(out, "  kind:       {}", pass.info.kind.as_str());
        let _ = writeln!(out, "  soundness:  {}", pass.info.soundness.as_str());
        let _ = writeln!(out, "  requires:   {}", join_or_dash(pass.info.requires));
        let _ = writeln!(out, "  provides:   {}", join_or_dash(pass.info.provides));
        let _ = writeln!(
            out,
            "  status:     {} ({})",
            pass.status.as_str(),
            pass.reason
        );
        out.push('\n');
    }
    out
}

fn join_or_dash(items: &[&str]) -> String {
    if items.is_empty() {
        "-".to_owned()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{BUILTIN_PASSES, PassStatus, plan};
    use crate::analysis::PathAnalysis;
    use crate::board_profile::BoardProfile;

    fn wcet_profile() -> BoardProfile {
        BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:pass-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
default_loop_bound = 4
"#,
        )
        .expect("valid profile")
    }

    #[test]
    fn pass_ids_are_unique() {
        let mut ids: Vec<&str> = BUILTIN_PASSES.iter().map(|pass| pass.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), BUILTIN_PASSES.len());
    }

    #[test]
    fn ipet_requires_a_wcet_profile_and_selection() {
        let states = plan(None, PathAnalysis::Ipet);
        let ipet = states
            .iter()
            .find(|pass| pass.info.id == "wcet.ipet")
            .expect("IPET descriptor");
        assert_eq!(ipet.status, PassStatus::Disabled);
        assert!(ipet.reason.contains("no [wcet]"));

        let board = wcet_profile();
        let states = plan(Some(&board), PathAnalysis::Ipet);
        let ipet = states
            .iter()
            .find(|pass| pass.info.id == "wcet.ipet")
            .expect("IPET descriptor");
        assert_eq!(ipet.status, PassStatus::Enabled);
        let longest_path = states
            .iter()
            .find(|pass| pass.info.id == "wcet.longest-path")
            .expect("longest-path descriptor");
        assert_eq!(longest_path.status, PassStatus::Disabled);
        assert!(longest_path.reason.contains("--path-analysis longest-path"));
        let layered = states
            .iter()
            .find(|pass| pass.info.id == "system.layered-model")
            .expect("layered model descriptor");
        assert_eq!(layered.status, PassStatus::Enabled);

        let states = plan(Some(&board), PathAnalysis::LongestPath);
        let ipet = states
            .iter()
            .find(|pass| pass.info.id == "wcet.ipet")
            .expect("IPET descriptor");
        assert_eq!(ipet.status, PassStatus::Disabled);
        assert!(ipet.reason.contains("--path-analysis ipet"));
        let longest_path = states
            .iter()
            .find(|pass| pass.info.id == "wcet.longest-path")
            .expect("longest-path descriptor");
        assert_eq!(longest_path.status, PassStatus::Enabled);
    }

    #[test]
    fn auto_loop_bounds_pass_follows_the_profile() {
        let enabled = wcet_profile();
        let states = plan(Some(&enabled), PathAnalysis::LongestPath);
        let pass = states
            .iter()
            .find(|pass| pass.info.id == "flow.auto-loop-bounds")
            .expect("auto-loop-bound descriptor");
        assert_eq!(pass.status, PassStatus::Enabled);

        let disabled = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:pass-test-no-auto"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
auto_loop_bounds = false
"#,
        )
        .expect("valid profile");
        let states = plan(Some(&disabled), PathAnalysis::LongestPath);
        let pass = states
            .iter()
            .find(|pass| pass.info.id == "flow.auto-loop-bounds")
            .expect("auto-loop-bound descriptor");
        assert_eq!(pass.status, PassStatus::Disabled);
    }

    #[test]
    fn optional_passes_are_disabled_without_a_profile() {
        let states = plan(None, PathAnalysis::LongestPath);
        for id in [
            "analysis.instruction-cache",
            "analysis.data-cache",
            "analysis.branch-prediction",
            "analysis.data-memory",
            "analysis.multicore",
            "flow.facts",
            "flow.auto-loop-bounds",
            "wcet.longest-path",
            "wcet.ipet",
            "system.layered-model",
        ] {
            let pass = states
                .iter()
                .find(|pass| pass.info.id == id)
                .expect("descriptor");
            assert_eq!(pass.status, PassStatus::Disabled, "{id}");
        }
    }
}
