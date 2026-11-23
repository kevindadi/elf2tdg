//! Flow facts consumed by IPET.
//!
//! The first importer reads `[wcet]` from the board profile. The type is kept
//! separate from the profile so later importers (F4 `.ff`, FFX, inferred
//! bounds) can feed the same IPET model without changing the path analysis.

use std::collections::BTreeMap;

use crate::board_profile::WcetProfile;

/// Bounds and assumptions used by IPET for one analysis run.
#[derive(Clone, Debug, Default)]
pub(crate) struct FlowFacts {
    source: String,
    default_loop_bound: Option<u32>,
    bound_nonterminating_loops: bool,
    loop_bounds: BTreeMap<u64, u32>,
}

impl FlowFacts {
    /// Builds flow facts from the board profile's `[wcet]` section.
    pub(crate) fn from_wcet_profile(profile: &WcetProfile) -> Self {
        Self {
            source: "board-profile [wcet]".to_owned(),
            default_loop_bound: profile.default_loop_bound(),
            bound_nonterminating_loops: profile.bound_nonterminating_loops(),
            loop_bounds: profile.loop_bounds().collect(),
        }
    }

    /// Human-readable source of these facts.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// Default loop bound applied to loops without an explicit entry.
    pub(crate) fn default_loop_bound(&self) -> Option<u32> {
        self.default_loop_bound
    }

    /// Whether loops without a static exit are explicitly bounded.
    pub(crate) fn bound_nonterminating_loops(&self) -> bool {
        self.bound_nonterminating_loops
    }

    /// Returns the bound for a loop header, preferring an explicit entry.
    pub(crate) fn bound_for(&self, header: u64) -> Option<u32> {
        self.loop_bounds
            .get(&header)
            .copied()
            .or(self.default_loop_bound)
    }

    /// Explicit loop bounds keyed by header address.
    pub(crate) fn loops(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.loop_bounds
            .iter()
            .map(|(header, bound)| (*header, *bound))
    }
}

#[cfg(test)]
mod tests {
    use super::FlowFacts;
    use crate::board_profile::BoardProfile;

    fn profile(text: &str) -> BoardProfile {
        BoardProfile::parse_toml(text).expect("valid profile")
    }

    #[test]
    fn reads_default_and_explicit_loop_bounds() {
        let board = profile(
            r#"
schema_version = 2
id = "board:flow-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true

[[wcet.loop_bounds]]
header = 0x1000
bound = 12
"#,
        );
        let wcet = board.wcet().expect("wcet section");
        let facts = FlowFacts::from_wcet_profile(wcet);
        assert_eq!(facts.default_loop_bound(), Some(4));
        assert!(facts.bound_nonterminating_loops());
        assert_eq!(facts.bound_for(0x1000), Some(12));
        assert_eq!(facts.bound_for(0x2000), Some(4));
        assert_eq!(facts.loops().collect::<Vec<_>>(), vec![(0x1000, 12)]);
    }

    #[test]
    fn explicit_bound_wins_over_default() {
        let board = profile(
            r#"
schema_version = 2
id = "board:flow-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
default_loop_bound = 2

[[wcet.loop_bounds]]
header = 0x400
bound = 7
"#,
        );
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        assert_eq!(facts.bound_for(0x400), Some(7));
        assert_eq!(facts.bound_for(0x800), Some(2));
        assert!(!facts.bound_nonterminating_loops());
    }
}
