//! Branch-target-buffer analysis.
//!
//! The model is a set-associative LRU BTB indexed by branch PC. Only intra-
//! function control transfers are modeled: a taken conditional branch or a
//! jump probes one target. Fallthrough fetches, calls, returns and indirect
//! target prediction are outside this model. BTB state starts cold at each
//! function entry and is not propagated across call summaries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::board_profile::BtbProfile;
use crate::cfg::{CfgBlockBtb, CfgBtbInfo, CfgEdgeKind, FunctionCfg, ProgramCfg};

/// BTB geometry used by the state machine and the IPET model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BtbGeometry {
    pub(crate) sets: u64,
    pub(crate) ways: usize,
    pub(crate) miss_penalty: u32,
}

impl BtbGeometry {
    pub(crate) fn from_profile(profile: &BtbProfile) -> Self {
        Self {
            sets: profile.sets(),
            ways: usize::try_from(profile.ways()).unwrap_or(usize::MAX),
            miss_penalty: profile.miss_penalty(),
        }
    }

    fn set_index(&self, site: u64) -> u64 {
        (site >> 1) % self.sets.max(1)
    }

    /// Probes one target. Returns whether the access missed and the resulting
    /// LRU state.
    pub(crate) fn access(&self, state: &BtbState, site: u64, target: u64) -> (bool, BtbState) {
        let index = self.set_index(site);
        let mut entries = state.sets.get(&index).cloned().unwrap_or_default();
        if let Some(position) = entries
            .iter()
            .position(|entry| entry.site == site && entry.target == target)
        {
            let entry = entries.remove(position);
            entries.insert(0, entry);
            return (false, state.with_set(index, entries));
        }
        let miss = true;
        if let Some(position) = entries.iter().position(|entry| entry.site == site) {
            entries.remove(position);
        } else if entries.len() >= self.ways {
            entries.pop();
        }
        entries.insert(0, BtbEntry { site, target });
        (miss, state.with_set(index, entries))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BtbEntry {
    site: u64,
    target: u64,
}

/// Concrete LRU BTB state. Entries are stored most-recently-used first.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BtbState {
    sets: BTreeMap<u64, Vec<BtbEntry>>,
}

impl BtbState {
    fn with_set(&self, index: u64, entries: Vec<BtbEntry>) -> Self {
        let mut sets = self.sets.clone();
        if entries.is_empty() {
            sets.remove(&index);
        } else {
            sets.insert(index, entries);
        }
        Self { sets }
    }
}

struct FunctionBtbResult {
    fallback: bool,
    transfers: u32,
}

#[must_use]
pub(crate) fn analyze_program(program: &mut ProgramCfg, profile: &BtbProfile) -> CfgBtbInfo {
    let geometry = BtbGeometry::from_profile(profile);
    let mut info = CfgBtbInfo {
        model: "set-associative-lru".to_owned(),
        entries: profile.entries(),
        ways: profile.ways(),
        sets: profile.sets(),
        miss_penalty: profile.miss_penalty(),
        max_states: profile.max_states(),
        functions_analyzed: 0,
        functions_fallback: 0,
        transfers_analyzed: 0,
        transfers_fallback: 0,
        caveats: vec![
            "BTB state starts cold at each function entry; calls, returns, fallthrough fetches and inter-function BTB state are not modeled. Only taken conditional branches and jump edges probe a target."
                .to_owned(),
            "The BTB is set-associative and LRU; branch-target prediction for returns and indirect calls, target prefetch and cross-function replacement are not modeled."
                .to_owned(),
        ],
    };
    for function in &mut program.functions {
        if function.cfg.blocks_by_address.is_empty() {
            continue;
        }
        let result = analyze_function(&mut function.cfg, &geometry, profile.max_states());
        if result.transfers == 0 {
            continue;
        }
        if result.fallback {
            info.functions_fallback = info.functions_fallback.saturating_add(1);
            info.transfers_fallback = info.transfers_fallback.saturating_add(result.transfers);
        } else {
            info.functions_analyzed = info.functions_analyzed.saturating_add(1);
            info.transfers_analyzed = info.transfers_analyzed.saturating_add(result.transfers);
        }
    }
    info
}

fn analyze_function(
    cfg: &mut FunctionCfg,
    geometry: &BtbGeometry,
    max_states: usize,
) -> FunctionBtbResult {
    let Some(entry) = cfg.entry else {
        return FunctionBtbResult {
            fallback: false,
            transfers: 0,
        };
    };
    let transfer_blocks: BTreeSet<NodeIndex> = cfg
        .blocks_by_address
        .values()
        .copied()
        .filter(|node| {
            cfg.graph
                .edges_directed(*node, Direction::Outgoing)
                .any(|edge| probes_btb(edge.weight().kind))
        })
        .collect();
    if transfer_blocks.is_empty() {
        return FunctionBtbResult {
            fallback: false,
            transfers: 0,
        };
    }
    let mut entry_states: BTreeMap<NodeIndex, BTreeSet<BtbState>> = BTreeMap::new();
    let mut misses: BTreeMap<NodeIndex, (u32, u32)> = BTreeMap::new();
    let mut processed: BTreeSet<(NodeIndex, BtbState)> = BTreeSet::new();
    let mut queue: VecDeque<(NodeIndex, BtbState)> = VecDeque::new();
    entry_states
        .entry(entry)
        .or_default()
        .insert(BtbState::default());
    queue.push_back((entry, BtbState::default()));
    while let Some((node, state)) = queue.pop_front() {
        if !processed.insert((node, state.clone())) {
            continue;
        }
        for edge in cfg.graph.edges_directed(node, Direction::Outgoing) {
            let (miss, next) = if probes_btb(edge.weight().kind) {
                geometry.access(&state, edge.weight().site, cfg.graph[edge.target()].address)
            } else {
                (false, state.clone())
            };
            let range = misses.entry(node).or_insert((u32::MAX, 0));
            let miss = u32::from(miss);
            range.0 = range.0.min(miss);
            range.1 = range.1.max(miss);
            if !push_state(
                edge.target(),
                next,
                &mut entry_states,
                &mut queue,
                max_states,
            ) {
                return fallback_function(cfg, geometry, &transfer_blocks);
            }
        }
    }
    let mut transfers = 0_u32;
    for node in &transfer_blocks {
        let states = entry_states.get(node).map_or(0, BTreeSet::len);
        let Some((min, max)) = misses.get(node).copied() else {
            continue;
        };
        transfers = transfers.saturating_add(1);
        add_btb_penalty(
            &mut cfg.graph[*node].cycles,
            min,
            max,
            geometry.miss_penalty,
        );
        cfg.graph[*node].btb = Some(CfgBlockBtb {
            misses_min: min,
            misses_max: max,
            entry_states: u32::try_from(states).unwrap_or(u32::MAX),
            fallback: false,
        });
    }
    FunctionBtbResult {
        fallback: false,
        transfers,
    }
}

pub(crate) fn probes_btb(kind: CfgEdgeKind) -> bool {
    matches!(kind, CfgEdgeKind::Branch | CfgEdgeKind::Jump)
}

fn push_state(
    node: NodeIndex,
    state: BtbState,
    entry_states: &mut BTreeMap<NodeIndex, BTreeSet<BtbState>>,
    queue: &mut VecDeque<(NodeIndex, BtbState)>,
    max_states: usize,
) -> bool {
    let states = entry_states.entry(node).or_default();
    if !states.contains(&state) {
        if states.len() >= max_states {
            return false;
        }
        states.insert(state.clone());
        queue.push_back((node, state));
    }
    true
}

fn fallback_function(
    cfg: &mut FunctionCfg,
    geometry: &BtbGeometry,
    transfer_blocks: &BTreeSet<NodeIndex>,
) -> FunctionBtbResult {
    let mut transfers = 0_u32;
    for node in transfer_blocks {
        transfers = transfers.saturating_add(1);
        add_btb_penalty(&mut cfg.graph[*node].cycles, 0, 1, geometry.miss_penalty);
        cfg.graph[*node].btb = Some(CfgBlockBtb {
            misses_min: 0,
            misses_max: 1,
            entry_states: 0,
            fallback: true,
        });
    }
    FunctionBtbResult {
        fallback: true,
        transfers,
    }
}

fn add_btb_penalty(
    cycles: &mut Option<elf2tdg_schema::CostRange>,
    min: u32,
    max: u32,
    penalty: u32,
) {
    let Some(cycles) = cycles else {
        return;
    };
    cycles.min += f64::from(min.saturating_mul(penalty));
    cycles.max += f64::from(max.saturating_mul(penalty));
}

#[cfg(test)]
mod tests {
    use super::{BtbGeometry, BtbState, analyze_function};
    use crate::cfg::{CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgTerminator, FunctionCfg};
    use elf2tdg_schema::CostRange;

    fn geometry(sets: u64, ways: usize) -> BtbGeometry {
        BtbGeometry {
            sets,
            ways,
            miss_penalty: 2,
        }
    }

    #[test]
    fn maps_cold_and_repeated_targets() {
        let geometry = geometry(2, 2);
        let cold = BtbState::default();
        let (miss, state) = geometry.access(&cold, 0x1000, 0x2000);
        assert!(miss);
        let (miss, state) = geometry.access(&state, 0x1000, 0x2000);
        assert!(!miss);
        let (miss, _) = geometry.access(&state, 0x1000, 0x2004);
        assert!(miss, "a changed target must miss");
    }

    #[test]
    fn evicts_the_least_recently_used_entry() {
        let geometry = geometry(1, 2);
        let cold = BtbState::default();
        let (_, state) = geometry.access(&cold, 0x1000, 0x2000);
        let (_, state) = geometry.access(&state, 0x1004, 0x2004);
        let (_, state) = geometry.access(&state, 0x1000, 0x2000);
        let (_, state) = geometry.access(&state, 0x1008, 0x2008);
        let (miss, _) = geometry.access(&state, 0x1004, 0x2004);
        assert!(miss, "the oldest entry must have been evicted");
    }

    #[test]
    fn charges_a_cold_taken_branch_and_leaves_fallthrough_free() {
        let cfg = FunctionCfg::build(
            vec![
                CfgBlockDraft {
                    address: 0x1000,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Branch,
                },
                CfgBlockDraft {
                    address: 0x1002,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Return,
                },
                CfgBlockDraft {
                    address: 0x1004,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Return,
                },
            ],
            vec![
                CfgEdgeDraft {
                    from: 0x1000,
                    to: 0x1002,
                    kind: CfgEdgeKind::Branch,
                    site: 0x1000,
                    conditional: true,
                },
                CfgEdgeDraft {
                    from: 0x1000,
                    to: 0x1004,
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1000,
                    conditional: true,
                },
            ],
            Some(0x1000),
        );
        let mut cfg = cfg;
        let result = analyze_function(&mut cfg, &geometry(1, 1), 16);
        assert!(!result.fallback);
        assert_eq!(result.transfers, 1);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let btb = block.btb.as_ref().expect("BTB metadata");
        assert_eq!(btb.misses_min, 0);
        assert_eq!(btb.misses_max, 1);
        let cycles = block.cycles.expect("cycles");
        assert_eq!(cycles.min, 1.0);
        assert_eq!(cycles.max, 3.0);
    }

    #[test]
    fn separates_set_indices() {
        let geometry = geometry(2, 1);
        let cold = BtbState::default();
        let (_, state) = geometry.access(&cold, 0x1000, 0x2000);
        let (miss, state) = geometry.access(&state, 0x1002, 0x2004);
        assert!(miss, "a cold access in a different set still misses");
        let (miss, _) = geometry.access(&state, 0x1000, 0x2000);
        assert!(!miss, "different sets must not evict each other");
    }
}
