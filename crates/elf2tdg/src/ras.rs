//! Return-address-stack analysis.
//!
//! The model keeps a bounded LIFO stack of return addresses. A function starts
//! with one symbolic caller-return entry. Each call-return edge models the
//! callee return as a push of the continuation address followed by a pop; the
//! push can evict the oldest entry when the stack is full. A function return
//! is a hit only when the symbolic entry is still on top. Indirect return
//! prediction, recursive nesting and cross-function stack occupancy are not
//! modeled.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::board_profile::RasProfile;
use crate::cfg::{CfgBlockRas, CfgEdgeKind, CfgRasInfo, CfgTerminator, FunctionCfg, ProgramCfg};

const ENTRY_TOKEN: u64 = u64::MAX;

/// Concrete return-address stack, oldest entry first and top last.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RasState {
    stack: Vec<u64>,
}

impl RasState {
    pub(crate) fn entry() -> Self {
        Self {
            stack: vec![ENTRY_TOKEN],
        }
    }

    /// Models a call and the callee's matching return. The continuation is
    /// pushed and immediately popped; the net effect is the stack after a
    /// possible capacity eviction.
    pub(crate) fn call_return(&self, continuation: u64, entries: usize) -> Self {
        let mut stack = self.stack.clone();
        if entries == 0 {
            stack.clear();
            return Self { stack };
        }
        while stack.len() >= entries {
            stack.remove(0);
        }
        stack.push(continuation);
        stack.pop();
        Self { stack }
    }

    /// Whether the function return pops the expected symbolic caller entry.
    pub(crate) fn return_miss(&self) -> bool {
        self.stack.last().copied() != Some(ENTRY_TOKEN)
    }
}

struct FunctionRasResult {
    fallback: bool,
    returns: u32,
}

#[must_use]
pub(crate) fn analyze_program(program: &mut ProgramCfg, profile: &RasProfile) -> CfgRasInfo {
    let entries = usize::try_from(profile.entries()).unwrap_or(usize::MAX);
    let mut info = CfgRasInfo {
        model: "bounded-lifo".to_owned(),
        entries: profile.entries(),
        miss_penalty: profile.miss_penalty(),
        max_states: profile.max_states(),
        functions_analyzed: 0,
        functions_fallback: 0,
        returns_analyzed: 0,
        returns_fallback: 0,
        caveats: vec![
            "Each function starts with one symbolic caller-return entry. A call-return edge pushes and pops its continuation; a full stack evicts the oldest entry. Recursive nesting, indirect return target prediction and cross-function stack occupancy are not modeled."
                .to_owned(),
            "A function return is a hit only when the symbolic entry is on top; returns after capacity eviction are charged as misses. The model is statistical and not a hardware proof."
                .to_owned(),
        ],
    };
    for function in &mut program.functions {
        if function.cfg.blocks_by_address.is_empty() {
            continue;
        }
        let result = analyze_function(
            &mut function.cfg,
            entries,
            profile.miss_penalty(),
            profile.max_states(),
        );
        if result.returns == 0 {
            continue;
        }
        if result.fallback {
            info.functions_fallback = info.functions_fallback.saturating_add(1);
            info.returns_fallback = info.returns_fallback.saturating_add(result.returns);
        } else {
            info.functions_analyzed = info.functions_analyzed.saturating_add(1);
            info.returns_analyzed = info.returns_analyzed.saturating_add(result.returns);
        }
    }
    info
}

fn analyze_function(
    cfg: &mut FunctionCfg,
    entries: usize,
    miss_penalty: u32,
    max_states: usize,
) -> FunctionRasResult {
    let Some(entry) = cfg.entry else {
        return FunctionRasResult {
            fallback: false,
            returns: 0,
        };
    };
    let return_blocks: BTreeSet<NodeIndex> = cfg
        .blocks_by_address
        .values()
        .copied()
        .filter(|node| cfg.graph[*node].terminator == CfgTerminator::Return)
        .collect();
    if return_blocks.is_empty() {
        return FunctionRasResult {
            fallback: false,
            returns: 0,
        };
    }
    let mut entry_states: BTreeMap<NodeIndex, BTreeSet<RasState>> = BTreeMap::new();
    let mut processed: BTreeSet<(NodeIndex, RasState)> = BTreeSet::new();
    let mut queue: VecDeque<(NodeIndex, RasState)> = VecDeque::new();
    let initial = RasState::entry();
    entry_states
        .entry(entry)
        .or_default()
        .insert(initial.clone());
    queue.push_back((entry, initial));
    while let Some((node, state)) = queue.pop_front() {
        if !processed.insert((node, state.clone())) {
            continue;
        }
        for edge in cfg.graph.edges_directed(node, Direction::Outgoing) {
            let next = if edge.weight().kind == CfgEdgeKind::CallReturn {
                state.call_return(cfg.graph[edge.target()].address, entries)
            } else {
                state.clone()
            };
            if !push_state(
                edge.target(),
                next,
                &mut entry_states,
                &mut queue,
                max_states,
            ) {
                return fallback_function(cfg, miss_penalty, &return_blocks);
            }
        }
    }
    let mut returns = 0_u32;
    for node in &return_blocks {
        let states = entry_states.get(node).cloned().unwrap_or_default();
        if states.is_empty() {
            continue;
        }
        returns = returns.saturating_add(1);
        let min = u32::from(states.iter().all(RasState::return_miss));
        let max = u32::from(states.iter().any(RasState::return_miss));
        add_ras_penalty(&mut cfg.graph[*node].cycles, min, max, miss_penalty);
        cfg.graph[*node].ras = Some(CfgBlockRas {
            misses_min: min,
            misses_max: max,
            entry_states: u32::try_from(states.len()).unwrap_or(u32::MAX),
            fallback: false,
        });
    }
    FunctionRasResult {
        fallback: false,
        returns,
    }
}

fn push_state(
    node: NodeIndex,
    state: RasState,
    entry_states: &mut BTreeMap<NodeIndex, BTreeSet<RasState>>,
    queue: &mut VecDeque<(NodeIndex, RasState)>,
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
    miss_penalty: u32,
    return_blocks: &BTreeSet<NodeIndex>,
) -> FunctionRasResult {
    let mut returns = 0_u32;
    for node in return_blocks {
        returns = returns.saturating_add(1);
        add_ras_penalty(&mut cfg.graph[*node].cycles, 0, 1, miss_penalty);
        cfg.graph[*node].ras = Some(CfgBlockRas {
            misses_min: 0,
            misses_max: 1,
            entry_states: 0,
            fallback: true,
        });
    }
    FunctionRasResult {
        fallback: true,
        returns,
    }
}

fn add_ras_penalty(
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
    use super::{RasState, analyze_function};
    use crate::cfg::{CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgTerminator, FunctionCfg};
    use elf2tdg_schema::CostRange;

    #[test]
    fn keeps_the_symbolic_return_when_capacity_allows() {
        let state = RasState::entry();
        assert!(!state.return_miss());
        let state = state.call_return(0x2000, 2);
        assert!(!state.return_miss());
    }

    #[test]
    fn evicts_the_entry_token_when_capacity_is_one() {
        let state = RasState::entry().call_return(0x2000, 1);
        assert!(state.return_miss());
    }

    #[test]
    fn charges_a_return_after_entry_token_eviction() {
        let mut cfg = FunctionCfg::build(
            vec![
                CfgBlockDraft {
                    address: 0x1000,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Fallthrough,
                },
                CfgBlockDraft {
                    address: 0x1002,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Call,
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
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1000,
                    conditional: false,
                },
                CfgEdgeDraft {
                    from: 0x1002,
                    to: 0x1004,
                    kind: CfgEdgeKind::CallReturn,
                    site: 0x1002,
                    conditional: false,
                },
            ],
            Some(0x1000),
        );
        let result = analyze_function(&mut cfg, 1, 2, 16);
        assert!(!result.fallback);
        assert_eq!(result.returns, 1);
        let return_block = &cfg.graph[cfg.blocks_by_address[&0x1004]];
        let ras = return_block.ras.as_ref().expect("RAS metadata");
        assert_eq!(ras.misses_min, 1);
        assert_eq!(ras.misses_max, 1);
        assert_eq!(return_block.cycles.expect("cycles").max, 3.0);
    }

    #[test]
    fn large_capacity_keeps_the_return_hit() {
        let mut cfg = FunctionCfg::build(
            vec![
                CfgBlockDraft {
                    address: 0x1000,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Fallthrough,
                },
                CfgBlockDraft {
                    address: 0x1002,
                    size: 2,
                    instructions: Vec::new(),
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Call,
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
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1000,
                    conditional: false,
                },
                CfgEdgeDraft {
                    from: 0x1002,
                    to: 0x1004,
                    kind: CfgEdgeKind::CallReturn,
                    site: 0x1002,
                    conditional: false,
                },
            ],
            Some(0x1000),
        );
        let result = analyze_function(&mut cfg, 4, 2, 16);
        assert!(!result.fallback);
        let return_block = &cfg.graph[cfg.blocks_by_address[&0x1004]];
        let ras = return_block.ras.as_ref().expect("RAS metadata");
        assert_eq!(ras.misses_max, 0);
        assert_eq!(return_block.cycles.expect("cycles").max, 1.0);
    }
}
