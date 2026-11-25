//! Static branch-prediction analysis.
//!
//! The analysis walks each function CFG with concrete predictor states. Static
//! policies need no state; the two-bit bimodal model keeps one saturating
//! counter per modeled branch site. Conditional branches are predicted and
//! charged a misprediction penalty when the modeled direction differs from the
//! actual CFG edge.
//!
//! Only conditional branches with exactly one taken edge and one fallthrough
//! edge are modeled. Indirect/table target prediction, return-address stacks,
//! branch-target buffers and global branch history are outside this scope.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use elf2tdg_schema::{Addr, CostRange};

use crate::board_profile::{BranchPredictionModel, BranchPredictionProfile, FirstExecutionHistory};
use crate::cfg::{
    CfgBlockBranchPrediction, CfgBranchDirection, CfgBranchOutcome, CfgBranchPredictionInfo,
    CfgBranchPredictionOutcome, CfgEdgeKind, CfgTerminator, FunctionCfg, ProgramCfg,
};

pub(crate) struct PredictorModel {
    model: BranchPredictionModel,
    mispredict_penalty: u32,
    initial_state: u8,
    first_execution_unknown: bool,
    history_bits: u8,
    initial_history: u64,
    max_states: usize,
}

impl PredictorModel {
    pub(crate) fn from_profile(profile: &BranchPredictionProfile) -> Self {
        let first_execution_unknown = matches!(
            profile.model(),
            BranchPredictionModel::Bimodal
                | BranchPredictionModel::GlobalHistory
                | BranchPredictionModel::Gshare
                | BranchPredictionModel::LocalHistory
        ) && profile.first_execution()
            == FirstExecutionHistory::Unknown;
        Self {
            model: profile.model(),
            mispredict_penalty: profile.mispredict_penalty(),
            initial_state: profile.initial_counter(),
            first_execution_unknown,
            history_bits: profile.history_bits().unwrap_or(0),
            initial_history: profile.initial_history().unwrap_or(0),
            max_states: profile.max_states(),
        }
    }

    pub(crate) fn entry_state(&self) -> PredictorState {
        if self.is_global_history() {
            PredictorState {
                history: self.initial_history & self.history_mask(),
                ..PredictorState::default()
            }
        } else {
            PredictorState::default()
        }
    }

    fn is_global_history(&self) -> bool {
        matches!(
            self.model,
            BranchPredictionModel::GlobalHistory | BranchPredictionModel::Gshare
        )
    }

    fn history_mask(&self) -> u64 {
        if self.history_bits == 0 {
            0
        } else if self.history_bits >= 64 {
            u64::MAX
        } else {
            (1_u64 << self.history_bits) - 1
        }
    }

    fn counter_key(&self, state: &PredictorState, site: u64) -> (u64, u64) {
        match self.model {
            BranchPredictionModel::GlobalHistory => (0, state.history & self.history_mask()),
            BranchPredictionModel::Gshare => {
                (0, (state.history ^ (site >> 1)) & self.history_mask())
            }
            BranchPredictionModel::LocalHistory => (
                site,
                state.local_history(site, self.initial_history) & self.history_mask(),
            ),
            BranchPredictionModel::StaticNotTaken
            | BranchPredictionModel::StaticTaken
            | BranchPredictionModel::Btfn
            | BranchPredictionModel::Bimodal => (site, 0),
        }
    }

    fn predict_counter(
        &self,
        _site: u64,
        taken_is_backward: bool,
        counter: u8,
    ) -> CfgBranchDirection {
        match self.model {
            BranchPredictionModel::StaticNotTaken => CfgBranchDirection::NotTaken,
            BranchPredictionModel::StaticTaken => CfgBranchDirection::Taken,
            BranchPredictionModel::Btfn => {
                if taken_is_backward {
                    CfgBranchDirection::Taken
                } else {
                    CfgBranchDirection::NotTaken
                }
            }
            BranchPredictionModel::Bimodal
            | BranchPredictionModel::GlobalHistory
            | BranchPredictionModel::Gshare
            | BranchPredictionModel::LocalHistory => {
                if counter >= 2 {
                    CfgBranchDirection::Taken
                } else {
                    CfgBranchDirection::NotTaken
                }
            }
        }
    }

    /// Counters that must be considered at `site` for this state.
    ///
    /// A known table entry has one value. An unexecuted entry under the
    /// unknown first-execution policy has all four two-bit values.
    pub(crate) fn possible_counters(&self, state: &PredictorState, site: u64) -> Vec<u8> {
        let key = self.counter_key(state, site);
        if self.first_execution_unknown && !state.seen(key) {
            (0..=3).collect()
        } else {
            vec![state.counter(key, self.initial_state)]
        }
    }

    pub(crate) fn predict_with_counter(
        &self,
        site: u64,
        taken_is_backward: bool,
        counter: u8,
    ) -> CfgBranchDirection {
        self.predict_counter(site, taken_is_backward, counter)
    }

    pub(crate) fn next_state_for_counter(
        &self,
        state: &PredictorState,
        site: u64,
        current: u8,
        actual: CfgBranchDirection,
    ) -> PredictorState {
        if !matches!(
            self.model,
            BranchPredictionModel::Bimodal
                | BranchPredictionModel::GlobalHistory
                | BranchPredictionModel::Gshare
                | BranchPredictionModel::LocalHistory
        ) {
            return state.clone();
        }
        let key = self.counter_key(state, site);
        let next = match actual {
            CfgBranchDirection::Taken => current.saturating_add(1).min(3),
            CfgBranchDirection::NotTaken => current.saturating_sub(1),
        };
        let mut state = state.clone();
        state.set(key, next, self.initial_state, self.first_execution_unknown);
        let bit = u64::from(actual == CfgBranchDirection::Taken);
        if matches!(
            self.model,
            BranchPredictionModel::GlobalHistory | BranchPredictionModel::Gshare
        ) {
            state.history = ((state.history << 1) | bit) & self.history_mask();
        } else if self.model == BranchPredictionModel::LocalHistory {
            let history = state.local_history(site, self.initial_history);
            let next_history = ((history << 1) | bit) & self.history_mask();
            if next_history == self.initial_history {
                state.local_history.remove(&site);
            } else {
                state.local_history.insert(site, next_history);
            }
        }
        state
    }

    pub(crate) fn mispredict_penalty(&self) -> u32 {
        self.mispredict_penalty
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PredictorState {
    history: u64,
    local_history: BTreeMap<u64, u64>,
    counters: BTreeMap<(u64, u64), u8>,
    seen: BTreeSet<(u64, u64)>,
}

impl PredictorState {
    fn local_history(&self, site: u64, initial: u64) -> u64 {
        self.local_history.get(&site).copied().unwrap_or(initial)
    }

    fn counter(&self, key: (u64, u64), initial: u8) -> u8 {
        self.counters.get(&key).copied().unwrap_or(initial)
    }

    fn seen(&self, key: (u64, u64)) -> bool {
        self.seen.contains(&key)
    }

    fn set(&mut self, key: (u64, u64), value: u8, initial: u8, mark_seen: bool) {
        if value == initial {
            self.counters.remove(&key);
        } else {
            self.counters.insert(key, value);
        }
        if mark_seen {
            self.seen.insert(key);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ConditionalBranch {
    pub(crate) site: u64,
    pub(crate) taken: NodeIndex,
    pub(crate) fallthrough: NodeIndex,
    pub(crate) taken_is_backward: bool,
}

pub(crate) fn conditional_branch(cfg: &FunctionCfg, node: NodeIndex) -> Option<ConditionalBranch> {
    let block = &cfg.graph[node];
    if block.terminator != CfgTerminator::Branch {
        return None;
    }
    let last = block.instructions.last()?;
    if !last.is_jump || !last.is_conditional {
        return None;
    }
    let mut taken = None;
    let mut fallthrough = None;
    for edge in cfg.graph.edges_directed(node, Direction::Outgoing) {
        match edge.weight().kind {
            CfgEdgeKind::Branch if taken.is_none() => taken = Some(edge.target()),
            CfgEdgeKind::Fallthrough if fallthrough.is_none() => fallthrough = Some(edge.target()),
            CfgEdgeKind::Branch
            | CfgEdgeKind::Fallthrough
            | CfgEdgeKind::Jump
            | CfgEdgeKind::CallReturn => return None,
        }
    }
    let taken = taken?;
    let fallthrough = fallthrough?;
    Some(ConditionalBranch {
        site: last.address,
        taken,
        fallthrough,
        taken_is_backward: cfg.graph[taken].address < last.address,
    })
}

#[derive(Clone, Copy)]
struct OutcomeEvaluation {
    mispredict: u32,
}

struct Evaluation {
    predicted: CfgBranchDirection,
    outcomes: Vec<OutcomeEvaluation>,
    next_states: Vec<(NodeIndex, PredictorState)>,
}

fn evaluate_branch(
    branch: ConditionalBranch,
    state: &PredictorState,
    model: &PredictorModel,
) -> Vec<Evaluation> {
    model
        .possible_counters(state, branch.site)
        .into_iter()
        .map(|counter| {
            let predicted =
                model.predict_with_counter(branch.site, branch.taken_is_backward, counter);
            let mut outcomes = Vec::with_capacity(2);
            let mut next_states = Vec::with_capacity(2);
            for (target, actual) in [
                (branch.taken, CfgBranchDirection::Taken),
                (branch.fallthrough, CfgBranchDirection::NotTaken),
            ] {
                let mispredict = u32::from(predicted != actual);
                outcomes.push(OutcomeEvaluation { mispredict });
                next_states.push((
                    target,
                    model.next_state_for_counter(state, branch.site, counter, actual),
                ));
            }
            Evaluation {
                predicted,
                outcomes,
                next_states,
            }
        })
        .collect()
}

struct OutcomeRange {
    predicted_taken: bool,
    predicted_not_taken: bool,
    min: u32,
    max: u32,
    observed: bool,
}

impl Default for OutcomeRange {
    fn default() -> Self {
        Self {
            predicted_taken: false,
            predicted_not_taken: false,
            min: u32::MAX,
            max: 0,
            observed: false,
        }
    }
}

impl OutcomeRange {
    fn observe(&mut self, evaluation: &Evaluation, index: usize) {
        match evaluation.predicted {
            CfgBranchDirection::Taken => self.predicted_taken = true,
            CfgBranchDirection::NotTaken => self.predicted_not_taken = true,
        }
        let mispredict = evaluation.outcomes[index].mispredict;
        if self.observed {
            self.min = self.min.min(mispredict);
            self.max = self.max.max(mispredict);
        } else {
            self.min = mispredict;
            self.max = mispredict;
            self.observed = true;
        }
    }

    fn predicted(&self) -> CfgBranchPredictionOutcome {
        match (self.predicted_taken, self.predicted_not_taken) {
            (true, false) => CfgBranchPredictionOutcome::Taken,
            (false, true) => CfgBranchPredictionOutcome::NotTaken,
            _ => CfgBranchPredictionOutcome::Mixed,
        }
    }
}

/// Runs branch-prediction analysis over every function in `program`.
///
/// The analysis adds misprediction penalties to block cycle ranges and attaches
/// branch metadata to modeled conditional-branch blocks.
#[must_use]
pub(crate) fn analyze_program(
    program: &mut ProgramCfg,
    profile: &BranchPredictionProfile,
) -> CfgBranchPredictionInfo {
    let model = PredictorModel::from_profile(profile);
    let mut info = CfgBranchPredictionInfo {
        model: profile.model_name().to_owned(),
        mispredict_penalty: profile.mispredict_penalty(),
        initial_state: matches!(
            profile.model(),
            BranchPredictionModel::Bimodal
                | BranchPredictionModel::GlobalHistory
                | BranchPredictionModel::Gshare
                | BranchPredictionModel::LocalHistory
        )
        .then(|| profile.initial_state_name().to_owned()),
        first_execution: (matches!(
            profile.model(),
            BranchPredictionModel::Bimodal
                | BranchPredictionModel::GlobalHistory
                | BranchPredictionModel::Gshare
                | BranchPredictionModel::LocalHistory
        ) && profile.first_execution() == FirstExecutionHistory::Unknown)
            .then(|| profile.first_execution_name().to_owned()),
        history_bits: profile
            .is_history_model()
            .then(|| profile.history_bits())
            .flatten(),
        initial_history: profile
            .is_history_model()
            .then(|| profile.initial_history())
            .flatten(),
        max_states: profile.max_states(),
        functions_analyzed: 0,
        functions_fallback: 0,
        branches_analyzed: 0,
        branches_fallback: 0,
        caveats: vec![
            "Each function starts with the configured predictor state for its standalone block ranges unless first_execution = \"unknown\" is selected; in that mode every unexecuted pattern-table entry is evaluated against all four possible two-bit counters and the worst modeled outcome is kept. IPET can propagate predictor state through direct calls when the per-function branch-cost and exit-state summaries are available."
                .to_owned(),
            "Only conditional branches with one taken edge and one fallthrough edge are modeled. global-history uses a branch-history register to index one shared pattern table; gshare XORs the history with branch-PC bits; local-history keeps a local history register per branch site and indexes a pattern table by the branch and local history. Indirect/table target prediction, returns, branch-target buffers, two-level history and tournament predictors are not modeled."
                .to_owned(),
            "Block cycle ranges include mispredictions for either successor; path-specific branch and predictor correlation is not modeled."
                .to_owned(),
            "Misprediction penalties are added to the base block cost and any configured pipeline branch penalty."
                .to_owned(),
        ],
    };
    for function in &mut program.functions {
        if function.cfg.blocks_by_address.is_empty() {
            continue;
        }
        let result = analyze_function(&mut function.cfg, &model);
        if result.branches == 0 {
            continue;
        }
        if result.fallback {
            info.functions_fallback = info.functions_fallback.saturating_add(1);
            info.branches_fallback = info.branches_fallback.saturating_add(result.branches);
        } else {
            info.functions_analyzed = info.functions_analyzed.saturating_add(1);
            info.branches_analyzed = info.branches_analyzed.saturating_add(result.branches);
        }
    }
    info
}

struct FunctionResult {
    fallback: bool,
    branches: u32,
}

#[allow(clippy::too_many_lines)]
fn analyze_function(cfg: &mut FunctionCfg, model: &PredictorModel) -> FunctionResult {
    let Some(entry) = cfg.entry else {
        return FunctionResult {
            fallback: false,
            branches: 0,
        };
    };
    let branches: BTreeMap<NodeIndex, ConditionalBranch> = cfg
        .blocks_by_address
        .values()
        .copied()
        .filter_map(|node| conditional_branch(cfg, node).map(|branch| (node, branch)))
        .collect();
    if branches.is_empty() {
        return FunctionResult {
            fallback: false,
            branches: 0,
        };
    }
    let mut entry_states: BTreeMap<NodeIndex, BTreeSet<PredictorState>> = BTreeMap::new();
    let mut evaluations: BTreeMap<NodeIndex, Vec<Evaluation>> = BTreeMap::new();
    let mut processed: BTreeSet<(NodeIndex, PredictorState)> = BTreeSet::new();
    let mut queue: VecDeque<(NodeIndex, PredictorState)> = VecDeque::new();
    let initial = model.entry_state();
    entry_states
        .entry(entry)
        .or_default()
        .insert(initial.clone());
    queue.push_back((entry, initial));

    while let Some((node, state)) = queue.pop_front() {
        if !processed.insert((node, state.clone())) {
            continue;
        }
        if let Some(branch) = branches.get(&node).copied() {
            let branch_evaluations = evaluate_branch(branch, &state, model);
            for evaluation in &branch_evaluations {
                for (target, next) in &evaluation.next_states {
                    if !push_state(*target, next.clone(), &mut entry_states, &mut queue, model) {
                        return fallback_function(cfg, &branches, model);
                    }
                }
            }
            evaluations
                .entry(node)
                .or_default()
                .extend(branch_evaluations);
        } else {
            for edge in cfg.graph.edges_directed(node, Direction::Outgoing) {
                if !push_state(
                    edge.target(),
                    state.clone(),
                    &mut entry_states,
                    &mut queue,
                    model,
                ) {
                    return fallback_function(cfg, &branches, model);
                }
            }
        }
    }

    let mut count = 0_u32;
    for (node, branch) in &branches {
        let Some(node_evaluations) = evaluations.get(node) else {
            continue;
        };
        let mut taken = OutcomeRange::default();
        let mut fallthrough = OutcomeRange::default();
        for evaluation in node_evaluations {
            taken.observe(evaluation, 0);
            fallthrough.observe(evaluation, 1);
        }
        let mispredicts_min = taken.min.min(fallthrough.min);
        let mispredicts_max = taken.max.max(fallthrough.max);
        let outcomes = vec![
            CfgBranchOutcome {
                target: cfg.graph[branch.taken].id.clone(),
                actual: CfgBranchDirection::Taken,
                predicted: taken.predicted(),
                mispredicts_min: taken.min,
                mispredicts_max: taken.max,
            },
            CfgBranchOutcome {
                target: cfg.graph[branch.fallthrough].id.clone(),
                actual: CfgBranchDirection::NotTaken,
                predicted: fallthrough.predicted(),
                mispredicts_min: fallthrough.min,
                mispredicts_max: fallthrough.max,
            },
        ];
        let block = &mut cfg.graph[*node];
        block.branch_prediction = Some(CfgBlockBranchPrediction {
            site: Addr::new(branch.site),
            mispredicts_min,
            mispredicts_max,
            entry_states: u32::try_from(node_evaluations.len()).unwrap_or(u32::MAX),
            fallback: false,
            outcomes,
        });
        add_penalty(
            &mut block.cycles,
            mispredicts_min,
            mispredicts_max,
            model.mispredict_penalty,
        );
        count = count.saturating_add(1);
    }
    FunctionResult {
        fallback: false,
        branches: count,
    }
}

fn push_state(
    target: NodeIndex,
    state: PredictorState,
    entry_states: &mut BTreeMap<NodeIndex, BTreeSet<PredictorState>>,
    queue: &mut VecDeque<(NodeIndex, PredictorState)>,
    model: &PredictorModel,
) -> bool {
    let states = entry_states.entry(target).or_default();
    if states.len() >= model.max_states && !states.contains(&state) {
        return false;
    }
    if states.insert(state.clone()) {
        queue.push_back((target, state));
    }
    true
}

fn fallback_function(
    cfg: &mut FunctionCfg,
    branches: &BTreeMap<NodeIndex, ConditionalBranch>,
    model: &PredictorModel,
) -> FunctionResult {
    let reachable_ids: BTreeSet<_> = crate::cfg_graph::analyze(cfg)
        .reachable
        .into_iter()
        .collect();
    let reachable: Vec<(NodeIndex, ConditionalBranch)> = branches
        .iter()
        .filter(|(node, _)| reachable_ids.contains(&cfg.graph[**node].id))
        .map(|(node, branch)| (*node, *branch))
        .collect();
    let mut count = 0_u32;
    for (node, branch) in reachable {
        let outcomes = vec![
            CfgBranchOutcome {
                target: cfg.graph[branch.taken].id.clone(),
                actual: CfgBranchDirection::Taken,
                predicted: CfgBranchPredictionOutcome::Mixed,
                mispredicts_min: 1,
                mispredicts_max: 1,
            },
            CfgBranchOutcome {
                target: cfg.graph[branch.fallthrough].id.clone(),
                actual: CfgBranchDirection::NotTaken,
                predicted: CfgBranchPredictionOutcome::Mixed,
                mispredicts_min: 1,
                mispredicts_max: 1,
            },
        ];
        let block = &mut cfg.graph[node];
        block.branch_prediction = Some(CfgBlockBranchPrediction {
            site: Addr::new(branch.site),
            mispredicts_min: 1,
            mispredicts_max: 1,
            entry_states: 0,
            fallback: true,
            outcomes,
        });
        add_penalty(&mut block.cycles, 1, 1, model.mispredict_penalty);
        count = count.saturating_add(1);
    }
    FunctionResult {
        fallback: true,
        branches: count,
    }
}

#[allow(clippy::cast_precision_loss)]
fn add_penalty(
    cycles: &mut Option<CostRange>,
    mispredicts_min: u32,
    mispredicts_max: u32,
    penalty: u32,
) {
    let Some(cycles) = cycles else {
        return;
    };
    cycles.min += f64::from(mispredicts_min.saturating_mul(penalty));
    cycles.max += f64::from(mispredicts_max.saturating_mul(penalty));
}

#[cfg(test)]
mod tests {
    use super::{PredictorModel, analyze_function};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgTerminator, FunctionCfg,
    };
    use elf2tdg_schema::CostRange;

    fn model(profile: &str) -> PredictorModel {
        let profile = BoardProfile::parse_toml(profile).expect("valid profile");
        PredictorModel::from_profile(profile.branch_prediction().expect("prediction profile"))
    }

    fn branch_cfg(taken: u64, fallthrough: u64) -> FunctionCfg {
        let branch = CfgInstruction {
            address: 0x1000,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "bne".to_owned(),
            operands: String::new(),
            text: "bne".to_owned(),
            is_call: false,
            is_jump: true,
            is_return: false,
            is_conditional: true,
            direct_target: Some(taken),
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        };
        let exit = CfgInstruction {
            address: fallthrough,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "bx".to_owned(),
            operands: "lr".to_owned(),
            text: "bx lr".to_owned(),
            is_call: false,
            is_jump: false,
            is_return: true,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        };
        let taken_block = CfgBlockDraft {
            address: taken,
            size: 2,
            instructions: vec![exit.clone()],
            calls: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            terminator: CfgTerminator::Return,
        };
        FunctionCfg::build(
            vec![
                CfgBlockDraft {
                    address: 0x1000,
                    size: 2,
                    instructions: vec![branch],
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Branch,
                },
                taken_block,
                CfgBlockDraft {
                    address: fallthrough,
                    size: 2,
                    instructions: vec![exit],
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Return,
                },
            ],
            vec![
                CfgEdgeDraft {
                    from: 0x1000,
                    to: taken,
                    kind: CfgEdgeKind::Branch,
                    site: 0x1000,
                    conditional: true,
                },
                CfgEdgeDraft {
                    from: 0x1000,
                    to: fallthrough,
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1000,
                    conditional: true,
                },
            ],
            Some(0x1000),
        )
    }

    fn looping_branch_cfg() -> FunctionCfg {
        let branch = CfgInstruction {
            address: 0x1000,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "bne".to_owned(),
            operands: String::new(),
            text: "bne".to_owned(),
            is_call: false,
            is_jump: true,
            is_return: false,
            is_conditional: true,
            direct_target: Some(0x1000),
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        };
        let exit = CfgInstruction {
            address: 0x1002,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "bx".to_owned(),
            operands: "lr".to_owned(),
            text: "bx lr".to_owned(),
            is_call: false,
            is_jump: false,
            is_return: true,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        };
        FunctionCfg::build(
            vec![
                CfgBlockDraft {
                    address: 0x1000,
                    size: 2,
                    instructions: vec![branch],
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Branch,
                },
                CfgBlockDraft {
                    address: 0x1002,
                    size: 2,
                    instructions: vec![exit],
                    calls: Vec::new(),
                    cycles: Some(CostRange::exact(1.0)),
                    terminator: CfgTerminator::Return,
                },
            ],
            vec![
                CfgEdgeDraft {
                    from: 0x1000,
                    to: 0x1000,
                    kind: CfgEdgeKind::Branch,
                    site: 0x1000,
                    conditional: true,
                },
                CfgEdgeDraft {
                    from: 0x1000,
                    to: 0x1002,
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1000,
                    conditional: true,
                },
            ],
            Some(0x1000),
        )
    }

    const BASE: &str = r#"
schema_version = 2
id = "board:branch-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000
"#;

    fn profile(model: &str, initial: &str) -> String {
        format!(
            "{BASE}\n[branch_prediction]\nmodel = \"{model}\"\nmispredict_penalty = 3\ninitial_state = \"{initial}\"\nmax_states = 16\n"
        )
    }

    fn unknown_first_profile(model: &str, initial: &str) -> String {
        format!(
            "{BASE}\n[branch_prediction]\nmodel = \"{model}\"\nmispredict_penalty = 3\ninitial_state = \"{initial}\"\nfirst_execution = \"unknown\"\nmax_states = 16\n"
        )
    }

    fn global_history_profile(model: &str, bits: u8, history: u64) -> String {
        format!(
            "{BASE}\n[branch_prediction]\nmodel = \"{model}\"\nmispredict_penalty = 3\ninitial_state = \"weakly-not-taken\"\nhistory_bits = {bits}\ninitial_history = {history}\nmax_states = 16\n"
        )
    }

    #[test]
    fn btfn_predicts_backward_taken_branches() {
        let mut cfg = branch_cfg(0x0ff0, 0x1002);
        let result = analyze_function(&mut cfg, &model(&profile("btfn", "weakly-not-taken")));
        assert!(!result.fallback);
        assert_eq!(result.branches, 1);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let prediction = block.branch_prediction.as_ref().expect("prediction");
        assert_eq!(prediction.mispredicts_min, 0);
        assert_eq!(prediction.mispredicts_max, 1);
        let taken = prediction
            .outcomes
            .iter()
            .find(|outcome| outcome.actual == crate::cfg::CfgBranchDirection::Taken)
            .expect("taken outcome");
        assert_eq!(
            taken.predicted,
            crate::cfg::CfgBranchPredictionOutcome::Taken
        );
        assert_eq!(taken.mispredicts_max, 0);
        let fallthrough = prediction
            .outcomes
            .iter()
            .find(|outcome| outcome.actual == crate::cfg::CfgBranchDirection::NotTaken)
            .expect("fallthrough outcome");
        assert_eq!(
            fallthrough.predicted,
            crate::cfg::CfgBranchPredictionOutcome::Taken
        );
        assert_eq!(fallthrough.mispredicts_min, 1);
        assert_eq!(fallthrough.mispredicts_max, 1);
        assert_eq!(block.cycles.expect("cycles").max, 4.0);
    }

    #[test]
    fn static_not_taken_mispredicts_the_taken_edge() {
        let mut cfg = branch_cfg(0x0ff0, 0x1002);
        let result = analyze_function(
            &mut cfg,
            &model(&profile("static-not-taken", "weakly-not-taken")),
        );
        assert!(!result.fallback);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let prediction = block.branch_prediction.as_ref().expect("prediction");
        let taken = prediction
            .outcomes
            .iter()
            .find(|outcome| outcome.actual == crate::cfg::CfgBranchDirection::Taken)
            .expect("taken outcome");
        assert_eq!(
            taken.predicted,
            crate::cfg::CfgBranchPredictionOutcome::NotTaken
        );
        assert_eq!(taken.mispredicts_min, 1);
        assert_eq!(taken.mispredicts_max, 1);
    }

    #[test]
    fn bimodal_initial_state_mispredicts_taken_edge() {
        let mut cfg = branch_cfg(0x0ff0, 0x1002);
        let result = analyze_function(&mut cfg, &model(&profile("bimodal", "weakly-not-taken")));
        assert!(!result.fallback);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let prediction = block.branch_prediction.as_ref().expect("prediction");
        assert_eq!(prediction.entry_states, 1);
        let taken = prediction
            .outcomes
            .iter()
            .find(|outcome| outcome.actual == crate::cfg::CfgBranchDirection::Taken)
            .expect("taken outcome");
        assert_eq!(
            taken.predicted,
            crate::cfg::CfgBranchPredictionOutcome::NotTaken
        );
        assert_eq!(taken.mispredicts_max, 1);
        let fallthrough = prediction
            .outcomes
            .iter()
            .find(|outcome| outcome.actual == crate::cfg::CfgBranchDirection::NotTaken)
            .expect("fallthrough outcome");
        assert_eq!(
            fallthrough.predicted,
            crate::cfg::CfgBranchPredictionOutcome::NotTaken
        );
        assert_eq!(fallthrough.mispredicts_max, 0);
    }

    #[test]
    fn bimodal_unknown_first_execution_considers_all_counters() {
        let mut cfg = branch_cfg(0x1004, 0x1002);
        let result = analyze_function(
            &mut cfg,
            &model(&unknown_first_profile("bimodal", "weakly-not-taken")),
        );
        assert!(!result.fallback);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let prediction = block.branch_prediction.as_ref().expect("prediction");
        assert!(prediction.entry_states >= 4);
        assert_eq!(prediction.mispredicts_min, 0);
        assert_eq!(prediction.mispredicts_max, 1);
        for outcome in &prediction.outcomes {
            assert_eq!(
                outcome.predicted,
                crate::cfg::CfgBranchPredictionOutcome::Mixed
            );
            assert_eq!(outcome.mispredicts_min, 0);
            assert_eq!(outcome.mispredicts_max, 1);
        }
    }

    #[test]
    fn global_history_updates_history_and_pattern_table() {
        let predictor = model(&global_history_profile("global-history", 2, 0));
        let initial = predictor.entry_state();
        assert_eq!(initial.history, 0);
        let counters = predictor.possible_counters(&initial, 0x1000);
        assert_eq!(counters, vec![1]);
        let taken = predictor.next_state_for_counter(
            &initial,
            0x1000,
            counters[0],
            crate::cfg::CfgBranchDirection::Taken,
        );
        assert_eq!(taken.history, 1);
        let counters = predictor.possible_counters(&taken, 0x1000);
        assert_eq!(counters, vec![1]);
        let not_taken = predictor.next_state_for_counter(
            &taken,
            0x1000,
            counters[0],
            crate::cfg::CfgBranchDirection::NotTaken,
        );
        assert_eq!(not_taken.history, 2);
    }

    #[test]
    fn local_history_updates_per_site_registers() {
        let predictor = model(&global_history_profile("local-history", 2, 0));
        let initial = predictor.entry_state();
        assert_eq!(initial.history, 0);
        assert_eq!(initial.local_history(0x1000, 0), 0);
        let counters = predictor.possible_counters(&initial, 0x1000);
        assert_eq!(counters, vec![1]);
        let taken = predictor.next_state_for_counter(
            &initial,
            0x1000,
            counters[0],
            crate::cfg::CfgBranchDirection::Taken,
        );
        assert_eq!(taken.local_history(0x1000, 0), 1);
        assert_eq!(taken.local_history(0x2000, 0), 0);
        let counters = predictor.possible_counters(&taken, 0x1000);
        assert_eq!(counters, vec![1]);
        let not_taken = predictor.next_state_for_counter(
            &taken,
            0x1000,
            counters[0],
            crate::cfg::CfgBranchDirection::NotTaken,
        );
        assert_eq!(not_taken.local_history(0x1000, 0), 2);
    }

    #[test]
    fn history_models_analyze_conditional_branches() {
        for model_name in ["global-history", "gshare", "local-history"] {
            let mut cfg = branch_cfg(0x1004, 0x1002);
            let result =
                analyze_function(&mut cfg, &model(&global_history_profile(model_name, 3, 5)));
            assert!(!result.fallback);
            let block = &cfg.graph[cfg.entry.expect("entry")];
            let prediction = block.branch_prediction.as_ref().expect("prediction");
            assert_eq!(prediction.entry_states, 1);
            assert_eq!(prediction.mispredicts_max, 1);
            assert_eq!(block.cycles.expect("cycles").max, 4.0);
        }
    }

    #[test]
    fn bimodal_loop_accumulates_predictor_states() {
        let mut cfg = looping_branch_cfg();
        let profile = r#"
schema_version = 2
id = "board:branch-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
max_states = 16
"#;
        let result = analyze_function(&mut cfg, &model(profile));
        assert!(!result.fallback);
        assert_eq!(result.branches, 1);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let prediction = block.branch_prediction.as_ref().expect("prediction");
        assert_eq!(prediction.entry_states, 3);
        assert_eq!(prediction.mispredicts_min, 0);
        assert_eq!(prediction.mispredicts_max, 1);
        assert!(
            prediction
                .outcomes
                .iter()
                .all(|outcome| outcome.predicted == crate::cfg::CfgBranchPredictionOutcome::Mixed)
        );
        assert_eq!(block.cycles.expect("cycles").max, 4.0);
    }

    #[test]
    fn state_limit_falls_back_to_all_mispredict() {
        let mut cfg = looping_branch_cfg();
        let profile = r#"
schema_version = 2
id = "board:branch-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
max_states = 1
"#;
        let result = analyze_function(&mut cfg, &model(profile));
        assert!(result.fallback);
        assert_eq!(result.branches, 1);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let prediction = block.branch_prediction.as_ref().expect("prediction");
        assert!(prediction.fallback);
        assert_eq!(prediction.entry_states, 0);
        assert_eq!(prediction.mispredicts_min, 1);
        assert_eq!(prediction.mispredicts_max, 1);
        assert_eq!(block.cycles.expect("cycles").min, 4.0);
        assert_eq!(block.cycles.expect("cycles").max, 4.0);
    }
}
