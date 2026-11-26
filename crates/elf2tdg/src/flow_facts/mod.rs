//! Flow facts consumed by IPET and the longest-path analysis.
//!
//! Facts come from the board profile's `[wcet]` section and from external F4
//! (`.ff`) or FFX (`.ffx`) files. F4/FFX facts are parsed into a symbolic
//! document first and resolved against the recovered `ProgramCfg`, so a fact
//! can name a loop by address, by function + offset, or by source file/line.
//! F4 `in ...` chains and FFX `<call>` nesting become resolved caller contexts;
//! the WCET backends analyze a function version per caller chain. F4 frames are
//! function-level. FFX frames can carry the call instruction address, either
//! explicitly or from a unique caller-to-callee edge, so two calls from the
//! same caller may select different callee versions.

mod f4;
mod ffx;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use elf2tdg_schema::{Addr, BlockId, FunctionId};
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::board_profile::WcetProfile;
use crate::cfg::{
    CfgBranchFactInfo, CfgCallFactInfo, CfgFlowFactsInfo, CfgFunction, CfgInfeasibleCallInfo,
    CfgInfeasibleElementInfo, CfgInfeasiblePathInfo, CfgLoopBoundInfo, ProgramCfg,
};
use crate::loop_bounds::InferredLoopBound;
use crate::rules::normalize_crate_hashes;

const MAX_CROSS_FUNCTION_GROUPS: usize = 16;
/// Largest numeric loop iteration accepted for a specific-iteration
/// cross-function conflict. Larger numbers are conservatively ignored to keep
/// the product automaton bounded; the omitted constraint only loses precision.
const MAX_SPECIFIC_ITERATION: u32 = 256;

#[derive(Clone, Debug)]
struct LoopBound {
    bound: u32,
    source: String,
}

/// One frame in a resolved caller chain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContextFrame {
    pub(crate) function: FunctionId,
    /// Call instruction that entered the next callee. `None` for a
    /// function-level context such as F4 `in ...`.
    pub(crate) site: Option<u64>,
}

impl ContextFrame {
    #[cfg(test)]
    pub(crate) fn function(function: FunctionId) -> Self {
        Self {
            function,
            site: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn call(function: FunctionId, site: u64) -> Self {
        Self {
            function,
            site: Some(site),
        }
    }

    fn matches(&self, analyzed: &Self) -> bool {
        self.function == analyzed.function
            && self.site.is_none_or(|site| Some(site) == analyzed.site)
    }

    fn site_specificity(&self) -> usize {
        usize::from(self.site.is_some())
    }
}

/// A loop bound restricted to a caller context.
#[derive(Clone, Debug)]
struct ContextualLoopBound {
    header: u64,
    bound: u32,
    /// Resolved caller chain, immediate caller first.
    context: Vec<ContextFrame>,
    /// Declared caller names for reports.
    context_names: Vec<String>,
    source: String,
}

/// Granularity of a declared caller context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContextKind {
    /// F4 `in ...`: the fact applies to every call from that caller function.
    Function,
    /// FFX nested `<call>`: OTAWA scopes the fact to a call instruction.
    /// An explicit `address`/`site` selects the site; otherwise a unique
    /// caller-to-callee edge is used. Multiple sites without an address are
    /// rejected with a warning.
    FfxCall,
}

/// Which conditional outcome a branch fact constrains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BranchOutcome {
    /// Conditional branch taken edge.
    Taken,
    /// Conditional branch fallthrough/not-taken edge.
    NotTaken,
    /// The whole conditional block never executes.
    Both,
}

impl BranchOutcome {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Taken => "taken",
            Self::NotTaken => "not-taken",
            Self::Both => "both",
        }
    }
}

/// A resolved branch/edge execution constraint.
#[derive(Clone, Debug)]
pub(crate) struct BranchConstraint {
    pub(crate) function: FunctionId,
    pub(crate) block: BlockId,
    pub(crate) site: u64,
    pub(crate) outcome: BranchOutcome,
    pub(crate) max_count: u32,
    /// Resolved caller chain, immediate caller first.
    pub(crate) context: Vec<ContextFrame>,
    pub(crate) context_names: Vec<String>,
    pub(crate) source: String,
}

/// A resolved call-site execution constraint.
#[derive(Clone, Debug)]
pub(crate) struct CallConstraint {
    pub(crate) function: FunctionId,
    pub(crate) block: BlockId,
    pub(crate) site: u64,
    pub(crate) max_count: u32,
    /// Resolved caller chain, immediate caller first.
    pub(crate) context: Vec<ContextFrame>,
    pub(crate) context_names: Vec<String>,
    pub(crate) source: String,
}

type CallSiteRef = (FunctionId, BlockId, u64);
type ResolvedContext = (Vec<ContextFrame>, Vec<String>);

/// Selects how contextual facts are matched during one analysis.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FactScope<'a> {
    /// One caller chain, immediate caller first.
    Context(&'a [ContextFrame]),
    /// Context-insensitive fallback; only context-free facts apply.
    Insensitive,
}

impl FactScope<'_> {
    /// Whether a fact declared for `fact_context` applies in this scope.
    pub(crate) fn matches(self, fact_context: &[ContextFrame]) -> bool {
        match self {
            Self::Context(context) => {
                fact_context.len() <= context.len()
                    && fact_context
                        .iter()
                        .zip(context.iter())
                        .all(|(fact, analyzed)| fact.matches(analyzed))
            }
            Self::Insensitive => fact_context.is_empty(),
        }
    }
}

/// Bounds and assumptions used by the WCET analyses for one analysis run.
#[derive(Clone, Debug, Default)]
pub(crate) struct FlowFacts {
    source: String,
    default_loop_bound: Option<u32>,
    bound_nonterminating_loops: bool,
    loop_bounds: BTreeMap<u64, LoopBound>,
    contextual_loops: Vec<ContextualLoopBound>,
    branches: Vec<BranchConstraint>,
    calls: Vec<CallConstraint>,
    infeasible_paths: Vec<InfeasiblePathConstraint>,
    warnings: Vec<String>,
}

fn context_sites_info(context: &[ContextFrame]) -> Option<Vec<Option<Addr>>> {
    context.iter().any(|frame| frame.site.is_some()).then(|| {
        context
            .iter()
            .map(|frame| frame.site.map(Addr::new))
            .collect()
    })
}

fn conflict_element_info(
    element: &InfeasibleElement,
    function: Option<&FunctionId>,
) -> CfgInfeasibleElementInfo {
    let function = function.cloned();
    match element {
        InfeasibleElement::Edge {
            source,
            target,
            site,
        } => CfgInfeasibleElementInfo {
            kind: "edge".to_owned(),
            function,
            source: Some(source.clone()),
            target: Some(target.clone()),
            site: Some(Addr::new(*site)),
        },
        InfeasibleElement::Block { block } => CfgInfeasibleElementInfo {
            kind: "block".to_owned(),
            function,
            source: Some(block.clone()),
            target: None,
            site: None,
        },
    }
}

impl FlowFacts {
    /// Builds flow facts from the board profile's `[wcet]` section.
    pub(crate) fn from_wcet_profile(profile: &WcetProfile) -> Self {
        Self {
            source: "board-profile [wcet]".to_owned(),
            default_loop_bound: profile.default_loop_bound(),
            bound_nonterminating_loops: profile.bound_nonterminating_loops(),
            loop_bounds: profile
                .loop_bounds()
                .map(|(header, bound)| {
                    (
                        header,
                        LoopBound {
                            bound,
                            source: "board-profile [wcet]".to_owned(),
                        },
                    )
                })
                .collect(),
            contextual_loops: Vec::new(),
            branches: Vec::new(),
            calls: Vec::new(),
            infeasible_paths: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Human-readable source summary.
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

    /// Returns a context-insensitive bound for a loop header.
    ///
    /// Contextual facts are folded in with their maximum because a
    /// context-insensitive analysis must cover every caller. A loop with only
    /// contextual facts and no global/default bound cannot be bounded safely
    /// and returns `None`.
    pub(crate) fn bound_for(&self, header: u64) -> Option<u32> {
        let baseline = self
            .loop_bounds
            .get(&header)
            .map(|entry| entry.bound)
            .or(self.default_loop_bound);
        let contextual = self
            .contextual_loops
            .iter()
            .filter(|entry| entry.header == header)
            .map(|entry| entry.bound)
            .max();
        match (baseline, contextual) {
            (Some(baseline), Some(contextual)) => Some(baseline.max(contextual)),
            (Some(baseline), None) => Some(baseline),
            (None, _) => None,
        }
    }

    /// Returns the bound for a loop in one caller context.
    ///
    /// The most specific matching caller chain wins. Within that specificity,
    /// conflicting facts keep the larger bound. A global fact is the fallback
    /// when no contextual fact matches, followed by the default bound.
    pub(crate) fn bound_for_context(&self, header: u64, context: &[ContextFrame]) -> Option<u32> {
        let mut best_length = 0;
        let mut best_specificity = 0;
        let mut best: Option<u32> = None;
        for entry in &self.contextual_loops {
            if entry.header != header || !FactScope::Context(context).matches(&entry.context) {
                continue;
            }
            let length = entry.context.len();
            let specificity: usize = entry
                .context
                .iter()
                .map(ContextFrame::site_specificity)
                .sum();
            if best.is_none() || (length, specificity) > (best_length, best_specificity) {
                best_length = length;
                best_specificity = specificity;
                best = Some(entry.bound);
            } else if (length, specificity) == (best_length, best_specificity) {
                best = Some(best.map_or(entry.bound, |bound| bound.max(entry.bound)));
            }
        }
        if best.is_some() {
            return best;
        }
        self.loop_bounds
            .get(&header)
            .map(|entry| entry.bound)
            .or(self.default_loop_bound)
    }

    /// Whether any loop bound is restricted to a caller context.
    pub(crate) fn has_contextual_loops(&self) -> bool {
        !self.contextual_loops.is_empty()
    }

    /// Whether any imported fact is restricted to a caller context.
    pub(crate) fn has_contextual_facts(&self) -> bool {
        self.has_contextual_loops()
            || self
                .branches
                .iter()
                .any(|branch| !branch.context.is_empty())
            || self.calls.iter().any(|call| !call.context.is_empty())
            || self
                .infeasible_paths
                .iter()
                .any(|conflict| conflict.applied && !conflict.context.is_empty())
    }

    /// Whether any contextual fact identifies a concrete call site.
    pub(crate) fn has_call_site_contexts(&self) -> bool {
        let site_specific =
            |context: &[ContextFrame]| context.iter().any(|frame| frame.site.is_some());
        self.contextual_loops
            .iter()
            .any(|entry| site_specific(&entry.context))
            || self
                .branches
                .iter()
                .any(|branch| site_specific(&branch.context))
            || self.calls.iter().any(|call| site_specific(&call.context))
            || self
                .infeasible_paths
                .iter()
                .any(|conflict| conflict.applied && site_specific(&conflict.context))
    }

    /// Resolved loop bounds keyed by header address, with provenance.
    pub(crate) fn loops(&self) -> impl Iterator<Item = (u64, u32, &str)> + '_ {
        self.loop_bounds
            .iter()
            .map(|(header, entry)| (*header, entry.bound, entry.source.as_str()))
    }

    /// Resolved branch/edge constraints.
    pub(crate) fn branches(&self) -> &[BranchConstraint] {
        &self.branches
    }

    /// Resolved call-site constraints.
    pub(crate) fn calls(&self) -> &[CallConstraint] {
        &self.calls
    }

    /// Resolved infeasible-path constraints and ignored conflict records.
    pub(crate) fn infeasible_paths(&self) -> &[InfeasiblePathConstraint] {
        &self.infeasible_paths
    }

    /// Whether any infeasible-path conflict was imported.
    pub(crate) fn has_infeasible_paths(&self) -> bool {
        !self.infeasible_paths.is_empty()
    }

    /// Whether any non-loop constraint was resolved.
    pub(crate) fn has_non_loop_facts(&self) -> bool {
        !self.branches.is_empty() || !self.calls.is_empty()
    }

    /// Warnings collected while importing flow facts.
    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Builds the JSON metadata object for the WCET document.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn info(&self) -> CfgFlowFactsInfo {
        let mut loops: Vec<CfgLoopBoundInfo> = self
            .loops()
            .map(|(header, bound, source)| CfgLoopBoundInfo {
                header: Addr::new(header),
                bound,
                context: Vec::new(),
                context_sites: None,
                source: source.to_owned(),
            })
            .collect();
        loops.extend(self.contextual_loops.iter().map(|entry| CfgLoopBoundInfo {
            header: Addr::new(entry.header),
            bound: entry.bound,
            context: entry.context_names.clone(),
            context_sites: context_sites_info(&entry.context),
            source: entry.source.clone(),
        }));
        CfgFlowFactsInfo {
            source: self.source().to_owned(),
            default_loop_bound: self.default_loop_bound,
            bound_nonterminating_loops: self.bound_nonterminating_loops,
            loops,
            branches: self
                .branches
                .iter()
                .map(|branch| CfgBranchFactInfo {
                    function: branch.function.clone(),
                    site: Addr::new(branch.site),
                    outcome: branch.outcome.name().to_owned(),
                    max_count: branch.max_count,
                    context: branch.context_names.clone(),
                    context_sites: context_sites_info(&branch.context),
                    source: branch.source.clone(),
                })
                .collect(),
            calls: self
                .calls
                .iter()
                .map(|call| CfgCallFactInfo {
                    function: call.function.clone(),
                    site: Addr::new(call.site),
                    max_count: call.max_count,
                    context: call.context_names.clone(),
                    context_sites: context_sites_info(&call.context),
                    source: call.source.clone(),
                })
                .collect(),
            conflicts: self
                .infeasible_paths
                .iter()
                .map(|conflict| {
                    let (scope, loop_header) = match &conflict.scope {
                        Some(InfeasibleScope::Function) => (Some("function".to_owned()), None),
                        Some(InfeasibleScope::Loop { header }) => {
                            (Some("loop".to_owned()), Some(header.clone()))
                        }
                        Some(InfeasibleScope::CrossFunction) => {
                            (Some("cross-function".to_owned()), None)
                        }
                        None => (None, None),
                    };
                    let elements = if let Some(cross) = &conflict.cross_function {
                        cross
                            .pattern
                            .iter()
                            .enumerate()
                            .map(|(index, slot)| match slot {
                                CrossFunctionSlot::Caller(element) => {
                                    conflict_element_info(element, Some(&cross.caller))
                                }
                                CrossFunctionSlot::Callee(element) => {
                                    let callee = cross
                                        .groups
                                        .iter()
                                        .find(|group| {
                                            index >= group.slot_start
                                                && index < group.slot_start + group.slot_len
                                        })
                                        .map_or(&cross.callee, |group| &group.callee);
                                    conflict_element_info(element, Some(callee))
                                }
                            })
                            .collect()
                    } else {
                        conflict
                            .elements
                            .iter()
                            .map(|element| conflict_element_info(element, None))
                            .collect()
                    };
                    let calls: Vec<CfgInfeasibleCallInfo> = conflict
                        .cross_function
                        .as_ref()
                        .map(|cross| {
                            cross
                                .groups
                                .iter()
                                .map(|group| CfgInfeasibleCallInfo {
                                    callee: group.callee.clone(),
                                    block: group.call_block.clone(),
                                    site: Addr::new(group.call_site),
                                    continuation: group.continuation.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let iteration = match &conflict.enforcement {
                        InfeasibleEnforcement::Automaton {
                            reset: OrderedReset::LoopSpecific { iteration, .. },
                        } => Some(*iteration),
                        InfeasibleEnforcement::CrossFunctionAutomaton => conflict
                            .cross_function
                            .as_ref()
                            .and_then(|cross| cross.specific_iteration),
                        InfeasibleEnforcement::Automaton { .. }
                        | InfeasibleEnforcement::Aggregate => None,
                    }
                    .map(|iteration| match iteration {
                        SpecificIteration::Number(number) => i64::from(number),
                        SpecificIteration::Last => -1,
                    });
                    CfgInfeasiblePathInfo {
                        function: conflict.function.clone(),
                        ordered: conflict.ordered,
                        applied: conflict.applied,
                        mode: conflict.applied.then(|| {
                            match conflict.enforcement {
                                InfeasibleEnforcement::Aggregate => "aggregate",
                                InfeasibleEnforcement::Automaton { .. }
                                | InfeasibleEnforcement::CrossFunctionAutomaton => "automaton",
                            }
                            .to_owned()
                        }),
                        reason: conflict.reason.clone(),
                        scope,
                        loop_header,
                        iteration,
                        call: calls.first().cloned(),
                        calls,
                        context: conflict.context_names.clone(),
                        context_sites: context_sites_info(&conflict.context),
                        elements,
                        source: conflict.source.clone(),
                    }
                })
                .collect(),
        }
    }

    /// Parses and applies F4/FFX files in order.
    pub(crate) fn apply_paths(
        &mut self,
        paths: &[PathBuf],
        program: &ProgramCfg,
    ) -> Result<(), String> {
        for path in paths {
            let document = FlowFactDocument::parse_file(path)?;
            self.apply_document(document, program)?;
        }
        Ok(())
    }

    /// Resolves and merges one parsed flow-fact document.
    ///
    /// Conflicting bounds for the same loop and caller context keep the larger
    /// value, which is conservative. Contextual facts are stored with their
    /// resolved caller chain and applied per function version.
    pub(crate) fn apply_document(
        &mut self,
        mut document: FlowFactDocument,
        program: &ProgramCfg,
    ) -> Result<(), String> {
        if document.checksum.is_some() {
            self.warnings.push(format!(
                "{}: checksum was parsed but not verified",
                document.origin
            ));
        }
        if self.source.is_empty() {
            self.source.clone_from(&document.origin);
        } else if !self.source.contains(&document.origin) {
            self.source = format!("{} + {}", self.source, document.origin);
        }
        self.warnings.append(&mut document.warnings);
        self.apply_loop_facts(&document, program)?;
        self.apply_branch_facts(&document, program)?;
        self.apply_call_facts(&document, program)?;
        self.apply_conflict_facts(&document, program)?;
        Ok(())
    }

    fn apply_loop_facts(
        &mut self,
        document: &FlowFactDocument,
        program: &ProgramCfg,
    ) -> Result<(), String> {
        for fact in &document.loops {
            let header = resolve_target(program, &fact.target, &document.origin)?;
            let function = function_for_block(program, header, &document.origin)?;
            let Some((context, context_names)) = resolve_context(
                program,
                &fact.context,
                &fact.context_sites,
                fact.context_kind,
                &function.id,
                &document.origin,
                &mut self.warnings,
            )?
            else {
                continue;
            };
            if !context.is_empty() {
                self.insert_contextual_loop(ContextualLoopBound {
                    header,
                    bound: fact.max,
                    context,
                    context_names,
                    source: document.origin.clone(),
                });
                continue;
            }
            self.insert_global_loop(
                header,
                LoopBound {
                    bound: fact.max,
                    source: document.origin.clone(),
                },
                &document.origin,
            );
        }
        Ok(())
    }

    fn insert_global_loop(&mut self, header: u64, candidate: LoopBound, origin: &str) {
        match self.loop_bounds.get_mut(&header) {
            Some(existing) => {
                if candidate.bound > existing.bound {
                    self.warnings.push(format!(
                        "{origin}: loop 0x{header:x} bound {} replaces {} from {}; using the larger bound",
                        candidate.bound, existing.bound, existing.source
                    ));
                    *existing = candidate;
                } else if candidate.bound < existing.bound {
                    self.warnings.push(format!(
                        "{origin}: loop 0x{header:x} bound {} is below {} from {}; keeping the larger bound",
                        candidate.bound, existing.bound, existing.source
                    ));
                } else if !existing.source.contains(origin) {
                    existing.source = format!("{} + {origin}", existing.source);
                }
            }
            None => {
                self.loop_bounds.insert(header, candidate);
            }
        }
    }

    fn apply_branch_facts(
        &mut self,
        document: &FlowFactDocument,
        program: &ProgramCfg,
    ) -> Result<(), String> {
        for fact in &document.branches {
            let (function, block, site) =
                resolve_branch_target(program, &fact.target, &document.origin)?;
            let Some((context, context_names)) = resolve_context(
                program,
                &fact.context,
                &fact.context_sites,
                fact.context_kind,
                &function,
                &document.origin,
                &mut self.warnings,
            )?
            else {
                continue;
            };
            self.insert_branch(BranchConstraint {
                function,
                block,
                site,
                outcome: fact.outcome,
                max_count: fact.max,
                context,
                context_names,
                source: document.origin.clone(),
            });
        }
        Ok(())
    }

    fn apply_call_facts(
        &mut self,
        document: &FlowFactDocument,
        program: &ProgramCfg,
    ) -> Result<(), String> {
        for fact in &document.calls {
            for (function, block, site) in resolve_call_target(
                program,
                &fact.target,
                fact.scope.as_deref(),
                &document.origin,
                &mut self.warnings,
            )? {
                let Some((context, context_names)) = resolve_context(
                    program,
                    &fact.context,
                    &fact.context_sites,
                    fact.context_kind,
                    &function,
                    &document.origin,
                    &mut self.warnings,
                )?
                else {
                    continue;
                };
                if let Some(callee) = &fact.callee {
                    verify_call_callee(program, &function, site, callee, &document.origin)?;
                }
                self.insert_call(CallConstraint {
                    function,
                    block,
                    site,
                    max_count: fact.max,
                    context,
                    context_names,
                    source: document.origin.clone(),
                });
            }
        }
        Ok(())
    }

    fn apply_conflict_facts(
        &mut self,
        document: &FlowFactDocument,
        program: &ProgramCfg,
    ) -> Result<(), String> {
        for fact in &document.conflicts {
            let constraint = resolve_conflict(program, fact, &document.origin, &mut self.warnings)?;
            if let Some(reason) = &constraint.reason {
                self.warnings.push(reason.clone());
            }
            self.infeasible_paths.push(constraint);
        }
        Ok(())
    }

    fn insert_contextual_loop(&mut self, candidate: ContextualLoopBound) {
        if let Some(existing) = self.contextual_loops.iter_mut().find(|existing| {
            existing.header == candidate.header && existing.context == candidate.context
        }) {
            if candidate.bound > existing.bound {
                self.warnings.push(format!(
                    "{}: loop 0x{:x} bound {} in context [{}] replaces {} from {}; using the larger bound",
                    candidate.source,
                    candidate.header,
                    candidate.bound,
                    candidate.context_names.join(" / "),
                    existing.bound,
                    existing.source
                ));
                *existing = candidate;
            } else if candidate.bound < existing.bound {
                self.warnings.push(format!(
                    "{}: loop 0x{:x} bound {} in context [{}] is below {} from {}; keeping the larger bound",
                    candidate.source,
                    candidate.header,
                    candidate.bound,
                    candidate.context_names.join(" / "),
                    existing.bound,
                    existing.source
                ));
            } else if !existing.source.contains(&candidate.source) {
                existing.source = format!("{} + {}", existing.source, candidate.source);
            }
        } else {
            self.contextual_loops.push(candidate);
        }
    }

    fn insert_branch(&mut self, candidate: BranchConstraint) {
        if let Some(existing) = self.branches.iter_mut().find(|existing| {
            existing.function == candidate.function
                && existing.site == candidate.site
                && existing.outcome == candidate.outcome
                && existing.context == candidate.context
        }) {
            if candidate.max_count < existing.max_count {
                existing.max_count = candidate.max_count;
                existing.source = candidate.source;
            } else if !existing.source.contains(&candidate.source) {
                existing.source = format!("{} + {}", existing.source, candidate.source);
            }
        } else {
            self.branches.push(candidate);
        }
    }

    fn insert_call(&mut self, candidate: CallConstraint) {
        if let Some(existing) = self.calls.iter_mut().find(|existing| {
            existing.function == candidate.function
                && existing.site == candidate.site
                && existing.context == candidate.context
        }) {
            if candidate.max_count < existing.max_count {
                existing.max_count = candidate.max_count;
                existing.source = candidate.source;
            } else if !existing.source.contains(&candidate.source) {
                existing.source = format!("{} + {}", existing.source, candidate.source);
            }
        } else {
            self.calls.push(candidate);
        }
    }

    /// Merges automatically inferred bounds conservatively.
    ///
    /// Explicit and default bounds are assumptions already present in the
    /// model, so an inferred value is accepted only when it is larger. That
    /// keeps the result an upper bound without silently lowering a user fact.
    pub(crate) fn apply_inferred_loops(
        &mut self,
        inferred: impl IntoIterator<Item = InferredLoopBound>,
    ) -> usize {
        let mut applied = 0;
        for entry in inferred {
            let candidate = LoopBound {
                bound: entry.bound,
                source: format!(
                    "inferred counted loop in {}: {}",
                    entry.function, entry.detail
                ),
            };
            let existing = self
                .loop_bounds
                .get(&entry.header)
                .map(|bound| bound.bound)
                .or(self.default_loop_bound);
            match existing {
                Some(existing) if entry.bound <= existing => {}
                Some(existing) => {
                    self.warnings.push(format!(
                        "loop 0x{:x}: inferred bound {} exceeds configured bound {existing}; using the larger inferred bound ({})",
                        entry.header, entry.bound, entry.detail
                    ));
                    self.loop_bounds.insert(entry.header, candidate);
                    applied += 1;
                }
                None => {
                    self.loop_bounds.insert(entry.header, candidate);
                    applied += 1;
                }
            }
        }
        if applied > 0 && !self.source.contains("auto loop bounds") {
            self.source.push_str(" + auto loop bounds");
        }
        applied
    }
}

/// Parsed flow-fact file before resolution against a `ProgramCfg`.
#[derive(Clone, Debug)]
pub(crate) struct FlowFactDocument {
    origin: String,
    checksum: Option<String>,
    loops: Vec<LoopFact>,
    branches: Vec<BranchFact>,
    calls: Vec<CallFact>,
    conflicts: Vec<ConflictFact>,
    warnings: Vec<String>,
}

impl FlowFactDocument {
    /// Parses flow-fact text. Test-only helper for synthetic programs.
    #[cfg(test)]
    pub(crate) fn parse_text(text: &str, origin: &str) -> Result<Self, String> {
        if text.trim_start().starts_with('<') {
            ffx::parse(text, origin)
        } else {
            f4::parse(text, origin)
        }
    }

    /// Parses a file, detecting FFX XML by content (and F4 otherwise).
    pub(crate) fn parse_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            format!("failed to read flow-fact file {}: {error}", path.display())
        })?;
        let origin = path.display().to_string();
        let is_ffx = text.trim_start().starts_with('<')
            || path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("ffx") || extension.eq_ignore_ascii_case("xml")
                });
        if is_ffx {
            ffx::parse(&text, &origin)
        } else {
            f4::parse(&text, &origin)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LoopFact {
    target: LoopTarget,
    max: u32,
    context: Vec<String>,
    context_sites: Vec<Option<u64>>,
    context_kind: ContextKind,
}

#[derive(Clone, Debug)]
pub(crate) enum LoopTarget {
    Address(u64),
    FunctionOffset {
        function: String,
        offset: u64,
    },
    SourceLine {
        function: Option<String>,
        file: String,
        line: u32,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct BranchFact {
    target: LocationTarget,
    outcome: BranchOutcome,
    max: u32,
    context: Vec<String>,
    context_sites: Vec<Option<u64>>,
    context_kind: ContextKind,
}

/// One parsed infeasible-path conflict.
#[derive(Clone, Debug)]
pub(crate) struct ConflictFact {
    elements: Vec<ConflictElementFact>,
    ordered: bool,
    scope: Option<String>,
    context: Vec<String>,
    context_sites: Vec<Option<u64>>,
    context_kind: ContextKind,
    /// Innermost enclosing `<loop>` context, when present.
    loop_context: Option<LoopTarget>,
    /// All enclosing `<loop>` contexts, outermost first.
    loop_contexts: Vec<LoopTarget>,
    /// Enclosing `<iteration>` context, when present.
    iteration: IterationContext,
    /// Innermost loop active where the `<iteration>` was declared.
    iteration_loop: Option<LoopTarget>,
}

/// Enclosing `<iteration>` context of a parsed conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IterationContext {
    /// No `<iteration>` element.
    None,
    /// `<iteration number="*">`.
    All,
    /// `<iteration number="INT">`; positive numbers are 1-based, and `-1`
    /// selects the last iteration.
    Specific(i64),
}

impl IterationContext {
    pub(crate) fn is_iteration(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A supported specific-iteration selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpecificIteration {
    /// A 1-based iteration number.
    Number(u32),
    /// The last iteration (`number="-1"`).
    Last,
}

#[derive(Clone, Debug)]
pub(crate) enum ConflictElementFact {
    Edge {
        src: u64,
        dst: u64,
    },
    Block {
        location: LocationTarget,
    },
    /// A direct callee invocation selected by name, containing elements that
    /// must all match inside one invocation of that call.
    Call {
        name: String,
        /// Optional call-instruction address disambiguating multiple sites.
        site: Option<u64>,
        elements: Vec<ConflictElementFact>,
    },
}

/// One resolved conflict element.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InfeasibleElement {
    Edge {
        source: BlockId,
        target: BlockId,
        site: u64,
    },
    Block {
        block: BlockId,
    },
}

/// Structural scope of a conflict constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InfeasibleScope {
    /// All elements execute at most once per function invocation.
    Function,
    /// Elements touch one non-nested natural loop. Unordered and
    /// iteration-scoped ordered forms are per iteration; loop-entry ordered
    /// automata span all iterations.
    Loop { header: BlockId },
    /// Elements span the declaring function and one or more directly called
    /// callees.
    CrossFunction,
}

/// How an infeasible-path conflict is enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InfeasibleEnforcement {
    /// Linear aggregate constraint over original block/edge counts.
    Aggregate,
    /// Product IPET with a sequence-progress automaton.
    Automaton { reset: OrderedReset },
    /// Product IPET with the selected call groups inlined for the conflict.
    CrossFunctionAutomaton,
}

/// Where an ordered-conflict automaton resets its progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OrderedReset {
    /// No reset; the sequence spans the whole function invocation.
    Function,
    /// Reset when entering the loop; the sequence spans all its iterations.
    LoopEntry { header: BlockId },
    /// Reset on loop entry and every backedge; the sequence is per iteration.
    LoopIteration { header: BlockId },
    /// Reset per iteration but activate the sequence only in the selected
    /// 1-based iteration or the last iteration.
    LoopSpecific {
        header: BlockId,
        iteration: SpecificIteration,
    },
}

/// Validate a numeric iteration context for an ordered conflict.
fn supported_specific_iteration(
    iteration: IterationContext,
) -> Result<Option<SpecificIteration>, String> {
    match iteration {
        IterationContext::None | IterationContext::All => Ok(None),
        IterationContext::Specific(-1) => Ok(Some(SpecificIteration::Last)),
        IterationContext::Specific(value) if value >= 1 => match u32::try_from(value).ok() {
            Some(number) if number <= MAX_SPECIFIC_ITERATION => {
                Ok(Some(SpecificIteration::Number(number)))
            }
            _ => Err(format!(
                "iteration {value} exceeds the analysis limit of {MAX_SPECIFIC_ITERATION}"
            )),
        },
        IterationContext::Specific(value) => {
            Err(format!("iteration number {value} is unsupported"))
        }
    }
}

/// One resolved infeasible-path conflict.
#[derive(Clone, Debug)]
pub(crate) struct InfeasiblePathConstraint {
    pub(crate) function: Option<FunctionId>,
    pub(crate) elements: Vec<InfeasibleElement>,
    pub(crate) ordered: bool,
    pub(crate) context: Vec<ContextFrame>,
    pub(crate) context_names: Vec<String>,
    pub(crate) source: String,
    pub(crate) scope: Option<InfeasibleScope>,
    pub(crate) applied: bool,
    pub(crate) enforcement: InfeasibleEnforcement,
    pub(crate) cross_function: Option<CrossFunctionConstraint>,
    pub(crate) reason: Option<String>,
}

/// A resolved ordered conflict whose elements span one call boundary.
///
/// The declaring function executes the caller-side elements and the selected
/// call. The callee-side elements must all appear inside one invocation of
/// that call; their relative order is preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CrossFunctionGroup {
    pub(crate) callee: FunctionId,
    pub(crate) call_block: BlockId,
    pub(crate) call_site: u64,
    pub(crate) continuation: BlockId,
    /// The caller's call-return edge, matched as a caller-side event.
    pub(crate) call_return: InfeasibleElement,
    /// First callee slot in [`CrossFunctionConstraint::pattern`].
    pub(crate) slot_start: usize,
    /// Number of callee slots.
    pub(crate) slot_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CrossFunctionConstraint {
    pub(crate) caller: FunctionId,
    /// First group, kept for single-group reporting and compatibility.
    pub(crate) callee: FunctionId,
    pub(crate) call_block: BlockId,
    pub(crate) call_site: u64,
    pub(crate) continuation: BlockId,
    /// The caller's call-return edge, matched as a caller-side event.
    pub(crate) call_return: InfeasibleElement,
    /// One entry per `<call>` group, in declaration order.
    pub(crate) groups: Vec<CrossFunctionGroup>,
    /// Sequence-reset scope. `Function` spans one invocation, `LoopEntry`
    /// spans all iterations of the loop, and `LoopIteration` resets on entry
    /// and every backedge.
    pub(crate) reset: OrderedReset,
    /// Selected specific iteration, when the conflict is enclosed in a
    /// numeric `<iteration>` context.
    pub(crate) specific_iteration: Option<SpecificIteration>,
    /// Conflict elements in declaration order.
    pub(crate) pattern: Vec<CrossFunctionSlot>,
}

/// One element of a cross-function ordered conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CrossFunctionSlot {
    /// An element in the declaring function.
    Caller(InfeasibleElement),
    /// An element in one callee group. Group identity is inferred from the
    /// `slot_start`/`slot_len` ranges in [`CrossFunctionConstraint::groups`].
    Callee(InfeasibleElement),
}

#[derive(Clone, Debug)]
pub(crate) struct CallFact {
    target: CallTarget,
    callee: Option<String>,
    /// Function containing the call site, when declared inside a function.
    scope: Option<String>,
    max: u32,
    context: Vec<String>,
    context_sites: Vec<Option<u64>>,
    context_kind: ContextKind,
}

#[derive(Clone, Debug)]
pub(crate) enum LocationTarget {
    Address(u64),
    FunctionOffset {
        function: String,
        offset: u64,
    },
    SourceLine {
        function: Option<String>,
        file: String,
        line: u32,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum CallTarget {
    Location(LocationTarget),
    Callee(String),
}

fn resolve_context(
    program: &ProgramCfg,
    names: &[String],
    sites: &[Option<u64>],
    kind: ContextKind,
    target: &FunctionId,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<ResolvedContext>, String> {
    if names.is_empty() {
        return Ok(Some((Vec::new(), Vec::new())));
    }
    let mut functions = Vec::with_capacity(names.len());
    for name in names {
        functions.push(resolve_context_function(program, name, origin)?.id.clone());
    }
    let mut context = Vec::with_capacity(functions.len());
    let mut callee = target.clone();
    for (index, caller) in functions.iter().enumerate() {
        let call_sites = call_sites_between(program, caller, &callee);
        let explicit_site = sites.get(index).copied().flatten();
        let site = match kind {
            ContextKind::Function => None,
            ContextKind::FfxCall => {
                if let Some(site) = explicit_site {
                    if !call_sites.contains(&site) {
                        warnings.push(format!(
                            "{origin}: FFX caller context [{}] selects call site 0x{site:x}, but {:?} does not call {:?} there; fact ignored",
                            names.join(" / "),
                            function_name(program, caller),
                            function_name(program, &callee)
                        ));
                        return Ok(None);
                    }
                    Some(site)
                } else if call_sites.len() == 1 {
                    call_sites.first().copied()
                } else if call_sites.len() > 1 {
                    warnings.push(format!(
                        "{origin}: FFX caller context [{}] is ambiguous because {:?} calls {:?} from multiple sites; add a call address or fact ignored",
                        names.join(" / "),
                        function_name(program, caller),
                        function_name(program, &callee)
                    ));
                    return Ok(None);
                } else {
                    None
                }
            }
        };
        if call_sites.is_empty() {
            warnings.push(format!(
                "{origin}: caller context [{}] has no {:?} -> {:?} call site; fact has no effect",
                names.join(" / "),
                function_name(program, caller),
                function_name(program, &callee)
            ));
        }
        context.push(ContextFrame {
            function: caller.clone(),
            site,
        });
        callee = caller.clone();
    }
    Ok(Some((context, names.to_vec())))
}

fn call_sites_between(
    program: &ProgramCfg,
    caller: &FunctionId,
    target: &FunctionId,
) -> BTreeSet<u64> {
    let Some(function) = program
        .functions
        .iter()
        .find(|function| &function.id == caller)
    else {
        return BTreeSet::new();
    };
    let analysis = crate::cfg_graph::analyze(&function.cfg);
    let reachable: BTreeSet<BlockId> = analysis.reachable.into_iter().collect();
    let mut sites = BTreeSet::new();
    for node in function.cfg.blocks_by_address.values() {
        let block = &function.cfg.graph[*node];
        if !reachable.contains(&block.id) {
            continue;
        }
        for call in &block.calls {
            let targets = call.target_function.as_ref().into_iter().chain(
                call.candidates
                    .iter()
                    .filter_map(|candidate| candidate.target_function.as_ref()),
            );
            if targets.into_iter().any(|candidate| candidate == target) {
                sites.insert(call.site);
            }
        }
    }
    sites
}

fn function_name<'a>(program: &'a ProgramCfg, function: &FunctionId) -> &'a str {
    program
        .functions
        .iter()
        .find(|candidate| &candidate.id == function)
        .map_or("<unknown>", |function| function.primary_name.as_str())
}

fn function_for_block<'a>(
    program: &'a ProgramCfg,
    address: u64,
    origin: &str,
) -> Result<&'a CfgFunction, String> {
    program
        .functions
        .iter()
        .find(|function| function.cfg.blocks_by_address.contains_key(&address))
        .ok_or_else(|| format!("{origin}: no function contains block 0x{address:x}"))
}

#[allow(clippy::too_many_lines)]
fn resolve_conflict(
    program: &ProgramCfg,
    fact: &ConflictFact,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<InfeasiblePathConstraint, String> {
    let mut record = InfeasiblePathConstraint {
        function: None,
        elements: Vec::new(),
        ordered: fact.ordered,
        context: Vec::new(),
        context_names: fact.context.clone(),
        source: origin.to_owned(),
        scope: None,
        applied: false,
        enforcement: InfeasibleEnforcement::Aggregate,
        cross_function: None,
        reason: None,
    };
    let Some(scope_name) = &fact.scope else {
        record.reason = Some(format!(
            "{origin}: conflict outside a <function> or <call> is ignored"
        ));
        return Ok(record);
    };
    let function = find_function(program, scope_name, origin)?;
    record.function = Some(function.id.clone());
    let Some((context, context_names)) = resolve_context(
        program,
        &fact.context,
        &fact.context_sites,
        fact.context_kind,
        &function.id,
        origin,
        warnings,
    )?
    else {
        record.reason = Some(format!("{origin}: conflict caller context is ambiguous"));
        return Ok(record);
    };
    record.context = context;
    record.context_names = context_names;
    if fact
        .elements
        .iter()
        .any(|element| matches!(element, ConflictElementFact::Call { .. }))
    {
        return resolve_cross_function_conflict(program, function, fact, record, origin, warnings);
    }
    if matches!(fact.iteration, IterationContext::Specific(_)) && !fact.ordered {
        record.reason = Some(format!(
            "{origin}: specific-iteration same-function conflicts are supported only with ordered=\"yes\"; conflict ignored"
        ));
        return Ok(record);
    }
    let mut elements = Vec::new();
    for element in &fact.elements {
        let Some(resolved) = resolve_conflict_element(program, function, element, origin, warnings)
        else {
            record.elements = elements;
            record.reason = Some(format!(
                "{origin}: conflict element could not be resolved; conflict ignored"
            ));
            return Ok(record);
        };
        elements.push(resolved);
    }
    let mut seen = BTreeSet::new();
    elements.retain(|element| seen.insert(element.clone()));
    record.elements = elements;
    if fact.ordered {
        return resolve_ordered_conflict(program, function, fact, record, origin);
    }
    match conflict_scope(function, &record.elements) {
        Ok(scope) => {
            if let Some(target) = &fact.loop_context {
                let header_address = resolve_target(program, target, origin)?;
                let context_function = function_for_block(program, header_address, origin)?;
                let Some(&node) = function.cfg.blocks_by_address.get(&header_address) else {
                    record.reason = Some(format!(
                        "{origin}: conflict loop context is not a block in {:?}; conflict ignored",
                        function.primary_name
                    ));
                    return Ok(record);
                };
                let expected = InfeasibleScope::Loop {
                    header: function.cfg.graph[node].id.clone(),
                };
                if context_function.id != function.id || scope != expected {
                    record.reason = Some(format!(
                        "{origin}: conflict loop context does not match its structural scope; conflict ignored"
                    ));
                    return Ok(record);
                }
            }
            if fact.loop_context.is_some() || fact.iteration.is_iteration() {
                let InfeasibleScope::Loop { header } = &scope else {
                    record.reason = Some(format!(
                        "{origin}: loop-scoped conflict has no matching loop; conflict ignored"
                    ));
                    return Ok(record);
                };
                let analysis = crate::cfg_graph::analyze(&function.cfg);
                let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == *header)
                else {
                    record.reason = Some(format!(
                        "{origin}: conflict loop is not a natural loop; conflict ignored"
                    ));
                    return Ok(record);
                };
                let loop_blocks: BTreeSet<&BlockId> = loop_.blocks.iter().collect();
                let outside = record.elements.iter().any(|element| match element {
                    InfeasibleElement::Edge { source, target, .. } => {
                        !loop_blocks.contains(source) || !loop_blocks.contains(target)
                    }
                    InfeasibleElement::Block { block } => !loop_blocks.contains(block),
                });
                if outside {
                    record.reason = Some(format!(
                        "{origin}: loop-scoped conflict has an element outside the loop; conflict ignored"
                    ));
                    return Ok(record);
                }
            }
            record.scope = Some(scope);
            record.applied = true;
        }
        Err(reason) => {
            record.reason = Some(format!("{origin}: {reason}; conflict ignored"));
        }
    }
    Ok(record)
}

#[derive(Clone, Debug)]
struct ResolvedConflictCallSite {
    block: NodeIndex,
    block_id: BlockId,
    site: u64,
}

#[allow(clippy::too_many_lines)]
fn resolve_cross_function_conflict(
    program: &ProgramCfg,
    function: &CfgFunction,
    fact: &ConflictFact,
    mut record: InfeasiblePathConstraint,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<InfeasiblePathConstraint, String> {
    if !fact.ordered {
        record.reason = Some(format!(
            "{origin}: cross-function conflicts are supported only with ordered=\"yes\"; conflict ignored"
        ));
        return Ok(record);
    }
    if fact
        .elements
        .iter()
        .filter(|element| matches!(element, ConflictElementFact::Call { .. }))
        .count()
        > MAX_CROSS_FUNCTION_GROUPS
    {
        record.reason = Some(format!(
            "{origin}: cross-function conflict has too many <call> groups; conflict ignored"
        ));
        return Ok(record);
    }

    let mut pattern = Vec::new();
    let mut seen = BTreeSet::new();
    let mut call_sites = BTreeSet::new();
    let mut groups: Vec<CrossFunctionGroup> = Vec::new();
    for element in &fact.elements {
        match element {
            ConflictElementFact::Call {
                name,
                site,
                elements,
            } => {
                let callee = find_function(program, name, origin)?;
                if callee.id == function.id {
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict call group targets the declaring function; conflict ignored"
                    ));
                    return Ok(record);
                }
                if callee.cfg.entry.is_none() {
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict callee {name:?} has no CFG entry; conflict ignored"
                    ));
                    return Ok(record);
                }
                let Some(site) =
                    resolve_conflict_call_site(function, callee, *site, origin, warnings)
                else {
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict call group has no unique call site; conflict ignored"
                    ));
                    return Ok(record);
                };
                if !call_sites.insert(site.site) {
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict repeats call site 0x{:x}; conflict ignored",
                        site.site
                    ));
                    return Ok(record);
                }
                let Some((call_return, continuation)) =
                    resolve_conflict_call_return(function, &site)
                else {
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict call site 0x{:x} has no unique call-return edge; conflict ignored",
                        site.site
                    ));
                    return Ok(record);
                };
                let slot_start = pattern.len();
                let mut seen_group = BTreeSet::new();
                for nested in elements {
                    let Some(resolved) =
                        resolve_conflict_element(program, callee, nested, origin, warnings)
                    else {
                        record.elements = flatten_pattern(&pattern);
                        record.reason = Some(format!(
                            "{origin}: cross-function conflict callee element could not be resolved; conflict ignored"
                        ));
                        return Ok(record);
                    };
                    if !seen_group.insert(resolved.clone()) {
                        record.elements = flatten_pattern(&pattern);
                        record.reason = Some(format!(
                            "{origin}: ordered conflict repeats an element; conflict ignored"
                        ));
                        return Ok(record);
                    }
                    pattern.push(CrossFunctionSlot::Callee(resolved));
                }
                let slot_len = pattern.len().saturating_sub(slot_start);
                groups.push(CrossFunctionGroup {
                    callee: callee.id.clone(),
                    call_block: site.block_id,
                    call_site: site.site,
                    continuation,
                    call_return,
                    slot_start,
                    slot_len,
                });
            }
            ConflictElementFact::Block { .. } | ConflictElementFact::Edge { .. } => {
                let Some(resolved) =
                    resolve_conflict_element(program, function, element, origin, warnings)
                else {
                    record.elements = flatten_pattern(&pattern);
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict caller element could not be resolved; conflict ignored"
                    ));
                    return Ok(record);
                };
                if !seen.insert(resolved.clone()) {
                    record.elements = flatten_pattern(&pattern);
                    record.reason = Some(format!(
                        "{origin}: ordered conflict repeats an element; conflict ignored"
                    ));
                    return Ok(record);
                }
                pattern.push(CrossFunctionSlot::Caller(resolved));
            }
        }
    }
    record.elements = flatten_pattern(&pattern);
    let mut scope_elements: Vec<InfeasibleElement> = pattern
        .iter()
        .filter_map(|slot| match slot {
            CrossFunctionSlot::Caller(element) => Some(element.clone()),
            CrossFunctionSlot::Callee(_) => None,
        })
        .collect();
    for group in &groups {
        scope_elements.push(InfeasibleElement::Block {
            block: group.call_block.clone(),
        });
        scope_elements.push(InfeasibleElement::Block {
            block: group.continuation.clone(),
        });
        scope_elements.push(group.call_return.clone());
    }
    let loop_scope = match declared_loop_scope(program, function, fact, &scope_elements, origin)? {
        DeclaredLoopOutcome::None => {
            if fact.iteration.is_iteration() {
                record.reason = Some(format!(
                    "{origin}: iteration-scoped cross-function ordered conflict lacks a loop context; conflict ignored"
                ));
                return Ok(record);
            }
            None
        }
        DeclaredLoopOutcome::Ignore(reason) => {
            record.reason = Some(format!("{origin}: {reason}; conflict ignored"));
            return Ok(record);
        }
        DeclaredLoopOutcome::Selected(scope) => {
            if fact.iteration.is_iteration()
                && pattern.iter().any(|slot| {
                    matches!(slot, CrossFunctionSlot::Caller(InfeasibleElement::Edge { source, target, .. })
                        if scope.backedges.contains(&(source.clone(), target.clone())))
                })
            {
                record.reason = Some(format!(
                    "{origin}: iteration-scoped cross-function ordered conflict contains a loop-backedge element; conflict ignored"
                ));
                return Ok(record);
            }
            let specific_iteration = match supported_specific_iteration(fact.iteration) {
                Ok(iteration) => iteration,
                Err(reason) => {
                    record.reason = Some(format!(
                        "{origin}: cross-function conflict {reason}; conflict ignored"
                    ));
                    return Ok(record);
                }
            };
            Some((
                scope.header,
                fact.iteration.is_iteration(),
                specific_iteration,
            ))
        }
    };
    let reset = match &loop_scope {
        Some((header, true, _)) => OrderedReset::LoopIteration {
            header: header.clone(),
        },
        Some((header, false, _)) => OrderedReset::LoopEntry {
            header: header.clone(),
        },
        None => OrderedReset::Function,
    };

    let Some(first) = groups.first() else {
        record.reason = Some(format!(
            "{origin}: cross-function conflict has no call group; conflict ignored"
        ));
        return Ok(record);
    };
    let specific_iteration = loop_scope.as_ref().and_then(|(_, _, specific)| *specific);
    let cross = CrossFunctionConstraint {
        caller: function.id.clone(),
        callee: first.callee.clone(),
        call_block: first.call_block.clone(),
        call_site: first.call_site,
        continuation: first.continuation.clone(),
        call_return: first.call_return.clone(),
        groups,
        reset,
        specific_iteration,
        pattern: pattern.clone(),
    };
    record.scope = match &loop_scope {
        Some((header, _, _)) => Some(InfeasibleScope::Loop {
            header: header.clone(),
        }),
        None => Some(InfeasibleScope::CrossFunction),
    };
    record.enforcement = InfeasibleEnforcement::CrossFunctionAutomaton;
    record.cross_function = Some(cross);
    record.applied = true;
    Ok(record)
}

fn flatten_pattern(pattern: &[CrossFunctionSlot]) -> Vec<InfeasibleElement> {
    pattern
        .iter()
        .map(|slot| match slot {
            CrossFunctionSlot::Caller(element) | CrossFunctionSlot::Callee(element) => {
                element.clone()
            }
        })
        .collect()
}

fn resolve_conflict_call_site(
    function: &CfgFunction,
    callee: &CfgFunction,
    requested_site: Option<u64>,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Option<ResolvedConflictCallSite> {
    let analysis = crate::cfg_graph::analyze(&function.cfg);
    let reachable: BTreeSet<BlockId> = analysis.reachable.into_iter().collect();
    let mut sites: BTreeMap<u64, NodeIndex> = BTreeMap::new();
    for node in function.cfg.blocks_by_address.values() {
        let block = &function.cfg.graph[*node];
        if !reachable.contains(&block.id) {
            continue;
        }
        for call in &block.calls {
            let targets_callee = call.target_function.as_ref() == Some(&callee.id)
                || call
                    .candidates
                    .iter()
                    .any(|candidate| candidate.target_function.as_ref() == Some(&callee.id));
            if targets_callee {
                sites.entry(call.site).or_insert(*node);
            }
        }
    }
    let selected = if let Some(site) = requested_site {
        let Some(&node) = sites.get(&site) else {
            warnings.push(format!(
                "{origin}: cross-function conflict <call> selects 0x{site:x}, but that is not a reachable call site of {}; conflict ignored",
                callee.primary_name
            ));
            return None;
        };
        Some((site, node))
    } else if sites.len() == 1 {
        let (&site, &node) = sites.iter().next()?;
        Some((site, node))
    } else if sites.is_empty() {
        warnings.push(format!(
            "{origin}: cross-function conflict <call> target has no call site; conflict ignored"
        ));
        None
    } else {
        warnings.push(format!(
            "{origin}: cross-function conflict <call> target is ambiguous: multiple call sites; add an address/site or conflict ignored"
        ));
        None
    };
    let (site, node) = selected?;
    let block = &function.cfg.graph[node];
    checked_call_site(function, block, site, origin, warnings).map(|(_, block_id, site)| {
        ResolvedConflictCallSite {
            block: node,
            block_id,
            site,
        }
    })
}

fn resolve_conflict_call_return(
    function: &CfgFunction,
    site: &ResolvedConflictCallSite,
) -> Option<(InfeasibleElement, BlockId)> {
    let mut edges = function
        .cfg
        .graph
        .edges_directed(site.block, petgraph::Direction::Outgoing)
        .filter(|edge| edge.weight().kind == crate::cfg::CfgEdgeKind::CallReturn);
    let edge = edges.next()?;
    if edges.next().is_some() {
        return None;
    }
    let target = function.cfg.graph[edge.target()].id.clone();
    let element = InfeasibleElement::Edge {
        source: site.block_id.clone(),
        target: target.clone(),
        site: edge.weight().site,
    };
    Some((element, target))
}

#[allow(clippy::too_many_lines)]
fn resolve_ordered_conflict(
    program: &ProgramCfg,
    function: &CfgFunction,
    fact: &ConflictFact,
    mut record: InfeasiblePathConstraint,
    origin: &str,
) -> Result<InfeasiblePathConstraint, String> {
    if fact.elements.len() != record.elements.len() {
        record.reason = Some(format!(
            "{origin}: ordered conflict repeats an element; conflict ignored"
        ));
        return Ok(record);
    }
    let specific_iteration = match supported_specific_iteration(fact.iteration) {
        Ok(iteration) => iteration,
        Err(reason) => {
            record.reason = Some(format!(
                "{origin}: specific-iteration ordered conflict {reason}; conflict ignored"
            ));
            return Ok(record);
        }
    };
    let selected_loop = match declared_loop_scope(
        program,
        function,
        fact,
        &record.elements,
        origin,
    )? {
        DeclaredLoopOutcome::None => {
            if fact.iteration.is_iteration() {
                record.reason = Some(format!(
                    "{origin}: iteration-scoped ordered conflict lacks a loop context; conflict ignored"
                ));
                return Ok(record);
            }
            None
        }
        DeclaredLoopOutcome::Selected(scope) => Some(scope),
        DeclaredLoopOutcome::Ignore(reason) => {
            record.reason = Some(format!("{origin}: {reason}; conflict ignored"));
            return Ok(record);
        }
    };
    let declared_loop = if let Some(scope) = &selected_loop {
        if fact.iteration.is_iteration() {
            if record.elements.iter().any(|element| match element {
                InfeasibleElement::Edge { source, target, .. } => {
                    scope.backedges.contains(&(source.clone(), target.clone()))
                }
                InfeasibleElement::Block { .. } => false,
            }) {
                record.reason = Some(format!(
                    "{origin}: iteration-scoped ordered conflict contains a loop-backedge element; conflict ignored"
                ));
                return Ok(record);
            }
            match specific_iteration {
                Some(iteration) => Some(OrderedReset::LoopSpecific {
                    header: scope.header.clone(),
                    iteration,
                }),
                None if fact.iteration == IterationContext::All => {
                    Some(OrderedReset::LoopIteration {
                        header: scope.header.clone(),
                    })
                }
                None => Some(OrderedReset::LoopEntry {
                    header: scope.header.clone(),
                }),
            }
        } else {
            Some(OrderedReset::LoopEntry {
                header: scope.header.clone(),
            })
        }
    } else {
        None
    };

    let structural = conflict_scope(function, &record.elements);
    if let Some(reset) = declared_loop {
        if let (
            OrderedReset::LoopIteration { header },
            Ok(InfeasibleScope::Loop {
                header: scope_header,
            }),
        ) = (&reset, &structural)
            && header == scope_header
        {
            match ordered_sequence_support(
                function,
                &record.elements,
                &InfeasibleScope::Loop {
                    header: header.clone(),
                },
                true,
            ) {
                OrderedSequenceSupport::Forced => {
                    record.scope = Some(InfeasibleScope::Loop {
                        header: header.clone(),
                    });
                    record.enforcement = InfeasibleEnforcement::Aggregate;
                    record.applied = true;
                    return Ok(record);
                }
                OrderedSequenceSupport::Impossible => {
                    record.reason = Some(format!(
                        "{origin}: ordered conflict sequence is structurally impossible; no constraint added"
                    ));
                    return Ok(record);
                }
                OrderedSequenceSupport::Unsupported => {}
            }
        }
        record.scope = Some(InfeasibleScope::Loop {
            header: reset.header().clone(),
        });
        record.enforcement = InfeasibleEnforcement::Automaton { reset };
        record.applied = true;
        return Ok(record);
    }

    if matches!(structural, Ok(InfeasibleScope::Function)) {
        match ordered_sequence_support(
            function,
            &record.elements,
            &InfeasibleScope::Function,
            false,
        ) {
            OrderedSequenceSupport::Forced => {
                record.scope = Some(InfeasibleScope::Function);
                record.enforcement = InfeasibleEnforcement::Aggregate;
                record.applied = true;
                return Ok(record);
            }
            OrderedSequenceSupport::Impossible => {
                record.reason = Some(format!(
                    "{origin}: ordered conflict sequence is structurally impossible; no constraint added"
                ));
                return Ok(record);
            }
            OrderedSequenceSupport::Unsupported => {}
        }
    }
    record.scope = Some(InfeasibleScope::Function);
    record.enforcement = InfeasibleEnforcement::Automaton {
        reset: OrderedReset::Function,
    };
    record.applied = true;
    Ok(record)
}

impl OrderedReset {
    fn header(&self) -> &BlockId {
        match self {
            Self::Function => unreachable!("function reset has no loop header"),
            Self::LoopEntry { header }
            | Self::LoopIteration { header }
            | Self::LoopSpecific { header, .. } => header,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrderedSequenceSupport {
    /// The specified order is the only structurally possible order.
    Forced,
    /// No execution can contain the sequence in the specified order.
    Impossible,
    /// Structural reduction is not applicable; use the automaton product.
    Unsupported,
}

fn ordered_sequence_support(
    function: &CfgFunction,
    elements: &[InfeasibleElement],
    scope: &InfeasibleScope,
    all_iterations: bool,
) -> OrderedSequenceSupport {
    if elements.len() <= 1 {
        return OrderedSequenceSupport::Forced;
    }
    let node_by_id: BTreeMap<BlockId, NodeIndex> = function
        .cfg
        .blocks_by_address
        .values()
        .map(|node| (function.cfg.graph[*node].id.clone(), *node))
        .collect();
    let analysis = crate::cfg_graph::analyze(&function.cfg);
    let (allowed_blocks, excluded_edges) = match scope {
        InfeasibleScope::Function => (None, BTreeSet::new()),
        InfeasibleScope::Loop { header } if all_iterations => {
            let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == *header) else {
                return OrderedSequenceSupport::Unsupported;
            };
            let blocks: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
            let backedges: BTreeSet<(BlockId, BlockId)> = analysis
                .loops
                .iter()
                .flat_map(|loop_| {
                    loop_
                        .backedges
                        .iter()
                        .map(|edge| (edge.from.clone(), edge.to.clone()))
                })
                .collect();
            (Some(blocks), backedges)
        }
        InfeasibleScope::Loop { .. } | InfeasibleScope::CrossFunction => {
            return OrderedSequenceSupport::Unsupported;
        }
    };
    if all_iterations
        && elements.iter().any(|element| match element {
            InfeasibleElement::Edge { source, target, .. } => {
                excluded_edges.contains(&(source.clone(), target.clone()))
            }
            InfeasibleElement::Block { .. } => false,
        })
    {
        return OrderedSequenceSupport::Unsupported;
    }
    for pair in elements.windows(2) {
        let (_, from_exit) = element_bounds(&pair[0]);
        let (to_entry, _) = element_bounds(&pair[1]);
        let Some(from_node) = node_by_id.get(from_exit) else {
            return OrderedSequenceSupport::Unsupported;
        };
        let Some(to_node) = node_by_id.get(to_entry) else {
            return OrderedSequenceSupport::Unsupported;
        };
        if !cfg_reaches(
            function,
            *from_node,
            *to_node,
            allowed_blocks.as_ref(),
            &excluded_edges,
        ) {
            return OrderedSequenceSupport::Impossible;
        }
    }
    OrderedSequenceSupport::Forced
}

fn element_bounds(element: &InfeasibleElement) -> (&BlockId, &BlockId) {
    match element {
        InfeasibleElement::Edge { source, target, .. } => (source, target),
        InfeasibleElement::Block { block } => (block, block),
    }
}

fn cfg_reaches(
    function: &CfgFunction,
    start: NodeIndex,
    goal: NodeIndex,
    allowed_blocks: Option<&BTreeSet<BlockId>>,
    excluded_edges: &BTreeSet<(BlockId, BlockId)>,
) -> bool {
    if start == goal {
        return true;
    }
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    seen.insert(start);
    while let Some(node) = stack.pop() {
        let source = function.cfg.graph[node].id.clone();
        for edge in function
            .cfg
            .graph
            .edges_directed(node, petgraph::Direction::Outgoing)
        {
            let target = edge.target();
            let target_id = function.cfg.graph[target].id.clone();
            if allowed_blocks.is_some_and(|blocks| !blocks.contains(&target_id)) {
                continue;
            }
            if excluded_edges.contains(&(source.clone(), target_id.clone())) {
                continue;
            }
            if target == goal {
                return true;
            }
            if seen.insert(target) {
                stack.push(target);
            }
        }
    }
    false
}

fn resolve_conflict_element(
    program: &ProgramCfg,
    function: &CfgFunction,
    element: &ConflictElementFact,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Option<InfeasibleElement> {
    match element {
        ConflictElementFact::Block { location } => {
            let block = resolve_conflict_block(program, function, location, origin, warnings)?;
            Some(InfeasibleElement::Block {
                block: block.id.clone(),
            })
        }
        ConflictElementFact::Edge { src, dst } => {
            let Some(source) = block_at(&function.cfg, *src) else {
                warnings.push(format!(
                    "{origin}: conflict edge source 0x{src:x} is not in function {:?}",
                    function.primary_name
                ));
                return None;
            };
            let Some(target) = block_at(&function.cfg, *dst) else {
                warnings.push(format!(
                    "{origin}: conflict edge target 0x{dst:x} is not in function {:?}",
                    function.primary_name
                ));
                return None;
            };
            let &source_node = function.cfg.blocks_by_address.get(&source.address)?;
            let &target_node = function.cfg.blocks_by_address.get(&target.address)?;
            let candidates: Vec<_> = function
                .cfg
                .graph
                .edges_directed(source_node, petgraph::Direction::Outgoing)
                .filter(|edge| edge.target() == target_node)
                .collect();
            let edge = match candidates.as_slice() {
                [edge] => *edge,
                [] => {
                    warnings.push(format!(
                        "{origin}: conflict edge 0x{src:x} -> 0x{dst:x} is not a CFG edge"
                    ));
                    return None;
                }
                _ => {
                    let matching: Vec<_> = candidates
                        .iter()
                        .filter(|edge| edge.weight().site == *src)
                        .collect();
                    if let [edge] = matching.as_slice() {
                        **edge
                    } else {
                        warnings.push(format!(
                            "{origin}: conflict edge 0x{src:x} -> 0x{dst:x} is ambiguous"
                        ));
                        return None;
                    }
                }
            };
            Some(InfeasibleElement::Edge {
                source: source.id.clone(),
                target: target.id.clone(),
                site: edge.weight().site,
            })
        }
        ConflictElementFact::Call { .. } => {
            // A call group is resolved separately against its callee.
            None
        }
    }
}

fn resolve_conflict_block(
    program: &ProgramCfg,
    function: &CfgFunction,
    location: &LocationTarget,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Option<crate::cfg::CfgBlock> {
    match location {
        LocationTarget::Address(address) => {
            let Some(block) = block_at(&function.cfg, *address) else {
                warnings.push(format!(
                    "{origin}: conflict block 0x{address:x} is not in function {:?}",
                    function.primary_name
                ));
                return None;
            };
            Some(block.clone())
        }
        LocationTarget::FunctionOffset {
            function: name,
            offset,
        } => {
            let resolved = find_function(program, name, origin).ok()?;
            if resolved.id != function.id {
                warnings.push(format!(
                    "{origin}: conflict block offset names a different function"
                ));
                return None;
            }
            let address = function.address.checked_add(*offset)?;
            let Some(&node) = function.cfg.blocks_by_address.get(&address) else {
                warnings.push(format!(
                    "{origin}: conflict block offset 0x{offset:x} is not a block in {:?}",
                    function.primary_name
                ));
                return None;
            };
            Some(function.cfg.graph[node].clone())
        }
        LocationTarget::SourceLine {
            function: name,
            file,
            line,
        } => {
            if let Some(name) = name {
                let resolved = find_function(program, name, origin).ok()?;
                if resolved.id != function.id {
                    warnings.push(format!(
                        "{origin}: conflict block source names a different function"
                    ));
                    return None;
                }
            }
            let matches: Vec<&crate::cfg::CfgBlock> = function
                .cfg
                .blocks_by_address
                .values()
                .map(|node| &function.cfg.graph[*node])
                .filter(|block| {
                    block.instructions.iter().any(|instruction| {
                        instruction.source.as_ref().is_some_and(|source| {
                            source.line == *line && file_matches(file, &source.file)
                        })
                    })
                })
                .collect();
            match matches.as_slice() {
                [block] => Some((*block).clone()),
                [] => {
                    warnings.push(format!(
                        "{origin}: no conflict block matches source {file}:{line}"
                    ));
                    None
                }
                _ => {
                    warnings.push(format!(
                        "{origin}: conflict block source {file}:{line} is ambiguous"
                    ));
                    None
                }
            }
        }
    }
}

fn conflict_scope(
    function: &CfgFunction,
    elements: &[InfeasibleElement],
) -> Result<InfeasibleScope, String> {
    let analysis = crate::cfg_graph::analyze(&function.cfg);
    let loop_sets: Vec<BTreeSet<BlockId>> = analysis
        .loops
        .iter()
        .map(|loop_| loop_.blocks.iter().cloned().collect())
        .collect();
    let element_blocks: Vec<Vec<BlockId>> = elements
        .iter()
        .map(|element| match element {
            InfeasibleElement::Edge { source, target, .. } => {
                vec![source.clone(), target.clone()]
            }
            InfeasibleElement::Block { block } => vec![block.clone()],
        })
        .collect();
    let touches: Vec<BTreeSet<usize>> = element_blocks
        .iter()
        .map(|blocks| {
            loop_sets
                .iter()
                .enumerate()
                .filter(|(_, loop_set)| blocks.iter().any(|block| loop_set.contains(block)))
                .map(|(index, _)| index)
                .collect()
        })
        .collect();
    if touches.iter().all(BTreeSet::is_empty) {
        return Ok(InfeasibleScope::Function);
    }
    if touches.iter().any(BTreeSet::is_empty) {
        return Err("conflict mixes loop and non-loop elements".to_owned());
    }
    let mut common = touches[0].clone();
    for touched in &touches[1..] {
        common.retain(|index| touched.contains(index));
    }
    if common.is_empty() {
        return Err("conflict elements do not share a natural loop".to_owned());
    }
    let mut best: Option<usize> = None;
    for index in common {
        let loop_set = &loop_sets[index];
        let nested = loop_sets.iter().enumerate().any(|(other, inner)| {
            other != index
                && inner.len() < loop_set.len()
                && inner.is_subset(loop_set)
                && element_blocks
                    .iter()
                    .any(|blocks| blocks.iter().any(|block| inner.contains(block)))
        });
        if nested {
            continue;
        }
        if best.is_none_or(|best| loop_set.len() < loop_sets[best].len()) {
            best = Some(index);
        }
    }
    let Some(index) = best else {
        return Err("conflict elements span nested loops".to_owned());
    };
    Ok(InfeasibleScope::Loop {
        header: analysis.loops[index].header.clone(),
    })
}

#[derive(Clone, Debug)]
struct DeclaredLoopScope {
    header: BlockId,
    blocks: BTreeSet<BlockId>,
    backedges: BTreeSet<(BlockId, BlockId)>,
}

enum DeclaredLoopOutcome {
    None,
    Selected(DeclaredLoopScope),
    Ignore(String),
}

struct ResolvedLoopContext {
    address: u64,
    scope: DeclaredLoopScope,
}

fn element_within_loop(element: &InfeasibleElement, blocks: &BTreeSet<BlockId>) -> bool {
    match element {
        InfeasibleElement::Block { block } => blocks.contains(block),
        InfeasibleElement::Edge { source, target, .. } => {
            blocks.contains(source) && blocks.contains(target)
        }
    }
}

/// Select the declaring loop or loop hierarchy that contains every conflict
/// event. With nested `<loop>` contexts, the innermost context that contains
/// all elements wins; an `<iteration>` context pins the selected loop to the
/// loop where the iteration was declared.
fn declared_loop_scope(
    program: &ProgramCfg,
    function: &CfgFunction,
    fact: &ConflictFact,
    elements: &[InfeasibleElement],
    origin: &str,
) -> Result<DeclaredLoopOutcome, String> {
    let contexts: Vec<LoopTarget> = if fact.loop_contexts.is_empty() {
        fact.loop_context.iter().cloned().collect()
    } else {
        fact.loop_contexts.clone()
    };
    if contexts.is_empty() {
        return Ok(DeclaredLoopOutcome::None);
    }
    let analysis = crate::cfg_graph::analyze(&function.cfg);
    let mut resolved = Vec::with_capacity(contexts.len());
    for target in contexts {
        let address = resolve_target(program, &target, origin)?;
        let context_function = function_for_block(program, address, origin)?;
        if context_function.id != function.id {
            return Ok(DeclaredLoopOutcome::Ignore(
                "conflict loop context belongs to another function".to_owned(),
            ));
        }
        let Some(&node) = function.cfg.blocks_by_address.get(&address) else {
            return Ok(DeclaredLoopOutcome::Ignore(format!(
                "conflict loop context is not a block in {:?}",
                function.primary_name
            )));
        };
        let header = function.cfg.graph[node].id.clone();
        let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == header) else {
            return Ok(DeclaredLoopOutcome::Ignore(
                "conflict loop context is not a natural loop".to_owned(),
            ));
        };
        resolved.push(ResolvedLoopContext {
            address,
            scope: DeclaredLoopScope {
                header,
                blocks: loop_.blocks.iter().cloned().collect(),
                backedges: loop_
                    .backedges
                    .iter()
                    .map(|edge| (edge.from.clone(), edge.to.clone()))
                    .collect(),
            },
        });
    }
    for pair in resolved.windows(2) {
        if !pair[1].scope.blocks.is_subset(&pair[0].scope.blocks) {
            return Ok(DeclaredLoopOutcome::Ignore(
                "declared loop contexts are not nested".to_owned(),
            ));
        }
    }
    let contains_all = |scope: &DeclaredLoopScope| {
        elements
            .iter()
            .all(|element| element_within_loop(element, &scope.blocks))
    };
    if fact.iteration.is_iteration() {
        let iteration_target = fact.iteration_loop.as_ref().or(fact.loop_context.as_ref());
        let Some(target) = iteration_target else {
            return Ok(DeclaredLoopOutcome::Ignore(
                "iteration-scoped conflict lacks an enclosing loop".to_owned(),
            ));
        };
        let address = resolve_target(program, target, origin)?;
        let Some(scope) = resolved
            .iter()
            .find(|context| context.address == address)
            .map(|context| context.scope.clone())
        else {
            return Ok(DeclaredLoopOutcome::Ignore(
                "iteration context is not an enclosing conflict loop".to_owned(),
            ));
        };
        if !contains_all(&scope) {
            return Ok(DeclaredLoopOutcome::Ignore(
                "iteration-scoped conflict has an element outside the loop".to_owned(),
            ));
        }
        return Ok(DeclaredLoopOutcome::Selected(scope));
    }
    for context in resolved.iter().rev() {
        if contains_all(&context.scope) {
            return Ok(DeclaredLoopOutcome::Selected(context.scope.clone()));
        }
    }
    Ok(DeclaredLoopOutcome::Ignore(
        "conflict has an element outside the declared loop contexts".to_owned(),
    ))
}

fn resolve_context_function<'a>(
    program: &'a ProgramCfg,
    name: &str,
    origin: &str,
) -> Result<&'a CfgFunction, String> {
    let Some(address) = parse_context_address(name) else {
        return find_function(program, name, origin);
    };
    let candidates: Vec<&CfgFunction> = program
        .functions
        .iter()
        .filter(|function| function.address == address)
        .collect();
    match candidates.as_slice() {
        [function] => Ok(function),
        [] => Err(format!(
            "{origin}: context function address 0x{address:x} was not found"
        )),
        _ => Err(format!(
            "{origin}: context function address 0x{address:x} is ambiguous"
        )),
    }
}

fn parse_context_address(value: &str) -> Option<u64> {
    let cleaned = value.trim().replace('_', "");
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

fn resolve_target(program: &ProgramCfg, target: &LoopTarget, origin: &str) -> Result<u64, String> {
    match target {
        LoopTarget::Address(address) => {
            if block_exists(program, *address) {
                Ok(*address)
            } else {
                Err(format!(
                    "{origin}: loop header 0x{address:x} is not a CFG block"
                ))
            }
        }
        LoopTarget::FunctionOffset { function, offset } => {
            let function = find_function(program, function, origin)?;
            let address = function
                .address
                .checked_add(*offset)
                .ok_or_else(|| format!("{origin}: loop offset overflows the address space"))?;
            if function.cfg.blocks_by_address.contains_key(&address) {
                Ok(address)
            } else {
                Err(format!(
                    "{origin}: function {:?} has no block at 0x{address:x}",
                    function.primary_name
                ))
            }
        }
        LoopTarget::SourceLine {
            function,
            file,
            line,
        } => resolve_source_loop(program, function.as_deref(), file, *line, origin),
    }
}

fn block_exists(program: &ProgramCfg, address: u64) -> bool {
    program
        .functions
        .iter()
        .any(|function| function.cfg.blocks_by_address.contains_key(&address))
}

fn find_function<'a>(
    program: &'a ProgramCfg,
    name: &str,
    origin: &str,
) -> Result<&'a CfgFunction, String> {
    let candidates: Vec<&CfgFunction> = program
        .functions
        .iter()
        .filter(|function| function_matches(function, name))
        .collect();
    match candidates.as_slice() {
        [function] => Ok(function),
        [] => Err(format!("{origin}: function {name:?} was not found")),
        _ => Err(format!(
            "{origin}: function {name:?} is ambiguous ({} matches)",
            candidates.len()
        )),
    }
}

fn function_matches(function: &CfgFunction, name: &str) -> bool {
    fn matches(candidate: &str, name: &str) -> bool {
        let candidate = normalize_crate_hashes(candidate);
        candidate == name
            || candidate
                .rsplit("::")
                .next()
                .is_some_and(|last| last == name)
    }
    matches(&function.primary_name, name)
        || function
            .demangled_name
            .as_deref()
            .is_some_and(|demangled| matches(demangled, name))
        || function
            .symbols
            .iter()
            .any(|symbol| symbol == name || matches(symbol, name))
}

fn resolve_source_loop(
    program: &ProgramCfg,
    function_name: Option<&str>,
    file: &str,
    line: u32,
    origin: &str,
) -> Result<u64, String> {
    let functions: Vec<&CfgFunction> = match function_name {
        Some(name) => vec![find_function(program, name, origin)?],
        None => program.functions.iter().collect(),
    };
    let mut matches = BTreeSet::new();
    for function in functions {
        let analysis = crate::cfg_graph::analyze(&function.cfg);
        for loop_ in &analysis.loops {
            let Some(node) = function
                .cfg
                .blocks_by_address
                .values()
                .copied()
                .find(|node| function.cfg.graph[*node].id == loop_.header)
            else {
                continue;
            };
            let block = &function.cfg.graph[node];
            if block.instructions.iter().any(|instruction| {
                instruction
                    .source
                    .as_ref()
                    .is_some_and(|source| source.line == line && file_matches(file, &source.file))
            }) {
                matches.insert(block.address);
            }
        }
    }
    match matches.len() {
        1 => matches
            .first()
            .copied()
            .ok_or_else(|| format!("{origin}: internal error resolving loop source")),
        0 => Err(format!(
            "{origin}: no natural loop header matches source {file}:{line}"
        )),
        _ => Err(format!(
            "{origin}: source {file}:{line} matches multiple loops (0x{:x}..)",
            matches.first().copied().unwrap_or(0)
        )),
    }
}

fn resolve_branch_target(
    program: &ProgramCfg,
    target: &LocationTarget,
    origin: &str,
) -> Result<(FunctionId, BlockId, u64), String> {
    let mut matches = Vec::new();
    match target {
        LocationTarget::Address(address) => {
            for function in &program.functions {
                if let Some(block) = block_at(&function.cfg, *address)
                    && block.terminator == crate::cfg::CfgTerminator::Branch
                    && !has_it_predication(block)
                    && block
                        .instructions
                        .last()
                        .is_some_and(|insn| insn.address == *address && insn.is_conditional)
                {
                    matches.push((function.id.clone(), block.id.clone(), *address));
                }
            }
        }
        LocationTarget::FunctionOffset { function, offset } => {
            let function = find_function(program, function, origin)?;
            let address = function
                .address
                .checked_add(*offset)
                .ok_or_else(|| format!("{origin}: branch offset overflows the address space"))?;
            if let Some(block) = block_at(&function.cfg, address)
                && block.terminator == crate::cfg::CfgTerminator::Branch
                && !has_it_predication(block)
                && block
                    .instructions
                    .last()
                    .is_some_and(|insn| insn.address == address && insn.is_conditional)
            {
                matches.push((function.id.clone(), block.id.clone(), address));
            }
        }
        LocationTarget::SourceLine {
            function,
            file,
            line,
        } => {
            let functions: Vec<&CfgFunction> = match function {
                Some(name) => vec![find_function(program, name, origin)?],
                None => program.functions.iter().collect(),
            };
            for function in functions {
                for block in function
                    .cfg
                    .blocks_by_address
                    .values()
                    .map(|node| &function.cfg.graph[*node])
                {
                    if block.terminator != crate::cfg::CfgTerminator::Branch {
                        continue;
                    }
                    let Some(last) = block.instructions.last() else {
                        continue;
                    };
                    if last.is_conditional
                        && !has_it_predication(block)
                        && last.source.as_ref().is_some_and(|source| {
                            source.line == *line && file_matches(file, &source.file)
                        })
                    {
                        matches.push((function.id.clone(), block.id.clone(), last.address));
                    }
                }
            }
        }
    }
    match matches.len() {
        1 => matches
            .pop()
            .ok_or_else(|| format!("{origin}: internal error resolving branch")),
        0 => Err(format!(
            "{origin}: no conditional branch matches the flow-fact target"
        )),
        _ => Err(format!(
            "{origin}: branch target matches multiple conditional branches"
        )),
    }
}

fn resolve_call_target(
    program: &ProgramCfg,
    target: &CallTarget,
    scope: Option<&str>,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<CallSiteRef>, String> {
    match target {
        CallTarget::Callee(name) => {
            resolve_callee_call_sites(program, name, scope, origin, warnings)
        }
        CallTarget::Location(location) => {
            resolve_location_call_sites(program, location, scope, origin, warnings)
        }
    }
}

fn resolve_callee_call_sites(
    program: &ProgramCfg,
    name: &str,
    scope: Option<&str>,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<CallSiteRef>, String> {
    let callee = find_function(program, name, origin)?;
    let scope = scope
        .map(|name| find_function(program, name, origin))
        .transpose()?;
    let mut sites = Vec::new();
    let mut matched = false;
    for function in &program.functions {
        if scope.is_some_and(|scope| scope.id != function.id) {
            continue;
        }
        for block in function
            .cfg
            .blocks_by_address
            .values()
            .map(|node| &function.cfg.graph[*node])
        {
            for call in &block.calls {
                if call.target_function.as_ref() != Some(&callee.id) {
                    continue;
                }
                matched = true;
                if let Some(site) = checked_call_site(function, block, call.site, origin, warnings)
                {
                    sites.push(site);
                }
            }
        }
    }
    if !matched {
        return Err(format!(
            "{origin}: no call site targets function {:?}",
            callee.primary_name
        ));
    }
    Ok(sites)
}

fn resolve_location_call_sites(
    program: &ProgramCfg,
    location: &LocationTarget,
    scope: Option<&str>,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<CallSiteRef>, String> {
    let scope = scope
        .map(|name| find_function(program, name, origin))
        .transpose()?;
    let scope_id = scope.as_ref().map(|function| &function.id);
    let (matched, found) = match location {
        LocationTarget::Address(address) => {
            collect_call_sites_at(program, *address, scope_id, origin, warnings)
        }
        LocationTarget::FunctionOffset { function, offset } => {
            let function = find_function(program, function, origin)?;
            if scope_id.is_some_and(|scope| scope != &function.id) {
                return Err(format!(
                    "{origin}: call location function {:?} does not match the enclosing function",
                    function.primary_name
                ));
            }
            let address = function
                .address
                .checked_add(*offset)
                .ok_or_else(|| format!("{origin}: call offset overflows the address space"))?;
            collect_call_sites_at(program, address, scope_id, origin, warnings)
        }
        LocationTarget::SourceLine {
            function,
            file,
            line,
        } => collect_call_sites_at_source(
            program,
            function.as_deref(),
            file,
            *line,
            scope_id,
            origin,
            warnings,
        )?,
    };
    finish_call_sites(found, matched, origin)
}

fn collect_call_sites_at(
    program: &ProgramCfg,
    address: u64,
    scope: Option<&FunctionId>,
    origin: &str,
    warnings: &mut Vec<String>,
) -> (bool, Vec<CallSiteRef>) {
    let mut found = Vec::new();
    let mut matched = false;
    for function in &program.functions {
        if scope.is_some_and(|scope| scope != &function.id) {
            continue;
        }
        if let Some(block) = block_at(&function.cfg, address)
            && let Some(call) = block.calls.iter().find(|call| call.site == address)
        {
            matched = true;
            if let Some(site) = checked_call_site(function, block, call.site, origin, warnings) {
                found.push(site);
            }
        }
    }
    (matched, found)
}

fn collect_call_sites_at_source(
    program: &ProgramCfg,
    function_name: Option<&str>,
    file: &str,
    line: u32,
    scope: Option<&FunctionId>,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<(bool, Vec<CallSiteRef>), String> {
    let functions: Vec<&CfgFunction> = match function_name {
        Some(name) => vec![find_function(program, name, origin)?],
        None => program.functions.iter().collect(),
    };
    let functions: Vec<&CfgFunction> = functions
        .into_iter()
        .filter(|function| scope.is_none_or(|scope| scope == &function.id))
        .collect();
    let mut found = Vec::new();
    let mut matched = false;
    for function in functions {
        for block in function
            .cfg
            .blocks_by_address
            .values()
            .map(|node| &function.cfg.graph[*node])
        {
            for call in &block.calls {
                let source_matches = block
                    .instructions
                    .iter()
                    .find(|insn| insn.address == call.site)
                    .and_then(|insn| insn.source.as_ref())
                    .is_some_and(|source| source.line == line && file_matches(file, &source.file));
                if source_matches {
                    matched = true;
                    if let Some(site) =
                        checked_call_site(function, block, call.site, origin, warnings)
                    {
                        found.push(site);
                    }
                }
            }
        }
    }
    Ok((matched, found))
}

fn finish_call_sites(
    found: Vec<CallSiteRef>,
    matched: bool,
    origin: &str,
) -> Result<Vec<CallSiteRef>, String> {
    match found.len() {
        0 if matched => Ok(found),
        0 => Err(format!(
            "{origin}: no call site matches the flow-fact target"
        )),
        1 => Ok(found),
        _ => Err(format!("{origin}: call target matches multiple call sites")),
    }
}

fn verify_call_callee(
    program: &ProgramCfg,
    function_id: &FunctionId,
    site: u64,
    callee_name: &str,
    origin: &str,
) -> Result<(), String> {
    let function = program
        .functions
        .iter()
        .find(|function| &function.id == function_id)
        .ok_or_else(|| format!("{origin}: internal error resolving call-site function"))?;
    let block = block_at(&function.cfg, site)
        .ok_or_else(|| format!("{origin}: call site 0x{site:x} is not in a CFG block"))?;
    let call = block
        .calls
        .iter()
        .find(|call| call.site == site)
        .ok_or_else(|| format!("{origin}: no call instruction at 0x{site:x}"))?;
    let callee = find_function(program, callee_name, origin)?;
    if call.target_function.as_ref() != Some(&callee.id) {
        return Err(format!(
            "{origin}: call site 0x{site:x} does not target function {callee_name:?}"
        ));
    }
    Ok(())
}

fn checked_call_site(
    function: &CfgFunction,
    block: &crate::cfg::CfgBlock,
    site: u64,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Option<CallSiteRef> {
    if block.calls.len() != 1 {
        warnings.push(format!(
            "{origin}: call site 0x{site:x} shares its block with other calls; fact not applied"
        ));
        return None;
    }
    let call = block.calls.iter().find(|call| call.site == site)?;
    if call.conditional {
        warnings.push(format!(
            "{origin}: conditional call site 0x{site:x} is not constrained by a block count"
        ));
        return None;
    }
    if !call.candidates.is_empty()
        || call.target_function.is_none()
        || call.unresolved
        || call.heuristic
    {
        warnings.push(format!(
            "{origin}: call site 0x{site:x} has multiple, unresolved or unnamed targets; fact not applied"
        ));
        return None;
    }
    if has_it_predication(block) {
        warnings.push(format!(
            "{origin}: call site 0x{site:x} is predicated; fact not applied"
        ));
        return None;
    }
    Some((function.id.clone(), block.id.clone(), site))
}

fn has_it_predication(block: &crate::cfg::CfgBlock) -> bool {
    block
        .instructions
        .iter()
        .any(|insn| insn.mnemonic.to_ascii_lowercase().starts_with("it"))
}

fn block_at(cfg: &crate::cfg::FunctionCfg, address: u64) -> Option<&crate::cfg::CfgBlock> {
    cfg.blocks_by_address
        .values()
        .map(|node| &cfg.graph[*node])
        .find(|block| {
            address >= block.address && address < block.address.saturating_add(block.size)
        })
}

fn file_matches(expected: &str, actual: &str) -> bool {
    let expected = expected.trim_start_matches("./");
    let actual = actual.trim_start_matches("./");
    if actual == expected || actual.ends_with(expected) {
        return true;
    }
    let expected_name = Path::new(expected)
        .file_name()
        .and_then(std::ffi::OsStr::to_str);
    let actual_name = Path::new(actual)
        .file_name()
        .and_then(std::ffi::OsStr::to_str);
    expected_name.is_some() && expected_name == actual_name
}

#[cfg(test)]
mod tests {
    use super::{
        ContextFrame, ContextKind, ContextualLoopBound, FactScope, FlowFacts,
        InfeasibleEnforcement, InfeasiblePathConstraint, LoopBound, block_at, checked_call_site,
        resolve_context,
    };
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgFunction, CfgInstruction, CfgTerminator,
        FunctionCfg, ProgramCfg,
    };
    use crate::loop_bounds::InferredLoopBound;
    use elf2tdg_schema::{Addr, FunctionId, FunctionKind, Language};

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
        assert_eq!(
            facts
                .loops()
                .map(|(header, bound, _)| (header, bound))
                .collect::<Vec<_>>(),
            vec![(0x1000, 12)]
        );
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

    fn inferred(header: u64, bound: u32) -> InferredLoopBound {
        InferredLoopBound {
            function: FunctionId::new("fn:0x1000"),
            header,
            bound,
            detail: format!("init=0 limit={bound} step=1"),
        }
    }

    #[test]
    fn inferred_bounds_merge_conservatively() {
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
bound = 10
"#,
        );
        let mut facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let applied = facts.apply_inferred_loops([
            inferred(0x100, 5),
            inferred(0x200, 1),
            inferred(0x400, 5),
            inferred(0x800, 8),
        ]);
        assert_eq!(applied, 2);
        assert_eq!(facts.bound_for(0x100), Some(5));
        assert_eq!(facts.bound_for(0x200), Some(2));
        assert_eq!(facts.bound_for(0x400), Some(10));
        assert_eq!(facts.bound_for(0x800), Some(8));
        assert!(facts.source().contains("auto loop bounds"));
        assert!(
            facts
                .warnings()
                .iter()
                .any(|warning| warning.contains("0x800") && warning.contains("exceeds"))
        );
        assert!(
            facts
                .info()
                .loops
                .iter()
                .any(|entry| entry.source.contains("inferred counted loop"))
        );
    }

    #[test]
    fn conditional_call_sites_are_not_constrained_by_call_facts() {
        let site = 0x1000;
        let instruction = CfgInstruction {
            address: site,
            size: 4,
            bytes: vec![0x3e, 0x00, 0x00, 0x1b],
            mnemonic: "blne".to_owned(),
            operands: "#0x1100".to_owned(),
            text: "blne #0x1100".to_owned(),
            is_call: true,
            is_jump: false,
            is_return: false,
            is_conditional: true,
            direct_target: Some(0x1100),
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: None,
            source: None,
        };
        let call = CfgCallSite {
            site,
            target: Some(0x1100),
            target_function: Some(FunctionId::new("fn:0x1100")),
            direct: true,
            tail: false,
            conditional: true,
            heuristic: false,
            unresolved: false,
            null_target: false,
            noreturn: false,
            candidates: Vec::new(),
        };
        let cfg = FunctionCfg::build(
            vec![CfgBlockDraft {
                address: site,
                size: 4,
                instructions: vec![instruction],
                calls: vec![call],
                cycles: None,
                terminator: CfgTerminator::Call,
            }],
            Vec::<CfgEdgeDraft>::new(),
            Some(site),
        );
        let function = CfgFunction {
            id: FunctionId::new("fn:0x1000"),
            primary_name: "caller".to_owned(),
            demangled_name: None,
            symbols: Vec::new(),
            language: Language::C,
            kind: FunctionKind::Normal,
            address: site,
            size: 4,
            section: ".text".to_owned(),
            source: None,
            inline_frames: Vec::new(),
            noreturn: None,
            cfg,
            wcet: None,
        };
        let block = block_at(&function.cfg, site).expect("call block");
        let mut warnings = Vec::new();
        let resolved = checked_call_site(&function, block, site, "test.ffx", &mut warnings);
        assert!(resolved.is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("conditional call"))
        );
    }
    fn caller(id: &str) -> FunctionId {
        FunctionId::new(id)
    }

    fn frame(id: &str) -> ContextFrame {
        ContextFrame::function(caller(id))
    }

    #[allow(dead_code)]
    fn call_frame(id: &str, site: u64) -> ContextFrame {
        ContextFrame::call(caller(id), site)
    }

    #[test]
    fn contextual_bounds_use_the_most_specific_call_chain() {
        let mut facts = FlowFacts {
            default_loop_bound: Some(4),
            ..FlowFacts::default()
        };
        facts.loop_bounds.insert(
            0x100,
            LoopBound {
                bound: 6,
                source: "profile".to_owned(),
            },
        );
        for (context, bound) in [
            (vec!["fn:main"], 2),
            (vec!["fn:main", "fn:reset"], 3),
            (vec!["fn:sensor"], 8),
        ] {
            facts.contextual_loops.push(ContextualLoopBound {
                header: 0x100,
                bound,
                context: context.iter().map(|name| frame(name)).collect(),
                context_names: context.iter().map(ToString::to_string).collect(),
                source: "facts.ffx".to_owned(),
            });
        }
        assert_eq!(facts.bound_for_context(0x100, &[frame("fn:main")]), Some(2));
        assert_eq!(
            facts.bound_for_context(0x100, &[frame("fn:main"), frame("fn:reset")]),
            Some(3)
        );
        assert_eq!(
            facts.bound_for_context(0x100, &[frame("fn:sensor")]),
            Some(8)
        );
        assert_eq!(
            facts.bound_for_context(0x100, &[frame("fn:other")]),
            Some(6)
        );
        assert_eq!(facts.bound_for(0x100), Some(8));
    }

    #[test]
    fn call_site_contexts_are_more_specific_than_function_contexts() {
        let mut facts = FlowFacts::default();
        facts.contextual_loops.push(ContextualLoopBound {
            header: 0x100,
            bound: 2,
            context: vec![frame("fn:main")],
            context_names: vec!["main".to_owned()],
            source: "function.ff".to_owned(),
        });
        facts.contextual_loops.push(ContextualLoopBound {
            header: 0x100,
            bound: 5,
            context: vec![call_frame("fn:main", 0x1000)],
            context_names: vec!["main".to_owned()],
            source: "call.ffx".to_owned(),
        });
        assert_eq!(facts.bound_for_context(0x100, &[frame("fn:main")]), Some(2));
        assert_eq!(
            facts.bound_for_context(0x100, &[call_frame("fn:main", 0x1000)]),
            Some(5)
        );
        assert_eq!(
            facts.bound_for_context(0x100, &[call_frame("fn:main", 0x1004)]),
            Some(2)
        );
        let info = facts.info();
        let site_loop = info
            .loops
            .iter()
            .find(|entry| entry.source == "call.ffx")
            .expect("site-specific loop");
        assert_eq!(site_loop.context_sites, Some(vec![Some(Addr::new(0x1000))]));
    }

    #[test]
    fn contextual_bounds_without_a_global_fallback_are_unbounded_when_insensitive() {
        let mut facts = FlowFacts::default();
        facts.contextual_loops.push(ContextualLoopBound {
            header: 0x100,
            bound: 2,
            context: vec![frame("fn:main")],
            context_names: vec!["main".to_owned()],
            source: "facts.ffx".to_owned(),
        });
        assert_eq!(facts.bound_for_context(0x100, &[frame("fn:main")]), Some(2));
        assert_eq!(facts.bound_for_context(0x100, &[frame("fn:other")]), None);
        assert_eq!(facts.bound_for(0x100), None);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ambiguous_ffx_contexts_are_ignored() {
        let target = FunctionId::new("fn:0x2000");
        let call = |site| CfgCallSite {
            site,
            target: Some(0x2000),
            target_function: Some(target.clone()),
            direct: true,
            tail: false,
            conditional: false,
            heuristic: false,
            unresolved: false,
            null_target: false,
            noreturn: false,
            candidates: Vec::new(),
        };
        let instruction = CfgInstruction {
            address: 0x1000,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "bl".to_owned(),
            operands: String::new(),
            text: "bl".to_owned(),
            is_call: true,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: Some(0x2000),
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: None,
            source: None,
        };
        let cfg = FunctionCfg::build(
            vec![CfgBlockDraft {
                address: 0x1000,
                size: 4,
                instructions: vec![instruction],
                calls: vec![call(0x1000), call(0x1002)],
                cycles: None,
                terminator: CfgTerminator::Call,
            }],
            Vec::<CfgEdgeDraft>::new(),
            Some(0x1000),
        );
        let caller_fn = CfgFunction {
            id: FunctionId::new("fn:0x1000"),
            primary_name: "caller".to_owned(),
            demangled_name: None,
            symbols: Vec::new(),
            language: Language::C,
            kind: FunctionKind::Normal,
            address: 0x1000,
            size: 4,
            section: ".text".to_owned(),
            source: None,
            inline_frames: Vec::new(),
            noreturn: None,
            cfg,
            wcet: None,
        };
        let program = ProgramCfg::new(vec![caller_fn]);
        let names = vec!["caller".to_owned()];
        let mut warnings = Vec::new();
        let resolved = resolve_context(
            &program,
            &names,
            &[],
            ContextKind::FfxCall,
            &target,
            "test.ffx",
            &mut warnings,
        )
        .expect("resolve");
        assert!(resolved.is_none());
        assert!(warnings.iter().any(|warning| warning.contains("ambiguous")));
        let resolved = resolve_context(
            &program,
            &names,
            &[],
            ContextKind::Function,
            &target,
            "test.ff",
            &mut warnings,
        )
        .expect("resolve");
        assert!(resolved.is_some());

        let resolved = resolve_context(
            &program,
            &names,
            &[Some(0x1002)],
            ContextKind::FfxCall,
            &target,
            "test.ffx",
            &mut warnings,
        )
        .expect("resolve")
        .expect("resolved call site");
        assert_eq!(resolved.0, vec![call_frame("fn:0x1000", 0x1002)]);

        let resolved = resolve_context(
            &program,
            &names,
            &[Some(0x9999)],
            ContextKind::FfxCall,
            &target,
            "test.ffx",
            &mut warnings,
        )
        .expect("resolve");
        assert!(resolved.is_none());
        assert!(warnings.iter().any(|warning| warning.contains("0x9999")));
    }

    #[test]
    fn contextual_infeasible_paths_request_context_analysis() {
        let mut facts = FlowFacts::default();
        assert!(!facts.has_contextual_facts());
        facts.infeasible_paths.push(InfeasiblePathConstraint {
            function: Some(caller("fn:target")),
            elements: Vec::new(),
            ordered: false,
            context: vec![frame("fn:main")],
            context_names: vec!["main".to_owned()],
            source: "conflict.ffx".to_owned(),
            scope: None,
            applied: true,
            enforcement: InfeasibleEnforcement::Aggregate,
            cross_function: None,
            reason: None,
        });
        assert!(facts.has_contextual_facts());
    }

    #[test]
    fn fact_scope_matches_prefixes_and_insensitive_scopes() {
        let context = [frame("fn:main")];
        assert!(FactScope::Context(&context).matches(&[frame("fn:main")]));
        assert!(!FactScope::Context(&context).matches(&[frame("fn:sensor")]));
        assert!(FactScope::Context(&context).matches(&[]));
        assert!(FactScope::Insensitive.matches(&[]));
        assert!(!FactScope::Insensitive.matches(&[frame("fn:main")]));

        let call_context = [call_frame("fn:main", 0x1000)];
        assert!(FactScope::Context(&call_context).matches(&[call_frame("fn:main", 0x1000)]));
        assert!(!FactScope::Context(&call_context).matches(&[call_frame("fn:main", 0x1004)]));
        assert!(FactScope::Context(&call_context).matches(&[frame("fn:main")]));
        assert!(!FactScope::Context(&context).matches(&[call_frame("fn:main", 0x1000)]));
    }
}
