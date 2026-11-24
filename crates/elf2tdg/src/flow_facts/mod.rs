//! Flow facts consumed by IPET and the longest-path analysis.
//!
//! Facts come from the board profile's `[wcet]` section and from external F4
//! (`.ff`) or FFX (`.ffx`) files. F4/FFX facts are parsed into a symbolic
//! document first and resolved against the recovered `ProgramCfg`, so a fact
//! can name a loop by address, by function + offset, or by source file/line.

mod f4;
mod ffx;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use elf2tdg_schema::{Addr, BlockId, FunctionId};

use crate::board_profile::WcetProfile;
use crate::cfg::{
    CfgBranchFactInfo, CfgCallFactInfo, CfgFlowFactsInfo, CfgFunction, CfgLoopBoundInfo, ProgramCfg,
};
use crate::loop_bounds::InferredLoopBound;
use crate::rules::normalize_crate_hashes;

#[derive(Clone, Debug)]
struct LoopBound {
    bound: u32,
    source: String,
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
    pub(crate) source: String,
}

/// A resolved call-site execution constraint.
#[derive(Clone, Debug)]
pub(crate) struct CallConstraint {
    pub(crate) function: FunctionId,
    pub(crate) block: BlockId,
    pub(crate) site: u64,
    pub(crate) max_count: u32,
    pub(crate) source: String,
}

type CallSiteRef = (FunctionId, BlockId, u64);

/// Bounds and assumptions used by the WCET analyses for one analysis run.
#[derive(Clone, Debug, Default)]
pub(crate) struct FlowFacts {
    source: String,
    default_loop_bound: Option<u32>,
    bound_nonterminating_loops: bool,
    loop_bounds: BTreeMap<u64, LoopBound>,
    branches: Vec<BranchConstraint>,
    calls: Vec<CallConstraint>,
    warnings: Vec<String>,
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
            branches: Vec::new(),
            calls: Vec::new(),
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

    /// Returns the bound for a loop header, preferring an explicit entry.
    pub(crate) fn bound_for(&self, header: u64) -> Option<u32> {
        self.loop_bounds
            .get(&header)
            .map(|entry| entry.bound)
            .or(self.default_loop_bound)
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

    /// Whether any non-loop constraint was resolved.
    pub(crate) fn has_non_loop_facts(&self) -> bool {
        !self.branches.is_empty() || !self.calls.is_empty()
    }

    /// Warnings collected while importing flow facts.
    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Builds the JSON metadata object for the WCET document.
    pub(crate) fn info(&self) -> CfgFlowFactsInfo {
        CfgFlowFactsInfo {
            source: self.source().to_owned(),
            default_loop_bound: self.default_loop_bound,
            bound_nonterminating_loops: self.bound_nonterminating_loops,
            loops: self
                .loops()
                .map(|(header, bound, source)| CfgLoopBoundInfo {
                    header: Addr::new(header),
                    bound,
                    source: source.to_owned(),
                })
                .collect(),
            branches: self
                .branches
                .iter()
                .map(|branch| CfgBranchFactInfo {
                    function: branch.function.clone(),
                    site: Addr::new(branch.site),
                    outcome: branch.outcome.name().to_owned(),
                    max_count: branch.max_count,
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
                    source: call.source.clone(),
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
    /// Conflicting bounds for the same loop keep the larger value, which is
    /// conservative. Context-specific facts are applied context-insensitively
    /// and produce a warning.
    pub(crate) fn apply_document(
        &mut self,
        document: FlowFactDocument,
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
        self.warnings.extend(document.warnings);
        for fact in &document.loops {
            if !fact.context.is_empty() {
                self.warnings.push(format!(
                    "{}: context-specific flow fact [{}] is applied context-insensitively",
                    document.origin,
                    fact.context.join(" / ")
                ));
            }
            let header = resolve_target(program, &fact.target, &document.origin)?;
            let candidate = LoopBound {
                bound: fact.max,
                source: document.origin.clone(),
            };
            match self.loop_bounds.get_mut(&header) {
                Some(existing) => {
                    if candidate.bound > existing.bound {
                        self.warnings.push(format!(
                            "{}: loop 0x{header:x} bound {} replaces {} from {}; using the larger bound",
                            document.origin, candidate.bound, existing.bound, existing.source
                        ));
                        *existing = candidate;
                    } else if candidate.bound < existing.bound {
                        self.warnings.push(format!(
                            "{}: loop 0x{header:x} bound {} is below {} from {}; keeping the larger bound",
                            document.origin, candidate.bound, existing.bound, existing.source
                        ));
                    } else if !existing.source.contains(&document.origin) {
                        existing.source = format!("{} + {}", existing.source, document.origin);
                    }
                }
                None => {
                    self.loop_bounds.insert(header, candidate);
                }
            }
        }
        for fact in &document.branches {
            if !fact.context.is_empty() {
                self.warnings.push(format!(
                    "{}: context-specific branch fact [{}] ignored because the analysis is context-insensitive",
                    document.origin,
                    fact.context.join(" / ")
                ));
                continue;
            }
            let (function, block, site) =
                resolve_branch_target(program, &fact.target, &document.origin)?;
            self.insert_branch(BranchConstraint {
                function,
                block,
                site,
                outcome: fact.outcome,
                max_count: fact.max,
                source: document.origin.clone(),
            });
        }
        for fact in &document.calls {
            if !fact.context.is_empty() {
                self.warnings.push(format!(
                    "{}: context-specific call fact [{}] ignored because the analysis is context-insensitive",
                    document.origin,
                    fact.context.join(" / ")
                ));
                continue;
            }
            for (function, block, site) in
                resolve_call_target(program, &fact.target, &document.origin, &mut self.warnings)?
            {
                if let Some(callee) = &fact.callee {
                    verify_call_callee(program, &function, site, callee, &document.origin)?;
                }
                self.insert_call(CallConstraint {
                    function,
                    block,
                    site,
                    max_count: fact.max,
                    source: document.origin.clone(),
                });
            }
        }
        Ok(())
    }

    fn insert_branch(&mut self, candidate: BranchConstraint) {
        if let Some(existing) = self.branches.iter_mut().find(|existing| {
            existing.function == candidate.function
                && existing.site == candidate.site
                && existing.outcome == candidate.outcome
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
            existing.function == candidate.function && existing.site == candidate.site
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
    warnings: Vec<String>,
}

impl FlowFactDocument {
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
}

#[derive(Clone, Debug)]
pub(crate) struct CallFact {
    target: CallTarget,
    callee: Option<String>,
    max: u32,
    context: Vec<String>,
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
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<CallSiteRef>, String> {
    match target {
        CallTarget::Callee(name) => resolve_callee_call_sites(program, name, origin, warnings),
        CallTarget::Location(location) => {
            resolve_location_call_sites(program, location, origin, warnings)
        }
    }
}

fn resolve_callee_call_sites(
    program: &ProgramCfg,
    name: &str,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<CallSiteRef>, String> {
    let callee = find_function(program, name, origin)?;
    let mut sites = Vec::new();
    let mut matched = false;
    for function in &program.functions {
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
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<CallSiteRef>, String> {
    let (matched, found) = match location {
        LocationTarget::Address(address) => {
            collect_call_sites_at(program, *address, origin, warnings)
        }
        LocationTarget::FunctionOffset { function, offset } => {
            let function = find_function(program, function, origin)?;
            let address = function
                .address
                .checked_add(*offset)
                .ok_or_else(|| format!("{origin}: call offset overflows the address space"))?;
            collect_call_sites_at(program, address, origin, warnings)
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
            origin,
            warnings,
        )?,
    };
    finish_call_sites(found, matched, origin)
}

fn collect_call_sites_at(
    program: &ProgramCfg,
    address: u64,
    origin: &str,
    warnings: &mut Vec<String>,
) -> (bool, Vec<CallSiteRef>) {
    let mut found = Vec::new();
    let mut matched = false;
    for function in &program.functions {
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
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<(bool, Vec<CallSiteRef>), String> {
    let functions: Vec<&CfgFunction> = match function_name {
        Some(name) => vec![find_function(program, name, origin)?],
        None => program.functions.iter().collect(),
    };
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
    use super::{FlowFacts, block_at, checked_call_site};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgFunction, CfgInstruction, CfgTerminator,
        FunctionCfg,
    };
    use crate::loop_bounds::InferredLoopBound;
    use elf2tdg_schema::{FunctionId, FunctionKind, Language};

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
}
