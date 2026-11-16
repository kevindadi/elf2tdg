//! Function-level control-flow graphs.
//!
//! The analyzer keeps a `FunctionCfg` per function. Basic blocks are nodes in
//! a `petgraph::StableDiGraph`; control-flow edges and call sites remain
//! explicit so the CLI can export a complete, lossless CFG for a future
//! IDA-style UI. TDG construction derives its function blocks and call edges
//! from this representation rather than maintaining a second CFG.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use elf2tdg_schema::{
    Addr, AwaitTarget, BlockId, ContextId, ContextKind, CostRange, Diagnostic, Edge, FunctionId,
    FunctionKind, ImageInfo, JoinTarget, Language, SourceLoc, SpawnTarget, Tdg,
};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde::Serialize;

use crate::arch::Decoder;
use crate::loader::{ArchKind, Image};
use crate::rules::normalize_crate_hashes;

/// Version of the JSON CFG document emitted by this module.
pub const CFG_SCHEMA_VERSION: &str = "1.0";

/// A control-flow terminator classification for a basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgTerminator {
    /// Falls through to the next block.
    Fallthrough,
    /// Ends with a call; the next block is the return continuation.
    Call,
    /// Returns from the function.
    Return,
    /// Conditional branch.
    Branch,
    /// Direct or indirect unconditional jump.
    Jump,
    /// Unresolved control transfer.
    Unresolved,
}

/// Kind of an intra-function CFG edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgEdgeKind {
    /// Sequential fallthrough.
    Fallthrough,
    /// Return continuation after a call.
    CallReturn,
    /// Taken conditional branch.
    Branch,
    /// Unconditional direct jump.
    Jump,
}

/// An intra-function CFG edge.
#[derive(Clone, Debug)]
pub struct CfgEdge {
    /// Edge classification.
    pub kind: CfgEdgeKind,
    /// Address of the terminating instruction that produced the edge.
    pub site: u64,
    /// Whether the edge is conditional.
    pub conditional: bool,
}

/// A statically known indirect target expression, retained for UI/debugging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CfgIndirectTarget {
    /// Target address held in a register.
    Register(String),
    /// Target pointer loaded from `[base + disp]`.
    RegisterMemory {
        /// Base register name.
        base: String,
        /// Signed displacement.
        disp: i64,
    },
    /// Target pointer stored at an absolute address.
    Memory(u64),
    /// Target address is `register + offset`.
    RegisterOffset {
        /// Register name.
        register: String,
        /// Signed offset.
        offset: i64,
    },
    /// Indexed memory access used by jump tables.
    IndexedMemory {
        /// Optional base register.
        base: Option<String>,
        /// Index register.
        index: String,
        /// Access size and index scale in bytes.
        scale: u8,
        /// Signed displacement.
        disp: i64,
    },
}

/// One decoded instruction, including raw bytes and control-flow metadata.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CfgInstruction {
    /// Instruction address.
    pub address: u64,
    /// Instruction size in bytes.
    pub size: u8,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Lowercase mnemonic.
    pub mnemonic: String,
    /// Operand text.
    pub operands: String,
    /// Combined mnemonic and operands.
    pub text: String,
    /// Call instruction.
    pub is_call: bool,
    /// Jump/branch instruction (excluding calls).
    pub is_jump: bool,
    /// Return/interrupt-return instruction.
    pub is_return: bool,
    /// Conditional branch.
    pub is_conditional: bool,
    /// Direct target address.
    pub direct_target: Option<u64>,
    /// Indirect target expression, when modeled.
    pub indirect: Option<CfgIndirectTarget>,
    /// Static instruction cost from the selected timing model.
    pub cycles: Option<CostRange>,
    /// Source location for this instruction, when DWARF describes it.
    pub source: Option<SourceLoc>,
}

/// A call site retained inside its containing basic block.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CfgCallSite {
    /// Call instruction address.
    pub site: u64,
    /// Resolved target address, when known.
    pub target: Option<u64>,
    /// Target function ID, when the target is a function entry.
    pub target_function: Option<FunctionId>,
    /// Statically direct target.
    pub direct: bool,
    /// Tail call.
    pub tail: bool,
    /// Conditional external branch modeled as a tail call.
    pub conditional: bool,
    /// Target was recovered heuristically.
    pub heuristic: bool,
    /// Target was not resolved.
    pub unresolved: bool,
}

/// A basic block in a function CFG.
#[derive(Clone, Debug)]
pub struct CfgBlock {
    /// Stable block ID (`bb:0x...`).
    pub id: BlockId,
    /// Block start address.
    pub address: u64,
    /// Block size in bytes.
    pub size: u64,
    /// Instructions in address order.
    pub instructions: Vec<CfgInstruction>,
    /// Calls made from this block.
    pub calls: Vec<CfgCallSite>,
    /// Static block cost (not a path time).
    pub cycles: Option<CostRange>,
    /// Control-flow terminator classification.
    pub terminator: CfgTerminator,
}

/// A function CFG graph. Node IDs are internal petgraph indices; stable block
/// IDs are carried in [`CfgBlock`].
#[derive(Clone, Debug, Default)]
pub struct FunctionCfg {
    /// Entry block, when the function was analyzed.
    pub entry: Option<NodeIndex>,
    /// Basic blocks and control-flow edges.
    pub graph: StableDiGraph<CfgBlock, CfgEdge>,
    /// Address-to-node index map.
    pub blocks_by_address: BTreeMap<u64, NodeIndex>,
    /// Calls recovered from undecoded gaps after unresolved indirect jumps.
    /// They are not attached to a basic block because control flow into the
    /// gap is not proven, but they remain available to downstream analysis.
    pub recovered_calls: Vec<CfgCallSite>,
    /// Executable addresses observed as data or literal pointers in this
    /// function. They model callback/ISR/task entries that escape through
    /// function pointers rather than direct call instructions.
    pub referenced_addresses: Vec<u64>,
}

/// Input block for building a CFG before petgraph node indices exist.
pub(crate) struct CfgBlockDraft {
    /// Block start address.
    pub address: u64,
    /// Block size in bytes.
    pub size: u64,
    /// Instructions in address order.
    pub instructions: Vec<CfgInstruction>,
    /// Calls made from this block.
    pub calls: Vec<CfgCallSite>,
    /// Static block cost.
    pub cycles: Option<CostRange>,
    /// Terminator classification.
    pub terminator: CfgTerminator,
}

/// Input edge for building a CFG before petgraph node indices exist.
pub(crate) struct CfgEdgeDraft {
    /// Source block address.
    pub from: u64,
    /// Target block address.
    pub to: u64,
    /// Edge classification.
    pub kind: CfgEdgeKind,
    /// Terminating instruction address.
    pub site: u64,
    /// Whether the edge is conditional.
    pub conditional: bool,
}

impl FunctionCfg {
    /// Builds a CFG from address-keyed blocks and edges.
    #[must_use]
    pub(crate) fn build(
        mut blocks: Vec<CfgBlockDraft>,
        edges: Vec<CfgEdgeDraft>,
        entry_address: Option<u64>,
    ) -> Self {
        blocks.sort_by_key(|block| block.address);
        let mut graph = StableDiGraph::new();
        let mut blocks_by_address = BTreeMap::new();
        for block in blocks {
            let id = BlockId::new(format!("bb:0x{:x}", block.address));
            let address = block.address;
            let node = graph.add_node(CfgBlock {
                id,
                address,
                size: block.size,
                instructions: block.instructions,
                calls: block.calls,
                cycles: block.cycles,
                terminator: block.terminator,
            });
            blocks_by_address.insert(address, node);
        }
        for edge in edges {
            let (Some(from), Some(to)) = (
                blocks_by_address.get(&edge.from).copied(),
                blocks_by_address.get(&edge.to).copied(),
            ) else {
                continue;
            };
            graph.add_edge(
                from,
                to,
                CfgEdge {
                    kind: edge.kind,
                    site: edge.site,
                    conditional: edge.conditional,
                },
            );
        }
        Self {
            entry: entry_address.and_then(|address| blocks_by_address.get(&address).copied()),
            graph,
            blocks_by_address,
            recovered_calls: Vec::new(),
            referenced_addresses: Vec::new(),
        }
    }

    /// Returns a node by block address.
    #[must_use]
    pub fn node_at(&self, address: u64) -> Option<NodeIndex> {
        self.blocks_by_address.get(&address).copied()
    }

    /// Returns a block by stable ID.
    #[must_use]
    pub fn block(&self, node: NodeIndex) -> Option<&CfgBlock> {
        self.graph.node_weight(node)
    }
}

/// Exportable metadata and graph for one function.
#[derive(Clone, Debug)]
pub struct CfgFunction {
    /// Stable function ID.
    pub id: FunctionId,
    /// Display name.
    pub primary_name: String,
    /// Demangled name, when distinct.
    pub demangled_name: Option<String>,
    /// Raw symbol aliases.
    pub symbols: Vec<String>,
    /// Inferred language.
    pub language: Language,
    /// Function role.
    pub kind: FunctionKind,
    /// Function start address.
    pub address: u64,
    /// Function size in bytes.
    pub size: u64,
    /// Section name.
    pub section: String,
    /// Source location.
    pub source: Option<SourceLoc>,
    /// Function CFG.
    pub cfg: FunctionCfg,
}

/// Program-wide CFG collection.
#[derive(Clone, Debug, Default)]
pub struct ProgramCfg {
    /// Functions sorted by address.
    pub functions: Vec<CfgFunction>,
}

impl ProgramCfg {
    /// Builds a program CFG from function records.
    #[must_use]
    pub fn new(mut functions: Vec<CfgFunction>) -> Self {
        functions.sort_by_key(|function| function.address);
        Self { functions }
    }

    /// Looks up a function by ID.
    #[must_use]
    pub fn function(&self, id: &FunctionId) -> Option<&CfgFunction> {
        self.functions.iter().find(|function| &function.id == id)
    }

    /// Looks up a function by start address.
    #[must_use]
    pub fn function_at(&self, address: u64) -> Option<&CfgFunction> {
        self.functions
            .iter()
            .find(|function| function.address == address)
    }

    /// Selects functions by exact name, symbol, or `0x` address. Without a
    /// selector, all functions are returned.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the selector matches no function or
    /// is ambiguous.
    pub fn select(&self, selector: Option<&str>) -> Result<Vec<&CfgFunction>, String> {
        let Some(selector) = selector else {
            return Ok(self.functions.iter().collect());
        };
        let selector = selector.trim();
        if selector.is_empty() {
            return Err("function selector is empty".to_owned());
        }
        if let Some(hex) = selector
            .strip_prefix("0x")
            .or_else(|| selector.strip_prefix("0X"))
        {
            let address = u64::from_str_radix(hex, 16)
                .map_err(|error| format!("invalid function address {selector:?}: {error}"))?;
            return self
                .function_at(address)
                .map(|function| vec![function])
                .ok_or_else(|| format!("no function starts at {selector}"));
        }
        let matches = |name: &str| {
            let normalized = normalize_crate_hashes(name);
            normalized == selector || name == selector
        };
        let exact: Vec<&CfgFunction> = self
            .functions
            .iter()
            .filter(|function| {
                matches(&function.primary_name)
                    || function.demangled_name.as_deref().is_some_and(matches)
                    || function.symbols.iter().any(|name| matches(name))
            })
            .collect();
        if exact.len() == 1 {
            return Ok(exact);
        }
        if exact.len() > 1 {
            return Err(format!(
                "function selector {selector:?} is ambiguous ({} matches)",
                exact.len()
            ));
        }
        let partial: Vec<&CfgFunction> = self
            .functions
            .iter()
            .filter(|function| {
                normalize_crate_hashes(&function.primary_name).contains(selector)
                    || function
                        .demangled_name
                        .as_deref()
                        .is_some_and(|name| normalize_crate_hashes(name).contains(selector))
                    || function
                        .symbols
                        .iter()
                        .any(|name| normalize_crate_hashes(name).contains(selector))
            })
            .collect();
        match partial.len() {
            0 => Err(format!("no function matches {selector:?}")),
            1 => Ok(partial),
            _ => Err(format!(
                "function selector {selector:?} is ambiguous ({} matches)",
                partial.len()
            )),
        }
    }

    /// Selects all functions reachable from `root` through calls and task
    /// creation.
    ///
    /// Traversal follows ordinary call edges plus spawn, callback-binding,
    /// join and await edges from the TDG. The special root `main` prefers the
    /// entry of the TDG main context, which is the language-level `main` (for
    /// example Rust's `main::main`) rather than the C runtime wrapper.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the root selector matches no
    /// function or is ambiguous.
    pub fn reachable_from(&self, tdg: &Tdg, root: &str) -> Result<Vec<&CfgFunction>, String> {
        self.reachable_from_with_pruning(tdg, root, false)
    }

    /// Single-root reachability with optional runtime-boundary pruning.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the root selector matches no
    /// function or is ambiguous.
    pub fn reachable_from_with_pruning(
        &self,
        tdg: &Tdg,
        root: &str,
        prune_runtime: bool,
    ) -> Result<Vec<&CfgFunction>, String> {
        let (seed_ids, selected_ids) = self.reachable_seeds(tdg, root)?;
        let reachable = self.reachable_ids(tdg, seed_ids, prune_runtime);
        Ok(self.selected_from_reachable(tdg, &reachable, selected_ids))
    }

    /// Collects asynchronous execution roots: main/startup/task contexts,
    /// vector-table ISR entries, callbacks and the ELF entry point.
    ///
    /// Default handler stubs repeated across unused vectors are excluded.
    #[must_use]
    pub fn system_roots(&self, tdg: &Tdg, image: &Image) -> Vec<FunctionId> {
        let mut roots = BTreeSet::new();
        for context in &tdg.contexts {
            let function = self.cfg_function_for_tdg_id(tdg, &context.entry);
            let default = function.is_some_and(is_default_handler)
                || tdg
                    .functions
                    .iter()
                    .find(|function| function.id == context.entry)
                    .is_some_and(|function| is_default_handler_name(&function.primary_name));
            if !default {
                roots.insert(context.entry.clone());
            }
        }
        for vector in &image.vector_table {
            let handler = image.canonical_address(vector.handler);
            if is_default_handler_address(image, handler) {
                continue;
            }
            if let Some(function) = self.function_covering(handler)
                && !is_default_handler(function)
            {
                roots.insert(function.id.clone());
            }
        }
        for target in riscv_trap_targets(image) {
            if let Some(function) = self.function_covering(target)
                && !is_default_handler(function)
            {
                roots.insert(function.id.clone());
            }
        }
        for edge in &tdg.edges {
            if let Edge::CallbackBind { callback, .. } = edge {
                roots.insert(callback.clone());
            }
        }
        if let Some(function) = self.function_covering(image.canonical_address(image.entry)) {
            roots.insert(function.id.clone());
        }
        if roots.is_empty() {
            for function in &self.functions {
                let name = normalize_crate_hashes(&function.primary_name);
                if name == "main" || name.ends_with("::main") {
                    roots.insert(function.id.clone());
                }
            }
        }
        roots.into_iter().collect()
    }

    /// Runs multi-root worklist reachability from all asynchronous entry points.
    ///
    /// When `prune_runtime` is true, known panic/format/compiler-builtin and
    /// drop-glue functions are retained as nodes but their callees are not
    /// expanded.
    #[must_use]
    pub fn reachable_from_system(
        &self,
        tdg: &Tdg,
        image: &Image,
        prune_runtime: bool,
    ) -> Vec<&CfgFunction> {
        let roots = self.system_roots(tdg, image);
        self.reachable_from_roots(tdg, &roots, prune_runtime)
    }

    /// Runs multi-root worklist reachability from an explicit root set.
    #[must_use]
    pub fn reachable_from_roots(
        &self,
        tdg: &Tdg,
        roots: &[FunctionId],
        prune_runtime: bool,
    ) -> Vec<&CfgFunction> {
        let mut seed_ids = Vec::new();
        let mut selected_ids = BTreeSet::new();
        for root in roots {
            seed_ids.push(root.clone());
            if let Some(function) = self.cfg_function_for_tdg_id(tdg, root) {
                selected_ids.insert(function.id.clone());
            }
        }
        let reachable = self.reachable_ids(tdg, seed_ids, prune_runtime);
        self.selected_from_reachable(tdg, &reachable, selected_ids)
    }

    fn reachable_ids(
        &self,
        tdg: &Tdg,
        seed_ids: Vec<FunctionId>,
        prune_runtime: bool,
    ) -> BTreeSet<FunctionId> {
        let mut adjacency = tdg_reachability(tdg);
        self.add_code_reference_edges(&mut adjacency);
        let mut reachable: BTreeSet<FunctionId> = BTreeSet::new();
        let mut pending: Vec<FunctionId> = Vec::new();
        for id in seed_ids {
            if reachable.insert(id.clone()) {
                pending.push(id);
            }
        }
        let mut cursor = 0;
        while cursor < pending.len() {
            let current = pending[cursor].clone();
            cursor += 1;
            if prune_runtime
                && self
                    .cfg_function_for_tdg_id(tdg, &current)
                    .is_some_and(is_runtime_boundary)
            {
                continue;
            }
            if let Some(next) = adjacency.get(&current) {
                for id in next {
                    if reachable.insert(id.clone()) {
                        pending.push(id.clone());
                    }
                }
            }
        }
        reachable
    }

    fn add_code_reference_edges(&self, adjacency: &mut BTreeMap<FunctionId, Vec<FunctionId>>) {
        for function in &self.functions {
            for address in &function.cfg.referenced_addresses {
                if let Some(target) = self.function_covering(*address)
                    && target.id != function.id
                {
                    adjacency
                        .entry(function.id.clone())
                        .or_default()
                        .push(target.id.clone());
                }
            }
        }
    }

    fn selected_from_reachable(
        &self,
        tdg: &Tdg,
        reachable: &BTreeSet<FunctionId>,
        mut selected_ids: BTreeSet<FunctionId>,
    ) -> Vec<&CfgFunction> {
        // Logical task entries in optimized images can be synthetic IDs such
        // as `fn:task:0x...` whose address lies inside a real CFG function.
        for id in reachable {
            if self.function(id).is_some() {
                selected_ids.insert(id.clone());
                continue;
            }
            let Some(function) = tdg.functions.iter().find(|function| &function.id == id) else {
                continue;
            };
            if let Some(cfg_function) = self.function_covering(function.address.get()) {
                selected_ids.insert(cfg_function.id.clone());
            }
        }
        self.functions
            .iter()
            .filter(|function| selected_ids.contains(&function.id))
            .collect()
    }

    fn reachable_seeds(
        &self,
        tdg: &Tdg,
        root: &str,
    ) -> Result<(Vec<FunctionId>, BTreeSet<FunctionId>), String> {
        if root == "main" {
            let mut entries: Vec<FunctionId> = tdg
                .contexts
                .iter()
                .filter(|context| context.kind == ContextKind::Main)
                .map(|context| context.entry.clone())
                .collect();
            let mut selected = BTreeSet::new();
            for entry in entries.clone() {
                if let Some(function) = self.cfg_function_for_tdg_id(tdg, &entry) {
                    selected.insert(function.id.clone());
                    // Synthetic task IDs can point inside a real function;
                    // seed the real ID too so its outgoing calls are followed.
                    entries.push(function.id.clone());
                }
            }
            if !selected.is_empty() {
                return Ok((entries, selected));
            }
        }
        let functions = self.select(Some(root))?;
        let ids: Vec<FunctionId> = functions
            .iter()
            .map(|function| function.id.clone())
            .collect();
        let selected = ids.iter().cloned().collect();
        Ok((ids, selected))
    }

    fn cfg_function_for_tdg_id<'a>(
        &'a self,
        tdg: &Tdg,
        id: &FunctionId,
    ) -> Option<&'a CfgFunction> {
        self.function(id).or_else(|| {
            let function = tdg.functions.iter().find(|function| &function.id == id)?;
            self.function_covering(function.address.get())
        })
    }

    fn function_covering(&self, address: u64) -> Option<&CfgFunction> {
        self.function_at(address).or_else(|| {
            self.functions.iter().find(|function| {
                function.size > 0
                    && address >= function.address
                    && address < function.address.saturating_add(function.size)
            })
        })
    }
}

fn riscv_trap_targets(image: &Image) -> Vec<u64> {
    if !matches!(image.arch, ArchKind::Riscv32 | ArchKind::Riscv64) {
        return Vec::new();
    }
    let Ok(decoder) = Decoder::new(image.arch) else {
        return Vec::new();
    };
    let mut targets = BTreeSet::new();
    for section in image.sections.iter().filter(|section| {
        section.executable && (section.name.contains("trap") || section.name.contains("vector"))
    }) {
        let mut offset = 0usize;
        while offset < section.data.len() {
            let address = section.address.saturating_add(offset as u64);
            match decoder.decode_one(&section.data[offset..], address) {
                Ok(Some(instruction)) => {
                    if (instruction.is_jump || instruction.is_call)
                        && !instruction.is_conditional
                        && let Some(target) = instruction.direct_target
                    {
                        targets.insert(image.canonical_address(target));
                    }
                    offset = offset.saturating_add(usize::from(instruction.size.max(2)));
                }
                _ => offset = offset.saturating_add(2),
            }
        }
    }
    targets.into_iter().collect()
}

fn is_default_handler(function: &CfgFunction) -> bool {
    is_default_handler_name(&function.primary_name)
}

fn is_default_handler_name(name: &str) -> bool {
    let normalized = normalize_crate_hashes(name).to_ascii_lowercase();
    normalized.contains("default_handler") || normalized.contains("defaulthandler")
}

fn is_default_handler_address(image: &Image, address: u64) -> bool {
    let mut names = image
        .symbols
        .iter()
        .filter(|symbol| symbol.canonical_address == address)
        .map(|symbol| symbol.name.as_str())
        .peekable();
    names.peek().is_some() && names.all(is_default_handler_name)
}

fn is_runtime_boundary(function: &CfgFunction) -> bool {
    let name = normalize_crate_hashes(&function.primary_name);
    [
        "core::panicking::",
        "std::panicking::",
        "core::fmt::",
        "alloc::fmt::",
        "compiler_builtins::",
        "core::ptr::drop_glue::",
        "core::ptr::drop_in_place::",
    ]
    .iter()
    .any(|prefix| name.contains(prefix))
}

fn tdg_reachability(tdg: &Tdg) -> BTreeMap<FunctionId, Vec<FunctionId>> {
    let context_entries: BTreeMap<&ContextId, &FunctionId> = tdg
        .contexts
        .iter()
        .map(|context| (&context.id, &context.entry))
        .collect();
    let mut adjacency: BTreeMap<FunctionId, Vec<FunctionId>> = BTreeMap::new();
    let mut add = |from: &FunctionId, to: &FunctionId| {
        adjacency.entry(from.clone()).or_default().push(to.clone());
    };
    for context in &tdg.contexts {
        let Some(parent) = &context.parent else {
            continue;
        };
        let (Some(parent_entry), Some(entry)) = (
            context_entries.get(parent),
            context_entries.get(&context.id),
        ) else {
            continue;
        };
        add(parent_entry, entry);
    }
    for edge in &tdg.edges {
        match edge {
            Edge::Call { caller, callee, .. } => add(caller, callee),
            Edge::Spawn {
                from_function,
                target,
                ..
            } => match target {
                SpawnTarget::Context { entry, .. } => {
                    add(from_function, entry);
                    // A task's spawner is part of the executable slice that
                    // leads to the task even when the call into the spawner
                    // itself was indirect.
                    add(entry, from_function);
                }
                SpawnTarget::Opaque { candidates } => {
                    for candidate in candidates {
                        add(from_function, candidate);
                    }
                }
            },
            Edge::CallbackBind {
                from_function,
                callback,
                ..
            } => add(from_function, callback),
            Edge::Join {
                from_function,
                target,
                ..
            } => match target {
                JoinTarget::Context { context } => {
                    if let Some(entry) = context_entries.get(context) {
                        add(from_function, entry);
                    }
                }
                JoinTarget::Opaque { candidates } => {
                    for context in candidates {
                        if let Some(entry) = context_entries.get(context) {
                            add(from_function, entry);
                        }
                    }
                }
            },
            Edge::Await {
                from_context,
                target,
                ..
            } => {
                let Some(from) = context_entries.get(from_context) else {
                    continue;
                };
                match target {
                    AwaitTarget::Context { context } => {
                        if let Some(entry) = context_entries.get(context) {
                            add(from, entry);
                        }
                    }
                    AwaitTarget::Function { function } => add(from, function),
                    AwaitTarget::Opaque { candidates } => {
                        for candidate in candidates {
                            add(from, candidate);
                        }
                    }
                }
            }
            Edge::IsrActivate { .. } | Edge::Preempts { .. } => {}
        }
    }
    adjacency
}

#[derive(Serialize)]
struct CfgDocument<'a> {
    cfg_schema_version: &'static str,
    image: &'a ImageInfo,
    functions: Vec<CfgFunctionView>,
    diagnostics: &'a [Diagnostic],
}

#[derive(Serialize)]
struct CfgFunctionView {
    id: FunctionId,
    primary_name: String,
    demangled_name: Option<String>,
    symbols: Vec<String>,
    language: Language,
    kind: FunctionKind,
    address: Addr,
    size: u64,
    section: String,
    source: Option<SourceLoc>,
    entry: Option<BlockId>,
    blocks: Vec<CfgBlockView>,
    edges: Vec<CfgEdgeView>,
    recovered_calls: Vec<CfgCallView>,
}

#[derive(Serialize)]
struct CfgBlockView {
    id: BlockId,
    address: Addr,
    size: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    instructions: Vec<CfgInstructionView>,
    calls: Vec<CfgCallView>,
    cycles: Option<CostRange>,
    terminator: CfgTerminator,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct CfgInstructionView {
    address: Addr,
    size: u8,
    bytes: String,
    mnemonic: String,
    operands: String,
    text: String,
    is_call: bool,
    is_jump: bool,
    is_return: bool,
    is_conditional: bool,
    direct_target: Option<Addr>,
    indirect: Option<CfgIndirectView>,
    source: Option<SourceLoc>,
}

#[derive(Serialize)]
struct CfgIndirectView {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    register: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scale: Option<u8>,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct CfgCallView {
    site: Addr,
    target: Option<Addr>,
    target_function: Option<FunctionId>,
    target_name: Option<String>,
    direct: bool,
    tail: bool,
    conditional: bool,
    heuristic: bool,
    unresolved: bool,
}

#[derive(Serialize)]
struct CfgEdgeView {
    from: BlockId,
    to: BlockId,
    kind: CfgEdgeKind,
    site: Addr,
    conditional: bool,
}

/// Serializes the CFG document for downstream tools.
///
/// # Errors
///
/// Returns an error when the function selector matches nothing or is
/// ambiguous, or when JSON serialization fails.
pub fn render_json(
    program: &ProgramCfg,
    tdg: &Tdg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select(selector)?;
    render_json_selected(program, tdg, &selected, include_instructions)
}

/// Serializes an explicitly selected set of CFGs for downstream tools.
///
/// # Errors
///
/// Returns an error when JSON serialization fails.
pub fn render_json_selected(
    program: &ProgramCfg,
    tdg: &Tdg,
    selected: &[&CfgFunction],
    include_instructions: bool,
) -> Result<String, String> {
    let functions = selected
        .iter()
        .map(|function| function_view(program, function, include_instructions))
        .collect();
    let document = CfgDocument {
        cfg_schema_version: CFG_SCHEMA_VERSION,
        image: &tdg.image,
        functions,
        diagnostics: &tdg.diagnostics,
    };
    serde_json::to_string_pretty(&document).map_err(|error| error.to_string())
}

fn function_view(
    program: &ProgramCfg,
    function: &CfgFunction,
    include_instructions: bool,
) -> CfgFunctionView {
    let cfg = &function.cfg;
    let mut blocks = Vec::new();
    for node in cfg.blocks_by_address.values() {
        let block = &cfg.graph[*node];
        blocks.push(CfgBlockView {
            id: block.id.clone(),
            address: Addr::new(block.address),
            size: block.size,
            instructions: if include_instructions {
                block.instructions.iter().map(instruction_view).collect()
            } else {
                Vec::new()
            },
            calls: block
                .calls
                .iter()
                .map(|call| call_view(program, call))
                .collect(),
            cycles: block.cycles,
            terminator: block.terminator,
        });
    }
    let mut edges = Vec::new();
    for edge in cfg.graph.edge_references() {
        edges.push(CfgEdgeView {
            from: cfg.graph[edge.source()].id.clone(),
            to: cfg.graph[edge.target()].id.clone(),
            kind: edge.weight().kind,
            site: Addr::new(edge.weight().site),
            conditional: edge.weight().conditional,
        });
    }
    edges.sort_by(|left, right| {
        (left.from.as_str(), left.to.as_str(), left.kind as u8).cmp(&(
            right.from.as_str(),
            right.to.as_str(),
            right.kind as u8,
        ))
    });
    let recovered_calls = cfg
        .recovered_calls
        .iter()
        .map(|call| call_view(program, call))
        .collect();
    CfgFunctionView {
        id: function.id.clone(),
        primary_name: function.primary_name.clone(),
        demangled_name: function.demangled_name.clone(),
        symbols: function.symbols.clone(),
        language: function.language,
        kind: function.kind,
        address: Addr::new(function.address),
        size: function.size,
        section: function.section.clone(),
        source: function.source.clone(),
        entry: cfg
            .entry
            .and_then(|node| cfg.graph.node_weight(node))
            .map(|block| block.id.clone()),
        blocks,
        edges,
        recovered_calls,
    }
}

fn call_view(program: &ProgramCfg, call: &CfgCallSite) -> CfgCallView {
    CfgCallView {
        site: Addr::new(call.site),
        target: call.target.map(Addr::new),
        target_function: call.target_function.clone(),
        target_name: call.target_function.as_ref().and_then(|id| {
            program
                .function(id)
                .map(|function| normalize_crate_hashes(&function.primary_name))
        }),
        direct: call.direct,
        tail: call.tail,
        conditional: call.conditional,
        heuristic: call.heuristic,
        unresolved: call.unresolved,
    }
}

fn instruction_view(instruction: &CfgInstruction) -> CfgInstructionView {
    CfgInstructionView {
        address: Addr::new(instruction.address),
        size: instruction.size,
        bytes: hex_bytes(&instruction.bytes),
        mnemonic: instruction.mnemonic.clone(),
        operands: instruction.operands.clone(),
        text: instruction.text.clone(),
        is_call: instruction.is_call,
        is_jump: instruction.is_jump,
        is_return: instruction.is_return,
        is_conditional: instruction.is_conditional,
        direct_target: instruction.direct_target.map(Addr::new),
        source: instruction.source.clone(),
        indirect: instruction.indirect.as_ref().map(|target| match target {
            CfgIndirectTarget::Register(register) => CfgIndirectView {
                kind: "register",
                register: Some(register.clone()),
                base: None,
                disp: None,
                address: None,
                offset: None,
                index: None,
                scale: None,
            },
            CfgIndirectTarget::RegisterMemory { base, disp } => CfgIndirectView {
                kind: "register-memory",
                register: None,
                base: Some(base.clone()),
                disp: Some(*disp),
                address: None,
                offset: None,
                index: None,
                scale: None,
            },
            CfgIndirectTarget::Memory(address) => CfgIndirectView {
                kind: "memory",
                register: None,
                base: None,
                disp: None,
                address: Some(Addr::new(*address)),
                offset: None,
                index: None,
                scale: None,
            },
            CfgIndirectTarget::RegisterOffset { register, offset } => CfgIndirectView {
                kind: "register-offset",
                register: Some(register.clone()),
                base: None,
                disp: None,
                address: None,
                offset: Some(*offset),
                index: None,
                scale: None,
            },
            CfgIndirectTarget::IndexedMemory {
                base,
                index,
                scale,
                disp,
            } => CfgIndirectView {
                kind: "indexed-memory",
                register: None,
                base: base.clone(),
                disp: Some(*disp),
                address: None,
                offset: None,
                index: Some(index.clone()),
                scale: Some(*scale),
            },
        }),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Renders selected function CFGs as Graphviz DOT.
///
/// # Errors
///
/// Returns an error when the function selector matches nothing or is
/// ambiguous.
/// Renders selected function CFGs as Graphviz DOT.
///
/// # Errors
///
/// Returns an error when the function selector matches nothing or is
/// ambiguous.
pub fn render_dot(
    program: &ProgramCfg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select(selector)?;
    Ok(render_dot_selected(
        program,
        &selected,
        include_instructions,
    ))
}

/// Renders an explicitly selected set of function CFGs as Graphviz DOT.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_dot_selected(
    program: &ProgramCfg,
    selected: &[&CfgFunction],
    include_instructions: bool,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "digraph cfg {{");
    let _ = writeln!(out, "  rankdir=LR;");
    let _ = writeln!(
        out,
        "  graph [fontname=\"Helvetica\", label=\"elf2tdg function CFG\", labelloc=t];"
    );
    let _ = writeln!(
        out,
        "  node [fontname=\"Helvetica\", fontsize=9, shape=box, style=\"rounded,filled\", fillcolor=\"#ffffff\", color=\"#555555\"];"
    );
    let _ = writeln!(out, "  edge [fontname=\"Helvetica\", fontsize=8];");

    let mut call_nodes: BTreeMap<String, String> = BTreeMap::new();
    for (function_index, function) in selected.iter().enumerate() {
        let cfg = &function.cfg;
        let name = crate::rules::normalize_crate_hashes(&function.primary_name);
        let _ = writeln!(out, "  subgraph cluster_cfg_{function_index} {{");
        let _ = writeln!(
            out,
            "    label=\"{}\\n0x{:x}\"; labeljust=l; fontsize=10; color=\"#999999\";",
            dot_escape(&shorten(&name, 64)),
            function.address
        );
        for node in cfg.blocks_by_address.values() {
            let block = &cfg.graph[*node];
            let _ = writeln!(
                out,
                "    \"{}\" [label=\"{}\"];",
                dot_escape(block.id.as_str()),
                dot_escape(&block_label(block, include_instructions))
            );
        }
        for edge in cfg.graph.edge_references() {
            let (label, color, style) = match edge.weight().kind {
                CfgEdgeKind::Fallthrough => ("fallthrough", "#777777", "solid"),
                CfgEdgeKind::CallReturn => ("return", "#4a6fa5", "solid"),
                CfgEdgeKind::Branch => ("branch", "#2471a3", "solid"),
                CfgEdgeKind::Jump => ("jump", "#333333", "bold"),
            };
            let _ = writeln!(
                out,
                "    \"{}\" -> \"{}\" [label=\"{}\", color=\"{color}\", style=\"{style}\"];",
                dot_escape(cfg.graph[edge.source()].id.as_str()),
                dot_escape(cfg.graph[edge.target()].id.as_str()),
                dot_escape(label)
            );
        }
        for node in cfg.blocks_by_address.values() {
            let block = &cfg.graph[*node];
            for call in &block.calls {
                let (key, label) = call_target(program, call);
                call_nodes.entry(key.clone()).or_insert(label);
                let label = if call.unresolved {
                    "call?".to_owned()
                } else if call.tail {
                    "tail call".to_owned()
                } else {
                    "call".to_owned()
                };
                let _ = writeln!(
                    out,
                    "    \"{}\" -> \"{}\" [label=\"{label}\", color=\"#117a65\", fontcolor=\"#117a65\", style=dashed];",
                    dot_escape(block.id.as_str()),
                    dot_escape(&key)
                );
            }
        }
        if !cfg.recovered_calls.is_empty() {
            let source = format!("recovered:{}", function.id);
            let _ = writeln!(
                out,
                "    \"{}\" [label=\"recovered calls\\n{} site(s)\", shape=note, style=\"dashed,filled\", fillcolor=\"#fdf2e9\", color=\"#b9770e\"];",
                dot_escape(&source),
                cfg.recovered_calls.len()
            );
            for call in &cfg.recovered_calls {
                let (key, label) = call_target(program, call);
                call_nodes.entry(key.clone()).or_insert(label);
                let _ = writeln!(
                    out,
                    "    \"{}\" -> \"{}\" [label=\"heuristic call\", color=\"#b9770e\", fontcolor=\"#b9770e\", style=dashed];",
                    dot_escape(&source),
                    dot_escape(&key)
                );
            }
        }
        let _ = writeln!(out, "  }}");
    }
    for (key, label) in call_nodes {
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\", shape=note, style=\"dashed,filled\", fillcolor=\"#f4f6f7\", color=\"#999999\"];",
            dot_escape(&key),
            dot_escape(&label)
        );
    }
    let _ = writeln!(out, "}}");
    out
}

/// Renders selected function CFGs as a Mermaid flowchart.
///
/// # Errors
///
/// Returns an error when the function selector matches nothing or is
/// ambiguous.
/// Renders selected function CFGs as a Mermaid flowchart.
///
/// # Errors
///
/// Returns an error when the function selector matches nothing or is
/// ambiguous.
pub fn render_mermaid(
    program: &ProgramCfg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select(selector)?;
    Ok(render_mermaid_selected(
        program,
        &selected,
        include_instructions,
    ))
}

/// Renders an explicitly selected set of function CFGs as a Mermaid flowchart.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_mermaid_selected(
    program: &ProgramCfg,
    selected: &[&CfgFunction],
    include_instructions: bool,
) -> String {
    let mut out = String::from("flowchart LR\n");
    let mut block_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut call_nodes: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (function_index, function) in selected.iter().enumerate() {
        let cfg = &function.cfg;
        let name = crate::rules::normalize_crate_hashes(&function.primary_name);
        let _ = writeln!(
            out,
            "  subgraph cfg{function_index}[\"{}\\n0x{:x}\"]",
            mermaid_escape(&shorten(&name, 64)),
            function.address
        );
        let _ = writeln!(out, "    direction LR");
        for node in cfg.blocks_by_address.values() {
            let block = &cfg.graph[*node];
            let id = format!("b{function_index}_{}", block.address);
            let _ = writeln!(
                out,
                "    {id}[\"{}\"]",
                mermaid_escape(&block_label(block, include_instructions))
            );
            block_ids.insert(block.id.as_str().to_owned(), id);
        }
        for edge in cfg.graph.edge_references() {
            let label = match edge.weight().kind {
                CfgEdgeKind::Fallthrough => "fallthrough",
                CfgEdgeKind::CallReturn => "return",
                CfgEdgeKind::Branch => "branch",
                CfgEdgeKind::Jump => "jump",
            };
            let source = &cfg.graph[edge.source()].id;
            let target = &cfg.graph[edge.target()].id;
            let (Some(source), Some(target)) = (
                block_ids.get(source.as_str()),
                block_ids.get(target.as_str()),
            ) else {
                continue;
            };
            let arrow = match edge.weight().kind {
                CfgEdgeKind::Jump => "==>",
                CfgEdgeKind::Fallthrough | CfgEdgeKind::CallReturn | CfgEdgeKind::Branch => "-->",
            };
            let _ = writeln!(out, "    {source} {arrow}|{label}| {target}");
        }
        if !cfg.recovered_calls.is_empty() {
            let _ = writeln!(
                out,
                "    rec{function_index}[\"recovered calls<br/>{} site(s)\"]",
                cfg.recovered_calls.len()
            );
        }
        let _ = writeln!(out, "  end");
    }
    for (function_index, function) in selected.iter().enumerate() {
        let cfg = &function.cfg;
        for node in cfg.blocks_by_address.values() {
            let block = &cfg.graph[*node];
            let Some(source) = block_ids.get(block.id.as_str()) else {
                continue;
            };
            for call in &block.calls {
                let (key, label) = call_target(program, call);
                let id = if let Some((id, _)) = call_nodes.get(&key) {
                    id.clone()
                } else {
                    let id = format!("call{}", call_nodes.len());
                    call_nodes.insert(key, (id.clone(), label.clone()));
                    let _ = writeln!(out, "  {id}[\"{}\"]", mermaid_escape(&label));
                    id
                };
                let _ = writeln!(
                    out,
                    "  {source} -.->|{}| {id}",
                    if call.unresolved {
                        "call?"
                    } else if call.tail {
                        "tail call"
                    } else {
                        "call"
                    }
                );
            }
        }
        if !cfg.recovered_calls.is_empty() {
            let recovered_id = format!("rec{function_index}");
            for call in &cfg.recovered_calls {
                let (key, label) = call_target(program, call);
                let id = if let Some((id, _)) = call_nodes.get(&key) {
                    id.clone()
                } else {
                    let id = format!("call{}", call_nodes.len());
                    call_nodes.insert(key, (id.clone(), label.clone()));
                    let _ = writeln!(out, "  {id}[\"{}\"]", mermaid_escape(&label));
                    id
                };
                let _ = writeln!(out, "  {recovered_id} -.->|recovered call| {id}");
            }
        }
    }
    out
}

fn block_label(block: &CfgBlock, include_instructions: bool) -> String {
    let mut label = format!(
        "bb 0x{:x}\n{} insn",
        block.address,
        block.instructions.len()
    );
    if include_instructions {
        for instruction in block.instructions.iter().take(8) {
            let _ = write!(label, "\n{}", instruction.text);
        }
        if block.instructions.len() > 8 {
            let _ = write!(label, "\n... +{} insn", block.instructions.len() - 8);
        }
    }
    if !block.calls.is_empty() {
        let _ = write!(label, "\n{} call(s)", block.calls.len());
    }
    label
}

fn call_target(program: &ProgramCfg, call: &CfgCallSite) -> (String, String) {
    if let Some(function_id) = &call.target_function {
        if let Some(function) = program.function(function_id) {
            let name = crate::rules::normalize_crate_hashes(&function.primary_name);
            return (
                format!("call:{function_id}"),
                format!("{}\n0x{:x}", shorten(&name, 48), function.address),
            );
        }
        return (
            format!("call:{function_id}"),
            format!("{function_id}\\n(entry)"),
        );
    }
    if let Some(target) = call.target {
        return (format!("call:0x{target:x}"), format!("0x{target:x}"));
    }
    (
        format!("call:unresolved:0x{:x}", call.site),
        "unresolved call".to_owned(),
    )
}

fn shorten(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut shortened: String = value.chars().take(max_chars.saturating_sub(3)).collect();
    shortened.push_str("...");
    shortened
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn mermaid_escape(value: &str) -> String {
    value
        .replace("\\n", "<br/>")
        .replace('\n', "<br/>")
        .replace('"', "'")
        .replace('[', "(")
        .replace(']', ")")
        .replace('{', "(")
        .replace('}', ")")
        .replace('|', "/")
}

#[cfg(test)]
mod tests {
    use super::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgEdgeKind, CfgFunction, CfgInstruction,
        CfgTerminator, FunctionCfg, ProgramCfg, riscv_trap_targets,
    };
    use crate::loader::{ArchKind, ByteOrder, ElfKind, Image, Section};
    use elf2tdg_schema::{FunctionId, FunctionKind, Language};

    fn instruction(address: u64, mnemonic: &str, is_call: bool) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 4,
            bytes: vec![0; 4],
            mnemonic: mnemonic.to_owned(),
            operands: String::new(),
            text: mnemonic.to_owned(),
            is_call,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            cycles: None,
            source: None,
        }
    }

    fn call(site: u64) -> CfgCallSite {
        CfgCallSite {
            site,
            target: Some(0x2000),
            target_function: Some(FunctionId::new("fn:0x2000")),
            direct: true,
            tail: false,
            conditional: false,
            heuristic: false,
            unresolved: false,
        }
    }

    fn block(
        address: u64,
        mnemonic: &str,
        is_call: bool,
        calls: Vec<CfgCallSite>,
        terminator: CfgTerminator,
    ) -> CfgBlockDraft {
        CfgBlockDraft {
            address,
            size: 4,
            instructions: vec![instruction(address, mnemonic, is_call)],
            calls,
            cycles: None,
            terminator,
        }
    }

    fn fixture() -> FunctionCfg {
        FunctionCfg::build(
            vec![
                block(
                    0x1000,
                    "call",
                    true,
                    vec![call(0x1000)],
                    CfgTerminator::Fallthrough,
                ),
                block(0x1004, "add", false, Vec::new(), CfgTerminator::Fallthrough),
                block(
                    0x1008,
                    "call",
                    true,
                    vec![call(0x1008)],
                    CfgTerminator::Fallthrough,
                ),
                block(0x100c, "ret", false, Vec::new(), CfgTerminator::Return),
            ],
            vec![
                CfgEdgeDraft {
                    from: 0x1000,
                    to: 0x1004,
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1000,
                    conditional: false,
                },
                CfgEdgeDraft {
                    from: 0x1004,
                    to: 0x1008,
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1004,
                    conditional: false,
                },
                CfgEdgeDraft {
                    from: 0x1008,
                    to: 0x100c,
                    kind: CfgEdgeKind::Fallthrough,
                    site: 0x1008,
                    conditional: false,
                },
            ],
            Some(0x1000),
        )
    }

    #[test]
    fn builds_cfg_nodes_edges_and_calls() {
        let cfg = fixture();
        assert_eq!(cfg.blocks_by_address.len(), 4);
        assert!(cfg.entry.is_some());
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph[cfg.node_at(0x1000).unwrap()].calls.len(), 1);
    }

    #[test]
    fn renders_dot_and_mermaid_with_call_targets() {
        let cfg = fixture();
        let function = CfgFunction {
            id: FunctionId::new("fn:0x1000"),
            primary_name: "demo".to_owned(),
            demangled_name: None,
            symbols: vec!["demo".to_owned()],
            language: Language::C,
            kind: FunctionKind::Normal,
            address: 0x1000,
            size: 0x10,
            section: ".text".to_owned(),
            source: None,
            cfg,
        };
        let program = ProgramCfg::new(vec![function]);
        let dot = super::render_dot(&program, Some("demo"), true).expect("dot");
        assert!(dot.contains("bb:0x1000"));
        assert!(dot.contains("fallthrough"));
        assert!(dot.contains("call:fn:0x2000"));
        let mermaid = super::render_mermaid(&program, None, true).expect("mermaid");
        assert!(mermaid.contains("flowchart LR"));
        assert!(mermaid.contains("demo"));
        assert!(mermaid.contains("call"));
    }

    #[test]
    fn extracts_riscv_trap_jump_targets() {
        // jal zero, 8 at 0x1000 -> 0x1008.
        let image = Image {
            path: "trap.elf".into(),
            arch: ArchKind::Riscv32,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::new(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".trap".to_owned(),
                address: 0x1000,
                size: 4,
                data: vec![0x6f, 0x00, 0x80, 0x00],
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
        };
        assert_eq!(riscv_trap_targets(&image), vec![0x1008]);
    }
}
