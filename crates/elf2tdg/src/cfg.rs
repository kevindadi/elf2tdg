//! Function-level control-flow graphs.
//!
//! The analyzer keeps a `FunctionCfg` per function. Basic blocks are nodes in
//! a `petgraph::StableDiGraph`; control-flow edges and call sites remain
//! explicit so the CLI can export a complete, lossless CFG for a future
//! IDA-style UI. TDG construction derives its function blocks and call edges
//! from this representation rather than maintaining a second CFG.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use elf2tdg_schema::{
    Addr, AwaitTarget, BlockId, ContextId, ContextKind, CostRange, Diagnostic, Edge, Function,
    FunctionId, FunctionKind, ImageInfo, JoinTarget, Language, SourceLoc, SpawnTarget, Tdg,
};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde::Serialize;

use crate::arch::Decoder;
use crate::loader::{ArchKind, Image};
use crate::rules::normalize_crate_hashes;

/// Version of the JSON CFG document emitted by this module.
pub const CFG_SCHEMA_VERSION: &str = "1.7";

/// A control-flow terminator classification for a basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgTerminator {
    /// Falls through to the next block.
    Fallthrough,
    /// Ends with a call; the next block is the return continuation.
    Call,
    /// Ends with a call that cannot return to this function.
    NoreturnCall,
    /// Returns from the function.
    Return,
    /// Conditional branch.
    Branch,
    /// Direct or indirect unconditional jump.
    Jump,
    /// Unresolved control transfer.
    Unresolved,
}

/// Why a function is known not to return to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgNoreturnReason {
    /// A well-known noreturn API/ABI symbol, such as `abort`, `exit` or a
    /// Rust panic entry point.
    Api,
    /// The recovered control-flow graph has no path back to the caller.
    ControlFlow,
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
    /// ARM `tbb`/`tbh` table branch.
    TableBranch {
        /// Optional table base register.
        base: Option<String>,
        /// Index register.
        index: String,
        /// Whether the table contains halfword offsets.
        halfword: bool,
    },
    /// ARM A32 `ldr pc, [table + index*4]` absolute-address table.
    TableLoad {
        /// Optional table base register.
        base: Option<String>,
        /// Index register.
        index: String,
        /// Signed displacement.
        disp: i64,
    },
    /// ARM A32 `add pc, base, index, lsl #2` branch-instruction table.
    BranchTable {
        /// Optional table base register.
        base: Option<String>,
        /// Index register.
        index: String,
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

/// One inlined subroutine range inside a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfgInlineFrame {
    /// Demangled function name, falling back to the raw DWARF name.
    pub name: String,
    /// Raw linkage name, when available.
    pub linkage_name: Option<String>,
    /// Source location of the inlined call, from `DW_AT_call_*`.
    pub call_site: Option<SourceLoc>,
    /// Start of the concrete inline range.
    pub low_pc: u64,
    /// Exclusive end of the concrete inline range.
    pub high_pc: u64,
    /// DWARF DIE nesting depth. Lower values are outer inline calls.
    pub depth: u32,
}

/// One candidate target of a multi-target indirect call.
#[derive(Clone, Debug)]
pub struct CfgCallCandidate {
    /// Candidate target address.
    pub target: u64,
    /// Candidate function ID, when the target is a function entry.
    pub target_function: Option<FunctionId>,
}

/// A call site retained inside its containing basic block.
///
/// There is exactly one record per call instruction. A bounded indirect call
/// keeps its alternatives in `candidates`; `target` remains the single-target
/// fast path.
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
    /// The target expression evaluates to a statically null function pointer.
    pub null_target: bool,
    /// The call cannot return to its continuation because every possible
    /// target is noreturn, or because its target is statically null.
    /// Conditional calls are never marked noreturn.
    pub noreturn: bool,
    /// Alternative targets when the call site has a bounded target set.
    pub candidates: Vec<CfgCallCandidate>,
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

    /// Removes call-return continuations for call sites marked noreturn and
    /// deletes blocks that were reachable only through those continuations.
    ///
    /// Blocks that were already unreachable before pruning are retained, as
    /// are blocks named by intra-function call targets.
    pub fn prune_noreturn_continuations(&mut self) -> bool {
        let Some(entry) = self.entry else {
            return false;
        };
        let before = self.reachable_nodes(entry);
        let mut changed = false;
        for node in self.blocks_by_address.values().copied().collect::<Vec<_>>() {
            let Some(block) = self.graph.node_weight(node) else {
                continue;
            };
            let Some(last) = block.instructions.last() else {
                continue;
            };
            if !last.is_call {
                continue;
            }
            let noreturn = block
                .calls
                .iter()
                .find(|call| call.site == last.address)
                .is_some_and(|call| call.noreturn && !call.conditional);
            if !noreturn {
                continue;
            }
            let edges: Vec<_> = self
                .graph
                .edges_directed(node, petgraph::Direction::Outgoing)
                .filter(|edge| {
                    edge.weight().kind == CfgEdgeKind::CallReturn
                        && edge.weight().site == last.address
                })
                .map(|edge| edge.id())
                .collect();
            for edge in edges {
                self.graph.remove_edge(edge);
                changed = true;
            }
            if self.graph[node].terminator != CfgTerminator::NoreturnCall {
                self.graph[node].terminator = CfgTerminator::NoreturnCall;
                changed = true;
            }
        }
        if !changed {
            return false;
        }

        let after = self.reachable_nodes(entry);
        let removed: Vec<NodeIndex> = before.difference(&after).copied().collect();
        if removed.is_empty() {
            return true;
        }
        for node in removed {
            self.graph.remove_node(node);
        }
        self.blocks_by_address
            .retain(|_, node| self.graph.contains_node(*node));
        true
    }

    fn reachable_nodes(&self, entry: NodeIndex) -> BTreeSet<NodeIndex> {
        let mut roots = BTreeSet::from([entry]);
        for call in self
            .blocks_by_address
            .values()
            .flat_map(|node| self.graph[*node].calls.iter())
            .chain(self.recovered_calls.iter())
        {
            let targets = call
                .target
                .into_iter()
                .chain(call.candidates.iter().map(|candidate| candidate.target));
            let target_node = targets.filter_map(|target| self.blocks_by_address.get(&target));
            roots.extend(target_node.copied());
        }
        let mut reachable = BTreeSet::new();
        let mut pending: Vec<NodeIndex> = roots.into_iter().collect();
        while let Some(node) = pending.pop() {
            if !reachable.insert(node) {
                continue;
            }
            pending.extend(
                self.graph
                    .neighbors_directed(node, petgraph::Direction::Outgoing)
                    .filter(|next| !reachable.contains(next)),
            );
        }
        reachable
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
    /// Inlined subroutine ranges inside this function, ordered by address and
    /// depth.
    pub inline_frames: Vec<CfgInlineFrame>,
    /// Why this function cannot return, when known.
    pub noreturn: Option<CfgNoreturnReason>,
    /// Function CFG.
    pub cfg: FunctionCfg,
}

/// Program-wide CFG collection.
#[derive(Clone, Debug, Default)]
pub struct ProgramCfg {
    /// Functions sorted by address.
    pub functions: Vec<CfgFunction>,
    /// Executable addresses recovered from pointer-sized words in allocated
    /// data sections. These are additional system roots for functions that
    /// are only reachable through callback tables or global function pointers.
    pub pointer_roots: Vec<u64>,
}

impl CfgFunction {
    /// Builds an empty CFG record from a TDG function that has no machine code
    /// in this image, such as an external import or a logical task entry.
    #[must_use]
    pub fn from_tdg_function(function: &Function) -> Self {
        Self {
            id: function.id.clone(),
            primary_name: function.primary_name.clone(),
            demangled_name: function.demangled_name.clone(),
            symbols: function.symbols.clone(),
            language: function.language,
            kind: function.kind,
            address: function.address.get(),
            size: function.size,
            section: function.section.clone().unwrap_or_default(),
            source: function.source.clone(),
            inline_frames: Vec::new(),
            noreturn: function
                .ext
                .get("elf2tdg.noreturn")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                .then(|| match function.ext.get("elf2tdg.noreturn_source") {
                    Some(serde_json::Value::String(source)) if source == "control-flow" => {
                        CfgNoreturnReason::ControlFlow
                    }
                    _ => CfgNoreturnReason::Api,
                }),
            cfg: FunctionCfg::default(),
        }
    }
}

impl ProgramCfg {
    /// Builds a program CFG from function records.
    #[must_use]
    pub fn new(mut functions: Vec<CfgFunction>) -> Self {
        functions.sort_by_key(|function| function.address);
        Self {
            functions,
            pointer_roots: Vec::new(),
        }
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
            .binary_search_by_key(&address, |function| function.address)
            .ok()
            .map(|index| &self.functions[index])
    }

    /// Selects functions by exact name, symbol, or `0x` address. Without a
    /// selector, all functions are returned.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the selector matches no function or
    /// is ambiguous.
    pub fn select(&self, selector: Option<&str>) -> Result<Vec<&CfgFunction>, String> {
        self.select_impl(selector, None)
    }

    /// Selects CFG functions with task-context aliases from `tdg`.
    ///
    /// In addition to function names, symbols and addresses, a selector may
    /// name an execution context (for example `app::sensor_task`). The
    /// context's entry function is then selected, so an async task name maps
    /// to its real `TaskStorage<...>::poll` function instead of a helper that
    /// merely contains the task name.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the selector matches no function or
    /// context, or when the match is ambiguous.
    pub fn select_with_tdg(
        &self,
        tdg: &Tdg,
        selector: Option<&str>,
    ) -> Result<Vec<&CfgFunction>, String> {
        self.select_impl(selector, Some(tdg))
    }

    fn select_impl(
        &self,
        selector: Option<&str>,
        tdg: Option<&Tdg>,
    ) -> Result<Vec<&CfgFunction>, String> {
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
        // Task/thread context names take precedence over helper functions
        // whose symbols merely contain the same text (for example Embassy
        // future initialization helpers).
        if let Some(tdg) = tdg {
            let aliases = unique_functions(
                tdg.contexts
                    .iter()
                    .filter(|context| is_task_context(context.kind))
                    .filter(|context| context_matches(&context.name, selector))
                    .filter_map(|context| self.cfg_function_for_tdg_id(tdg, &context.entry)),
            );
            if aliases.len() == 1 {
                return Ok(aliases);
            }
            if aliases.len() > 1 {
                return Err(format!(
                    "function selector {selector:?} matches multiple task contexts ({} matches)",
                    aliases.len()
                ));
            }
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

        let mut partial: Vec<&CfgFunction> = self
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
        if let Some(tdg) = tdg {
            partial.extend(
                tdg.contexts
                    .iter()
                    .filter(|context| normalize_crate_hashes(&context.name).contains(selector))
                    .filter_map(|context| self.cfg_function_for_tdg_id(tdg, &context.entry)),
            );
        }
        let partial = unique_functions(partial);
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

    /// Resolves an address to a non-special function suitable for a general
    /// symbol/DWARF root. Default-handler stubs, PLT stubs and external
    /// imports are not code bodies in this image and are excluded.
    fn function_root_at<'a>(
        &'a self,
        default_handlers: &BTreeSet<u64>,
        address: u64,
    ) -> Option<&'a CfgFunction> {
        if default_handlers.contains(&address) {
            return None;
        }
        let function = self.function_covering(address)?;
        (!is_default_handler(function)
            && !matches!(function.kind, FunctionKind::Plt | FunctionKind::External))
        .then_some(function)
    }

    /// Collects execution roots: main/startup/task contexts, Cortex-M vector
    /// handlers, ARM/AArch64 exception vectors, RISC-V trap vectors, callbacks,
    /// global pointer roots, init/fini entry points and the ELF entry point.
    ///
    /// Symbol and DWARF entries are deliberately excluded: they are discovery
    /// roots for lossless export, not proof that the image executes the
    /// function. Dead-code and reachability passes should start here.
    #[must_use]
    pub fn execution_roots(&self, tdg: &Tdg, image: &Image) -> Vec<FunctionId> {
        let mut roots = BTreeSet::new();
        let default_handlers = default_handler_addresses(image);
        self.collect_execution_roots(tdg, image, &default_handlers, &mut roots);
        roots.into_iter().collect()
    }

    /// Collects all CFG export roots: execution roots plus every function
    /// represented by a code symbol or DWARF subprogram.
    ///
    /// This is the default lossless CFG scope. Use [`Self::execution_roots`]
    /// for reachability or dead-code decisions.
    ///
    /// Default handler stubs repeated across unused vectors are excluded.
    #[must_use]
    pub fn system_roots(&self, tdg: &Tdg, image: &Image) -> Vec<FunctionId> {
        let mut roots = BTreeSet::new();
        let default_handlers = default_handler_addresses(image);
        self.collect_execution_roots(tdg, image, &default_handlers, &mut roots);
        for symbol in &image.symbols {
            if let Some(function) =
                self.function_root_at(&default_handlers, symbol.canonical_address)
            {
                roots.insert(function.id.clone());
            }
        }
        if let Some(dwarf) = &image.dwarf {
            for function in &dwarf.functions {
                let Some((low, _)) = function.primary_range() else {
                    continue;
                };
                if let Some(function) =
                    self.function_root_at(&default_handlers, image.canonical_address(low))
                {
                    roots.insert(function.id.clone());
                }
            }
        }
        roots.into_iter().collect()
    }

    fn collect_execution_roots(
        &self,
        tdg: &Tdg,
        image: &Image,
        default_handlers: &BTreeSet<u64>,
        roots: &mut BTreeSet<FunctionId>,
    ) {
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
        for target in architecture_root_addresses(image) {
            if default_handlers.contains(&target) {
                continue;
            }
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
        for address in &self.pointer_roots {
            if let Some(function) = self.function_covering(*address)
                && !is_default_handler(function)
                && !matches!(function.kind, FunctionKind::Plt | FunctionKind::External)
            {
                roots.insert(function.id.clone());
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
    }

    /// Runs multi-root worklist reachability from all CFG export roots:
    /// execution roots plus symbol/DWARF discovery roots.
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

    /// Runs reachability from execution roots only.
    ///
    /// Symbol/DWARF discovery-only roots are not seeded. Unresolved call
    /// edges remain explicit unknown frontiers; callers that need sound
    /// dead-code elimination must not treat a missing candidate as absence of
    /// a call.
    #[must_use]
    pub fn reachable_from_execution_roots(
        &self,
        tdg: &Tdg,
        image: &Image,
        prune_runtime: bool,
    ) -> Vec<&CfgFunction> {
        let roots = self.execution_roots(tdg, image);
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
        let functions = self.select_with_tdg(tdg, Some(root))?;
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

fn is_task_context(kind: ContextKind) -> bool {
    matches!(
        kind,
        ContextKind::Thread
            | ContextKind::ScopedThread
            | ContextKind::AsyncTask
            | ContextKind::Executor
            | ContextKind::TimerCallback
    )
}

fn context_matches(name: &str, selector: &str) -> bool {
    let normalized = normalize_crate_hashes(name);
    normalized == selector
        || normalized
            .rsplit("::")
            .next()
            .is_some_and(|short| short == selector)
}

fn unique_functions<'a>(
    functions: impl IntoIterator<Item = &'a CfgFunction>,
) -> Vec<&'a CfgFunction> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for function in functions {
        if seen.insert(function.id.clone()) {
            unique.push(function);
        }
    }
    unique
}

/// Returns architecture-level root addresses that are not ordinary call
/// targets: vector/trap handlers, exception-vector code and ELF init/fini
/// entry points.
#[must_use]
pub(crate) fn architecture_root_addresses(image: &Image) -> Vec<u64> {
    let mut roots: BTreeSet<u64> = image
        .vector_table
        .iter()
        .map(|vector| image.canonical_address(vector.handler))
        .collect();
    for symbol in &image.symbols {
        if matches!(
            symbol.name.as_str(),
            "_init" | "_fini" | "__libc_csu_init" | "__libc_csu_fini"
        ) || is_architecture_root_symbol_name(&symbol.name)
        {
            roots.insert(symbol.canonical_address);
        }
    }

    let Ok(decoder) = Decoder::new(image.arch) else {
        return roots.into_iter().collect();
    };
    let step = matches!(
        image.arch,
        ArchKind::Thumb | ArchKind::Riscv32 | ArchKind::Riscv64
    )
    .then_some(2usize)
    .unwrap_or(4);
    for section in image
        .sections
        .iter()
        .filter(|section| section.executable && is_architecture_root_section(&section.name))
    {
        roots.insert(section.address);
        if image.arch == ArchKind::Aarch64 && section.data.len() >= 128 {
            // AArch64 exception-vector entries are 128 bytes apart. Each
            // entry can be code rather than a branch, so retain its address.
            for index in 0..16usize {
                let Some(offset) = index.checked_mul(128) else {
                    break;
                };
                if offset >= section.data.len() {
                    break;
                }
                let words = &section.data[offset..section.data.len().min(offset + 4)];
                if words.iter().any(|byte| *byte != 0) {
                    roots.insert(section.address.saturating_add(offset as u64));
                }
            }
        }
        let mut offset = 0usize;
        while offset < section.data.len() {
            let address = section.address.saturating_add(offset as u64);
            match decoder.decode_one(&section.data[offset..], address) {
                Ok(Some(instruction)) => {
                    if (instruction.is_jump || instruction.is_call)
                        && !instruction.is_conditional
                        && let Some(target) = instruction.direct_target
                    {
                        let target = image.canonical_address(target);
                        if image.is_executable(target) {
                            roots.insert(target);
                        }
                    }
                    offset = offset.saturating_add(usize::from(instruction.size.max(2)));
                }
                _ => offset = offset.saturating_add(step),
            }
        }
    }
    roots.into_iter().collect()
}

fn is_architecture_root_symbol_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let name = name.trim_start_matches('_');
    matches!(
        name,
        "vector"
            | "vectors"
            | "vector_table"
            | "isr_vector"
            | "trap"
            | "trap_entry"
            | "trap_handler"
            | "exception"
            | "exceptions"
            | "exception_handler"
            | "exception_vectors"
    ) || name.ends_with("_vector_table")
        || name.ends_with("_vectors")
        || name.ends_with("_trap")
        || name.ends_with("_trap_entry")
        || name.ends_with("_trap_handler")
        || name.ends_with("_exception_handler")
}

fn is_architecture_root_section(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        ".vector",
        ".vectors",
        ".vector_table",
        ".isr_vector",
        ".isr",
        ".trap",
        ".trap_vector",
        ".exception",
        ".exceptions",
        ".exception_vectors",
    ]
    .iter()
    .any(|prefix| {
        name == *prefix || name.starts_with(&format!("{prefix}.")) || name.ends_with(prefix)
    })
}

fn is_default_handler(function: &CfgFunction) -> bool {
    is_default_handler_name(&function.primary_name)
}

fn default_handler_addresses(image: &Image) -> BTreeSet<u64> {
    image
        .symbols
        .iter()
        .filter(|symbol| is_default_handler_name(&symbol.name))
        .map(|symbol| symbol.canonical_address)
        .collect()
}

fn is_default_handler_name(name: &str) -> bool {
    let normalized = normalize_crate_hashes(name).to_ascii_lowercase();
    normalized.contains("default_handler") || normalized.contains("defaulthandler")
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pointer_roots: Vec<Addr>,
    functions: Vec<CfgFunctionView>,
    diagnostics: Vec<&'a Diagnostic>,
    #[serde(skip_serializing_if = "is_zero")]
    diagnostics_omitted: usize,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &usize) -> bool {
    *value == 0
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    inline_frames: Vec<CfgInlineView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_code: Option<CfgNoCodeView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    noreturn: Option<CfgNoreturnReason>,
    entry: Option<BlockId>,
    blocks: Vec<CfgBlockView>,
    edges: Vec<CfgEdgeView>,
    recovered_calls: Vec<CfgCallView>,
}

#[derive(Serialize)]
struct CfgNoCodeView {
    reason: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct CfgInlineView {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    linkage_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_site: Option<SourceLoc>,
    low: Addr,
    high: Addr,
    depth: u32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    halfword: Option<bool>,
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
    #[serde(skip_serializing_if = "is_false")]
    null_target: bool,
    #[serde(skip_serializing_if = "is_false")]
    noreturn: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    candidates: Vec<CfgCallCandidateView>,
}

#[derive(Serialize)]
struct CfgCallCandidateView {
    target: Addr,
    target_function: Option<FunctionId>,
    target_name: Option<String>,
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
    let selected = program.select_with_tdg(tdg, selector)?;
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
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let diagnostics: Vec<&Diagnostic> = tdg
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic
                .function
                .as_ref()
                .is_none_or(|function| selected_ids.contains(function))
        })
        .collect();
    let diagnostics_omitted = tdg.diagnostics.len().saturating_sub(diagnostics.len());
    let document = CfgDocument {
        cfg_schema_version: CFG_SCHEMA_VERSION,
        image: &tdg.image,
        pointer_roots: program
            .pointer_roots
            .iter()
            .copied()
            .map(Addr::new)
            .collect(),
        functions,
        diagnostics,
        diagnostics_omitted,
    };
    serde_json::to_string_pretty(&document).map_err(|error| error.to_string())
}

fn no_code_view(function: &CfgFunction) -> Option<CfgNoCodeView> {
    if !function.cfg.blocks_by_address.is_empty() {
        return None;
    }
    let (reason, message) = match function.kind {
        FunctionKind::External => (
            "external",
            "declared external symbol; no machine code in this image",
        ),
        FunctionKind::TaskEntry if function.size == 0 => (
            "logical",
            "logical task entry; no standalone machine code at the spawn site",
        ),
        _ => (
            "unavailable",
            "no basic blocks were recovered for this function",
        ),
    };
    Some(CfgNoCodeView { reason, message })
}

fn no_code_label(function: &CfgFunction) -> Option<String> {
    let view = no_code_view(function)?;
    let name = normalize_crate_hashes(&function.primary_name);
    Some(format!(
        "{}\n{}\n{}",
        match view.reason {
            "external" => "external function",
            "logical" => "logical task entry",
            _ => "no CFG blocks",
        },
        shorten(&name, 64),
        view.message
    ))
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
    let inline_frames = function
        .inline_frames
        .iter()
        .map(|frame| CfgInlineView {
            name: frame.name.clone(),
            linkage_name: frame.linkage_name.clone(),
            call_site: frame.call_site.clone(),
            low: Addr::new(frame.low_pc),
            high: Addr::new(frame.high_pc),
            depth: frame.depth,
        })
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
        inline_frames,
        no_code: no_code_view(function),
        noreturn: function.noreturn,
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
        null_target: call.null_target,
        noreturn: call.noreturn,
        candidates: call
            .candidates
            .iter()
            .map(|candidate| CfgCallCandidateView {
                target: Addr::new(candidate.target),
                target_function: candidate.target_function.clone(),
                target_name: candidate.target_function.as_ref().and_then(|id| {
                    program
                        .function(id)
                        .map(|function| normalize_crate_hashes(&function.primary_name))
                }),
            })
            .collect(),
    }
}

#[allow(clippy::too_many_lines)]
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
                halfword: None,
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
                halfword: None,
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
                halfword: None,
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
                halfword: None,
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
                halfword: None,
            },
            CfgIndirectTarget::TableBranch {
                base,
                index,
                halfword,
            } => CfgIndirectView {
                kind: "table-branch",
                register: None,
                base: base.clone(),
                disp: None,
                address: None,
                offset: None,
                index: Some(index.clone()),
                scale: Some(if *halfword { 2 } else { 1 }),
                halfword: Some(*halfword),
            },
            CfgIndirectTarget::TableLoad { base, index, disp } => CfgIndirectView {
                kind: "table-load",
                register: None,
                base: base.clone(),
                disp: Some(*disp),
                address: None,
                offset: None,
                index: Some(index.clone()),
                scale: Some(4),
                halfword: None,
            },
            CfgIndirectTarget::BranchTable { base, index } => CfgIndirectView {
                kind: "branch-table",
                register: None,
                base: base.clone(),
                disp: None,
                address: None,
                offset: None,
                index: Some(index.clone()),
                scale: Some(4),
                halfword: None,
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

/// Renders a CFG as Graphviz DOT with task-context selector aliases from
/// `tdg`.
///
/// # Errors
///
/// Returns an error when the selector matches nothing or is ambiguous.
pub fn render_dot_with_tdg(
    program: &ProgramCfg,
    tdg: &Tdg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select_with_tdg(tdg, selector)?;
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
        if let Some(label) = no_code_label(function) {
            let _ = writeln!(
                out,
                "    \"nocode_{function_index}\" [label=\"{}\", shape=note, style=\"dashed,filled\", fillcolor=\"#f4f6f7\", color=\"#999999\"];",
                dot_escape(&label)
            );
        }
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
                let label = if call.unresolved {
                    "call?".to_owned()
                } else if call.null_target {
                    "null target".to_owned()
                } else if call.noreturn {
                    "noreturn call".to_owned()
                } else if call.tail {
                    "tail call".to_owned()
                } else {
                    "call".to_owned()
                };
                for (key, target_label) in call_targets(program, call) {
                    call_nodes.entry(key.clone()).or_insert(target_label);
                    let _ = writeln!(
                        out,
                        "    \"{}\" -> \"{}\" [label=\"{label}\", color=\"#117a65\", fontcolor=\"#117a65\", style=dashed];",
                        dot_escape(block.id.as_str()),
                        dot_escape(&key)
                    );
                }
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
                for (key, label) in call_targets(program, call) {
                    call_nodes.entry(key.clone()).or_insert(label);
                    let _ = writeln!(
                        out,
                        "    \"{}\" -> \"{}\" [label=\"heuristic call\", color=\"#b9770e\", fontcolor=\"#b9770e\", style=dashed];",
                        dot_escape(&source),
                        dot_escape(&key)
                    );
                }
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

/// Renders a CFG as a Mermaid flowchart with task-context selector aliases
/// from `tdg`.
///
/// # Errors
///
/// Returns an error when the selector matches nothing or is ambiguous.
pub fn render_mermaid_with_tdg(
    program: &ProgramCfg,
    tdg: &Tdg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select_with_tdg(tdg, selector)?;
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
        if let Some(label) = no_code_label(function) {
            let _ = writeln!(
                out,
                "    nc{function_index}[\"{}\"]",
                mermaid_escape(&label)
            );
        }
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
                let relation = if call.unresolved {
                    "call?"
                } else if call.null_target {
                    "null target"
                } else if call.noreturn {
                    "noreturn call"
                } else if call.tail {
                    "tail call"
                } else {
                    "call"
                };
                for (key, label) in call_targets(program, call) {
                    let id = if let Some((id, _)) = call_nodes.get(&key) {
                        id.clone()
                    } else {
                        let id = format!("call{}", call_nodes.len());
                        call_nodes.insert(key, (id.clone(), label.clone()));
                        let _ = writeln!(out, "  {id}[\"{}\"]", mermaid_escape(&label));
                        id
                    };
                    let _ = writeln!(out, "  {source} -.->|{relation}| {id}");
                }
            }
        }
        if !cfg.recovered_calls.is_empty() {
            let recovered_id = format!("rec{function_index}");
            for call in &cfg.recovered_calls {
                for (key, label) in call_targets(program, call) {
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
        let candidate_count: usize = block.calls.iter().map(|call| call.candidates.len()).sum();
        if candidate_count == 0 {
            let _ = write!(label, "\n{} call(s)", block.calls.len());
        } else {
            let _ = write!(
                label,
                "\n{} call(s), {} candidate target(s)",
                block.calls.len(),
                candidate_count
            );
        }
        if block.terminator == CfgTerminator::NoreturnCall
            || block.calls.iter().any(|call| call.noreturn)
        {
            let _ = write!(label, "\nnoreturn");
        }
    }
    label
}

fn call_targets(program: &ProgramCfg, call: &CfgCallSite) -> Vec<(String, String)> {
    if call.null_target {
        return vec![(
            format!("call:null:0x{:x}", call.site),
            "null function pointer".to_owned(),
        )];
    }
    if !call.candidates.is_empty() {
        return call
            .candidates
            .iter()
            .map(|candidate| {
                target_label(
                    program,
                    candidate.target,
                    candidate.target_function.as_ref(),
                )
            })
            .collect();
    }
    if let Some(target) = call.target {
        return vec![target_label(program, target, call.target_function.as_ref())];
    }
    vec![(
        format!("call:unresolved:0x{:x}", call.site),
        "unresolved call".to_owned(),
    )]
}

fn target_label(
    program: &ProgramCfg,
    target: u64,
    target_function: Option<&FunctionId>,
) -> (String, String) {
    if let Some(function_id) = target_function {
        if let Some(function) = program.function(function_id) {
            let name = crate::rules::normalize_crate_hashes(&function.primary_name);
            return (
                format!("call:{function_id}"),
                format!("{}\n0x{:x}", shorten(&name, 48), function.address),
            );
        }
        return (
            format!("call:{function_id}"),
            format!("{function_id}\n(entry)"),
        );
    }
    (format!("call:0x{target:x}"), format!("0x{target:x}"))
}

fn shorten(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut shortened: String = value.chars().take(max_chars.saturating_sub(3)).collect();
    shortened.push_str("...");
    shortened
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
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

/// Machine-readable CFG validation issue code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgValidationCode {
    /// A function ID or name is empty or malformed.
    InvalidFunction,
    /// Two functions share an ID.
    DuplicateFunctionId,
    /// Function records are not sorted by address.
    FunctionOrder,
    /// A function's address range overflows or contradicts its blocks.
    InvalidFunctionRange,
    /// An inline frame range is empty or outside its function.
    InvalidInlineRange,
    /// A function has basic blocks but no entry node.
    MissingEntry,
    /// A function has an entry node but no basic blocks.
    UnexpectedEntry,
    /// The entry node does not belong to the graph or its function.
    InvalidEntry,
    /// The address map and the petgraph node set disagree.
    InconsistentBlockMap,
    /// Two graph nodes have the same block address or block ID.
    DuplicateBlock,
    /// A block ID does not match its address.
    InvalidBlockId,
    /// A block has no instructions or an inconsistent size.
    EmptyBlock,
    /// Instruction addresses, sizes or extents are inconsistent.
    InvalidInstructionRange,
    /// A basic block lies outside its containing function.
    InvalidBlockRange,
    /// A function's referenced-address list is not sorted or contains duplicates.
    InvalidReferenceList,
    /// A call record is attached to the wrong instruction or block.
    InvalidCallSite,
    /// Two call records share a site in one block.
    DuplicateCallSite,
    /// A call has inconsistent resolved/unresolved target fields.
    InvalidCallTarget,
    /// A call has contradictory boolean flags.
    InvalidCallFlags,
    /// A block terminator does not match its final instruction.
    InvalidTerminator,
    /// A CFG edge is inconsistent with its source block or terminator.
    InvalidEdge,
    /// Two CFG edges have the same source, target, kind and site.
    DuplicateEdge,
    /// A pointer root is repeated.
    InvalidPointerRoot,
    /// A call references a function ID missing from the program CFG.
    DanglingFunctionReference,
}

/// One CFG validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgValidationIssue {
    /// Machine-readable issue code.
    pub code: CfgValidationCode,
    /// JSON-pointer-like location inside the CFG document.
    pub path: String,
    /// Human-readable explanation.
    pub message: String,
}

/// Error returned by CFG `ensure_valid` methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgValidationError {
    /// All issues found.
    pub issues: Vec<CfgValidationIssue>,
}

impl fmt::Display for CfgValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CFG validation failed with {} issue(s)",
            self.issues.len()
        )
    }
}

impl std::error::Error for CfgValidationError {}

impl FunctionCfg {
    /// Validates the graph structure and block/call invariants.
    ///
    /// An empty vector means the CFG is structurally consistent. Reachability
    /// is not required: retained orphan blocks and intra-function call targets
    /// are valid.
    #[must_use]
    pub fn validate(&self) -> Vec<CfgValidationIssue> {
        self.validate_with_limit(usize::MAX)
    }

    /// Validates the CFG, collecting at most `limit` issues.
    #[must_use]
    pub fn validate_with_limit(&self, limit: usize) -> Vec<CfgValidationIssue> {
        let mut validator = CfgValidator::new(None, limit);
        validator.validate_function_cfg(self, None, "/cfg");
        validator.issues
    }

    /// Validates the CFG and converts issues into an error.
    ///
    /// # Errors
    ///
    /// Returns [`CfgValidationError`] when any issue is found.
    pub fn ensure_valid(&self) -> Result<(), CfgValidationError> {
        ensure_valid_cfg(self.validate())
    }
}

impl CfgFunction {
    /// Validates function metadata and its attached CFG.
    #[must_use]
    pub fn validate(&self) -> Vec<CfgValidationIssue> {
        self.validate_with_limit(usize::MAX)
    }

    /// Validates the function, collecting at most `limit` issues.
    #[must_use]
    pub fn validate_with_limit(&self, limit: usize) -> Vec<CfgValidationIssue> {
        let mut validator = CfgValidator::new(None, limit);
        validator.validate_function(self, "");
        validator.issues
    }

    /// Validates the function and converts issues into an error.
    ///
    /// # Errors
    ///
    /// Returns [`CfgValidationError`] when any issue is found.
    pub fn ensure_valid(&self) -> Result<(), CfgValidationError> {
        ensure_valid_cfg(self.validate())
    }
}

impl ProgramCfg {
    /// Validates all function CFGs and their cross-references.
    #[must_use]
    pub fn validate(&self) -> Vec<CfgValidationIssue> {
        self.validate_with_limit(usize::MAX)
    }

    /// Validates the program CFG, collecting at most `limit` issues.
    #[must_use]
    pub fn validate_with_limit(&self, limit: usize) -> Vec<CfgValidationIssue> {
        let mut validator = CfgValidator::new(Some(self), limit);
        validator.validate_program();
        validator.issues
    }

    /// Validates the program CFG and converts issues into an error.
    ///
    /// # Errors
    ///
    /// Returns [`CfgValidationError`] when any issue is found.
    pub fn ensure_valid(&self) -> Result<(), CfgValidationError> {
        ensure_valid_cfg(self.validate())
    }
}

fn ensure_valid_cfg(issues: Vec<CfgValidationIssue>) -> Result<(), CfgValidationError> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(CfgValidationError { issues })
    }
}

struct CfgValidator<'a> {
    program: Option<&'a ProgramCfg>,
    function_ids: BTreeSet<FunctionId>,
    issues: Vec<CfgValidationIssue>,
    limit: usize,
}

impl<'a> CfgValidator<'a> {
    fn new(program: Option<&'a ProgramCfg>, limit: usize) -> Self {
        let function_ids = program.map_or_else(BTreeSet::new, |program| {
            program
                .functions
                .iter()
                .map(|function| function.id.clone())
                .collect()
        });
        Self {
            program,
            function_ids,
            issues: Vec::new(),
            limit,
        }
    }

    fn push(
        &mut self,
        code: CfgValidationCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.issues.len() < self.limit {
            self.issues.push(CfgValidationIssue {
                code,
                path: path.into(),
                message: message.into(),
            });
        }
    }

    fn validate_program(&mut self) {
        let Some(program) = self.program else {
            return;
        };
        let mut seen_ids = BTreeSet::new();
        let mut previous_address = None;
        for (index, function) in program.functions.iter().enumerate() {
            let path = format!("/functions/{index}");
            if !seen_ids.insert(function.id.clone()) {
                self.push(
                    CfgValidationCode::DuplicateFunctionId,
                    format!("{path}/id"),
                    format!("duplicate function ID {}", function.id),
                );
            }
            if let Some(previous) = previous_address
                && function.address < previous
            {
                self.push(
                    CfgValidationCode::FunctionOrder,
                    format!("{path}/address"),
                    "functions are not sorted by address",
                );
            }
            previous_address = Some(function.address);
            self.validate_function(function, &path);
        }
        let mut seen_roots = BTreeSet::new();
        for (index, address) in program.pointer_roots.iter().enumerate() {
            if !seen_roots.insert(*address) {
                self.push(
                    CfgValidationCode::InvalidPointerRoot,
                    format!("/pointer_roots/{index}"),
                    format!("duplicate pointer root 0x{address:x}"),
                );
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_function(&mut self, function: &CfgFunction, path: &str) {
        if !function.id.is_well_formed() {
            self.push(
                CfgValidationCode::InvalidFunction,
                format!("{path}/id"),
                format!("invalid function ID {:?}", function.id),
            );
        }
        if function.primary_name.trim().is_empty() {
            self.push(
                CfgValidationCode::InvalidFunction,
                format!("{path}/primary_name"),
                "function primary_name must not be empty",
            );
        }
        let function_end = function.address.checked_add(function.size);
        if function_end.is_none() {
            self.push(
                CfgValidationCode::InvalidFunctionRange,
                format!("{path}/size"),
                "function address range overflows u64",
            );
        }
        if function.size == 0 && !function.cfg.blocks_by_address.is_empty() {
            self.push(
                CfgValidationCode::InvalidFunctionRange,
                format!("{path}/size"),
                "a function with basic blocks must have a non-zero size",
            );
        }
        for (index, frame) in function.inline_frames.iter().enumerate() {
            let frame_path = format!("{path}/inline_frames/{index}");
            if frame.low_pc >= frame.high_pc {
                self.push(
                    CfgValidationCode::InvalidInlineRange,
                    format!("{frame_path}/high"),
                    "inline frame high address must be greater than low",
                );
            }
            if function.size > 0
                && let Some(end) = function_end
                && (frame.low_pc < function.address || frame.high_pc > end)
            {
                self.push(
                    CfgValidationCode::InvalidInlineRange,
                    frame_path,
                    "inline frame lies outside the containing function",
                );
            }
        }
        if let Some(entry) = function.cfg.entry
            && let Some(block) = function.cfg.graph.node_weight(entry)
            && block.address != function.address
        {
            self.push(
                CfgValidationCode::InvalidEntry,
                format!("{path}/cfg/entry"),
                "entry block address does not match the function start",
            );
        }
        self.validate_function_cfg(&function.cfg, Some(function), &format!("{path}/cfg"));
    }

    #[allow(clippy::too_many_lines)]
    fn validate_function_cfg(
        &mut self,
        cfg: &FunctionCfg,
        function: Option<&CfgFunction>,
        path: &str,
    ) {
        let node_count = cfg.graph.node_count();
        if cfg.blocks_by_address.len() != node_count {
            self.push(
                CfgValidationCode::InconsistentBlockMap,
                format!("{path}/blocks_by_address"),
                format!(
                    "{} address-map entries for {node_count} graph nodes",
                    cfg.blocks_by_address.len()
                ),
            );
        }
        match cfg.entry {
            Some(entry) if cfg.graph.contains_node(entry) => {}
            Some(_) => self.push(
                CfgValidationCode::InvalidEntry,
                format!("{path}/entry"),
                "entry node is not present in the graph",
            ),
            None if node_count > 0 => self.push(
                CfgValidationCode::MissingEntry,
                format!("{path}/entry"),
                "non-empty CFG has no entry node",
            ),
            None => {}
        }
        if cfg.entry.is_some() && node_count == 0 {
            self.push(
                CfgValidationCode::UnexpectedEntry,
                format!("{path}/entry"),
                "empty CFG has an entry node",
            );
        }

        let mut mapped_nodes = BTreeSet::new();
        let mut block_ids = BTreeSet::new();
        for (address, node) in &cfg.blocks_by_address {
            if !cfg.graph.contains_node(*node) {
                self.push(
                    CfgValidationCode::InconsistentBlockMap,
                    format!("{path}/blocks_by_address/0x{address:x}"),
                    "address map points at a missing graph node",
                );
                continue;
            }
            if !mapped_nodes.insert(*node) {
                self.push(
                    CfgValidationCode::InconsistentBlockMap,
                    format!("{path}/blocks_by_address/0x{address:x}"),
                    "multiple addresses map to the same graph node",
                );
            }
            let block = &cfg.graph[*node];
            if block.address != *address {
                self.push(
                    CfgValidationCode::InconsistentBlockMap,
                    format!("{path}/blocks_by_address/0x{address:x}"),
                    format!("graph node address is 0x{:x}", block.address),
                );
            }
            if !block_ids.insert(block.id.clone()) {
                self.push(
                    CfgValidationCode::DuplicateBlock,
                    format!("{path}/blocks/0x{address:x}/id"),
                    format!("duplicate block ID {}", block.id),
                );
            }
            let expected_id = format!("bb:0x{address:x}");
            if block.id.as_str() != expected_id {
                self.push(
                    CfgValidationCode::InvalidBlockId,
                    format!("{path}/blocks/0x{address:x}/id"),
                    format!("block ID {} does not match address 0x{address:x}", block.id),
                );
            }
            self.validate_block(cfg, *node, block, function, path);
        }
        for node in cfg.graph.node_indices() {
            if !mapped_nodes.contains(&node) {
                let address = cfg.graph[node].address;
                self.push(
                    CfgValidationCode::InconsistentBlockMap,
                    format!("{path}/blocks/0x{address:x}"),
                    "graph node is missing from blocks_by_address",
                );
            }
        }
        let mut previous_end: Option<u64> = None;
        for (address, node) in &cfg.blocks_by_address {
            if !cfg.graph.contains_node(*node) {
                continue;
            }
            let block = &cfg.graph[*node];
            if block.address.checked_add(block.size).is_some()
                && previous_end.is_some_and(|previous| block.address < previous)
            {
                self.push(
                    CfgValidationCode::InvalidBlockRange,
                    format!("{path}/blocks/0x{address:x}"),
                    "basic blocks overlap or are out of order",
                );
            }
            previous_end = block.address.checked_add(block.size);
        }

        let mut attached_sites = BTreeSet::new();
        for block in cfg.blocks_by_address.values() {
            for call in &cfg.graph[*block].calls {
                attached_sites.insert(call.site);
            }
        }
        let mut recovered_sites = BTreeSet::new();
        for (index, call) in cfg.recovered_calls.iter().enumerate() {
            let call_path = format!("{path}/recovered_calls/{index}");
            if !recovered_sites.insert(call.site) {
                self.push(
                    CfgValidationCode::DuplicateCallSite,
                    format!("{call_path}/site"),
                    format!("duplicate recovered call site 0x{:x}", call.site),
                );
            }
            if attached_sites.contains(&call.site) {
                self.push(
                    CfgValidationCode::InvalidCallSite,
                    format!("{call_path}/site"),
                    "recovered call site is also attached to a basic block",
                );
            }
            self.validate_call(call, &call_path);
        }
        let mut previous_reference = None;
        for (index, address) in cfg.referenced_addresses.iter().enumerate() {
            if let Some(previous) = previous_reference
                && *address <= previous
            {
                self.push(
                    CfgValidationCode::InvalidReferenceList,
                    format!("{path}/referenced_addresses/{index}"),
                    "referenced addresses must be sorted and unique",
                );
            }
            previous_reference = Some(*address);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_block(
        &mut self,
        cfg: &FunctionCfg,
        node: NodeIndex,
        block: &CfgBlock,
        function: Option<&CfgFunction>,
        path: &str,
    ) {
        let block_path = format!("{path}/blocks/0x{:x}", block.address);
        let Some(block_end) = block.address.checked_add(block.size) else {
            self.push(
                CfgValidationCode::InvalidBlockRange,
                format!("{block_path}/size"),
                "block address range overflows u64",
            );
            return;
        };
        if block.size == 0 {
            self.push(
                CfgValidationCode::EmptyBlock,
                format!("{block_path}/size"),
                "basic block has zero size",
            );
        }
        if block.instructions.is_empty() {
            self.push(
                CfgValidationCode::EmptyBlock,
                block_path.clone(),
                "basic block has no instructions",
            );
            return;
        }
        if let Some(function) = function
            && function.size > 0
            && let Some(function_end) = function.address.checked_add(function.size)
            && (block.address < function.address || block_end > function_end)
        {
            self.push(
                CfgValidationCode::InvalidBlockRange,
                block_path.clone(),
                "basic block lies outside its containing function",
            );
        }
        let mut expected = block.address;
        let mut block_ends = None;
        for (index, instruction) in block.instructions.iter().enumerate() {
            let instruction_path = format!("{block_path}/instructions/{index}");
            if instruction.size == 0 {
                self.push(
                    CfgValidationCode::InvalidInstructionRange,
                    format!("{instruction_path}/size"),
                    "instruction has zero size",
                );
            }
            if instruction.address != expected {
                self.push(
                    CfgValidationCode::InvalidInstructionRange,
                    format!("{instruction_path}/address"),
                    format!(
                        "instruction starts at 0x{:x}, expected 0x{expected:x}",
                        instruction.address
                    ),
                );
            }
            expected = instruction
                .address
                .saturating_add(u64::from(instruction.size));
            block_ends = Some(expected);
        }
        if block_ends != Some(block_end) {
            self.push(
                CfgValidationCode::InvalidInstructionRange,
                format!("{block_path}/size"),
                "instruction stream does not end at the block end",
            );
        }
        let last = block.instructions.last().expect("non-empty instructions");
        if block.calls.iter().any(|call| call.site != last.address) {
            self.push(
                CfgValidationCode::InvalidCallSite,
                format!("{block_path}/calls"),
                "attached call record is not at the block terminator",
            );
        }
        let mut recorded_sites = BTreeSet::new();
        for (index, call) in block.calls.iter().enumerate() {
            let call_path = format!("{block_path}/calls/{index}");
            if !recorded_sites.insert(call.site) {
                self.push(
                    CfgValidationCode::DuplicateCallSite,
                    format!("{call_path}/site"),
                    format!("duplicate call site 0x{:x}", call.site),
                );
            }
            let Some(instruction) = block
                .instructions
                .iter()
                .find(|instruction| instruction.address == call.site)
            else {
                self.push(
                    CfgValidationCode::InvalidCallSite,
                    format!("{call_path}/site"),
                    "call site does not name an instruction in this block",
                );
                self.validate_call(call, &call_path);
                continue;
            };
            if !instruction.is_call && !instruction.is_jump {
                self.push(
                    CfgValidationCode::InvalidCallSite,
                    format!("{call_path}/site"),
                    "call record is attached to a non-call, non-jump instruction",
                );
            }
            if instruction.is_call && call.tail {
                self.push(
                    CfgValidationCode::InvalidCallFlags,
                    format!("{call_path}/tail"),
                    "call instruction must not be marked as a tail call",
                );
            }
            if instruction.is_jump && !call.tail {
                self.push(
                    CfgValidationCode::InvalidCallFlags,
                    format!("{call_path}/tail"),
                    "tail-call record on a jump must set tail=true",
                );
            }
            if call.direct != instruction.direct_target.is_some() {
                self.push(
                    CfgValidationCode::InvalidCallFlags,
                    format!("{call_path}/direct"),
                    "direct flag does not match the instruction target",
                );
            }
            if call.conditional != instruction.is_conditional {
                self.push(
                    CfgValidationCode::InvalidCallFlags,
                    format!("{call_path}/conditional"),
                    "conditional flag does not match the instruction",
                );
            }
            self.validate_call(call, &call_path);
        }
        let call_instructions: BTreeSet<u64> = block
            .instructions
            .iter()
            .filter(|instruction| instruction.is_call)
            .map(|instruction| instruction.address)
            .collect();
        for site in call_instructions {
            if !recorded_sites.contains(&site) {
                self.push(
                    CfgValidationCode::InvalidCallSite,
                    format!("{block_path}/calls"),
                    format!("call instruction 0x{site:x} has no call record"),
                );
            }
        }

        let call_at_last = block.calls.iter().find(|call| call.site == last.address);
        if last.is_return {
            if block.terminator != CfgTerminator::Return {
                self.push(
                    CfgValidationCode::InvalidTerminator,
                    format!("{block_path}/terminator"),
                    "return instruction must use the return terminator",
                );
            }
        } else if last.is_call {
            let expected = if call_at_last.is_some_and(|call| call.noreturn && !call.conditional) {
                CfgTerminator::NoreturnCall
            } else {
                CfgTerminator::Call
            };
            if block.terminator != expected {
                self.push(
                    CfgValidationCode::InvalidTerminator,
                    format!("{block_path}/terminator"),
                    format!(
                        "call terminator is {:?}, expected {expected:?}",
                        block.terminator
                    ),
                );
            }
        } else if last.is_jump {
            if !matches!(
                block.terminator,
                CfgTerminator::Branch | CfgTerminator::Jump | CfgTerminator::Unresolved
            ) {
                self.push(
                    CfgValidationCode::InvalidTerminator,
                    format!("{block_path}/terminator"),
                    "jump instruction must use a jump/branch/unresolved terminator",
                );
            }
        } else if block.terminator != CfgTerminator::Fallthrough {
            self.push(
                CfgValidationCode::InvalidTerminator,
                format!("{block_path}/terminator"),
                "non-terminating instruction must use fallthrough",
            );
        }

        self.validate_edges(cfg, node, block, last, block_end, &block_path);
    }

    #[allow(clippy::too_many_lines)]
    fn validate_edges(
        &mut self,
        cfg: &FunctionCfg,
        node: NodeIndex,
        block: &CfgBlock,
        last: &CfgInstruction,
        block_end: u64,
        block_path: &str,
    ) {
        let mut seen = BTreeSet::new();
        for edge in cfg
            .graph
            .edges_directed(node, petgraph::Direction::Outgoing)
        {
            let target = edge.target();
            let target_block = &cfg.graph[target];
            let edge_path = format!("{block_path}/edges/0x{:x}", edge.weight().site);
            if matches!(
                block.terminator,
                CfgTerminator::Return | CfgTerminator::NoreturnCall
            ) {
                self.push(
                    CfgValidationCode::InvalidEdge,
                    edge_path,
                    "returning/noreturn block must not have successors",
                );
                continue;
            }
            if edge.weight().site != last.address {
                self.push(
                    CfgValidationCode::InvalidEdge,
                    format!("{edge_path}/site"),
                    "edge site is not the final instruction of the source block",
                );
            }
            if edge.weight().conditional != last.is_conditional {
                self.push(
                    CfgValidationCode::InvalidEdge,
                    format!("{edge_path}/conditional"),
                    "edge conditional flag does not match the source instruction",
                );
            }
            if cfg.blocks_by_address.get(&target_block.address) != Some(&target) {
                self.push(
                    CfgValidationCode::InvalidEdge,
                    format!("{edge_path}/to"),
                    "edge target is not represented in blocks_by_address",
                );
            }
            match edge.weight().kind {
                CfgEdgeKind::Fallthrough => {
                    if target_block.address != block_end {
                        self.push(
                            CfgValidationCode::InvalidEdge,
                            format!("{edge_path}/to"),
                            "fallthrough edge does not target the next block",
                        );
                    }
                    if matches!(
                        block.terminator,
                        CfgTerminator::Call | CfgTerminator::NoreturnCall | CfgTerminator::Return
                    ) {
                        self.push(
                            CfgValidationCode::InvalidEdge,
                            format!("{edge_path}/kind"),
                            "returning call/return block cannot have a fallthrough edge",
                        );
                    }
                }
                CfgEdgeKind::CallReturn => {
                    if block.terminator != CfgTerminator::Call || !last.is_call {
                        self.push(
                            CfgValidationCode::InvalidEdge,
                            format!("{edge_path}/kind"),
                            "call-return edge requires a returning call terminator",
                        );
                    }
                    if target_block.address != block_end {
                        self.push(
                            CfgValidationCode::InvalidEdge,
                            format!("{edge_path}/to"),
                            "call-return edge does not target the next block",
                        );
                    }
                }
                CfgEdgeKind::Branch => {
                    if block.terminator != CfgTerminator::Branch {
                        self.push(
                            CfgValidationCode::InvalidEdge,
                            format!("{edge_path}/kind"),
                            "branch edge requires a branch terminator",
                        );
                    }
                }
                CfgEdgeKind::Jump => {
                    if block.terminator != CfgTerminator::Jump {
                        self.push(
                            CfgValidationCode::InvalidEdge,
                            format!("{edge_path}/kind"),
                            "jump edge requires a jump terminator",
                        );
                    }
                }
            }
            let key = (
                node.index(),
                target.index(),
                edge_kind_code(edge.weight().kind),
                edge.weight().site,
                edge.weight().conditional,
            );
            if !seen.insert(key) {
                self.push(
                    CfgValidationCode::DuplicateEdge,
                    edge_path,
                    "duplicate CFG edge",
                );
            }
        }
    }

    fn validate_call(&mut self, call: &CfgCallSite, path: &str) {
        if call.noreturn && call.conditional {
            self.push(
                CfgValidationCode::InvalidCallFlags,
                format!("{path}/noreturn"),
                "conditional call cannot be marked noreturn",
            );
        }
        if call.noreturn && call.unresolved {
            self.push(
                CfgValidationCode::InvalidCallFlags,
                format!("{path}/noreturn"),
                "unresolved call cannot be marked noreturn",
            );
        }
        if call.null_target
            && (call.target.is_some() || !call.candidates.is_empty() || call.unresolved)
        {
            self.push(
                CfgValidationCode::InvalidCallTarget,
                path,
                "null-target call must not carry another target",
            );
        }
        if call.unresolved && !call.candidates.is_empty() {
            self.push(
                CfgValidationCode::InvalidCallFlags,
                format!("{path}/unresolved"),
                "unresolved call must not carry candidates",
            );
        }
        if !call.candidates.is_empty() {
            if call.target.is_some() {
                self.push(
                    CfgValidationCode::InvalidCallTarget,
                    format!("{path}/target"),
                    "candidate-set call must not also have a single target",
                );
            }
            let mut candidate_targets = BTreeSet::new();
            for (index, candidate) in call.candidates.iter().enumerate() {
                if !candidate_targets.insert(candidate.target) {
                    self.push(
                        CfgValidationCode::InvalidCallTarget,
                        format!("{path}/candidates/{index}"),
                        format!("duplicate candidate target 0x{:x}", candidate.target),
                    );
                }
                if let Some(id) = &candidate.target_function
                    && self.program.is_some()
                    && !self.function_ids.contains(id)
                {
                    self.push(
                        CfgValidationCode::DanglingFunctionReference,
                        format!("{path}/candidates/{index}/target_function"),
                        format!("candidate references missing function {id}"),
                    );
                }
            }
        }
        if call.target_function.is_some() && call.target.is_none() {
            self.push(
                CfgValidationCode::InvalidCallTarget,
                format!("{path}/target_function"),
                "target_function requires a single resolved target",
            );
        }
        if !call.unresolved
            && !call.null_target
            && call.target.is_none()
            && call.candidates.is_empty()
        {
            self.push(
                CfgValidationCode::InvalidCallTarget,
                path,
                "resolved call has no target or candidates",
            );
        }
        if let Some(id) = &call.target_function
            && self.program.is_some()
            && !self.function_ids.contains(id)
        {
            self.push(
                CfgValidationCode::DanglingFunctionReference,
                format!("{path}/target_function"),
                format!("call references missing function {id}"),
            );
        }
    }
}

fn edge_kind_code(kind: CfgEdgeKind) -> u8 {
    match kind {
        CfgEdgeKind::Fallthrough => 0,
        CfgEdgeKind::CallReturn => 1,
        CfgEdgeKind::Branch => 2,
        CfgEdgeKind::Jump => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgEdgeKind, CfgFunction, CfgInstruction,
        CfgTerminator, CfgValidationCode, FunctionCfg, ProgramCfg, architecture_root_addresses,
        function_view, render_dot_selected, render_mermaid_selected,
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
            null_target: false,
            noreturn: false,
            candidates: Vec::new(),
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

    fn no_code_function(kind: FunctionKind, name: &str, address: u64) -> CfgFunction {
        CfgFunction {
            id: FunctionId::new(format!("fn:0x{address:x}")),
            primary_name: name.to_owned(),
            demangled_name: Some(name.to_owned()),
            symbols: vec![name.to_owned()],
            language: Language::Rust,
            kind,
            address,
            size: 0,
            section: String::new(),
            source: None,
            inline_frames: Vec::new(),
            noreturn: None,
            cfg: FunctionCfg::default(),
        }
    }

    #[test]
    fn renders_external_and_logical_functions_without_code() {
        let external = no_code_function(FunctionKind::External, "malloc", 0x2000);
        let logical = no_code_function(FunctionKind::TaskEntry, "app::sensor_task", 0x3000);
        let program = ProgramCfg::new(vec![external, logical]);

        let external_view =
            serde_json::to_value(function_view(&program, &program.functions[0], false))
                .expect("external view");
        assert_eq!(external_view["no_code"]["reason"], "external");
        assert_eq!(external_view["blocks"].as_array().map(Vec::len), Some(0));
        let logical_view =
            serde_json::to_value(function_view(&program, &program.functions[1], false))
                .expect("logical view");
        assert_eq!(logical_view["no_code"]["reason"], "logical");
        assert_eq!(logical_view["blocks"].as_array().map(Vec::len), Some(0));

        assert_eq!(
            program
                .select(Some("app::sensor_task"))
                .expect("logical selector")
                .len(),
            1
        );
        let selected: Vec<&CfgFunction> = program.functions.iter().collect();
        let dot = render_dot_selected(&program, &selected, false);
        assert!(dot.contains("external function"));
        assert!(dot.contains("logical task entry"));
        let mermaid = render_mermaid_selected(&program, &selected, false);
        assert!(mermaid.contains("external function"));
        assert!(mermaid.contains("logical task entry"));
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
            inline_frames: Vec::new(),
            noreturn: None,
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
            imported_slots: std::collections::BTreeMap::new(),
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".trap".to_owned(),
                    address: 0x1000,
                    size: 4,
                    data: vec![0x6f, 0x00, 0x80, 0x00],
                    executable: true,
                    writable: false,
                    alloc: true,
                },
                Section {
                    name: ".text".to_owned(),
                    address: 0x1008,
                    size: 4,
                    data: vec![0x67, 0x80, 0x00, 0x00],
                    executable: true,
                    writable: false,
                    alloc: true,
                },
            ],
            symbols: Vec::new(),
            has_symbols: false,
            has_debug_info: false,
            has_relocations: false,
            arm_cpu: None,
            vector_table: Vec::new(),
            dwarf: None,
            dwarf_error: None,
            data_symbols: std::collections::BTreeMap::default(),
        };
        assert_eq!(architecture_root_addresses(&image), vec![0x1000, 0x1008]);
    }

    #[test]
    fn extracts_aarch64_exception_vector_entries() {
        // b #0x1004 at 0x1000; ret at 0x1004.
        let image = Image {
            path: "vectors.elf".into(),
            arch: ArchKind::Aarch64,
            byte_order: ByteOrder::Little,
            elf_kind: ElfKind::Exec,
            entry: 0x1000,
            relocated_pointers: std::collections::BTreeMap::new(),
            imported_slots: std::collections::BTreeMap::new(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".vectors".to_owned(),
                address: 0x1000,
                size: 8,
                data: vec![0x01, 0x00, 0x00, 0x14, 0xc0, 0x03, 0x5f, 0xd6],
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
            data_symbols: std::collections::BTreeMap::default(),
        };
        assert_eq!(architecture_root_addresses(&image), vec![0x1000, 0x1004]);
    }

    fn typed_instruction(
        address: u64,
        mnemonic: &str,
        is_call: bool,
        is_jump: bool,
        is_return: bool,
    ) -> CfgInstruction {
        let mut instruction = instruction(address, mnemonic, is_call);
        instruction.is_jump = is_jump;
        instruction.is_return = is_return;
        instruction
    }

    fn valid_cfg_function(address: u64, size: u64, cfg: FunctionCfg) -> CfgFunction {
        CfgFunction {
            id: FunctionId::new(format!("fn:0x{address:x}")),
            primary_name: format!("sub_0x{address:x}"),
            demangled_name: None,
            symbols: Vec::new(),
            language: Language::C,
            kind: FunctionKind::Normal,
            address,
            size,
            section: ".text".to_owned(),
            source: None,
            inline_frames: Vec::new(),
            noreturn: None,
            cfg,
        }
    }

    fn valid_program() -> ProgramCfg {
        let mut call_instruction = typed_instruction(0x1000, "call", true, false, false);
        call_instruction.direct_target = Some(0x2000);
        let caller = FunctionCfg::build(
            vec![
                block(
                    0x1000,
                    "call",
                    true,
                    vec![call(0x1000)],
                    CfgTerminator::Call,
                ),
                CfgBlockDraft {
                    address: 0x1004,
                    size: 4,
                    instructions: vec![typed_instruction(0x1004, "ret", false, false, true)],
                    calls: Vec::new(),
                    cycles: None,
                    terminator: CfgTerminator::Return,
                },
            ],
            vec![CfgEdgeDraft {
                from: 0x1000,
                to: 0x1004,
                kind: CfgEdgeKind::CallReturn,
                site: 0x1000,
                conditional: false,
            }],
            Some(0x1000),
        );
        let mut caller = valid_cfg_function(0x1000, 8, caller);
        let entry = caller.cfg.node_at(0x1000).expect("caller entry");
        caller.cfg.graph[entry].instructions[0].direct_target = Some(0x2000);

        let target_instruction = typed_instruction(0x2000, "ret", false, false, true);
        let target = FunctionCfg::build(
            vec![CfgBlockDraft {
                address: 0x2000,
                size: 4,
                instructions: vec![target_instruction],
                calls: Vec::new(),
                cycles: None,
                terminator: CfgTerminator::Return,
            }],
            Vec::new(),
            Some(0x2000),
        );
        let target = valid_cfg_function(0x2000, 4, target);
        ProgramCfg::new(vec![caller, target])
    }

    #[test]
    fn accepts_valid_program_cfg() {
        let program = valid_program();
        assert!(program.validate().is_empty(), "{:#?}", program.validate());
    }

    #[test]
    fn reports_broken_cfg_invariants() {
        let mut noreturn_edge = valid_program();
        let node = noreturn_edge.functions[0]
            .cfg
            .node_at(0x1000)
            .expect("caller block");
        let block = &mut noreturn_edge.functions[0].cfg.graph[node];
        block.calls[0].noreturn = true;
        block.terminator = CfgTerminator::NoreturnCall;
        assert!(
            noreturn_edge
                .validate()
                .iter()
                .any(|issue| { issue.code == CfgValidationCode::InvalidEdge })
        );

        let mut bad_flags = valid_program();
        let node = bad_flags.functions[0]
            .cfg
            .node_at(0x1000)
            .expect("caller block");
        bad_flags.functions[0].cfg.graph[node].calls[0].conditional = true;
        bad_flags.functions[0].cfg.graph[node].calls[0].noreturn = true;
        assert!(
            bad_flags
                .validate()
                .iter()
                .any(|issue| { issue.code == CfgValidationCode::InvalidCallFlags })
        );

        let mut dangling = valid_program();
        dangling.functions.pop();
        assert!(
            dangling
                .validate()
                .iter()
                .any(|issue| { issue.code == CfgValidationCode::DanglingFunctionReference })
        );

        let mut duplicate_root = valid_program();
        duplicate_root.pointer_roots = vec![0x1000, 0x1000];
        assert!(
            duplicate_root
                .validate()
                .iter()
                .any(|issue| { issue.code == CfgValidationCode::InvalidPointerRoot })
        );

        let mut bad_entry = valid_program();
        let return_node = bad_entry.functions[0]
            .cfg
            .node_at(0x1004)
            .expect("return block");
        bad_entry.functions[0].cfg.entry = Some(return_node);
        assert!(
            bad_entry
                .validate()
                .iter()
                .any(|issue| { issue.code == CfgValidationCode::InvalidEntry })
        );
    }
}
