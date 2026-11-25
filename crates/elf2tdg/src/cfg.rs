//! Function-level control-flow graphs.
//!
//! The analyzer keeps a `FunctionCfg` per function and a self-contained
//! [`ProgramCfg`] at program level. Basic blocks are nodes in a
//! `petgraph::StableDiGraph`; control-flow edges and call sites remain explicit
//! so the CLI can export a complete, lossless CFG. `ProgramCfg` also owns
//! execution roots, the interprocedural call graph, concurrency annotations,
//! locks, diagnostics and timing metadata. The program CFG is the only exported graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use elf2tdg_schema::{
    Addr, AwaitKind, AwaitTarget, BlockId, Confidence, Context, ContextId, ContextKind, CostRange,
    Diagnostic, Edge, Function, FunctionId, FunctionKind, ImageInfo, JoinKind, JoinTarget,
    Language, LockEvent, LockKind, LockOperation, RuntimeId, Scope, ScopeKind, SourceLoc,
    SpawnKind, SpawnTarget, TimingInfo,
};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde::Serialize;

use crate::arch::Decoder;
use crate::loader::{ArchKind, Image};
use crate::rules::normalize_crate_hashes;

/// Version of the JSON CFG document emitted by this module.
pub const CFG_SCHEMA_VERSION: &str = "2.35";

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
    /// Conditional branch or ARM/Thumb instruction with an explicit condition.
    pub is_conditional: bool,
    /// Direct target address.
    pub direct_target: Option<u64>,
    /// Indirect target expression, when modeled.
    pub indirect: Option<CfgIndirectTarget>,
    /// Data-memory accesses decoded from this instruction.
    pub memory_accesses: Vec<CfgMemoryAccess>,
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
    /// Conditional call, or a conditional external branch modeled as a tail
    /// call.
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
    /// Instruction-cache analysis for this block, when a cache profile is
    /// active.
    pub cache: Option<CfgBlockCache>,
    /// Data-cache analysis for this block, when a data-cache profile is
    /// active.
    pub data_cache: Option<CfgBlockDataCache>,
    /// Branch-prediction analysis for this block, when a prediction profile is
    /// active and this is a modeled conditional branch.
    pub branch_prediction: Option<CfgBlockBranchPrediction>,
    /// Branch-target-buffer analysis for this block, when a BTB profile is
    /// active and the block ends in a modeled transfer.
    pub btb: Option<CfgBlockBtb>,
    /// Data-memory latency analysis for this block, when memory regions declare
    /// data-access timing.
    pub data_memory: Option<CfgBlockDataMemory>,
    /// Multicore interference attribution for this block.
    pub multicore: Option<CfgBlockMulticore>,
    /// Control-flow terminator classification.
    pub terminator: CfgTerminator,
}

/// Multicore interference attributed to one basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockMulticore {
    /// Data read accesses charged to the interference budget.
    pub data_read_accesses: u32,
    /// Data write accesses charged to the interference budget.
    pub data_write_accesses: u32,
    /// Instruction fetches charged to the interference budget.
    pub instruction_fetches: u32,
    /// Total interference cycles added to the block cost.
    pub interference_cycles: u32,
}

/// Program-level multicore interference metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgMulticoreInfo {
    /// Interference model name.
    pub model: String,
    /// Total cores in the system.
    pub cores: u32,
    /// Core analyzed by this run.
    pub core_id: u32,
    /// Confidence in the interference budget, when declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Interference budget per data read.
    pub data_read_interference_cycles: u32,
    /// Interference budget per data write.
    pub data_write_interference_cycles: u32,
    /// Interference budget per instruction fetch.
    pub instruction_fetch_interference_cycles: u32,
    /// Functions with at least one analyzed block.
    pub functions_analyzed: u32,
    /// Blocks with at least one charged event.
    pub blocks_analyzed: u32,
    /// Total data read accesses charged.
    pub data_read_accesses: u32,
    /// Total data write accesses charged.
    pub data_write_accesses: u32,
    /// Total instruction fetches charged.
    pub instruction_fetches: u32,
    /// Total interference cycles added across the program.
    pub interference_cycles: u32,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// One execution root in the layered system model.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemTask {
    /// Stable local task ID (`t0`, `t1`, ...).
    pub id: String,
    /// Root function.
    pub function: FunctionId,
    /// Root category.
    pub kind: CfgRootKind,
    /// Human-readable task/handler name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Local WCET result for this root.
    pub status: CfgWcetStatus,
    /// Local worst-case cycles, when finite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<f64>,
    /// Local worst-case time in nanoseconds, when finite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<f64>,
    /// Fixed scheduling priority, when configured. Larger values run first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Maximum configured hold time per lock and critical section, in ns.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub locks: BTreeMap<String, u64>,
    /// Maximum activations modeled in the current bound window.
    pub activation_bound: u32,
    /// Period used to derive the release bound, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_ns: Option<u64>,
    /// Release offset from the start of the bound window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_offset_ns: Option<u64>,
    /// Release jitter applied conservatively to the first release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_jitter_ns: Option<u64>,
    /// Relative deadline from each release, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ns: Option<u64>,
}

/// One place in the coarse layered Petri-net representation.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemPlace {
    /// Stable place ID.
    pub id: String,
    /// Place category: `core`, `ready` or `done`.
    pub kind: String,
    /// Initial tokens.
    pub tokens: u32,
    /// Maximum token capacity.
    pub capacity: u32,
}

/// One transition in the coarse layered Petri-net representation.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemTransition {
    /// Stable transition ID.
    pub id: String,
    /// Transition category; currently `execute`.
    pub kind: String,
    /// Task ID consumed by this transition.
    pub task: String,
    /// Local WCET cost charged when the transition fires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_cycles: Option<f64>,
    /// Maximum modeled firings.
    pub activations: u32,
    /// Input place IDs.
    pub inputs: Vec<String>,
    /// Output place IDs.
    pub outputs: Vec<String>,
}

/// One transition firing count from the state-equation ILP.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemFiring {
    /// Transition ID.
    pub transition: String,
    /// Number of modeled firings.
    pub fires: u32,
}

/// Result of the Petri-net state-equation ILP relaxation.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemPetriSolution {
    /// Solver backend.
    pub solver: String,
    /// Relaxation name (`state-equation`).
    pub relaxation: String,
    /// Solver status (`optimal`, `infeasible`, `unbounded`, ...).
    pub status: String,
    /// Solved objective, when a finite optimum was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objective: Option<f64>,
    /// Positive transition firing counts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub firing: Vec<CfgSystemFiring>,
}

/// One concurrency dependency between program functions.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemDependency {
    /// Dependency kind: `spawn`, `join`, `await`, `callback`, `scope-enter`
    /// or `scope-exit`.
    pub kind: String,
    /// Function containing the operation.
    pub from: FunctionId,
    /// Resolved target function, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<FunctionId>,
    /// Bounded alternatives when the target is not unique.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<FunctionId>,
    /// Call site.
    pub site: Addr,
    /// Runtime that defines the operation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// API symbol/name, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// One explicit fork/join constraint between system tasks.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemLink {
    /// Link kind (`fork` or `join`).
    pub kind: String,
    /// Source task ID.
    pub from: String,
    /// Target task ID.
    pub to: String,
    /// Source root function.
    pub from_function: FunctionId,
    /// Target root function.
    pub to_function: FunctionId,
    /// Maximum relation count per source activation.
    pub count: u32,
}

/// Coarse bound produced by the layered model.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemBound {
    /// Bound scope. The current scope is one activation per execution root on
    /// the analyzed core.
    pub scope: String,
    /// Aggregate status over all modeled tasks.
    pub status: CfgWcetStatus,
    /// Sum of local worst-case cycles, when every task has a finite cost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<f64>,
    /// Sum of local worst-case nanoseconds, when every task has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<f64>,
    /// Number of modeled tasks.
    pub tasks: u32,
    /// Largest activation bound across modeled tasks.
    pub max_activations: u32,
    /// Assumptions required by this bound.
    pub assumptions: Vec<String>,
}

/// Discrete-time-expanded Petri-net feasibility result.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemTimedInfo {
    /// Timed model name.
    pub model: String,
    /// Time-slot width in nanoseconds.
    pub slot_ns: u64,
    /// Number of slots in the bound window.
    pub horizon_slots: u32,
    /// `feasible`, `infeasible`, `unsupported` or `no-local-time`.
    pub status: String,
    /// Number of task activation instances.
    pub activations: u32,
    /// Total execution slots required by all activations.
    pub execution_slots: u32,
    /// Number of binary slot variables.
    pub variables: u32,
    /// Model caveats.
    pub caveats: Vec<String>,
}

/// Per-task response-time result.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemResponseTask {
    /// Task ID.
    pub task: String,
    /// Root function.
    pub function: FunctionId,
    /// `bounded`, `partial`, `unbounded`, `no-local-time` or `unknown`.
    pub status: String,
    /// Response-time upper bound in nanoseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<f64>,
    /// Blocking time included in the response bound, when modeled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_ns: Option<f64>,
    /// Relative deadline, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ns: Option<u64>,
    /// Whether the finite response bound exceeds the deadline.
    pub deadline_missed: bool,
    /// Why the response bound is unavailable or partial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Per-task response-time analysis result.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemResponseInfo {
    /// Analysis model name.
    pub model: String,
    /// Per-task results.
    pub tasks: Vec<CfgSystemResponseTask>,
    /// Model caveats.
    pub caveats: Vec<String>,
}

/// Per-task blocking-time result.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemBlockingTask {
    /// Task ID.
    pub task: String,
    /// `bounded` or `unknown`.
    pub status: String,
    /// Blocking-time upper bound in nanoseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<f64>,
    /// Lower-priority task that determines the bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    /// Lock held by the blocker that determines the bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock: Option<String>,
    /// Why the blocking bound is unavailable or incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A potential direct priority inversion on a shared lock.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemInversion {
    /// Lock name.
    pub lock: String,
    /// Higher-priority task that can be blocked.
    pub blocked: String,
    /// Lower-priority task that can hold the lock.
    pub blocker: String,
    /// Priority of the blocked task.
    pub blocked_priority: u32,
    /// Priority of the blocking task.
    pub blocker_priority: u32,
    /// Maximum blocker hold time in nanoseconds.
    pub hold_ns: u64,
}

/// Blocking and priority-inversion analysis result.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemBlockingInfo {
    /// Blocking protocol name.
    pub model: String,
    /// Per-task blocking bounds.
    pub tasks: Vec<CfgSystemBlockingTask>,
    /// Direct priority-inversion relations between modeled tasks.
    pub inversions: Vec<CfgSystemInversion>,
    /// Model caveats.
    pub caveats: Vec<String>,
}

/// Layered system model and coarse bound.
#[derive(Clone, Debug, Serialize)]
pub struct CfgSystemModelInfo {
    /// Model name.
    pub model: String,
    /// Total cores in the configured system.
    pub cores: u32,
    /// Analyzed core.
    pub core_id: u32,
    /// Bound window for periodic releases and resource budgets, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub horizon_ns: Option<u64>,
    /// Execution-root tasks included in the concurrent bound.
    pub tasks: Vec<CfgSystemTask>,
    /// Startup/main boot roots excluded from the concurrent bound.
    pub boot_roots: u32,
    /// Petri-net places.
    pub places: Vec<CfgSystemPlace>,
    /// Petri-net transitions.
    pub transitions: Vec<CfgSystemTransition>,
    /// Concurrency dependencies between functions.
    pub dependencies: Vec<CfgSystemDependency>,
    /// Explicit fork/join constraints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<CfgSystemLink>,
    /// State-equation ILP solution, when the model was solved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub petri: Option<CfgSystemPetriSolution>,
    /// Discrete-time-expanded feasibility result, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed: Option<CfgSystemTimedInfo>,
    /// Blocking and priority-inversion analysis, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking: Option<CfgSystemBlockingInfo>,
    /// Per-task response-time upper bounds.
    pub response: CfgSystemResponseInfo,
    /// Coarse bound.
    pub bound: CfgSystemBound,
    /// Model caveats.
    pub caveats: Vec<String>,
}

/// Instruction-cache cost analysis for one basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockCache {
    /// Number of instruction-fetch line accesses in the block.
    pub fetches: u32,
    /// Minimum modeled cache misses across reachable entry states.
    pub misses_min: u32,
    /// Maximum modeled cache misses across reachable entry states.
    pub misses_max: u32,
    /// Number of distinct cache states reaching the block.
    pub entry_states: u32,
    /// Analysis fell back to an all-miss bound for this block.
    #[serde(skip_serializing_if = "is_false")]
    pub fallback: bool,
    /// Per-line logical blocks and their hit ranges.
    pub lines: Vec<CfgBlockCacheLine>,
}

/// Kind of data-memory access recorded on an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgMemoryAccessKind {
    /// Load/read access.
    Read,
    /// Store/write access.
    Write,
    /// Read-modify-write or atomic access.
    ReadWrite,
}

/// How a data-memory address was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgMemoryResolution {
    /// The instruction encodes the absolute address directly.
    Direct,
    /// The base register was recovered by the bounded value analysis.
    Register,
    /// The address depends on an unknown register, index or stack value.
    Unresolved,
}

/// One data-memory access attached to an instruction.
#[derive(Clone, Debug, Serialize)]
pub struct CfgMemoryAccess {
    /// Read, write or read-modify-write.
    pub kind: CfgMemoryAccessKind,
    /// Statically resolved absolute address, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Addr>,
    /// Access width in bytes.
    pub width: u32,
    /// Address-resolution method.
    pub resolution: CfgMemoryResolution,
    /// Base register name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Index register name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    /// Signed displacement from the base or absolute address.
    pub disp: i64,
}

/// Classification of one cache line within a basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgCacheLineClass {
    /// Every modeled entry state hits this line on every access.
    AlwaysHit,
    /// No modeled entry state hits this line.
    AlwaysMiss,
    /// The line hits in some states and misses in others.
    MayHit,
}

/// Per-line instruction-cache hit range for a basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockCacheLine {
    /// Cache-line start address.
    pub line: Addr,
    /// First instruction address in this line-split fragment.
    pub first_address: Addr,
    /// Bytes of instructions in this fragment.
    pub size: u32,
    /// Instructions touching this fragment (an instruction spanning two lines
    /// is counted in both fragments).
    pub instructions: u32,
    /// Number of fetch accesses to this line.
    pub accesses: u32,
    /// Classification across modeled entry states.
    pub classification: CfgCacheLineClass,
    /// Minimum modeled hits across entry states.
    pub hits_min: u32,
    /// Maximum modeled hits across entry states.
    pub hits_max: u32,
    /// Minimum modeled misses across entry states.
    pub misses_min: u32,
    /// Maximum modeled misses across entry states.
    pub misses_max: u32,
}

/// One natural-loop region with persistent cache lines.
#[derive(Clone, Debug, Serialize)]
pub struct CfgCachePersistenceRegion {
    /// Function containing the loop.
    pub function: FunctionId,
    /// Loop header block.
    pub header: BlockId,
    /// Number of blocks in the loop.
    pub blocks: u32,
    /// Persistent line start addresses.
    pub lines: Vec<Addr>,
}

/// Line-split persistence and first-miss analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgCachePersistenceInfo {
    /// Persistence model name.
    pub model: String,
    /// Natural loops inspected.
    pub loops_analyzed: u32,
    /// Natural loops with at least one persistent line.
    pub loops_persistent: u32,
    /// Distinct line addresses proved persistent in at least one loop.
    pub persistent_lines: u32,
    /// Per-loop persistent-line regions.
    pub regions: Vec<CfgCachePersistenceRegion>,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

impl CfgCachePersistenceInfo {
    /// Creates an empty persistence record for one cache model.
    pub(crate) fn new(model: &str, caveats: Vec<String>) -> Self {
        Self {
            model: model.to_owned(),
            loops_analyzed: 0,
            loops_persistent: 0,
            persistent_lines: 0,
            regions: Vec::new(),
            caveats,
        }
    }
}

/// Program-level instruction-cache analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgCacheInfo {
    /// Model name.
    pub model: String,
    /// Total cache size in bytes.
    pub size: u64,
    /// Cache line size in bytes.
    pub line_bytes: u32,
    /// Associativity.
    pub ways: u32,
    /// Number of cache sets.
    pub sets: u64,
    /// Extra core cycles charged for each modeled miss.
    pub miss_penalty: u32,
    /// Assumed cache state at each function entry.
    pub entry_state: String,
    /// Whether call-return edges invalidate the modeled cache state.
    pub invalidate_on_call: bool,
    /// Per-block state-explosion limit.
    pub max_states: usize,
    /// Functions with complete cache analysis.
    pub functions_analyzed: u32,
    /// Functions that fell back to an all-miss bound.
    pub functions_fallback: u32,
    /// Blocks with complete cache state results.
    pub blocks_analyzed: u32,
    /// Blocks that fell back to an all-miss bound.
    pub blocks_fallback: u32,
    /// Line-split persistence and first-miss analysis.
    pub persistence: CfgCachePersistenceInfo,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Per-line data-cache hit range for a basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockDataCacheLine {
    /// Cache-line start address.
    pub line: Addr,
    /// Number of modeled line accesses.
    pub accesses: u32,
    /// Number of read accesses.
    pub reads: u32,
    /// Number of write accesses.
    pub writes: u32,
    /// Classification across modeled entry states.
    pub classification: CfgCacheLineClass,
    /// Minimum modeled hits across entry states.
    pub hits_min: u32,
    /// Maximum modeled hits across entry states.
    pub hits_max: u32,
    /// Minimum modeled misses across entry states.
    pub misses_min: u32,
    /// Maximum modeled misses across entry states.
    pub misses_max: u32,
}

/// Data-cache analysis for one basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockDataCache {
    /// Decoded data-memory accesses in this block.
    pub memory_accesses: u32,
    /// Accesses with a statically resolved address.
    pub resolved_memory_accesses: u32,
    /// Accesses whose address could not be resolved.
    pub unresolved_memory_accesses: u32,
    /// Number of modeled cache-line accesses from resolved addresses.
    pub line_accesses: u32,
    /// Minimum modeled misses across entry states.
    pub misses_min: u32,
    /// Maximum modeled misses across entry states.
    pub misses_max: u32,
    /// Number of distinct cache states reaching the block.
    pub entry_states: u32,
    /// Whether the function fell back to an all-miss bound.
    pub fallback: bool,
    /// Per-line hit and miss ranges.
    pub lines: Vec<CfgBlockDataCacheLine>,
}

/// Program-level data-cache analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgDataCacheInfo {
    /// Model name.
    pub model: String,
    /// Total cache size in bytes.
    pub size: u64,
    /// Cache line size in bytes.
    pub line_bytes: u32,
    /// Associativity.
    pub ways: u32,
    /// Number of cache sets.
    pub sets: u64,
    /// Extra core cycles charged for each modeled miss.
    pub miss_penalty: u32,
    /// Whether store misses allocate a cache line.
    pub write_allocate: bool,
    /// Assumed cache state at each function entry.
    pub entry_state: String,
    /// Whether call-return edges invalidate the modeled cache state.
    pub invalidate_on_call: bool,
    /// Per-block state-explosion limit.
    pub max_states: usize,
    /// Decoded data-memory accesses in analyzed blocks.
    pub memory_accesses: u32,
    /// Accesses with a statically resolved address.
    pub resolved_memory_accesses: u32,
    /// Accesses whose address could not be resolved.
    pub unresolved_memory_accesses: u32,
    /// Number of modeled cache-line accesses.
    pub line_accesses: u32,
    /// Functions with complete cache analysis.
    pub functions_analyzed: u32,
    /// Functions that fell back to an all-miss bound.
    pub functions_fallback: u32,
    /// Blocks with complete cache state results.
    pub blocks_analyzed: u32,
    /// Blocks that fell back to an all-miss bound.
    pub blocks_fallback: u32,
    /// Cache-line persistence analysis.
    pub persistence: CfgCachePersistenceInfo,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Actual or predicted direction of a conditional branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgBranchDirection {
    /// Branch taken.
    Taken,
    /// Branch not taken (fallthrough).
    NotTaken,
}

/// Prediction assigned to one conditional-branch outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgBranchPredictionOutcome {
    /// Predicted taken.
    Taken,
    /// Predicted not taken.
    NotTaken,
    /// Different entry states predict different directions, or the function
    /// fell back to an all-mispredict bound.
    Mixed,
}

/// Prediction result for one outgoing edge of a conditional branch.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBranchOutcome {
    /// Successor block reached by this outcome.
    pub target: BlockId,
    /// Actual direction represented by this edge.
    pub actual: CfgBranchDirection,
    /// Predicted direction across modeled entry states.
    pub predicted: CfgBranchPredictionOutcome,
    /// Minimum modeled mispredictions for this outcome.
    pub mispredicts_min: u32,
    /// Maximum modeled mispredictions for this outcome.
    pub mispredicts_max: u32,
}

/// Branch-prediction analysis for one conditional-branch block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockBranchPrediction {
    /// Branch instruction address.
    pub site: Addr,
    /// Minimum modeled mispredictions across outgoing outcomes.
    pub mispredicts_min: u32,
    /// Maximum modeled mispredictions across outgoing outcomes.
    pub mispredicts_max: u32,
    /// Number of distinct predictor states reaching the block.
    pub entry_states: u32,
    /// Whether the function fell back to an all-mispredict bound.
    pub fallback: bool,
    /// Per-successor prediction outcomes.
    pub outcomes: Vec<CfgBranchOutcome>,
}

/// Branch-target-buffer analysis for one basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockBtb {
    /// Minimum modeled BTB misses on this block's outgoing transfers.
    pub misses_min: u32,
    /// Maximum modeled BTB misses on this block's outgoing transfers.
    pub misses_max: u32,
    /// Number of distinct BTB states reaching the block.
    pub entry_states: u32,
    /// Whether the function fell back to an all-miss BTB bound.
    pub fallback: bool,
}

/// Program-level branch-target-buffer analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBtbInfo {
    /// BTB model name.
    pub model: String,
    /// Total modeled BTB entries.
    pub entries: u64,
    /// Associativity.
    pub ways: u32,
    /// Number of sets (`entries / ways`).
    pub sets: u64,
    /// Cycles charged for one BTB miss.
    pub miss_penalty: u32,
    /// Per-block BTB state limit.
    pub max_states: usize,
    /// Functions with complete BTB analysis.
    pub functions_analyzed: u32,
    /// Functions that fell back to an all-miss bound.
    pub functions_fallback: u32,
    /// Transfer blocks with complete analysis.
    pub transfers_analyzed: u32,
    /// Transfer blocks that fell back to an all-miss bound.
    pub transfers_fallback: u32,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Program-level branch-prediction analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBranchPredictionInfo {
    /// Predictor model name.
    pub model: String,
    /// Extra cycles charged for each modeled misprediction.
    pub mispredict_penalty: u32,
    /// Initial two-bit counter state for the `bimodal` model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_state: Option<String>,
    /// First-execution history policy (`initial` or `unknown`), when it is
    /// not the default `initial` policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_execution: Option<String>,
    /// Global branch-history register width (`global-history` or `gshare`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_bits: Option<u8>,
    /// Initial global branch-history register value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_history: Option<u64>,
    /// Level-1 history source for `two-level` (`global` or `local`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level1_history: Option<String>,
    /// Level-2 pattern-table scope for `two-level` (`global` or `per-address`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level2_table: Option<String>,
    /// Initial choice-predictor counter for `tournament`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice_initial_state: Option<String>,
    /// Per-block predictor-state limit.
    pub max_states: usize,
    /// Functions with complete prediction analysis.
    pub functions_analyzed: u32,
    /// Functions that fell back to an all-mispredict bound.
    pub functions_fallback: u32,
    /// Conditional branch blocks with complete analysis.
    pub branches_analyzed: u32,
    /// Conditional branch blocks that fell back to an all-mispredict bound.
    pub branches_fallback: u32,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Data-memory wait cycles attributed to one memory region in a basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgDataMemoryRegion {
    /// Region name from the board profile.
    pub region: String,
    /// Region kind (`flash`, `ram`, `peripheral` or `other`).
    pub kind: String,
    /// Number of accesses touching this region.
    pub accesses: u32,
    /// Number of accessed bytes in this region.
    pub bytes: u64,
    /// Read wait cycles attributed to this region.
    pub read_wait_cycles: u32,
    /// Write wait cycles attributed to this region.
    pub write_wait_cycles: u32,
}

/// Data-memory latency analysis for one basic block.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBlockDataMemory {
    /// Decoded data-memory accesses in the block.
    pub accesses: u32,
    /// Accesses with a statically resolved address.
    pub resolved_accesses: u32,
    /// Accesses whose address could not be resolved.
    pub unresolved_accesses: u32,
    /// Resolved accesses touching at least one configured memory region.
    pub mapped_accesses: u32,
    /// Resolved accesses touching at least one address outside all regions.
    pub unmapped_accesses: u32,
    /// Read wait cycles added to the block cost.
    pub read_wait_cycles: u32,
    /// Write wait cycles added to the block cost.
    pub write_wait_cycles: u32,
    /// Total wait cycles added to the block cost.
    pub wait_cycles: u32,
    /// Per-region breakdown.
    pub regions: Vec<CfgDataMemoryRegion>,
}

/// Program-level data-memory latency analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgDataMemoryInfo {
    /// Model name.
    pub model: String,
    /// Functions with at least one analyzed block.
    pub functions_analyzed: u32,
    /// Blocks with at least one data-memory access.
    pub blocks_analyzed: u32,
    /// Decoded data-memory accesses in analyzed blocks.
    pub accesses: u32,
    /// Accesses with a statically resolved address.
    pub resolved_accesses: u32,
    /// Accesses whose address could not be resolved.
    pub unresolved_accesses: u32,
    /// Resolved accesses touching configured regions.
    pub mapped_accesses: u32,
    /// Resolved accesses touching addresses outside all regions.
    pub unmapped_accesses: u32,
    /// Read wait cycles added to block costs.
    pub read_wait_cycles: u32,
    /// Write wait cycles added to block costs.
    pub write_wait_cycles: u32,
    /// Total wait cycles added to block costs.
    pub wait_cycles: u32,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Program-level pipeline metadata and fallback edge stalls.
#[derive(Clone, Debug, Serialize)]
pub struct CfgPipelineInfo {
    /// Model name.
    pub model: String,
    /// CFG edges with a positive inter-block pipeline stall.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<CfgPipelineEdgeInfo>,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Pipeline stall charged when one CFG edge is taken.
#[derive(Clone, Debug, Serialize)]
pub struct CfgPipelineEdgeInfo {
    /// Function containing the edge.
    pub function: FunctionId,
    /// Source block address.
    pub source: Addr,
    /// Target block address.
    pub target: Addr,
    /// Terminating instruction that produced the edge.
    pub site: Addr,
    /// Extra modeled cycles over the target block's ready-entry schedule.
    pub stall_cycles: f64,
}

/// Worst-case execution-time status for a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgWcetStatus {
    /// A finite upper bound was computed.
    Bounded,
    /// A finite estimate was computed, but inputs are incomplete.
    Partial,
    /// The cost is unbounded or unsupported.
    Unbounded,
    /// No estimate could be computed.
    Unknown,
}

/// WCET result for one function.
#[derive(Clone, Debug, Serialize)]
pub struct CfgFunctionWcet {
    /// Result status.
    pub status: CfgWcetStatus,
    /// Worst-case cycles, when finite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<f64>,
    /// Worst-case time in nanoseconds, when a core frequency is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<f64>,
    /// Worst-case local block path.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<BlockId>,
    /// Why the result is unbounded, partial or unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unresolved call sites seen on reachable local blocks.
    pub unresolved_calls: u32,
    /// Calls to functions without a local WCET summary.
    pub external_calls: u32,
    /// IPET solver result, when the IPET path analysis was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipet: Option<CfgIpetSolution>,
}

/// Full cache conflict-graph flow summary for one IPET function version.
#[derive(Clone, Debug, Serialize)]
pub struct CfgCacheCcgInfo {
    /// CCG model name.
    pub model: String,
    /// Cache sets with CCG flow.
    pub sets: u32,
    /// CCG access nodes.
    pub nodes: u32,
    /// CCG transition edges.
    pub edges: u32,
    /// Number of generated CCG constraints.
    pub constraints: u32,
    /// Model caveats.
    pub caveats: Vec<String>,
}

/// Cache conflict-graph constraint summary for one IPET function version.
#[derive(Clone, Debug, Serialize)]
pub struct CfgCacheConflictGraphInfo {
    /// Conflict-graph model name.
    pub model: String,
    /// Cache sets with at least one conflict constraint.
    pub sets: u32,
    /// Cache lines with a conflict bound.
    pub lines: u32,
    /// Number of generated conflict constraints.
    pub constraints: u32,
    /// Model caveats.
    pub caveats: Vec<String>,
}

/// Solver result for one IPET function model.
#[derive(Clone, Debug, Serialize)]
pub struct CfgIpetSolution {
    /// Solver backend name.
    pub solver: String,
    /// Solver termination status (`optimal`, `time-limit` or `gap-limit`).
    pub status: String,
    /// Maximal objective value in cycles.
    pub objective: f64,
    /// Cache model used by the IPET constraints, when cache analysis is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_model: Option<String>,
    /// Cache conflict-graph constraints, when the aggregate model is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_conflicts: Option<CfgCacheConflictGraphInfo>,
    /// Full cache conflict-graph flow, when the CCG model is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ccg: Option<CfgCacheCcgInfo>,
    /// Pipeline model used by the IPET constraints (`state-product` or
    /// `edge-context`), when a pipeline profile is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline_model: Option<String>,
    /// Branch-prediction model used by the IPET constraints, when active.
    /// `state-product` is local to one function; `interprocedural-state-product`
    /// carries predictor state and branch costs through direct calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_model: Option<String>,
    /// Branch-target-buffer model used by the IPET constraints, when active.
    /// `state-product` propagates concrete BTB state; `block-bounds` falls
    /// back to per-block miss bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btb_model: Option<String>,
    /// Positive block execution counts from the solution.
    pub blocks: Vec<CfgIpetBlockCount>,
}

/// One block execution count from an IPET solution.
#[derive(Clone, Debug, Serialize)]
pub struct CfgIpetBlockCount {
    /// Basic block.
    pub block: BlockId,
    /// Number of executions in the maximal solution.
    pub executions: u64,
}

/// WCET result for one execution root.
#[derive(Clone, Debug, Serialize)]
pub struct CfgWcetRoot {
    /// Root function.
    pub function: FunctionId,
    /// Root category.
    pub kind: CfgRootKind,
    /// Human-readable task/handler name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Result status inherited from the function summary.
    pub status: CfgWcetStatus,
    /// Worst-case cycles, when finite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<f64>,
    /// Worst-case time in nanoseconds, when a core frequency is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ns: Option<f64>,
    /// Worst-case local block path.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<BlockId>,
}

/// Program-level WCET analysis metadata.
#[derive(Clone, Debug, Serialize)]
pub struct CfgWcetInfo {
    /// Analysis model name.
    pub model: String,
    /// Default loop bound, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_loop_bound: Option<u32>,
    /// Per-block unrolling state limit for the longest-path model.
    pub max_states: usize,
    /// Core frequency used for `time_ns`, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_hz: Option<u64>,
    /// Solver backend, when the IPET model was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solver: Option<String>,
    /// Flow facts supplied to IPET, when the IPET model was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_facts: Option<CfgFlowFactsInfo>,
    /// Functions with a bounded result.
    pub functions_analyzed: u32,
    /// Functions with a partial result.
    pub functions_partial: u32,
    /// Functions with an unbounded result.
    pub functions_unbounded: u32,
    /// Functions with an unknown result.
    pub functions_unknown: u32,
    /// Per-root WCET results.
    pub roots: Vec<CfgWcetRoot>,
    /// Analysis caveats.
    pub caveats: Vec<String>,
}

/// Flow facts used by IPET, recorded for reproducibility.
#[derive(Clone, Debug, Serialize)]
pub struct CfgFlowFactsInfo {
    /// Where the facts came from.
    pub source: String,
    /// Default loop bound, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_loop_bound: Option<u32>,
    /// Whether loops without a static exit were explicitly bounded.
    pub bound_nonterminating_loops: bool,
    /// Resolved loop bounds. Contextual entries may repeat a header.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub loops: Vec<CfgLoopBoundInfo>,
    /// Non-loop branch execution facts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub branches: Vec<CfgBranchFactInfo>,
    /// Non-loop call execution facts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CfgCallFactInfo>,
    /// Infeasible-path conflicts, including ignored or unsupported records.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<CfgInfeasiblePathInfo>,
}

/// One resolved infeasible-path conflict.
#[derive(Clone, Debug, Serialize)]
pub struct CfgInfeasiblePathInfo {
    /// Declaring function; for a cross-function conflict, the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionId>,
    /// Whether the FFX conflict declared an edge order.
    pub ordered: bool,
    /// Whether the constraint was added to the IPET model.
    pub applied: bool,
    /// Enforcement mode (`aggregate` or `automaton`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Why the conflict was not applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Constraint scope: `function`, `loop` or `cross-function`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Loop header for a per-iteration constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_header: Option<BlockId>,
    /// Selected call boundary for a cross-function constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<CfgInfeasibleCallInfo>,
    /// Caller context (immediate caller first), when contextual.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
    /// Conflict elements in declaration order.
    pub elements: Vec<CfgInfeasibleElementInfo>,
    /// Source of the conflict.
    pub source: String,
}

/// The direct call boundary selected by a cross-function conflict.
#[derive(Clone, Debug, Serialize)]
pub struct CfgInfeasibleCallInfo {
    /// Callee function.
    pub callee: FunctionId,
    /// Caller block containing the unique call site.
    pub block: BlockId,
    /// Call instruction address.
    pub site: Addr,
    /// Caller continuation block after the call returns.
    pub continuation: BlockId,
}

/// One edge or block in an infeasible-path conflict.
#[derive(Clone, Debug, Serialize)]
pub struct CfgInfeasibleElementInfo {
    /// `edge` or `block`.
    pub kind: String,
    /// Function containing the element, when the conflict spans a call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionId>,
    /// Source block for an edge, or the block itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<BlockId>,
    /// Target block for an edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<BlockId>,
    /// CFG control instruction location of an edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<Addr>,
}

/// One resolved branch/edge execution fact.
#[derive(Clone, Debug, Serialize)]
pub struct CfgBranchFactInfo {
    /// Function containing the branch.
    pub function: FunctionId,
    /// Conditional branch instruction address.
    pub site: Addr,
    /// `taken`, `not-taken` or `both`.
    pub outcome: String,
    /// Maximum executions of that edge/block.
    pub max_count: u32,
    /// Caller context (immediate caller first), when contextual.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
    /// Source of the fact.
    pub source: String,
}

/// One resolved call-site execution fact.
#[derive(Clone, Debug, Serialize)]
pub struct CfgCallFactInfo {
    /// Caller function.
    pub function: FunctionId,
    /// Call instruction address.
    pub site: Addr,
    /// Maximum calls from this site.
    pub max_count: u32,
    /// Caller context (immediate caller first), when contextual.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
    /// Source of the fact.
    pub source: String,
}

/// One resolved loop bound from the flow facts.
#[derive(Clone, Debug, Serialize)]
pub struct CfgLoopBoundInfo {
    /// Loop header block address.
    pub header: Addr,
    /// Maximum loop header iterations per external entry.
    pub bound: u32,
    /// Caller context (immediate caller first), when contextual.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
    /// Source of the bound (board profile, F4/FFX file, inference or a merge).
    pub source: String,
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
    /// Computes reachability, SCCs, natural loops, dominators and
    /// post-dominators for this function.
    #[must_use]
    pub fn analyze_graph(&self) -> crate::cfg_graph::CfgGraphAnalysis {
        crate::cfg_graph::analyze(self)
    }

    /// Removes proven-unreachable blocks and merges contiguous fallthrough
    /// blocks. Returns a report describing removed and merged blocks.
    #[must_use]
    pub fn normalize(&mut self) -> crate::cfg_graph::CfgNormalization {
        crate::cfg_graph::normalize(self)
    }

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
                cache: None,
                data_cache: None,
                branch_prediction: None,
                btb: None,
                data_memory: None,
                multicore: None,
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
    /// WCET analysis for this function, when a WCET profile is active.
    pub wcet: Option<CfgFunctionWcet>,
}

/// Why a function is treated as a root of the program CFG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CfgRootKind {
    /// Reset/startup code.
    Startup,
    /// Language-level main entry.
    Main,
    /// Interrupt/exception handler.
    Isr,
    /// Task or thread entry.
    Task,
    /// Callback entry.
    Callback,
    /// Function address recovered from a pointer or function-pointer table.
    Pointer,
}

/// A root function and the evidence that makes it a root.
#[derive(Clone, Debug, Serialize)]
pub struct CfgRoot {
    /// Root function.
    pub function: FunctionId,
    /// Root category.
    pub kind: CfgRootKind,
    /// Human-readable context/task/handler name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Interrupt vector index, for ISR roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<u32>,
    /// Interrupt number, when derivable from the vector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irq: Option<u32>,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// A program-level call edge derived from call sites in function CFGs.
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CfgCallEdge {
    /// Function containing the call site.
    pub caller: FunctionId,
    /// Resolved callee, or `None` for an unresolved call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee: Option<FunctionId>,
    /// Bounded alternative callees for an unresolved or multi-target call.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<FunctionId>,
    /// Call-site address.
    pub site: Addr,
    /// Statically direct target.
    pub direct: bool,
    /// Tail call.
    pub tail: bool,
    /// Conditional call.
    pub conditional: bool,
    /// Target was recovered by a heuristic.
    pub heuristic: bool,
    /// No callee could be resolved.
    pub unresolved: bool,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// A concurrency-relevant operation attached to a function call site.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CfgConcurrencyKind {
    /// Creation of a task/thread/async task.
    Spawn {
        /// Runtime that defines the API.
        runtime: RuntimeId,
        /// API symbol/name.
        api: String,
        /// Recovered task label.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Resolved entry function.
        #[serde(skip_serializing_if = "Option::is_none")]
        entry: Option<FunctionId>,
        /// Bounded candidate entries when the target is opaque.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        candidates: Vec<FunctionId>,
        /// Kind of execution unit created.
        spawn_kind: SpawnKind,
    },
    /// Join/detach/abort of another execution context.
    Join {
        /// Join operation.
        join_kind: JoinKind,
        /// Resolved target entry function.
        #[serde(skip_serializing_if = "Option::is_none")]
        entry: Option<FunctionId>,
        /// Bounded target entries.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        candidates: Vec<FunctionId>,
    },
    /// Await of another task/future.
    Await {
        /// Await operation.
        await_kind: AwaitKind,
        /// Resolved target entry/future function.
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<FunctionId>,
        /// Bounded target functions.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        candidates: Vec<FunctionId>,
    },
    /// Registration of a callback.
    CallbackBind {
        /// Registered callback function.
        callback: FunctionId,
        /// Runtime that defines the registration API.
        runtime: RuntimeId,
        /// API symbol/name.
        api: String,
    },
    /// Entry to a structured-concurrency scope.
    ScopeEnter {
        /// Scope flavor.
        scope_kind: ScopeKind,
        /// Whether scope exit implies a join.
        implicit_join: bool,
    },
    /// Exit from a structured-concurrency scope.
    ScopeExit {
        /// Scope flavor.
        scope_kind: ScopeKind,
    },
}

/// A concurrency annotation at a function call site.
#[derive(Clone, Debug, Serialize)]
pub struct CfgConcurrencySite {
    /// Function containing the operation.
    pub function: FunctionId,
    /// Call site address.
    pub site: Addr,
    /// Operation and resolved targets.
    pub operation: CfgConcurrencyKind,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// A lock or synchronization event attached to the CFG.
#[derive(Clone, Debug, Serialize)]
pub struct CfgLockEvent {
    /// Function containing the lock operation.
    pub function: FunctionId,
    /// Instruction address of a direct call, or inline-range low PC.
    pub site: Addr,
    /// Exclusive high PC for an inlined operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extent: Option<Addr>,
    /// Source-level call site for an inlined operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_site: Option<SourceLoc>,
    /// Runtime that defines the API.
    pub runtime: RuntimeId,
    /// API symbol/name.
    pub api: String,
    /// Lock/synchronization primitive kind.
    pub lock_kind: LockKind,
    /// Acquire/try-acquire/release.
    pub operation: LockOperation,
    /// Event came from a DWARF inline range.
    #[serde(skip_serializing_if = "is_false")]
    pub inlined: bool,
    /// Inline nesting depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_depth: Option<u32>,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// Alternative name for a function, such as a task-context name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfgAlias {
    /// Alias text.
    pub name: String,
    /// Target function.
    pub function: FunctionId,
    /// Whether this is a task/thread context alias.
    pub task: bool,
}

/// Program-wide CFG collection and CFG-native analysis metadata.
#[derive(Clone, Debug, Default)]
pub struct ProgramCfg {
    /// Functions sorted by address.
    pub functions: Vec<CfgFunction>,
    /// Executable addresses recovered from pointer-sized words in allocated
    /// data sections. These are additional system roots for functions that
    /// are only reachable through callback tables or global function pointers.
    pub pointer_roots: Vec<u64>,
    /// Execution roots recovered from startup/main, vectors, tasks, callbacks
    /// and pointer tables.
    pub roots: Vec<CfgRoot>,
    /// Interprocedural call edges derived from function CFG call sites.
    pub calls: Vec<CfgCallEdge>,
    /// Concurrency-relevant call-site annotations.
    pub concurrency: Vec<CfgConcurrencySite>,
    /// Lock acquire/release events.
    pub locks: Vec<CfgLockEvent>,
    /// Alternative function names used by selectors.
    pub aliases: Vec<CfgAlias>,
    /// Image metadata used by the CFG document.
    pub image: Option<ImageInfo>,
    /// Timing model and frequency metadata.
    pub timing: Option<TimingInfo>,
    /// Instruction-cache analysis metadata.
    pub cache: Option<CfgCacheInfo>,
    /// Data-cache analysis metadata.
    pub data_cache: Option<CfgDataCacheInfo>,
    /// Branch-prediction analysis metadata.
    pub branch_prediction: Option<CfgBranchPredictionInfo>,
    /// Branch-target-buffer analysis metadata.
    pub btb: Option<CfgBtbInfo>,
    /// Data-memory latency analysis metadata.
    pub data_memory: Option<CfgDataMemoryInfo>,
    /// Pipeline model metadata and fallback edge stalls.
    pub pipeline: Option<CfgPipelineInfo>,
    /// Full inter-block pipeline state tables, keyed by function address.
    pub(crate) pipeline_states: BTreeMap<u64, crate::timing::PipelineFunctionModel>,
    /// Multicore interference analysis metadata.
    pub multicore: Option<CfgMulticoreInfo>,
    /// WCET analysis metadata.
    pub wcet: Option<CfgWcetInfo>,
    /// Layered system model and coarse system bound.
    pub system_model: Option<CfgSystemModelInfo>,
    /// Analysis diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl CfgFunction {
    /// Builds an empty CFG record from a runtime function record that has no
    /// machine code in this image, such as an external import or a logical
    /// task entry.
    #[must_use]
    pub fn from_function_record(function: &Function) -> Self {
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
            wcet: None,
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
            ..Self::default()
        }
    }

    /// Rebuilds CFG-native analysis metadata from the runtime facts produced
    /// during analysis.
    ///
    /// This is the bridge for the runtime rule engine: rules emit shared
    /// context/relation records, but the resulting roots, call graph,
    /// concurrency sites and locks are stored on the CFG.
    pub(crate) fn attach_analysis_metadata(
        &mut self,
        contexts: &[Context],
        edges: &[Edge],
        locks: &[LockEvent],
        scopes: &[Scope],
    ) {
        self.rebuild_call_edges();
        self.attach_roots(contexts, edges);
        self.attach_aliases(contexts);
        self.attach_concurrency(contexts, edges, scopes);
        self.attach_locks(locks);
    }

    fn rebuild_call_edges(&mut self) {
        let mut edges = Vec::new();
        let mut seen = BTreeSet::new();
        for function in &self.functions {
            let calls = function
                .cfg
                .blocks_by_address
                .values()
                .flat_map(|node| function.cfg.graph[*node].calls.iter())
                .chain(function.cfg.recovered_calls.iter());
            for call in calls {
                if call.null_target {
                    continue;
                }
                let candidates: Vec<FunctionId> = call
                    .candidates
                    .iter()
                    .filter_map(|candidate| candidate.target_function.clone())
                    .collect();
                if call.unresolved {
                    push_call_edge(
                        &mut edges, &mut seen, function, call, None, candidates, true,
                    );
                } else if call.candidates.is_empty() {
                    push_call_edge(
                        &mut edges,
                        &mut seen,
                        function,
                        call,
                        call.target_function.clone(),
                        Vec::new(),
                        call.target_function.is_none(),
                    );
                } else {
                    for candidate in candidates {
                        push_call_edge(
                            &mut edges,
                            &mut seen,
                            function,
                            call,
                            Some(candidate),
                            Vec::new(),
                            false,
                        );
                    }
                }
            }
        }
        edges.sort_by(|left, right| {
            (
                left.caller.as_str(),
                left.site.get(),
                left.callee.as_ref().map(FunctionId::as_str),
                left.unresolved,
            )
                .cmp(&(
                    right.caller.as_str(),
                    right.site.get(),
                    right.callee.as_ref().map(FunctionId::as_str),
                    right.unresolved,
                ))
        });
        self.calls = edges;
    }

    fn attach_roots(&mut self, contexts: &[Context], edges: &[Edge]) {
        let isr_metadata: BTreeMap<&ContextId, (u32, Option<u32>, Option<String>)> = edges
            .iter()
            .filter_map(|edge| match edge {
                Edge::IsrActivate {
                    to_context,
                    vector,
                    irq,
                    name,
                    ..
                } => Some((to_context, (*vector, *irq, name.clone()))),
                _ => None,
            })
            .collect();
        let mut roots = Vec::new();
        let mut seen = BTreeSet::new();
        for context in contexts {
            let Some(kind) = cfg_root_kind(context.kind) else {
                continue;
            };
            if self.function(&context.entry).is_none() {
                continue;
            }
            let (vector, irq, isr_name) = isr_metadata
                .get(&context.id)
                .map_or((None, None, None), |(vector, irq, name)| {
                    (Some(*vector), *irq, name.clone())
                });
            let key = (context.entry.as_str().to_owned(), kind, vector, irq);
            if !seen.insert(key) {
                continue;
            }
            roots.push(CfgRoot {
                function: context.entry.clone(),
                kind,
                name: isr_name.or_else(|| Some(context.name.clone())),
                vector,
                irq,
                confidence: match kind {
                    CfgRootKind::Startup | CfgRootKind::Main | CfgRootKind::Isr => Confidence::High,
                    CfgRootKind::Task | CfgRootKind::Callback | CfgRootKind::Pointer => {
                        Confidence::Medium
                    }
                },
            });
        }
        for address in &self.pointer_roots {
            let Some(function) = self.function_at(*address) else {
                continue;
            };
            let key = (
                function.id.as_str().to_owned(),
                CfgRootKind::Pointer,
                None,
                None,
            );
            if seen.insert(key) {
                roots.push(CfgRoot {
                    function: function.id.clone(),
                    kind: CfgRootKind::Pointer,
                    name: Some(function.primary_name.clone()),
                    vector: None,
                    irq: None,
                    confidence: Confidence::Medium,
                });
            }
        }
        roots.sort_by(|left, right| {
            (left.function.as_str(), left.kind, left.vector, left.irq).cmp(&(
                right.function.as_str(),
                right.kind,
                right.vector,
                right.irq,
            ))
        });
        self.roots = roots;
    }

    fn attach_aliases(&mut self, contexts: &[Context]) {
        let mut aliases: Vec<CfgAlias> = contexts
            .iter()
            .filter(|context| !context.name.trim().is_empty())
            .filter(|context| self.function(&context.entry).is_some())
            .map(|context| CfgAlias {
                name: context.name.clone(),
                function: context.entry.clone(),
                task: is_task_context(context.kind),
            })
            .collect();
        aliases.sort_by(|left, right| {
            (left.name.as_str(), left.function.as_str(), left.task).cmp(&(
                right.name.as_str(),
                right.function.as_str(),
                right.task,
            ))
        });
        aliases.dedup_by(|left, right| {
            left.name == right.name && left.function == right.function && left.task == right.task
        });
        self.aliases = aliases;
    }

    #[allow(clippy::too_many_lines)]
    fn attach_concurrency(&mut self, contexts: &[Context], edges: &[Edge], scopes: &[Scope]) {
        let entries: BTreeMap<&ContextId, &FunctionId> = contexts
            .iter()
            .map(|context| (&context.id, &context.entry))
            .collect();
        let mut sites = Vec::new();
        for edge in edges {
            match edge {
                Edge::Spawn {
                    from_function,
                    target,
                    site,
                    runtime,
                    api,
                    name,
                    spawn_kind,
                    confidence,
                    ..
                } => {
                    let (entry, candidates) = spawn_target_entries(target, &entries);
                    sites.push(CfgConcurrencySite {
                        function: from_function.clone(),
                        site: *site,
                        operation: CfgConcurrencyKind::Spawn {
                            runtime: runtime.clone(),
                            api: api.clone(),
                            name: name.clone(),
                            entry,
                            candidates,
                            spawn_kind: *spawn_kind,
                        },
                        confidence: *confidence,
                    });
                }
                Edge::Join {
                    from_function,
                    target,
                    site,
                    join_kind,
                    confidence,
                    ..
                } => {
                    let (entry, candidates) = join_target_entries(target, &entries);
                    sites.push(CfgConcurrencySite {
                        function: from_function.clone(),
                        site: *site,
                        operation: CfgConcurrencyKind::Join {
                            join_kind: *join_kind,
                            entry,
                            candidates,
                        },
                        confidence: *confidence,
                    });
                }
                Edge::Await {
                    from_context,
                    target,
                    site,
                    await_kind,
                    confidence,
                    ..
                } => {
                    let Some(function) = entries.get(from_context) else {
                        continue;
                    };
                    let (target, candidates) = await_target_entries(target, &entries);
                    sites.push(CfgConcurrencySite {
                        function: (*function).clone(),
                        site: *site,
                        operation: CfgConcurrencyKind::Await {
                            await_kind: *await_kind,
                            target,
                            candidates,
                        },
                        confidence: *confidence,
                    });
                }
                Edge::CallbackBind {
                    from_function,
                    callback,
                    site,
                    runtime,
                    api,
                    confidence,
                    ..
                } => {
                    sites.push(CfgConcurrencySite {
                        function: from_function.clone(),
                        site: *site,
                        operation: CfgConcurrencyKind::CallbackBind {
                            callback: callback.clone(),
                            runtime: runtime.clone(),
                            api: api.clone(),
                        },
                        confidence: *confidence,
                    });
                }
                _ => {}
            }
        }
        for scope in scopes {
            let Some(function) = entries.get(&scope.entering_context) else {
                continue;
            };
            sites.push(CfgConcurrencySite {
                function: (*function).clone(),
                site: scope.enter_site,
                operation: CfgConcurrencyKind::ScopeEnter {
                    scope_kind: scope.kind,
                    implicit_join: scope.implicit_join,
                },
                confidence: scope.confidence,
            });
            if let Some(exit_site) = scope.exit_site {
                sites.push(CfgConcurrencySite {
                    function: (*function).clone(),
                    site: exit_site,
                    operation: CfgConcurrencyKind::ScopeExit {
                        scope_kind: scope.kind,
                    },
                    confidence: scope.confidence,
                });
            }
        }
        sites.sort_by(|left, right| {
            (left.function.as_str(), left.site.get())
                .cmp(&(right.function.as_str(), right.site.get()))
        });
        self.concurrency = sites;
    }

    fn attach_locks(&mut self, locks: &[LockEvent]) {
        let mut events: Vec<CfgLockEvent> = locks
            .iter()
            .map(|lock| CfgLockEvent {
                function: lock.function.clone(),
                site: lock.site,
                extent: lock.extent,
                call_site: lock.call_site.clone(),
                runtime: lock.runtime.clone(),
                api: lock.api.clone(),
                lock_kind: lock.lock_kind,
                operation: lock.operation,
                inlined: lock.inlined,
                inline_depth: lock.inline_depth,
                confidence: lock.confidence,
            })
            .collect();
        events.sort_by(|left, right| {
            (left.function.as_str(), left.site.get())
                .cmp(&(right.function.as_str(), right.site.get()))
        });
        self.locks = events;
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
        self.select_impl(selector)
    }

    #[allow(clippy::too_many_lines)]
    fn select_impl(&self, selector: Option<&str>) -> Result<Vec<&CfgFunction>, String> {
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
        let task_aliases = unique_functions(
            self.aliases
                .iter()
                .filter(|alias| alias.task && context_matches(&alias.name, selector))
                .filter_map(|alias| self.function(&alias.function)),
        );
        if task_aliases.len() == 1 {
            return Ok(task_aliases);
        }
        if task_aliases.len() > 1 {
            return Err(format!(
                "function selector {selector:?} matches multiple task contexts ({} matches)",
                task_aliases.len()
            ));
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
        partial.extend(
            self.aliases
                .iter()
                .filter(|alias| normalize_crate_hashes(&alias.name).contains(selector))
                .filter_map(|alias| self.function(&alias.function)),
        );
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
    /// Traversal follows CFG call edges plus spawn, callback-binding, join,
    /// await and code-reference annotations. The special root `main` prefers a
    /// CFG main root, which is the language-level `main` (for example Rust's
    /// `main::main`) rather than the C runtime wrapper.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the root selector matches no
    /// function or is ambiguous.
    pub fn reachable_from(&self, root: &str) -> Result<Vec<&CfgFunction>, String> {
        self.reachable_from_with_pruning(root, false)
    }

    /// Single-root reachability with optional runtime-boundary pruning.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the root selector matches no
    /// function or is ambiguous.
    pub fn reachable_from_with_pruning(
        &self,
        root: &str,
        prune_runtime: bool,
    ) -> Result<Vec<&CfgFunction>, String> {
        let (seed_ids, selected_ids) = self.reachable_seeds(root)?;
        let reachable = self.reachable_ids(seed_ids, prune_runtime);
        Ok(self.selected_from_reachable(&reachable, selected_ids))
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
    pub fn execution_roots(&self, image: &Image) -> Vec<FunctionId> {
        let mut roots = BTreeSet::new();
        let default_handlers = default_handler_addresses(image);
        self.collect_execution_roots(image, &default_handlers, &mut roots);
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
    pub fn system_roots(&self, image: &Image) -> Vec<FunctionId> {
        let mut roots = BTreeSet::new();
        let default_handlers = default_handler_addresses(image);
        self.collect_execution_roots(image, &default_handlers, &mut roots);
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
        image: &Image,
        default_handlers: &BTreeSet<u64>,
        roots: &mut BTreeSet<FunctionId>,
    ) {
        for root in &self.roots {
            let default = self
                .function(&root.function)
                .is_some_and(is_default_handler)
                || self
                    .function(&root.function)
                    .is_some_and(|function| is_default_handler_name(&function.primary_name));
            if !default {
                roots.insert(root.function.clone());
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
        for site in &self.concurrency {
            if let CfgConcurrencyKind::CallbackBind { callback, .. } = &site.operation {
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
    pub fn reachable_from_system(&self, image: &Image, prune_runtime: bool) -> Vec<&CfgFunction> {
        let roots = self.system_roots(image);
        self.reachable_from_roots(&roots, prune_runtime)
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
        image: &Image,
        prune_runtime: bool,
    ) -> Vec<&CfgFunction> {
        let roots = self.execution_roots(image);
        self.reachable_from_roots(&roots, prune_runtime)
    }

    /// Runs multi-root worklist reachability from an explicit root set.
    #[must_use]
    pub fn reachable_from_roots(
        &self,
        roots: &[FunctionId],
        prune_runtime: bool,
    ) -> Vec<&CfgFunction> {
        let mut seed_ids = Vec::new();
        let mut selected_ids = BTreeSet::new();
        for root in roots {
            seed_ids.push(root.clone());
            if self.function(root).is_some() {
                selected_ids.insert(root.clone());
            }
        }
        let reachable = self.reachable_ids(seed_ids, prune_runtime);
        self.selected_from_reachable(&reachable, selected_ids)
    }

    fn reachable_ids(
        &self,
        seed_ids: Vec<FunctionId>,
        prune_runtime: bool,
    ) -> BTreeSet<FunctionId> {
        let mut adjacency = self.program_reachability();
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
            if prune_runtime && self.function(&current).is_some_and(is_runtime_boundary) {
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

    fn program_reachability(&self) -> BTreeMap<FunctionId, Vec<FunctionId>> {
        let mut adjacency: BTreeMap<FunctionId, Vec<FunctionId>> = BTreeMap::new();
        let mut add = |from: &FunctionId, to: &FunctionId| {
            adjacency.entry(from.clone()).or_default().push(to.clone());
        };
        for call in &self.calls {
            if let Some(callee) = &call.callee {
                add(&call.caller, callee);
            }
            for candidate in &call.candidates {
                add(&call.caller, candidate);
            }
        }
        for site in &self.concurrency {
            match &site.operation {
                CfgConcurrencyKind::Spawn {
                    entry, candidates, ..
                } => {
                    if let Some(entry) = entry {
                        add(&site.function, entry);
                        // A task's spawner remains part of the executable
                        // slice leading to the task when the spawn call itself
                        // was indirect.
                        add(entry, &site.function);
                    }
                    for candidate in candidates {
                        add(&site.function, candidate);
                    }
                }
                CfgConcurrencyKind::Join {
                    entry, candidates, ..
                } => {
                    if let Some(entry) = entry {
                        add(&site.function, entry);
                    }
                    for candidate in candidates {
                        add(&site.function, candidate);
                    }
                }
                CfgConcurrencyKind::Await {
                    target, candidates, ..
                } => {
                    if let Some(target) = target {
                        add(&site.function, target);
                    }
                    for candidate in candidates {
                        add(&site.function, candidate);
                    }
                }
                CfgConcurrencyKind::CallbackBind { callback, .. } => {
                    add(&site.function, callback);
                }
                CfgConcurrencyKind::ScopeEnter { .. } | CfgConcurrencyKind::ScopeExit { .. } => {}
            }
        }
        adjacency
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
        reachable: &BTreeSet<FunctionId>,
        mut selected_ids: BTreeSet<FunctionId>,
    ) -> Vec<&CfgFunction> {
        for id in reachable {
            if self.function(id).is_some() {
                selected_ids.insert(id.clone());
            }
        }
        self.functions
            .iter()
            .filter(|function| selected_ids.contains(&function.id))
            .collect()
    }

    fn reachable_seeds(
        &self,
        root: &str,
    ) -> Result<(Vec<FunctionId>, BTreeSet<FunctionId>), String> {
        if root == "main" {
            let entries: Vec<FunctionId> = self
                .roots
                .iter()
                .filter(|root| root.kind == CfgRootKind::Main)
                .filter(|root| self.function(&root.function).is_some())
                .map(|root| root.function.clone())
                .collect();
            if !entries.is_empty() {
                let selected = entries.iter().cloned().collect();
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

fn push_call_edge(
    edges: &mut Vec<CfgCallEdge>,
    seen: &mut BTreeSet<(String, u64, Option<String>, bool)>,
    function: &CfgFunction,
    call: &CfgCallSite,
    callee: Option<FunctionId>,
    candidates: Vec<FunctionId>,
    unresolved: bool,
) {
    let key = (
        function.id.as_str().to_owned(),
        call.site,
        callee.as_ref().map(|callee| callee.as_str().to_owned()),
        unresolved,
    );
    if !seen.insert(key) {
        return;
    }
    let confidence = if unresolved {
        Confidence::Unknown
    } else if call.heuristic {
        Confidence::Low
    } else if call.direct {
        Confidence::High
    } else {
        Confidence::Medium
    };
    edges.push(CfgCallEdge {
        caller: function.id.clone(),
        callee,
        candidates,
        site: Addr::new(call.site),
        direct: call.direct,
        tail: call.tail,
        conditional: call.conditional,
        heuristic: call.heuristic,
        unresolved,
        confidence,
    });
}

fn cfg_root_kind(kind: ContextKind) -> Option<CfgRootKind> {
    match kind {
        ContextKind::Startup => Some(CfgRootKind::Startup),
        ContextKind::Main => Some(CfgRootKind::Main),
        ContextKind::Isr => Some(CfgRootKind::Isr),
        ContextKind::TimerCallback => Some(CfgRootKind::Callback),
        ContextKind::Thread
        | ContextKind::ScopedThread
        | ContextKind::AsyncTask
        | ContextKind::Executor
        | ContextKind::SystemWorkqueue
        | ContextKind::KernelThread => Some(CfgRootKind::Task),
        ContextKind::Unknown => None,
    }
}

fn spawn_target_entries(
    target: &SpawnTarget,
    entries: &BTreeMap<&ContextId, &FunctionId>,
) -> (Option<FunctionId>, Vec<FunctionId>) {
    match target {
        SpawnTarget::Context { entry, .. } => (Some(entry.clone()), Vec::new()),
        SpawnTarget::Opaque { candidates } => (
            None,
            candidates
                .iter()
                .filter(|candidate| {
                    // Opaque spawn candidates are function IDs already, not
                    // context IDs; keep only entries that exist in the CFG.
                    entries.values().any(|entry| *entry == *candidate)
                })
                .cloned()
                .collect(),
        ),
    }
}

fn join_target_entries(
    target: &JoinTarget,
    entries: &BTreeMap<&ContextId, &FunctionId>,
) -> (Option<FunctionId>, Vec<FunctionId>) {
    match target {
        JoinTarget::Context { context } => (
            entries.get(context).map(|entry| (*entry).clone()),
            Vec::new(),
        ),
        JoinTarget::Opaque { candidates } => (
            None,
            candidates
                .iter()
                .filter_map(|context| entries.get(context).map(|entry| (*entry).clone()))
                .collect(),
        ),
    }
}

fn await_target_entries(
    target: &AwaitTarget,
    entries: &BTreeMap<&ContextId, &FunctionId>,
) -> (Option<FunctionId>, Vec<FunctionId>) {
    match target {
        AwaitTarget::Context { context } => (
            entries.get(context).map(|entry| (*entry).clone()),
            Vec::new(),
        ),
        AwaitTarget::Function { function } => (Some(function.clone()), Vec::new()),
        AwaitTarget::Opaque { candidates } => (None, candidates.clone()),
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

#[derive(Serialize)]
struct CfgDocument<'a> {
    cfg_schema_version: &'static str,
    image: &'a ImageInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    timing: Option<&'a TimingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<&'a CfgCacheInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_cache: Option<&'a CfgDataCacheInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    branch_prediction: Option<&'a CfgBranchPredictionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    btb: Option<&'a CfgBtbInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_memory: Option<&'a CfgDataMemoryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pipeline: Option<&'a CfgPipelineInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multicore: Option<&'a CfgMulticoreInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wcet: Option<&'a CfgWcetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_model: Option<&'a CfgSystemModelInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pointer_roots: Vec<Addr>,
    #[serde(skip_serializing_if = "is_empty_slice")]
    roots: &'a [CfgRoot],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    calls: Vec<&'a CfgCallEdge>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    concurrency: Vec<&'a CfgConcurrencySite>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locks: Vec<&'a CfgLockEvent>,
    functions: Vec<CfgFunctionView>,
    diagnostics: Vec<&'a Diagnostic>,
    #[serde(skip_serializing_if = "is_zero")]
    diagnostics_omitted: usize,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_empty_slice<T>(value: &&[T]) -> bool {
    value.is_empty()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    wcet: Option<CfgFunctionWcet>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<CfgBlockCache>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_cache: Option<CfgBlockDataCache>,
    #[serde(skip_serializing_if = "Option::is_none")]
    branch_prediction: Option<CfgBlockBranchPrediction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    btb: Option<CfgBlockBtb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_memory: Option<CfgBlockDataMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multicore: Option<CfgBlockMulticore>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    memory_accesses: Vec<CfgMemoryAccess>,
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
/// ambiguous, when program metadata is missing, or when serialization fails.
pub fn render_json(
    program: &ProgramCfg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select(selector)?;
    render_json_selected(program, &selected, include_instructions)
}

/// Serializes explicitly selected CFGs using program-CFG metadata.
///
/// # Errors
///
/// Returns an error when the image metadata is absent or serialization fails.
pub fn render_json_selected(
    program: &ProgramCfg,
    selected: &[&CfgFunction],
    include_instructions: bool,
) -> Result<String, String> {
    let image = program
        .image
        .as_ref()
        .ok_or_else(|| "program CFG has no image metadata".to_owned())?;
    let functions = selected
        .iter()
        .map(|function| function_view(program, function, include_instructions))
        .collect();
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let diagnostics: Vec<&Diagnostic> = program
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic
                .function
                .as_ref()
                .is_none_or(|function| selected_ids.contains(function))
        })
        .collect();
    let diagnostics_omitted = program.diagnostics.len().saturating_sub(diagnostics.len());
    let calls = program
        .calls
        .iter()
        .filter(|call| selected_ids.contains(&call.caller))
        .collect();
    let concurrency = program
        .concurrency
        .iter()
        .filter(|site| selected_ids.contains(&site.function))
        .collect();
    let locks = program
        .locks
        .iter()
        .filter(|lock| selected_ids.contains(&lock.function))
        .collect();
    let document = CfgDocument {
        cfg_schema_version: CFG_SCHEMA_VERSION,
        image,
        timing: program.timing.as_ref(),
        cache: program.cache.as_ref(),
        data_cache: program.data_cache.as_ref(),
        branch_prediction: program.branch_prediction.as_ref(),
        btb: program.btb.as_ref(),
        data_memory: program.data_memory.as_ref(),
        pipeline: program.pipeline.as_ref(),
        multicore: program.multicore.as_ref(),
        wcet: program.wcet.as_ref(),
        system_model: program.system_model.as_ref(),
        pointer_roots: program
            .pointer_roots
            .iter()
            .copied()
            .map(Addr::new)
            .collect(),
        roots: &program.roots,
        calls,
        concurrency,
        locks,
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
            cache: block.cache.clone(),
            data_cache: block.data_cache.clone(),
            branch_prediction: block.branch_prediction.clone(),
            btb: block.btb.clone(),
            data_memory: block.data_memory.clone(),
            multicore: block.multicore.clone(),
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
        wcet: function.wcet.clone(),
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
        memory_accesses: instruction.memory_accesses.clone(),
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
            memory_accesses: Vec::new(),
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
            wcet: None,
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
            wcet: None,
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
            wcet: None,
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
