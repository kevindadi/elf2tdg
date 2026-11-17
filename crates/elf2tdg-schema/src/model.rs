//! Core graph entities: image metadata, functions, basic blocks, execution
//! contexts, typed edges, scopes and diagnostics.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::addr::Addr;
use crate::id::{BlockId, ContextId, EdgeId, FunctionId, LockEventId, RuntimeId, ScopeId};
use crate::timing::{BlockTiming, FunctionTiming, InstructionTiming, TimingInfo};

/// A complete Task Dependency Graph document.
///
/// Use [`Tdg::validate`] before consuming a document produced by another
/// tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Tdg {
    /// Schema version, for example `1.1`.
    pub schema_version: String,
    /// Producer metadata, for reproducibility.
    pub tool: ToolInfo,
    /// Source image metadata.
    pub image: ImageInfo,
    /// Timing models, frequency domains and global caveats.
    #[serde(default)]
    pub timing: TimingInfo,
    /// Function nodes, including their basic blocks.
    pub functions: Vec<Function>,
    /// Execution-context nodes.
    pub contexts: Vec<Context>,
    /// Call-graph and concurrency-control edges.
    pub edges: Vec<Edge>,
    /// Lock/semaphore acquire and release events, including inlined sites.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locks: Vec<LockEvent>,
    /// Structured-concurrency scopes (for example OpenMP parallel regions).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<Scope>,
    /// Analyzer diagnostics. A document may still be valid with diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    /// Extension point for downstream tools. Keys should be namespaced.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, Value>,
}

/// Identifies the producer and the data tables it used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolInfo {
    /// Tool name.
    pub name: String,
    /// Tool version.
    pub version: String,
    /// Version of the concurrency-detection rule database.
    pub rules_version: String,
    /// Version of the instruction-timing tables.
    pub timing_tables_version: String,
}

/// Metadata about the analyzed ELF image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImageInfo {
    /// Path or basename of the analyzed file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// SHA-256 of the file, when computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// GNU build ID, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// Architecture identifier, for example `thumbv7em`, `riscv32imac`,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    /// Byte order.
    pub endianness: Endianness,
    /// ELF entry point. For Thumb images this may retain the low interworking
    /// bit.
    pub entry: Addr,
    /// ELF file type.
    pub elf_type: ElfType,
    /// Whether a symbol table is present.
    pub has_symbols: bool,
    /// Whether DWARF debug information is present.
    pub has_debug_info: bool,
    /// Whether relocation records are present (for example from
    /// `--emit-relocs`).
    pub has_relocations: bool,
    /// Loadable segments, useful for VMA/LMA reasoning and memory-region timing
    /// parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_segments: Vec<LoadSegment>,
}

/// ELF byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Endianness {
    /// Little endian.
    Little,
    /// Big endian.
    Big,
    /// Unknown or unsupported.
    Unknown,
}

/// ELF file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ElfType {
    /// Executable.
    Exec,
    /// Shared object / PIE.
    Dyn,
    /// Relocatable object.
    Rel,
    /// Anything else.
    Unknown,
}

/// A loadable ELF segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LoadSegment {
    /// Virtual address.
    pub vaddr: Addr,
    /// Physical/load address.
    pub paddr: Addr,
    /// Offset in the file.
    pub file_offset: u64,
    /// Size in the file.
    pub file_size: u64,
    /// Size in memory (may exceed `file_size` for `.bss`).
    pub mem_size: u64,
    /// Segment permissions.
    pub flags: SegmentFlags,
}

/// Permissions of a loadable segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentFlags {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

/// A function node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Function {
    /// Stable function ID (`fn:...`).
    pub id: FunctionId,
    /// Primary display name. For Rust/C++ this is normally the demangled name.
    pub primary_name: String,
    /// Demangled name when it differs from `primary_name` or adds information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demangled_name: Option<String>,
    /// Raw symbol names. Multiple entries represent aliases or ICF-folded
    /// functions sharing one address range.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<String>,
    /// Source language inferred from symbols/debug info.
    pub language: Language,
    /// Function start address.
    pub address: Addr,
    /// Function size in bytes. Zero means unknown.
    pub size: u64,
    /// Section name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Primary role of the function.
    pub kind: FunctionKind,
    /// Basic blocks, when the function body was analyzed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<BasicBlock>,
    /// Aggregate block-cost metadata. Not an execution time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<FunctionTiming>,
    /// Source location of the function definition, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLoc>,
    /// Callers for which this function was inlined. Logical call-graph edges
    /// also carry `inlined: true`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_sites: Vec<InlineSite>,
    /// Extension point. Keys should be namespaced.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, Value>,
}

impl Function {
    /// Returns the first address past the function, if the size is known and
    /// the range does not overflow.
    #[must_use]
    pub fn end(&self) -> Option<Addr> {
        self.address.checked_add(self.size)
    }
}

/// Source language inferred for a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    /// Rust.
    Rust,
    /// C.
    C,
    /// C++.
    Cpp,
    /// Assembly.
    Assembly,
    /// Mixed or compiler-generated code.
    Mixed,
    /// Unknown.
    Unknown,
}

/// Primary role of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionKind {
    /// Ordinary function.
    Normal,
    /// Reset/startup entry.
    Entry,
    /// Interrupt/exception handler.
    Isr,
    /// Entry point of a thread or async task. Context membership is authoritative.
    TaskEntry,
    /// Poll function of an async future.
    FuturePoll,
    /// Linker-generated thunk/veneer.
    Thunk,
    /// PLT entry on dynamically linked targets.
    Plt,
    /// Runtime trampoline such as `thread_start` or `_M_run`.
    Trampoline,
    /// RTOS/kernel function.
    Kernel,
    /// Declared but not present in this image.
    External,
    /// Unknown.
    Unknown,
}

/// A basic block with optional intra-function CFG successors and timing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BasicBlock {
    /// Stable block ID (`bb:...`).
    pub id: BlockId,
    /// Block start address.
    pub address: Addr,
    /// Block size in bytes. Zero means unknown.
    pub size: u64,
    /// Intra-function successors. Calls and cross-context edges are stored in
    /// [`Tdg::edges`], not here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub successors: Vec<BlockId>,
    /// Optional per-instruction detail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instructions: Vec<InstructionTiming>,
    /// Block timing estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<BlockTiming>,
}

impl BasicBlock {
    /// Returns the first address past the block, if the size is known and the
    /// range does not overflow.
    #[must_use]
    pub fn end(&self) -> Option<Addr> {
        self.address.checked_add(self.size)
    }
}

/// A source position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceLoc {
    /// Source file path as recorded in debug info.
    pub file: String,
    /// One-based line number.
    pub line: u32,
    /// One-based column number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// An inlining site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InlineSite {
    /// Function into which this function was inlined.
    pub caller: FunctionId,
    /// Call site address in `caller`.
    pub site: Addr,
    /// Inline depth, starting at 1 for a direct inlining site.
    #[serde(default)]
    pub depth: u32,
}

/// An execution context.
///
/// Contexts are what make the TDG more than a call graph: a function can be
/// reachable from several contexts, and edges such as `spawn` and `join`
/// connect functions to contexts rather than to functions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Context {
    /// Stable context ID (`ctx:...`).
    pub id: ContextId,
    /// Display name, for example a task name or IRQ name.
    pub name: String,
    /// Context kind.
    pub kind: ContextKind,
    /// Entry function.
    pub entry: FunctionId,
    /// Context that created this one, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ContextId>,
    /// Scheduling model.
    pub scheduling: Scheduling,
    /// Runtime priority. The meaning of the number is given by `scheme`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// Core ID on multi-core targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<u16>,
    /// Clock domain used for this context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency_domain: Option<crate::id::FrequencyDomainId>,
    /// The spawn edge that created this context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn_edge: Option<EdgeId>,
    /// Extension point. Keys should be namespaced.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, Value>,
}

/// Kind of an execution context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ContextKind {
    /// Reset/startup code.
    Startup,
    /// Main thread/task.
    Main,
    /// Preemptive or cooperative OS thread.
    Thread,
    /// Thread created inside a structured-concurrency scope.
    ScopedThread,
    /// Async task spawned on an executor.
    AsyncTask,
    /// Executor/driver context itself.
    Executor,
    /// Interrupt/exception handler.
    Isr,
    /// Timer callback executed in a timer-service context.
    TimerCallback,
    /// RTOS system workqueue context.
    SystemWorkqueue,
    /// Kernel thread.
    KernelThread,
    /// Unknown.
    Unknown,
}

/// Scheduling discipline of a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Scheduling {
    /// Can preempt lower-priority contexts.
    Preemptive,
    /// Runs until it yields/awaits.
    Cooperative,
    /// Interrupt context; preempts normal execution.
    Interrupt,
    /// Unknown.
    Unknown,
}

/// A runtime priority value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Priority {
    /// Raw value as reported by the runtime API.
    pub raw: i64,
    /// How to interpret the value.
    pub scheme: PriorityScheme,
}

/// Priority ordering convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PriorityScheme {
    /// Smaller numbers are higher priority (`Zephyr`, `ThreadX`).
    LowerIsHigher,
    /// Larger numbers are higher priority (`FreeRTOS`, pthread).
    HigherIsHigher,
    /// Unknown or not applicable.
    Unknown,
}

/// A typed edge.
///
/// The `kind` field selects the variant. Every edge has an ID, a source/site
/// and explicit confidence; there are no implicit guesses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Edge {
    /// Ordinary call-graph edge.
    ///
    /// A bounded indirect target set may be represented as multiple `Call`
    /// edges sharing the same `site`, one per candidate callee.
    Call {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// Calling function.
        caller: FunctionId,
        /// Called function.
        callee: FunctionId,
        /// Call site address in `caller`.
        site: Addr,
        /// Whether the target was resolved statically.
        direct: bool,
        /// Whether this is a tail call (the call site is a jump).
        tail: bool,
        /// Whether this edge exists only in the logical (pre-inlining) graph.
        inlined: bool,
        /// Resolution confidence.
        confidence: Confidence,
    },
    /// Creation of a new execution context.
    Spawn {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// Function containing the spawn call.
        from_function: FunctionId,
        /// Target context, or an explicit opaque target when the entry could
        /// not be resolved.
        target: SpawnTarget,
        /// Spawn call-site address in `from_function`.
        site: Addr,
        /// Runtime that defined the API, for example `freertos` or
        /// `rust-embassy`.
        runtime: RuntimeId,
        /// API symbol/name, for example `xTaskCreate`.
        api: String,
        /// Optional task label recovered from a closure/future type or the
        /// resolved entry symbol.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// What kind of execution unit was created.
        spawn_kind: SpawnKind,
        /// Priority passed to the API, when it is a constant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<Priority>,
        /// Resolution confidence.
        confidence: Confidence,
    },
    /// Synchronization with another context.
    Join {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// Function containing the join/detach/abort call.
        from_function: FunctionId,
        /// Context containing the call, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_context: Option<ContextId>,
        /// Context being joined/detached/aborted, or an explicit opaque
        /// target.
        target: JoinTarget,
        /// Call-site address in `from_function`.
        site: Addr,
        /// Kind of synchronization.
        join_kind: JoinKind,
        /// Scope that provides an implicit join, when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<ScopeId>,
        /// Resolution confidence.
        confidence: Confidence,
    },
    /// An async task awaits a future/task.
    Await {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// Awaiting context.
        from_context: ContextId,
        /// What is being awaited.
        target: AwaitTarget,
        /// Await call/poll site.
        site: Addr,
        /// Kind of await operation.
        await_kind: AwaitKind,
        /// Resolution confidence. Await targets are often opaque without data
        /// flow.
        confidence: Confidence,
    },
    /// Registration of a callback that runs in another context.
    CallbackBind {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// Function performing the registration.
        from_function: FunctionId,
        /// Registered callback function.
        callback: FunctionId,
        /// Context in which the callback runs, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_context: Option<ContextId>,
        /// Registration call-site address.
        site: Addr,
        /// Runtime that defines the registration API.
        runtime: RuntimeId,
        /// API symbol/name.
        api: String,
        /// Resolution confidence.
        confidence: Confidence,
    },
    /// Activation of an ISR through a vector table.
    IsrActivate {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// ISR context.
        to_context: ContextId,
        /// Architecture vector index.
        vector: u32,
        /// IRQ number, when distinguishable from the vector index.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        irq: Option<u32>,
        /// IRQ/peripheral name, when known (for example from an SVD).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Resolution confidence.
        confidence: Confidence,
    },
    /// Derived preemption relation, usually ISR over thread contexts.
    ///
    /// This edge is a projection of priority/scheduling metadata and is marked
    /// `derived` so consumers can ignore it.
    Preempts {
        /// Stable edge ID (`e:...`).
        id: EdgeId,
        /// Higher-priority/preempting context.
        from_context: ContextId,
        /// Preempted context.
        to_context: ContextId,
        /// Whether the edge was derived rather than observed.
        #[serde(default)]
        derived: bool,
        /// Confidence.
        confidence: Confidence,
    },
}

impl Edge {
    /// Returns the edge ID.
    #[must_use]
    pub fn id(&self) -> &EdgeId {
        match self {
            Self::Call { id, .. }
            | Self::Spawn { id, .. }
            | Self::Join { id, .. }
            | Self::Await { id, .. }
            | Self::CallbackBind { id, .. }
            | Self::IsrActivate { id, .. }
            | Self::Preempts { id, .. } => id,
        }
    }

    /// Returns the call/registration site, when the edge variant has one.
    #[must_use]
    pub fn site(&self) -> Option<Addr> {
        match self {
            Self::Call { site, .. }
            | Self::Spawn { site, .. }
            | Self::Join { site, .. }
            | Self::Await { site, .. }
            | Self::CallbackBind { site, .. } => Some(*site),
            Self::IsrActivate { .. } | Self::Preempts { .. } => None,
        }
    }
}

/// A lock/semaphore acquire or release event.
///
/// Lock events are not call-graph edges: the analyzer usually cannot prove
/// which object instance is locked without points-to analysis. The event keeps
/// the API, lock kind, operation, concrete source/inline range and containing
/// function/context so downstream tools can pair or visualise events using
/// additional data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LockEvent {
    /// Stable event ID (`lock:...`).
    pub id: LockEventId,
    /// Function containing the lock operation.
    pub function: FunctionId,
    /// Execution context containing the operation, when reachable from a
    /// known context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextId>,
    /// Instruction address of a direct call, or the low PC of an inline range.
    pub site: Addr,
    /// Exclusive high PC when the operation was inlined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<Addr>,
    /// Source call site from `DW_AT_call_file`/`DW_AT_call_line` when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_site: Option<SourceLoc>,
    /// Runtime that defined the API, for example `pthread` or `freertos`.
    pub runtime: RuntimeId,
    /// API symbol/name, for example `pthread_mutex_lock`.
    pub api: String,
    /// Kind of lock or synchronization primitive.
    pub lock_kind: LockKind,
    /// Acquire/try-acquire/release operation.
    pub operation: LockOperation,
    /// Whether this event came from a DWARF inline range rather than a direct
    /// machine call.
    #[serde(default)]
    pub inlined: bool,
    /// DWARF inline nesting depth when `inlined` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_depth: Option<u32>,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// Kind of lock or synchronization primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LockKind {
    /// Mutex.
    Mutex,
    /// Reader-writer lock with an unspecified read/write side.
    RwLock,
    /// Read side of a reader-writer lock.
    RwLockRead,
    /// Write side of a reader-writer lock.
    RwLockWrite,
    /// Spin lock.
    SpinLock,
    /// Counting/binary semaphore.
    Semaphore,
    /// Other or unclassified lock primitive.
    Other,
}

/// Operation performed on a lock or semaphore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LockOperation {
    /// Blocking acquire.
    Acquire,
    /// Non-blocking/try acquire.
    TryAcquire,
    /// Release.
    Release,
}

/// Resolution of a spawn edge's target.
///
/// An unresolved spawn is still represented as an edge: the call site is
/// valuable evidence, and inventing a context/entry would be worse than
/// reporting an opaque target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "resolution", rename_all = "kebab-case")]
pub enum SpawnTarget {
    /// The created context and its entry were resolved.
    Context {
        /// Context created by the call.
        context: ContextId,
        /// Entry function of the new context. Must equal the context entry.
        entry: FunctionId,
    },
    /// The entry/target could not be resolved.
    Opaque {
        /// Candidate entry functions, when a bounded analysis produced any.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        candidates: Vec<FunctionId>,
    },
}

/// Resolution of a join/detach/abort target.
///
/// Thread handles are frequently opaque at `-O2` even when symbols are
/// available, so an unresolved join is first-class rather than omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "resolution", rename_all = "kebab-case")]
pub enum JoinTarget {
    /// The joined context was resolved.
    Context {
        /// Context being joined/detached/aborted.
        context: ContextId,
    },
    /// The handle could not be resolved to a context.
    Opaque {
        /// Candidate contexts, when a bounded analysis produced any.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        candidates: Vec<ContextId>,
    },
}

/// Kind of execution unit created by a spawn operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SpawnKind {
    /// OS thread (pthread, `FreeRTOS` task, `Zephyr` thread, ...).
    OsThread,
    /// Thread scoped to a structured-concurrency region.
    ScopedThread,
    /// Async task on an executor.
    AsyncTask,
    /// Task owned by an executor/driver context.
    ExecutorTask,
    /// OpenMP parallel region.
    #[serde(rename = "openmp-region")]
    OpenMpRegion,
    /// Rayon task/job.
    RayonTask,
    /// Timer callback.
    TimerCallback,
    /// Unknown.
    Unknown,
}

/// Kind of join/synchronization operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JoinKind {
    /// Wait for completion.
    Join,
    /// Detach without waiting.
    Detach,
    /// Terminate/abort.
    Abort,
    /// Implicit join at the end of a scope.
    ScopeEnd,
    /// Barrier/parallel-region join.
    Barrier,
    /// Unknown.
    Unknown,
}

/// Target of an await operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "resolution", rename_all = "kebab-case")]
pub enum AwaitTarget {
    /// A known context.
    Context {
        /// Context being awaited.
        context: ContextId,
    },
    /// A known function/future.
    Function {
        /// Function/future being awaited.
        function: FunctionId,
    },
    /// The target could not be resolved.
    Opaque {
        /// Candidate functions, when a bounded analysis produced any.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        candidates: Vec<FunctionId>,
    },
}

/// Kind of async await.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AwaitKind {
    /// `.await` on a future.
    Await,
    /// `select!`/race-style wait.
    Select,
    /// Awaiting a join handle.
    JoinHandle,
    /// Unknown.
    Unknown,
}

/// A structured-concurrency scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Scope {
    /// Stable scope ID (`scope:...`).
    pub id: ScopeId,
    /// Scope flavor.
    pub kind: ScopeKind,
    /// Context that entered the scope.
    pub entering_context: ContextId,
    /// Scope-entry call site.
    pub enter_site: Addr,
    /// Scope-exit call site, when identifiable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_site: Option<Addr>,
    /// Whether the scope implies a join at exit.
    pub implicit_join: bool,
    /// Spawn edges belonging to the scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<EdgeId>,
    /// Resolution confidence.
    pub confidence: Confidence,
}

/// Flavor of a structured-concurrency scope.
///
/// The enum retains variants for compatibility. The default no-std Rust
/// profile emits OpenMP parallel-region scopes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeKind {
    /// Rust `std::thread::scope` (schema vocabulary).
    RustThreadScope,
    /// Rayon `scope`.
    RayonScope,
    /// Rayon `join` (fork-join pair).
    RayonJoin,
    /// Crossbeam `scope`.
    CrossbeamScope,
    /// OpenMP parallel region.
    #[serde(rename = "openmp-parallel")]
    OpenMpParallel,
    /// TBB task group.
    TbbTaskGroup,
    /// Unknown.
    Unknown,
}

/// An analyzer diagnostic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Diagnostic {
    /// Stable machine-readable code, for example
    /// `unresolved-spawn-target`.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Related function, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionId>,
    /// Related context, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextId>,
    /// Related address, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<Addr>,
    /// Structured details for downstream filtering.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

/// Diagnostic severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational.
    Info,
    /// The result may be incomplete or approximate.
    Warning,
    /// The output is invalid or analysis failed for this item.
    Error,
}

/// Confidence in an inferred fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Direct, unambiguous evidence (symbol, relocation, DWARF).
    High,
    /// Strong pattern match, but with assumptions.
    Medium,
    /// Heuristic or partially resolved.
    Low,
    /// Not assessed.
    Unknown,
}
