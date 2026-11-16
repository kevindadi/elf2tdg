//! Runtime API recognition rules.
//!
//! Rules match resolved callee functions by raw C symbol or demangled Rust/C++
//! path. Rust symbols are normalized by removing `[crate-hash]` segments so a
//! rule can say `std::thread::...` regardless of the toolchain hash.
//!
//! Rust's monomorphized spawn/scope symbols carry the closure/future type as
//! their first generic argument, e.g.
//!
//! ```text
//! std::thread::functions::spawn::<app::main::{closure#0}, ()>
//! ```
//!
//! [`extract_first_generic_arg`] recovers that type, which can then be matched
//! to the closure function node emitted by the compiler.

use elf2tdg_schema::{AwaitKind, Confidence, Function, JoinKind, ScopeKind, SpawnKind};

/// Runtime operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleOp {
    /// Creates a new thread/task/context.
    Spawn,
    /// Waits for or terminates another context.
    Join,
    /// Async await.
    Await,
    /// Structured-concurrency scope.
    Scope,
}

/// How a rule matches a callee function.
#[derive(Debug, Clone, Copy)]
pub enum Matcher {
    /// Exact raw symbol name.
    RawExact(&'static str),
    /// Raw symbol name contains the pattern.
    RawContains(&'static str),
    /// Normalized demangled name contains the pattern.
    DemangledContains(&'static str),
    /// Normalized demangled name contains every pattern.
    DemangledContainsAll(&'static [&'static str]),
}

/// One runtime API rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Runtime identifier, for example `rust-std`.
    pub runtime: &'static str,
    /// Human-readable API name.
    pub api: &'static str,
    /// Operation kind.
    pub op: RuleOp,
    /// Spawn kind for `Spawn` rules.
    pub spawn_kind: SpawnKind,
    /// Scope kind for `Scope` rules.
    pub scope_kind: ScopeKind,
    /// Join kind for `Join` rules.
    pub join_kind: JoinKind,
    /// Await kind for `Await` rules.
    pub await_kind: AwaitKind,
    /// Matcher.
    pub matcher: Matcher,
    /// Confidence in the classification.
    pub confidence: Confidence,
    /// Whether the callee's first generic argument is a closure/future type
    /// that may name the spawned body.
    pub closure_generic: bool,
    /// Ignore calls made from inside the Rust runtime itself. This prevents
    /// double-reporting `thread::spawn` as both the user call and an internal
    /// `Builder::spawn` call.
    pub filter_runtime_caller: bool,
    /// Argument index carrying the spawn entry function pointer, for C-style
    /// APIs whose entry can be recovered by bounded value tracking.
    pub entry_arg: Option<usize>,
}

const fn spawn(
    runtime: &'static str,
    api: &'static str,
    spawn_kind: SpawnKind,
    matcher: Matcher,
    confidence: Confidence,
    closure_generic: bool,
    filter_runtime_caller: bool,
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Spawn,
        spawn_kind,
        scope_kind: ScopeKind::Unknown,
        join_kind: JoinKind::Unknown,
        await_kind: AwaitKind::Unknown,
        matcher,
        confidence,
        closure_generic,
        filter_runtime_caller,
        entry_arg: None,
    }
}

const fn spawn_c(
    runtime: &'static str,
    api: &'static str,
    spawn_kind: SpawnKind,
    matcher: Matcher,
    confidence: Confidence,
    entry_arg: usize,
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Spawn,
        spawn_kind,
        scope_kind: ScopeKind::Unknown,
        join_kind: JoinKind::Unknown,
        await_kind: AwaitKind::Unknown,
        matcher,
        confidence,
        closure_generic: false,
        filter_runtime_caller: true,
        entry_arg: Some(entry_arg),
    }
}

const fn join(
    runtime: &'static str,
    api: &'static str,
    join_kind: JoinKind,
    matcher: Matcher,
    confidence: Confidence,
    filter_runtime_caller: bool,
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Join,
        spawn_kind: SpawnKind::Unknown,
        scope_kind: ScopeKind::Unknown,
        join_kind,
        await_kind: AwaitKind::Unknown,
        matcher,
        confidence,
        closure_generic: false,
        filter_runtime_caller,
        entry_arg: None,
    }
}

const fn await_rule(
    runtime: &'static str,
    api: &'static str,
    await_kind: AwaitKind,
    matcher: Matcher,
    confidence: Confidence,
    filter_runtime_caller: bool,
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Await,
        spawn_kind: SpawnKind::Unknown,
        scope_kind: ScopeKind::Unknown,
        join_kind: JoinKind::Unknown,
        await_kind,
        matcher,
        confidence,
        closure_generic: false,
        filter_runtime_caller,
        entry_arg: None,
    }
}

const fn scope(
    runtime: &'static str,
    api: &'static str,
    scope_kind: ScopeKind,
    matcher: Matcher,
    confidence: Confidence,
    closure_generic: bool,
    filter_runtime_caller: bool,
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Scope,
        spawn_kind: SpawnKind::Unknown,
        scope_kind,
        join_kind: JoinKind::Unknown,
        await_kind: AwaitKind::Unknown,
        matcher,
        confidence,
        closure_generic,
        filter_runtime_caller,
        entry_arg: None,
    }
}

static RULES: &[Rule] = &[
    // ---- Rust std: structured concurrency and threads ---------------------
    scope(
        "rust-std",
        "thread::scope",
        ScopeKind::RustThreadScope,
        Matcher::DemangledContains("std::thread::scoped::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-std",
        "thread::scope",
        ScopeKind::RustThreadScope,
        Matcher::DemangledContains("std::thread::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "thread::Builder::spawn_scoped",
        SpawnKind::ScopedThread,
        Matcher::DemangledContains("std::thread::builder::Builder>::spawn_scoped::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "Scope::spawn",
        SpawnKind::ScopedThread,
        Matcher::DemangledContains("std::thread::scoped::Scope>::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "thread::Builder::spawn_unchecked",
        SpawnKind::OsThread,
        Matcher::DemangledContains("std::thread::builder::Builder>::spawn_unchecked::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "thread::lifecycle::spawn_unchecked",
        SpawnKind::OsThread,
        Matcher::DemangledContains("std::thread::lifecycle::spawn_unchecked::<"),
        Confidence::Medium,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "thread::Builder::spawn",
        SpawnKind::OsThread,
        Matcher::DemangledContains("std::thread::builder::Builder>::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "thread::spawn",
        SpawnKind::OsThread,
        Matcher::DemangledContains("std::thread::functions::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-std",
        "thread::spawn",
        SpawnKind::OsThread,
        Matcher::DemangledContains("std::thread::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    join(
        "rust-std",
        "JoinHandle::join",
        JoinKind::Join,
        Matcher::DemangledContainsAll(&["std::thread::join_handle::JoinHandle", ">::join"]),
        Confidence::High,
        true,
    ),
    join(
        "rust-std",
        "JoinHandle::join",
        JoinKind::Join,
        Matcher::DemangledContainsAll(&["std::thread::JoinHandle", ">::join"]),
        Confidence::High,
        true,
    ),
    join(
        "rust-std",
        "ScopedJoinHandle::join",
        JoinKind::Join,
        Matcher::DemangledContainsAll(&["std::thread::scoped::ScopedJoinHandle", ">::join"]),
        Confidence::High,
        true,
    ),
    join(
        "rust-std",
        "JoinHandle::abort",
        JoinKind::Abort,
        Matcher::DemangledContainsAll(&["std::thread::JoinHandle", ">::abort"]),
        Confidence::Medium,
        true,
    ),
    // ---- Rayon -----------------------------------------------------------
    scope(
        "rust-rayon",
        "rayon::scope",
        ScopeKind::RayonScope,
        Matcher::DemangledContains("rayon_core::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-rayon",
        "rayon::join",
        ScopeKind::RayonJoin,
        Matcher::DemangledContains("rayon_core::join::join::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-rayon",
        "rayon::join",
        ScopeKind::RayonJoin,
        Matcher::DemangledContains("rayon_core::join::join_context::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-rayon",
        "rayon::join",
        ScopeKind::RayonJoin,
        Matcher::DemangledContains("rayon_core::join::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-rayon",
        "rayon::scope",
        ScopeKind::RayonScope,
        Matcher::DemangledContains("rayon_core::scope::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-rayon",
        "rayon::Scope::spawn",
        SpawnKind::RayonTask,
        Matcher::DemangledContains("rayon_core::scope::Scope>::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-rayon",
        "rayon::ParallelIterator",
        ScopeKind::RayonScope,
        Matcher::DemangledContainsAll(&["rayon", "ParallelIterator>::"]),
        Confidence::Low,
        false,
        true,
    ),
    spawn(
        "rust-rayon",
        "rayon::spawn",
        SpawnKind::RayonTask,
        Matcher::DemangledContains("rayon_core::spawn::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-rayon",
        "rayon::spawn",
        SpawnKind::RayonTask,
        Matcher::DemangledContains("rayon_core::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-rayon",
        "rayon::spawn",
        SpawnKind::RayonTask,
        Matcher::DemangledContains("rayon::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-rayon",
        "rayon::scope",
        ScopeKind::RayonScope,
        Matcher::DemangledContains("rayon::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    // ---- crossbeam -------------------------------------------------------
    scope(
        "rust-crossbeam",
        "crossbeam::scope",
        ScopeKind::CrossbeamScope,
        Matcher::DemangledContains("crossbeam_utils::thread::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-crossbeam",
        "crossbeam::Scope::spawn",
        SpawnKind::ScopedThread,
        Matcher::DemangledContains("crossbeam_utils::thread::Scope>::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    scope(
        "rust-crossbeam",
        "crossbeam::scope",
        ScopeKind::CrossbeamScope,
        Matcher::DemangledContains("crossbeam::thread::scope::<"),
        Confidence::High,
        true,
        true,
    ),
    join(
        "rust-crossbeam",
        "crossbeam::ScopedJoinHandle::join",
        JoinKind::Join,
        Matcher::DemangledContainsAll(&["crossbeam_utils::thread::ScopedJoinHandle", ">::join"]),
        Confidence::High,
        true,
    ),
    join(
        "rust-crossbeam",
        "crossbeam::ScopedJoinHandle::join",
        JoinKind::Join,
        Matcher::DemangledContainsAll(&["crossbeam::thread::ScopedJoinHandle", ">::join"]),
        Confidence::High,
        true,
    ),
    spawn(
        "rust-crossbeam",
        "crossbeam::Scope::spawn",
        SpawnKind::ScopedThread,
        Matcher::DemangledContains("crossbeam::thread::Scope>::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    // ---- Tokio / async-std / smol ---------------------------------------
    spawn(
        "rust-tokio",
        "tokio::task::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("tokio::task::spawn::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-tokio",
        "tokio::task::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("tokio::task::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-tokio",
        "tokio::task::spawn_blocking",
        SpawnKind::OsThread,
        Matcher::DemangledContains("tokio::task::spawn_blocking::<"),
        Confidence::Medium,
        true,
        true,
    ),
    spawn(
        "rust-tokio",
        "tokio::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("tokio::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    await_rule(
        "rust-tokio",
        "tokio::JoinHandle::poll",
        AwaitKind::JoinHandle,
        Matcher::DemangledContainsAll(&["tokio::task::join_handle::JoinHandle", "::poll"]),
        Confidence::Medium,
        true,
    ),
    spawn(
        "rust-async-std",
        "async_std::task::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("async_std::task::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    spawn(
        "rust-async-std",
        "async_std::task::spawn_blocking",
        SpawnKind::OsThread,
        Matcher::DemangledContains("async_std::task::spawn_blocking::<"),
        Confidence::Medium,
        true,
        true,
    ),
    await_rule(
        "rust-async-std",
        "async_std::JoinHandle::poll",
        AwaitKind::JoinHandle,
        Matcher::DemangledContainsAll(&["async_std::task::join_handle::JoinHandle", "::poll"]),
        Confidence::Medium,
        true,
    ),
    await_rule(
        "rust-async-std",
        "async_std::JoinHandle::poll",
        AwaitKind::JoinHandle,
        Matcher::DemangledContainsAll(&["async_std::task::JoinHandle", "::poll"]),
        Confidence::Medium,
        true,
    ),
    spawn(
        "rust-smol",
        "smol::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("smol::spawn::<"),
        Confidence::High,
        true,
        true,
    ),
    await_rule(
        "rust-smol",
        "smol::Task::poll",
        AwaitKind::JoinHandle,
        Matcher::DemangledContainsAll(&["smol::task::Task", "::poll"]),
        Confidence::Low,
        true,
    ),
    spawn(
        "rust-embassy",
        "embassy::Spawner::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("embassy_executor::Spawner>::spawn::<"),
        Confidence::Medium,
        true,
        true,
    ),
    spawn(
        "rust-embassy",
        "embassy::Spawner::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContainsAll(&["embassy_executor::", "Spawner>::spawn::<"]),
        Confidence::Medium,
        true,
        true,
    ),
    await_rule(
        "rust-embassy",
        "embassy::Task::poll",
        AwaitKind::JoinHandle,
        Matcher::DemangledContainsAll(&["embassy_executor::task::Task", "::poll"]),
        Confidence::Low,
        true,
    ),
    spawn(
        "rust-rtic",
        "rtic::spawn",
        SpawnKind::ExecutorTask,
        Matcher::DemangledContainsAll(&["rtic::", "spawn"]),
        Confidence::Medium,
        true,
        true,
    ),
    // ---- C++ standard library and OpenMP --------------------------------
    // C++ symbols remain Itanium-mangled. The constructor instantiations for
    // a callable are identifiable by the template marker after C1/C2; move
    // constructors do not contain it. Runtime code later matches that marker
    // against generated `_M_run` symbols to recover a conservative entry.
    spawn(
        "cpp-std",
        "std::thread::thread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt6threadC1I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::thread::thread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt6threadCI1I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::thread::thread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt6threadCI2I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::thread::thread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt6threadC2I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::thread::thread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt3__16threadC1I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::thread::thread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt3__16threadC2I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::jthread::jthread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt7jthreadC1I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::jthread::jthread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt7jthreadC2I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::jthread::jthread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt3__17jthreadC1I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::jthread::jthread",
        SpawnKind::OsThread,
        Matcher::RawContains("_ZNSt3__17jthreadC2I"),
        Confidence::Medium,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::async",
        SpawnKind::AsyncTask,
        Matcher::RawContains("_ZNSt5asyncI"),
        Confidence::Low,
        false,
        true,
    ),
    spawn(
        "cpp-std",
        "std::async",
        SpawnKind::AsyncTask,
        Matcher::RawContains("_ZNSt3__15asyncI"),
        Confidence::Low,
        false,
        true,
    ),
    join(
        "cpp-std",
        "std::thread::join",
        JoinKind::Join,
        Matcher::RawContains("_ZNSt6thread4joinEv"),
        Confidence::High,
        true,
    ),
    join(
        "cpp-std",
        "std::thread::join",
        JoinKind::Join,
        Matcher::RawContains("_ZNSt3__16thread4joinEv"),
        Confidence::High,
        true,
    ),
    join(
        "cpp-std",
        "std::thread::detach",
        JoinKind::Detach,
        Matcher::RawContains("_ZNSt6thread6detachEv"),
        Confidence::High,
        true,
    ),
    join(
        "cpp-std",
        "std::thread::detach",
        JoinKind::Detach,
        Matcher::RawContains("_ZNSt3__16thread6detachEv"),
        Confidence::High,
        true,
    ),
    join(
        "cpp-std",
        "std::jthread::join",
        JoinKind::Join,
        Matcher::RawContains("_ZNSt7jthread4joinEv"),
        Confidence::High,
        true,
    ),
    join(
        "cpp-std",
        "std::jthread::join",
        JoinKind::Join,
        Matcher::RawContains("_ZNSt3__17jthread4joinEv"),
        Confidence::High,
        true,
    ),
    // OpenMP outlined regions are real parallel contexts. GCC's GOMP passes
    // the entry as argument 0; LLVM's libomp fork-call passes it as argument 2.
    spawn_c(
        "openmp",
        "GOMP_parallel",
        SpawnKind::OpenMpRegion,
        Matcher::RawExact("GOMP_parallel"),
        Confidence::High,
        0,
    ),
    spawn_c(
        "openmp",
        "GOMP_parallel_start",
        SpawnKind::OpenMpRegion,
        Matcher::RawExact("GOMP_parallel_start"),
        Confidence::High,
        0,
    ),
    spawn_c(
        "openmp",
        "__kmpc_fork_call",
        SpawnKind::OpenMpRegion,
        Matcher::RawExact("__kmpc_fork_call"),
        Confidence::High,
        2,
    ),
    spawn_c(
        "openmp",
        "__kmpc_fork_teams",
        SpawnKind::OpenMpRegion,
        Matcher::RawExact("__kmpc_fork_teams"),
        Confidence::High,
        2,
    ),
    // ---- POSIX / RTOS C APIs (entry argument recovered by value tracking) --
    spawn_c(
        "pthread",
        "pthread_create",
        SpawnKind::OsThread,
        Matcher::RawExact("pthread_create"),
        Confidence::High,
        2,
    ),
    spawn_c(
        "pthread",
        "pthread_create",
        SpawnKind::OsThread,
        Matcher::RawExact("_pthread_create"),
        Confidence::High,
        2,
    ),
    join(
        "pthread",
        "pthread_join",
        JoinKind::Join,
        Matcher::RawExact("pthread_join"),
        Confidence::High,
        true,
    ),
    join(
        "pthread",
        "pthread_detach",
        JoinKind::Detach,
        Matcher::RawExact("pthread_detach"),
        Confidence::High,
        true,
    ),
    spawn_c(
        "freertos",
        "xTaskCreate",
        SpawnKind::OsThread,
        Matcher::RawExact("xTaskCreate"),
        Confidence::High,
        0,
    ),
    spawn_c(
        "freertos",
        "xTaskCreateStatic",
        SpawnKind::OsThread,
        Matcher::RawExact("xTaskCreateStatic"),
        Confidence::High,
        0,
    ),
    spawn_c(
        "freertos",
        "xTaskCreatePinnedToCore",
        SpawnKind::OsThread,
        Matcher::RawExact("xTaskCreatePinnedToCore"),
        Confidence::High,
        0,
    ),
    join(
        "freertos",
        "vTaskDelete",
        JoinKind::Abort,
        Matcher::RawExact("vTaskDelete"),
        Confidence::High,
        true,
    ),
    spawn_c(
        "zephyr",
        "k_thread_create",
        SpawnKind::OsThread,
        Matcher::RawExact("k_thread_create"),
        Confidence::High,
        3,
    ),
    join(
        "zephyr",
        "k_thread_join",
        JoinKind::Join,
        Matcher::RawExact("k_thread_join"),
        Confidence::High,
        true,
    ),
    join(
        "zephyr",
        "k_thread_abort",
        JoinKind::Abort,
        Matcher::RawExact("k_thread_abort"),
        Confidence::High,
        true,
    ),
    spawn_c(
        "threadx",
        "tx_thread_create",
        SpawnKind::OsThread,
        Matcher::RawExact("tx_thread_create"),
        Confidence::High,
        2,
    ),
    join(
        "threadx",
        "tx_thread_terminate",
        JoinKind::Abort,
        Matcher::RawExact("tx_thread_terminate"),
        Confidence::High,
        true,
    ),
];

/// Matches a callee function against the rule database.
#[must_use]
pub fn match_function(function: &Function) -> Option<&'static Rule> {
    let primary = normalize_crate_hashes(&function.primary_name);
    let demangled = function
        .demangled_name
        .as_deref()
        .map(normalize_crate_hashes);
    RULES
        .iter()
        .find(|rule| rule.matches(function, &primary, demangled.as_deref()))
}

impl Rule {
    fn matches(&self, function: &Function, primary: &str, demangled: Option<&str>) -> bool {
        match self.matcher {
            Matcher::RawExact(name) => {
                primary == name || function.symbols.iter().any(|symbol| symbol == name)
            }
            Matcher::RawContains(needle) => {
                primary.contains(needle)
                    || function
                        .symbols
                        .iter()
                        .any(|symbol| symbol.contains(needle))
            }
            _ => {
                self.matches_demangled(primary)
                    || demangled.is_some_and(|name| self.matches_demangled(name))
            }
        }
    }

    fn matches_demangled(&self, name: &str) -> bool {
        match self.matcher {
            Matcher::DemangledContains(needle) => name.contains(needle),
            Matcher::DemangledContainsAll(needles) => {
                needles.iter().all(|needle| name.contains(needle))
            }
            Matcher::RawExact(_) | Matcher::RawContains(_) => false,
        }
    }
}

/// Matches an already-demangled function name against the rule database.
#[must_use]
pub fn match_demangled_name(name: &str) -> Option<&'static Rule> {
    let normalized = normalize_crate_hashes(name);
    RULES
        .iter()
        .find(|rule| rule.matches_demangled(&normalized))
}

/// Removes rustc-demangle crate-hash segments such as `[f9fb83b88fa27b65]`.
#[must_use]
pub fn normalize_crate_hashes(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if character == '['
            && let Some(close) = name[index + 1..].find(']')
        {
            let content = &name[index + 1..index + 1 + close];
            if content.len() >= 8 && content.chars().all(|c| c.is_ascii_hexdigit()) {
                let end = index + 1 + close;
                while let Some(&(next_index, _)) = chars.peek() {
                    if next_index <= end {
                        chars.next();
                    } else {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(character);
    }
    out
}

/// Extracts the Itanium-mangled lambda/callable marker from a C++ thread
/// constructor such as
/// `_ZNSt6threadC1IZ4mainEUlvE_JEvEEOT_DpOT0_`.
///
/// The marker (`Z4mainEUlvE_` here) also appears in the generated
/// `_State_impl<...>::_M_run` symbol, which lets the analyzer recover a
/// conservative thread entry without a full C++ demangler.
#[must_use]
pub fn cpp_callable_marker(name: &str) -> Option<&str> {
    let constructor = ["CI1I", "CI2I", "C1I", "C2I"]
        .iter()
        .find_map(|pattern| name.find(pattern).map(|index| index + pattern.len()))?;
    let suffix = &name[constructor..];
    let start = suffix.find('Z')?;
    let tail = &suffix[start..];
    let end = tail.find('J').unwrap_or(tail.len());
    let marker = &tail[..end];
    (marker.len() >= 4 && marker.starts_with('Z')).then_some(marker)
}

/// Extracts the first generic argument from a demangled Rust function symbol.
///
/// For `std::thread::functions::spawn::<app::main::{closure#0}, ()>` this
/// returns `app::main::{closure#0}`.
#[must_use]
pub fn extract_first_generic_arg(name: &str) -> Option<String> {
    let normalized = normalize_crate_hashes(name);
    let start = normalized.rfind("::<")? + 3;
    let mut depth = 1usize;
    let mut end = None;
    for (offset, character) in normalized[start..].char_indices() {
        match character {
            '<' => depth += 1,
            '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = Some(start + offset);
                    break;
                }
            }
            ',' if depth == 1 => {
                end = Some(start + offset);
                break;
            }
            _ => {}
        }
    }
    let candidate = normalized[start..end?].trim();
    if candidate.is_empty() || candidate == "()" {
        None
    } else {
        Some(candidate.to_owned())
    }
}

/// Whether a function belongs to the Rust runtime implementation.
///
/// Calls originating inside these crates are ignored so a single user
/// `thread::spawn` is not also reported as an internal `Builder::spawn`.
#[must_use]
pub fn is_runtime_internal(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "std::",
        "core::",
        "alloc::",
        "rayon_core::",
        "rayon::",
        "crossbeam_utils::",
        "crossbeam::",
        "tokio::",
        "async_std::",
        "smol::",
        "embassy_executor::",
        "rtic::",
        "futures_",
    ];
    // C++ runtime symbols are still Itanium-mangled when they reach here.
    const CPP_PREFIXES: &[&str] = &[
        "_ZNSt6thread",
        "_ZNKSt6thread",
        "_ZNSt7jthread",
        "_ZNKSt7jthread",
        "_ZNSt5async",
        "_ZNSt6future",
        "_ZNSt7promise",
        "_ZNSt3__16thread",
        "_ZNKSt3__16thread",
        "_ZNSt3__17jthread",
        "_ZNKSt3__17jthread",
        "_ZNSt3__15async",
    ];
    if CPP_PREFIXES
        .iter()
        .any(|prefix| name.trim_start().starts_with(prefix))
    {
        return true;
    }
    let normalized = normalize_crate_hashes(name);
    let mut normalized = normalized.trim();
    loop {
        let trimmed = normalized
            .trim_start_matches(|character: char| {
                character == '<' || character == '&' || character.is_whitespace()
            })
            .trim();
        let trimmed = trimmed.strip_prefix("mut ").unwrap_or(trimmed).trim();
        if trimmed == normalized {
            break;
        }
        normalized = trimmed;
    }
    PREFIXES.iter().any(|prefix| normalized.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::{
        RuleOp, cpp_callable_marker, extract_first_generic_arg, is_runtime_internal,
        match_demangled_name, match_function, normalize_crate_hashes,
    };
    use elf2tdg_schema::{Addr, Function, FunctionId, FunctionKind, Language, SpawnKind};
    use std::collections::BTreeMap;

    fn function(primary: &str, symbols: &[&str], language: Language) -> Function {
        Function {
            id: FunctionId::new("fn:0x1000"),
            primary_name: primary.to_owned(),
            demangled_name: Some(primary.to_owned()),
            symbols: symbols.iter().map(|symbol| (*symbol).to_owned()).collect(),
            language,
            address: Addr::new(0x1000),
            size: 0,
            section: Some(".text".to_owned()),
            kind: FunctionKind::Normal,
            blocks: Vec::new(),
            timing: None,
            source: None,
            inline_sites: Vec::new(),
            ext: BTreeMap::new(),
        }
    }

    #[test]
    fn normalizes_crate_hashes() {
        assert_eq!(
            normalize_crate_hashes(
                "std[f9fb83b88fa27b65]::thread::functions::spawn::<app[0123456789abcdef]::main::{closure#0}, ()>"
            ),
            "std::thread::functions::spawn::<app::main::{closure#0}, ()>"
        );
    }

    #[test]
    fn extracts_closure_type() {
        assert_eq!(
            extract_first_generic_arg(
                "std::thread::functions::spawn::<app::main::{closure#0}, ()>"
            )
            .as_deref(),
            Some("app::main::{closure#0}")
        );
        assert_eq!(
            extract_first_generic_arg(
                "<std::thread::scoped::Scope>::spawn::<app::main::{closure#1}::{closure#0}, ()>"
            )
            .as_deref(),
            Some("app::main::{closure#1}::{closure#0}")
        );
    }

    #[test]
    fn matches_rust_spawn_and_scope() {
        let spawn = function(
            "std[f9fb83b88fa27b65]::thread::functions::spawn::<app[0123456789abcdef]::main::{closure#0}, ()>",
            &["_RINvNtNtNtCslsElW4ClnEv_3std6thread...E"],
            Language::Rust,
        );
        let rule = match_function(&spawn).expect("spawn rule");
        assert_eq!(rule.op, RuleOp::Spawn);
        assert_eq!(rule.spawn_kind, SpawnKind::OsThread);

        let scope = function(
            "std[f9fb83b88fa27b65]::thread::scoped::scope::<app[0123456789abcdef]::main::{closure#1}, ()>",
            &["_RINvNtNtCslsElW4ClnEv_3std6thread...E"],
            Language::Rust,
        );
        let rule = match_function(&scope).expect("scope rule");
        assert_eq!(rule.op, RuleOp::Scope);
    }

    #[test]
    fn matches_parallel_and_async_runtimes() {
        for (name, runtime, op) in [
            (
                "rayon_core[1111111111111111]::scope::<app::main::{closure#0}, ()>",
                "rust-rayon",
                RuleOp::Scope,
            ),
            (
                "rayon_core[1111111111111111]::join::<app::a, app::b>",
                "rust-rayon",
                RuleOp::Scope,
            ),
            (
                "tokio[2222222222222222]::task::spawn::spawn::<app::main::{closure#0}>",
                "rust-tokio",
                RuleOp::Spawn,
            ),
            (
                "tokio[2222222222222222]::task::spawn::<app::main::{closure#0}>",
                "rust-tokio",
                RuleOp::Spawn,
            ),
            (
                "<embassy_executor[3333333333333333]::spawner::Spawner>::spawn::<app::main::{closure#0}>",
                "rust-embassy",
                RuleOp::Spawn,
            ),
            (
                "<crossbeam_utils[4444444444444444]::thread::Scope>::spawn::<app::main::{closure#0}, ()>",
                "rust-crossbeam",
                RuleOp::Spawn,
            ),
        ] {
            let function = function(name, &["_R..."], Language::Rust);
            let rule = match_function(&function).unwrap_or_else(|| panic!("no rule for {name}"));
            assert_eq!(rule.runtime, runtime, "{name}");
            assert_eq!(rule.op, op, "{name}");
        }
    }

    #[test]
    fn matches_demangled_inline_names() {
        let rule = match_demangled_name(
            "std::thread::lifecycle::spawn_unchecked::<app[1234567890abcdef]::main::{closure#0}, ()>",
        )
        .expect("lifecycle spawn rule");
        assert_eq!(rule.runtime, "rust-std");
        assert_eq!(rule.op, RuleOp::Spawn);
    }

    #[test]
    fn matches_async_handle_polls() {
        for (name, runtime) in [
            (
                "async_std::task::join_handle::JoinHandle<app::main::{closure#0}> as core::future::future::Future>::poll",
                "rust-async-std",
            ),
            (
                "smol::task::Task<app::main::{closure#0}> as core::future::future::Future>::poll",
                "rust-smol",
            ),
            (
                "embassy_executor::task::Task<app::main::{closure#0}> as core::future::future::Future>::poll",
                "rust-embassy",
            ),
        ] {
            let rule = match_demangled_name(name).unwrap_or_else(|| panic!("no rule for {name}"));
            assert_eq!(rule.runtime, runtime);
            assert_eq!(rule.op, RuleOp::Await);
        }
    }

    #[test]
    fn matches_c_rtos_apis() {
        let create = function("pthread_create", &["pthread_create"], Language::C);
        let rule = match_function(&create).expect("pthread rule");
        assert_eq!(rule.runtime, "pthread");
        assert_eq!(rule.op, RuleOp::Spawn);

        let task = function("xTaskCreate", &["xTaskCreate"], Language::C);
        let rule = match_function(&task).expect("freertos rule");
        assert_eq!(rule.runtime, "freertos");
    }

    #[test]
    fn detects_runtime_internal_callers() {
        assert!(is_runtime_internal(
            "std[f9fb83b88fa27b65]::thread::functions::spawn::<...>"
        ));
        assert!(!is_runtime_internal("app::main"));
        assert!(!is_runtime_internal("<app::Worker>::run"));
        assert!(is_runtime_internal(
            "<&mut crossbeam_utils[1111111111111111]::thread::scope<...>>::call_mut"
        ));
        assert!(!is_runtime_internal("<&mut app::Worker>::call_mut"));
        assert!(is_runtime_internal("_ZNSt6thread15_M_start_threadE..."));
        assert!(is_runtime_internal("_ZNKSt6thread8joinableEv"));
        assert!(!is_runtime_internal("_Z4bodyi"));
    }

    #[test]
    fn matches_cpp_threads_and_openmp() {
        let constructor = function(
            "_ZNSt6threadC1IZ4mainEUlvE_JEvEEOT_DpOT0_",
            &["_ZNSt6threadC1IZ4mainEUlvE_JEvEEOT_DpOT0_"],
            Language::Cpp,
        );
        let rule = match_function(&constructor).expect("C++ thread constructor rule");
        assert_eq!(rule.runtime, "cpp-std");
        assert_eq!(rule.op, RuleOp::Spawn);
        assert_eq!(rule.spawn_kind, SpawnKind::OsThread);

        let join = function(
            "_ZNSt6thread4joinEv",
            &["_ZNSt6thread4joinEv"],
            Language::Cpp,
        );
        let rule = match_function(&join).expect("C++ join rule");
        assert_eq!(rule.op, RuleOp::Join);

        let gomp = function("GOMP_parallel", &["GOMP_parallel"], Language::C);
        let rule = match_function(&gomp).expect("GOMP rule");
        assert_eq!(rule.runtime, "openmp");
        assert_eq!(rule.entry_arg, Some(0));

        let kmpc = function("__kmpc_fork_call", &["__kmpc_fork_call"], Language::C);
        let rule = match_function(&kmpc).expect("libomp rule");
        assert_eq!(rule.runtime, "openmp");
        assert_eq!(rule.entry_arg, Some(2));
    }

    #[test]
    fn extracts_cpp_callable_marker() {
        assert_eq!(
            cpp_callable_marker("_ZNSt6threadC1IZ4mainEUlvE_JEvEEOT_DpOT0_"),
            Some("Z4mainEUlvE_")
        );
        assert_eq!(
            cpp_callable_marker("_ZNSt6threadCI1IZ4mainEUlvE_JEvEEOT_DpOT0_"),
            Some("Z4mainEUlvE_")
        );
        assert_eq!(cpp_callable_marker("_ZNSt6threadD1Ev"), None);
    }
}
