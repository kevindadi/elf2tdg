//! Runtime API recognition rules.
//!
//! Rules match resolved callee functions by raw C symbol or demangled Rust/C++
//! path. Rust symbols are normalized by removing `[crate-hash]` segments so a
//! rule can say `embassy_executor::...` regardless of the toolchain hash.
//!
//! Rust's monomorphized spawn symbols carry the future type as their first
//! generic argument, e.g.
//!
//! ```text
//! <embassy_executor::spawner::Spawner>::spawn::<app::sensor_task::{closure#0}>
//! ```
//!
//! [`extract_first_generic_arg`] recovers that type, which can then be matched
//! to the task poll function emitted by the compiler.

use elf2tdg_schema::{
    AwaitKind, Confidence, Function, JoinKind, LockKind, LockOperation, ScopeKind, SpawnKind,
};

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
    /// Lock/semaphore operation.
    Lock,
    /// Registration of a callback/function pointer.
    Callback,
}

/// Lock metadata attached to a [`RuleOp::Lock`] rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockSpec {
    /// Lock class.
    pub kind: LockKind,
    /// Acquire/try-acquire/release operation.
    pub operation: LockOperation,
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
    /// Runtime identifier, for example `rust-embassy`.
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
    /// Ignore calls made from inside the runtime implementation itself. This
    /// prevents double-reporting a public spawn API and its internal
    /// implementation layer.
    pub filter_runtime_caller: bool,
    /// Argument index carrying the spawn entry function pointer, for C-style
    /// APIs whose entry can be recovered by bounded value tracking.
    pub entry_arg: Option<usize>,
    /// Lock/semaphore classification for [`RuleOp::Lock`].
    pub lock: Option<LockSpec>,
    /// Callback entry argument indices for [`RuleOp::Callback`].
    pub callback_args: Option<&'static [usize]>,
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
        lock: None,
        callback_args: None,
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
        lock: None,
        callback_args: None,
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
        lock: None,
        callback_args: None,
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
        lock: None,
        callback_args: None,
    }
}

const fn lock(
    runtime: &'static str,
    api: &'static str,
    kind: LockKind,
    operation: LockOperation,
    matcher: Matcher,
    confidence: Confidence,
    filter_runtime_caller: bool,
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Lock,
        spawn_kind: SpawnKind::Unknown,
        scope_kind: ScopeKind::Unknown,
        join_kind: JoinKind::Unknown,
        await_kind: AwaitKind::Unknown,
        matcher,
        confidence,
        closure_generic: false,
        filter_runtime_caller,
        entry_arg: None,
        lock: Some(LockSpec { kind, operation }),
        callback_args: None,
    }
}

const fn callback(
    runtime: &'static str,
    api: &'static str,
    matcher: Matcher,
    confidence: Confidence,
    entry_args: &'static [usize],
) -> Rule {
    Rule {
        runtime,
        api,
        op: RuleOp::Callback,
        spawn_kind: SpawnKind::Unknown,
        scope_kind: ScopeKind::Unknown,
        join_kind: JoinKind::Unknown,
        await_kind: AwaitKind::Unknown,
        matcher,
        confidence,
        closure_generic: false,
        filter_runtime_caller: false,
        entry_arg: None,
        lock: None,
        callback_args: Some(entry_args),
    }
}

static RULES: &[Rule] = &[
    // ---- Rust embedded runtimes (no_std) --------------------------------
    spawn(
        "rust-embassy",
        "embassy::Spawner::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContains("embassy_executor::Spawner>::spawn::<"),
        Confidence::Medium,
        true,
        false,
    ),
    spawn(
        "rust-embassy",
        "embassy::Spawner::spawn",
        SpawnKind::AsyncTask,
        Matcher::DemangledContainsAll(&["embassy_executor::", "Spawner>::spawn::<"]),
        Confidence::Medium,
        true,
        false,
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
    // ---- Callback / function-pointer registration -----------------------
    callback(
        "libc",
        "atexit",
        Matcher::RawExact("atexit"),
        Confidence::High,
        &[0],
    ),
    callback(
        "libc",
        "__cxa_atexit",
        Matcher::RawExact("__cxa_atexit"),
        Confidence::High,
        &[0],
    ),
    callback(
        "libc",
        "on_exit",
        Matcher::RawExact("on_exit"),
        Confidence::High,
        &[0],
    ),
    callback(
        "libc",
        "signal",
        Matcher::RawExact("signal"),
        Confidence::High,
        &[1],
    ),
    callback(
        "libc",
        "bsd_signal",
        Matcher::RawExact("bsd_signal"),
        Confidence::High,
        &[1],
    ),
    callback(
        "libc",
        "qsort",
        Matcher::RawExact("qsort"),
        Confidence::High,
        &[3],
    ),
    callback(
        "libc",
        "bsearch",
        Matcher::RawExact("bsearch"),
        Confidence::High,
        &[4],
    ),
    callback(
        "pthread",
        "pthread_once",
        Matcher::RawExact("pthread_once"),
        Confidence::High,
        &[1],
    ),
    callback(
        "pthread",
        "pthread_key_create",
        Matcher::RawExact("pthread_key_create"),
        Confidence::High,
        &[1],
    ),
    callback(
        "pthread",
        "pthread_atfork",
        Matcher::RawExact("pthread_atfork"),
        Confidence::High,
        &[0, 1, 2],
    ),
    callback(
        "libc",
        "ftw",
        Matcher::RawExact("ftw"),
        Confidence::Medium,
        &[1],
    ),
    callback(
        "libc",
        "nftw",
        Matcher::RawExact("nftw"),
        Confidence::Medium,
        &[1],
    ),
    callback(
        "libc",
        "scandir",
        Matcher::RawExact("scandir"),
        Confidence::Medium,
        &[2, 3],
    ),
    callback(
        "freertos",
        "xTimerCreate",
        Matcher::RawExact("xTimerCreate"),
        Confidence::High,
        &[4],
    ),
    callback(
        "freertos",
        "xTimerCreateStatic",
        Matcher::RawExact("xTimerCreateStatic"),
        Confidence::High,
        &[4],
    ),
    callback(
        "freertos",
        "xTimerPendFunctionCall",
        Matcher::RawExact("xTimerPendFunctionCall"),
        Confidence::High,
        &[0],
    ),
    callback(
        "freertos",
        "xTimerPendFunctionCallFromISR",
        Matcher::RawExact("xTimerPendFunctionCallFromISR"),
        Confidence::High,
        &[0],
    ),
    callback(
        "zephyr",
        "k_timer_init",
        Matcher::RawExact("k_timer_init"),
        Confidence::High,
        &[1, 2],
    ),
    callback(
        "zephyr",
        "z_impl_k_timer_init",
        Matcher::RawExact("z_impl_k_timer_init"),
        Confidence::High,
        &[1, 2],
    ),
    callback(
        "zephyr",
        "k_work_init",
        Matcher::RawExact("k_work_init"),
        Confidence::High,
        &[1],
    ),
    callback(
        "threadx",
        "tx_timer_create",
        Matcher::RawExact("tx_timer_create"),
        Confidence::High,
        &[2],
    ),
    // ---- pthread / POSIX -------------------------------------------------
    lock(
        "pthread",
        "pthread_mutex_lock",
        LockKind::Mutex,
        LockOperation::Acquire,
        Matcher::RawExact("pthread_mutex_lock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_mutex_trylock",
        LockKind::Mutex,
        LockOperation::TryAcquire,
        Matcher::RawExact("pthread_mutex_trylock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_mutex_unlock",
        LockKind::Mutex,
        LockOperation::Release,
        Matcher::RawExact("pthread_mutex_unlock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_rwlock_rdlock",
        LockKind::RwLockRead,
        LockOperation::Acquire,
        Matcher::RawExact("pthread_rwlock_rdlock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_rwlock_wrlock",
        LockKind::RwLockWrite,
        LockOperation::Acquire,
        Matcher::RawExact("pthread_rwlock_wrlock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_rwlock_tryrdlock",
        LockKind::RwLockRead,
        LockOperation::TryAcquire,
        Matcher::RawExact("pthread_rwlock_tryrdlock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_rwlock_trywrlock",
        LockKind::RwLockWrite,
        LockOperation::TryAcquire,
        Matcher::RawExact("pthread_rwlock_trywrlock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "pthread_rwlock_unlock",
        LockKind::RwLock,
        LockOperation::Release,
        Matcher::RawExact("pthread_rwlock_unlock"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "sem_wait",
        LockKind::Semaphore,
        LockOperation::Acquire,
        Matcher::RawExact("sem_wait"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "sem_trywait",
        LockKind::Semaphore,
        LockOperation::TryAcquire,
        Matcher::RawExact("sem_trywait"),
        Confidence::High,
        true,
    ),
    lock(
        "pthread",
        "sem_post",
        LockKind::Semaphore,
        LockOperation::Release,
        Matcher::RawExact("sem_post"),
        Confidence::High,
        true,
    ),
    // ---- FreeRTOS / Zephyr / ThreadX ------------------------------------
    lock(
        "freertos",
        "xSemaphoreTake",
        LockKind::Semaphore,
        LockOperation::Acquire,
        Matcher::RawExact("xSemaphoreTake"),
        Confidence::High,
        true,
    ),
    lock(
        "freertos",
        "xSemaphoreTakeRecursive",
        LockKind::Semaphore,
        LockOperation::Acquire,
        Matcher::RawExact("xSemaphoreTakeRecursive"),
        Confidence::High,
        true,
    ),
    lock(
        "freertos",
        "xSemaphoreGive",
        LockKind::Semaphore,
        LockOperation::Release,
        Matcher::RawExact("xSemaphoreGive"),
        Confidence::High,
        true,
    ),
    lock(
        "freertos",
        "xSemaphoreGiveRecursive",
        LockKind::Semaphore,
        LockOperation::Release,
        Matcher::RawExact("xSemaphoreGiveRecursive"),
        Confidence::High,
        true,
    ),
    lock(
        "zephyr",
        "k_mutex_lock",
        LockKind::Mutex,
        LockOperation::Acquire,
        Matcher::RawExact("k_mutex_lock"),
        Confidence::High,
        true,
    ),
    lock(
        "zephyr",
        "k_mutex_unlock",
        LockKind::Mutex,
        LockOperation::Release,
        Matcher::RawExact("k_mutex_unlock"),
        Confidence::High,
        true,
    ),
    lock(
        "zephyr",
        "k_sem_take",
        LockKind::Semaphore,
        LockOperation::Acquire,
        Matcher::RawExact("k_sem_take"),
        Confidence::High,
        true,
    ),
    lock(
        "zephyr",
        "k_sem_give",
        LockKind::Semaphore,
        LockOperation::Release,
        Matcher::RawExact("k_sem_give"),
        Confidence::High,
        true,
    ),
    lock(
        "threadx",
        "tx_mutex_get",
        LockKind::Mutex,
        LockOperation::Acquire,
        Matcher::RawExact("tx_mutex_get"),
        Confidence::High,
        true,
    ),
    lock(
        "threadx",
        "tx_mutex_put",
        LockKind::Mutex,
        LockOperation::Release,
        Matcher::RawExact("tx_mutex_put"),
        Confidence::High,
        true,
    ),
    lock(
        "threadx",
        "tx_semaphore_get",
        LockKind::Semaphore,
        LockOperation::Acquire,
        Matcher::RawExact("tx_semaphore_get"),
        Confidence::High,
        true,
    ),
    lock(
        "threadx",
        "tx_semaphore_put",
        LockKind::Semaphore,
        LockOperation::Release,
        Matcher::RawExact("tx_semaphore_put"),
        Confidence::High,
        true,
    ),
    // ---- C++ std::mutex / shared_mutex ----------------------------------
    lock(
        "cpp-std",
        "std::mutex::lock",
        LockKind::Mutex,
        LockOperation::Acquire,
        Matcher::RawExact("_ZNSt5mutex4lockEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::mutex::try_lock",
        LockKind::Mutex,
        LockOperation::TryAcquire,
        Matcher::RawExact("_ZNSt5mutex8try_lockEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::mutex::unlock",
        LockKind::Mutex,
        LockOperation::Release,
        Matcher::RawExact("_ZNSt5mutex6unlockEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::shared_mutex::lock_shared",
        LockKind::RwLockRead,
        LockOperation::Acquire,
        Matcher::RawExact("_ZNSt12shared_mutex11lock_sharedEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::shared_mutex::unlock_shared",
        LockKind::RwLockRead,
        LockOperation::Release,
        Matcher::RawExact("_ZNSt12shared_mutex13unlock_sharedEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::shared_mutex::try_lock_shared",
        LockKind::RwLockRead,
        LockOperation::TryAcquire,
        Matcher::RawExact("_ZNSt12shared_mutex15try_lock_sharedEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::shared_mutex::lock",
        LockKind::RwLockWrite,
        LockOperation::Acquire,
        Matcher::RawExact("_ZNSt12shared_mutex4lockEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::shared_mutex::unlock",
        LockKind::RwLockWrite,
        LockOperation::Release,
        Matcher::RawExact("_ZNSt12shared_mutex6unlockEv"),
        Confidence::High,
        true,
    ),
    lock(
        "cpp-std",
        "std::shared_mutex::try_lock",
        LockKind::RwLockWrite,
        LockOperation::TryAcquire,
        Matcher::RawExact("_ZNSt12shared_mutex8try_lockEv"),
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

/// Matches an inlined subroutine by its demangled name and raw linkage name.
///
/// Demangled rules are tried first. Raw matchers are needed for C++ inline
/// frames whose Itanium symbol is not demangled by the lightweight display
/// name path.
#[must_use]
pub fn match_inline_names(name: &str, raw_linkage: Option<&str>) -> Option<&'static Rule> {
    let normalized = normalize_crate_hashes(name);
    RULES.iter().find(|rule| {
        rule.matches_demangled(&normalized)
            || raw_linkage.is_some_and(|raw| match rule.matcher {
                Matcher::RawExact(expected) => raw == expected,
                Matcher::RawContains(needle) => raw.contains(needle),
                Matcher::DemangledContains(_) | Matcher::DemangledContainsAll(_) => false,
            })
    })
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

/// Returns true when a function is known by API or ABI convention not to
/// return to its caller.
///
/// This is deliberately a name-based classification: it covers C/POSIX exit
/// and abort entry points, Rust panic entry points, compiler runtime failure
/// hooks and C++ termination/unwind helpers. Functions that merely contain a
/// halt loop are classified from their recovered control-flow graph instead.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn is_noreturn_name(name: &str) -> bool {
    let normalized = normalize_crate_hashes(name);
    // Rust monomorphized names end in `::<...>`; drop that suffix before
    // taking the final path component so `begin_panic::<&str>` still matches.
    let path = normalized
        .split("::<")
        .next()
        .unwrap_or(normalized.as_str());
    let bare = path
        .rsplit("::")
        .next()
        .unwrap_or(path)
        .split('<')
        .next()
        .unwrap_or(path)
        .split('(')
        .next()
        .unwrap_or(path)
        .trim();
    let namespaced = normalized.contains("::");

    if !namespaced
        && matches!(
            bare,
            "abort"
                | "_abort"
                | "exit"
                | "_exit"
                | "_Exit"
                | "quick_exit"
                | "thrd_exit"
                | "pthread_exit"
                | "longjmp"
                | "_longjmp"
                | "siglongjmp"
                | "__longjmp_chk"
                | "__assert"
                | "__assert_fail"
                | "__assert_func"
                | "__assert_perror_fail"
                | "__stack_chk_fail"
                | "__stack_chk_fail_local"
                | "__libc_fatal"
                | "__cxa_throw"
                | "__cxa_rethrow"
                | "__cxa_pure_virtual"
                | "__cxa_call_terminate"
                | "terminate"
                | "_Unwind_Resume"
                | "__rust_start_panic"
                | "rust_begin_unwind"
                | "rust_panic"
                | "__rust_alloc_error_handler"
                | "__rg_oom"
                | "NVIC_SystemReset"
                | "__NVIC_SystemReset"
                | "k_panic"
                | "z_fatal_error"
                | "arch_system_halt"
                | "esp_system_abort"
                | "esp_restart"
        )
    {
        return true;
    }

    if normalized.contains("::panicking::")
        && (bare.starts_with("panic")
            || bare.starts_with("begin_panic")
            || bare.starts_with("rust_panic")
            || bare == "assert_failed")
    {
        return true;
    }
    if normalized.contains("::intrinsics::") && matches!(bare, "abort" | "unreachable") {
        return true;
    }
    if normalized.contains("::hint::") && bare == "unreachable_unchecked" {
        return true;
    }
    if normalized.contains("::process::") && matches!(bare, "abort" | "exit" | "_exit") {
        return true;
    }
    if normalized.contains("::alloc::")
        && matches!(bare, "handle_alloc_error" | "capacity_overflow")
    {
        return true;
    }
    if (normalized.contains("::option::") || normalized.contains("::result::"))
        && bare == "unwrap_failed"
    {
        return true;
    }
    if normalized.contains("::slice::index::")
        && bare.starts_with("slice_")
        && bare.ends_with("_fail")
    {
        return true;
    }
    if normalized.contains("::str::") && bare == "slice_error_fail" {
        return true;
    }
    if normalized.contains("std::terminate")
        || normalized.contains("__gnu_cxx::__verbose_terminate_handler")
        || normalized.starts_with("_ZSt9terminate")
    {
        return true;
    }
    false
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
/// For `<embassy_executor::spawner::Spawner>::spawn::<app::sensor_task>`
/// this returns `app::sensor_task`.
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
/// Calls originating inside these crates are ignored so a public runtime API
/// is not also reported as its internal implementation layer.
#[must_use]
pub fn is_runtime_internal(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "core::",
        "alloc::",
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
        RuleOp, cpp_callable_marker, extract_first_generic_arg, is_noreturn_name,
        is_runtime_internal, match_demangled_name, match_function, match_inline_names,
        normalize_crate_hashes,
    };
    use elf2tdg_schema::{
        Addr, Function, FunctionId, FunctionKind, Language, LockKind, LockOperation, SpawnKind,
    };
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
                "<embassy_executor[3333333333333333]::spawner::Spawner>::spawn::<app[0123456789abcdef]::sensor_task::{closure#0}>"
            ),
            "<embassy_executor::spawner::Spawner>::spawn::<app::sensor_task::{closure#0}>"
        );
    }

    #[test]
    fn extracts_closure_type() {
        assert_eq!(
            extract_first_generic_arg(
                "<embassy_executor::spawner::Spawner>::spawn::<app::sensor_task::{closure#0}>"
            )
            .as_deref(),
            Some("app::sensor_task::{closure#0}")
        );
        assert_eq!(
            extract_first_generic_arg(
                "<embassy_executor::spawner::Spawner>::spawn::<app::monitor_task>"
            )
            .as_deref(),
            Some("app::monitor_task")
        );
    }

    #[test]
    fn matches_embedded_rust_spawns_only() {
        let embassy = function(
            "<embassy_executor[3333333333333333]::spawner::Spawner>::spawn::<app::sensor_task::{closure#0}>",
            &["_R..."],
            Language::Rust,
        );
        let rule = match_function(&embassy).expect("Embassy spawner rule");
        assert_eq!(rule.runtime, "rust-embassy");
        assert_eq!(rule.op, RuleOp::Spawn);
        assert_eq!(rule.spawn_kind, SpawnKind::AsyncTask);

        let rtic = function(
            "rtic[4444444444444444]::spawn::<app::sensor_task>",
            &["_R..."],
            Language::Rust,
        );
        let rule = match_function(&rtic).expect("RTIC spawn rule");
        assert_eq!(rule.runtime, "rust-rtic");
        assert_eq!(rule.op, RuleOp::Spawn);

        let std_thread = function(
            "std[f9fb83b88fa27b65]::thread::functions::spawn::<app[0123456789abcdef]::main::{closure#0}, ()>",
            &["_RINvNtNtNtCslsElW4ClnEv_3std6thread...E"],
            Language::Rust,
        );
        assert!(
            match_function(&std_thread).is_none(),
            "std::thread is outside the supported no_std Rust profile"
        );
        let tokio = function(
            "tokio[2222222222222222]::task::spawn::<app::main::{closure#0}>",
            &["_R..."],
            Language::Rust,
        );
        assert!(
            match_function(&tokio).is_none(),
            "tokio is outside the supported no_std Rust profile"
        );
    }

    #[test]
    fn matches_embassy_inline_spawner_calls() {
        let rule = match_demangled_name(
            "<embassy_executor[3333333333333333]::spawner::Spawner>::spawn::<app[1234567890abcdef]::sensor_task::{closure#0}>",
        )
        .expect("Embassy inline spawner rule");
        assert_eq!(rule.runtime, "rust-embassy");
        assert_eq!(rule.op, RuleOp::Spawn);
    }

    #[test]
    fn matches_embassy_task_poll() {
        let rule = match_demangled_name(
            "embassy_executor::task::Task<app::main::{closure#0}> as core::future::future::Future>::poll",
        )
        .expect("Embassy task poll rule");
        assert_eq!(rule.runtime, "rust-embassy");
        assert_eq!(rule.op, RuleOp::Await);
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
    fn matches_lock_rules_by_demangled_and_raw_names() {
        let pthread = function(
            "pthread_mutex_unlock",
            &["pthread_mutex_unlock"],
            Language::C,
        );
        let rule = match_function(&pthread).expect("pthread unlock rule");
        assert_eq!(rule.op, RuleOp::Lock);
        assert_eq!(rule.lock.map(|lock| lock.kind), Some(LockKind::Mutex));
        assert_eq!(
            rule.lock.map(|lock| lock.operation),
            Some(LockOperation::Release)
        );

        let inline = match_inline_names("std::mutex::lock", Some("_ZNSt5mutex4lockEv"))
            .expect("C++ inline lock rule");
        assert_eq!(inline.op, RuleOp::Lock);
        assert_eq!(inline.lock.map(|lock| lock.kind), Some(LockKind::Mutex));

        let std_mutex = function(
            "<std[f9fb83b88fa27b65]::sync::poison::mutex::Mutex<u64>>::lock",
            &["_R..."],
            Language::Rust,
        );
        assert!(
            match_function(&std_mutex).is_none(),
            "std Mutex is outside the supported no_std Rust profile"
        );
    }

    #[test]
    fn detects_runtime_internal_callers() {
        assert!(is_runtime_internal(
            "<embassy_executor[3333333333333333]::raw::TaskStorage<...>>::poll"
        ));
        assert!(is_runtime_internal(
            "core[581b33c2f4131567]::future::poll_fn"
        ));
        assert!(is_runtime_internal("alloc[51c8835889e4393a]::vec::Vec<u8>"));
        assert!(!is_runtime_internal("app::main"));
        assert!(!is_runtime_internal("<app::Worker>::run"));
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

    #[test]
    fn matches_callback_registration_rules() {
        let qsort = function("qsort", &["qsort"], Language::C);
        let rule = match_function(&qsort).expect("qsort callback rule");
        assert_eq!(rule.op, RuleOp::Callback);
        assert_eq!(rule.callback_args, Some(&[3][..]));

        let atfork = function("pthread_atfork", &["pthread_atfork"], Language::C);
        let rule = match_function(&atfork).expect("pthread_atfork callback rule");
        assert_eq!(rule.op, RuleOp::Callback);
        assert_eq!(rule.callback_args, Some(&[0, 1, 2][..]));

        let timer = function("xTimerCreate", &["xTimerCreate"], Language::C);
        let rule = match_function(&timer).expect("FreeRTOS timer callback rule");
        assert_eq!(rule.op, RuleOp::Callback);
        assert_eq!(rule.callback_args, Some(&[4][..]));
    }

    #[test]
    fn classifies_noreturn_api_names() {
        for name in [
            "abort",
            "_exit",
            "std::process::exit",
            "pthread_exit",
            "longjmp",
            "__stack_chk_fail",
            "__cxa_throw",
            "std::terminate",
            "core[581b33c2f4131567]::panicking::panic_fmt",
            "core::panicking::panic_const::panic_const_async_fn_resumed",
            "core::panicking::begin_panic::<&str>",
            "core::panicking::assert_failed::<u32>",
            "core::option::Option<T>::unwrap_failed",
            "alloc::alloc::handle_alloc_error",
            "core::slice::index::slice_end_index_len_fail",
            "NVIC_SystemReset",
            "k_panic",
        ] {
            assert!(is_noreturn_name(name), "{name} should be noreturn");
        }
        for name in [
            "main",
            "app::abort",
            "app::halt_forever",
            "core::panicking::panic_count::increase",
            "core::fmt::write",
            "DefaultHandler",
            "HardFault",
            "malloc",
        ] {
            assert!(!is_noreturn_name(name), "{name} should not be noreturn");
        }
    }
}
