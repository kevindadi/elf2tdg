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
    // ---- RTOS C APIs (entry argument recovered by value tracking) ---------
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
/// This is deliberately a name-based classification: it covers C exit and
/// abort entry points, Rust panic entry points, compiler runtime failure hooks
/// and C++ ABI termination/unwind helpers. Functions that merely contain a halt
/// loop are classified from their recovered control-flow graph instead.
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
    false
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
        RuleOp, extract_first_generic_arg, is_noreturn_name, is_runtime_internal,
        match_demangled_name, match_function, normalize_crate_hashes,
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
    fn rejects_cpp_standard_library_concurrency_and_locks() {
        for name in [
            "_ZNSt6threadC1IZ4mainEUlvE_JEvEEOT_DpOT0_",
            "_ZNSt6thread4joinEv",
            "_ZNSt6thread6detachEv",
            "_ZNSt6asyncIZ4mainEUlvE_JEvEESt6futureINSt9result_ofIFvvEE4typeEEDpOT_",
            "_ZNSt5mutex4lockEv",
            "_ZNSt12shared_mutex4lockEv",
        ] {
            let function = function(name, &[name], Language::Cpp);
            assert!(
                match_function(&function).is_none(),
                "{name} is outside the supported global no-std profile"
            );
        }
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
        let task = function("xTaskCreate", &["xTaskCreate"], Language::C);
        let rule = match_function(&task).expect("freertos rule");
        assert_eq!(rule.runtime, "freertos");
        assert_eq!(rule.op, RuleOp::Spawn);

        let zephyr = function("k_thread_create", &["k_thread_create"], Language::C);
        let rule = match_function(&zephyr).expect("zephyr rule");
        assert_eq!(rule.runtime, "zephyr");

        let threadx = function("tx_thread_create", &["tx_thread_create"], Language::C);
        let rule = match_function(&threadx).expect("threadx rule");
        assert_eq!(rule.runtime, "threadx");
    }

    #[test]
    fn matches_rtos_lock_rules() {
        let take = function("xSemaphoreTake", &["xSemaphoreTake"], Language::C);
        let rule = match_function(&take).expect("FreeRTOS semaphore take rule");
        assert_eq!(rule.op, RuleOp::Lock);
        assert_eq!(rule.lock.map(|lock| lock.kind), Some(LockKind::Semaphore));
        assert_eq!(
            rule.lock.map(|lock| lock.operation),
            Some(LockOperation::Acquire)
        );

        let give = function("xSemaphoreGive", &["xSemaphoreGive"], Language::C);
        let rule = match_function(&give).expect("FreeRTOS semaphore give rule");
        assert_eq!(rule.op, RuleOp::Lock);
        assert_eq!(
            rule.lock.map(|lock| lock.operation),
            Some(LockOperation::Release)
        );

        let mutex = function("k_mutex_lock", &["k_mutex_lock"], Language::C);
        let rule = match_function(&mutex).expect("Zephyr mutex rule");
        assert_eq!(rule.lock.map(|lock| lock.kind), Some(LockKind::Mutex));

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
        assert!(!is_runtime_internal("_Z4bodyi"));
    }

    #[test]
    fn rejects_host_runtime_apis() {
        for name in [
            "pthread_create",
            "pthread_join",
            "pthread_mutex_lock",
            "pthread_rwlock_rdlock",
            "sem_wait",
            "sem_post",
            "GOMP_parallel",
            "__kmpc_fork_call",
            "atexit",
            "qsort",
            "signal",
            "pthread_atfork",
        ] {
            let function = function(name, &[name], Language::C);
            assert!(
                match_function(&function).is_none(),
                "{name} is outside the supported global no-std profile"
            );
        }
    }

    #[test]
    fn matches_rtos_callback_registration_rules() {
        let timer = function("xTimerCreate", &["xTimerCreate"], Language::C);
        let rule = match_function(&timer).expect("FreeRTOS timer callback rule");
        assert_eq!(rule.op, RuleOp::Callback);
        assert_eq!(rule.callback_args, Some(&[4][..]));

        let zephyr = function("k_timer_init", &["k_timer_init"], Language::C);
        let rule = match_function(&zephyr).expect("Zephyr timer callback rule");
        assert_eq!(rule.op, RuleOp::Callback);
        assert_eq!(rule.callback_args, Some(&[1, 2][..]));

        let threadx = function("tx_timer_create", &["tx_timer_create"], Language::C);
        let rule = match_function(&threadx).expect("ThreadX timer callback rule");
        assert_eq!(rule.op, RuleOp::Callback);
        assert_eq!(rule.callback_args, Some(&[2][..]));
    }

    #[test]
    fn classifies_noreturn_api_names() {
        for name in [
            "abort",
            "_exit",
            "longjmp",
            "__stack_chk_fail",
            "__cxa_throw",
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
