//! C helper-wrapper parameter forwarding.
//!
//! GCC at `-O0` spills `pthread_create`'s function-pointer argument to the
//! stack before reloading it into the ABI register. This test checks that the
//! analyzer follows the spill/reload pair, resolves the caller's argument, and
//! links the join back to the forwarded thread context.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::loader;
use elf2tdg_schema::{ContextKind, Edge, JoinTarget, SpawnTarget};

fn compile_fixture(name: &str, source_text: &str) -> Option<PathBuf> {
    let available = Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        eprintln!("skipping C fixture {name}: gcc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-c-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join(format!("{name}.c"));
    std::fs::write(&source, source_text).ok()?;
    let binary = directory.join(name);
    let status = Command::new("gcc")
        .args(["-O0", "-g", "-pthread", "-o"])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping C fixture {name}: compilation failed");
        None
    }
}

const WRAPPER_SOURCE: &str = r"
#include <pthread.h>

void *worker(void *arg) {
    (void)arg;
    return 0;
}

__attribute__((noinline)) static void start_worker(
    pthread_t *thread, void *(*entry)(void *), void *arg) {
    pthread_create(thread, 0, entry, arg);
}

int main(void) {
    pthread_t thread;
    start_worker(&thread, worker, (void *)0);
    pthread_join(thread, 0);
    return 0;
}
";

const INDIRECT_CALL_SOURCE: &str = r"
volatile int ticks;

__attribute__((noinline)) void target(void) {
    ticks++;
}

void (*stored_entry)(void) = target;

int main(void) {
    stored_entry();
    return 0;
}
";

const STORED_POINTER_SOURCE: &str = r"
#include <pthread.h>

void *worker(void *arg) {
    (void)arg;
    return 0;
}

void *(*stored_entry)(void *) = worker;

int main(void) {
    pthread_t thread;
    pthread_create(&thread, 0, stored_entry, 0);
    pthread_join(thread, 0);
    return 0;
}
";

#[test]
fn forwards_wrapper_entry_and_resolves_join() {
    let Some(binary) = compile_fixture("wrapper", WRAPPER_SOURCE) else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    let worker = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "worker")
        .expect("worker function");
    let spawn = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Spawn {
                runtime,
                target: SpawnTarget::Context { context, entry },
                ..
            } if runtime.as_str() == "pthread" => Some((context, entry)),
            _ => None,
        })
        .expect("forwarded pthread spawn");
    assert_eq!(spawn.1, &worker.id);
    let context = tdg
        .contexts
        .iter()
        .find(|candidate| candidate.id == *spawn.0)
        .expect("thread context");
    assert_eq!(context.kind, ContextKind::Thread);
    assert_eq!(context.entry, worker.id);

    let join = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Join { target, .. } => Some(target),
            _ => None,
        })
        .expect("join edge");
    assert!(matches!(join, JoinTarget::Context { .. }));
    assert!(
        tdg.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "forwarded-spawn-entry"),
        "missing wrapper-forwarding diagnostic"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn resolves_indirect_call_through_global_pointer() {
    let Some(binary) = compile_fixture("indirect_call", INDIRECT_CALL_SOURCE) else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    let target = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "target")
        .expect("target function");
    let call = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Call { callee, direct, .. } if callee == &target.id => Some(*direct),
            _ => None,
        })
        .expect("resolved indirect call edge");
    assert!(!call, "indirect call must not be marked direct");
    assert!(
        tdg.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-indirect-call"),
        "missing resolved-indirect-call diagnostic"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn resolves_entry_loaded_from_global_pointer() {
    let Some(binary) = compile_fixture("stored_pointer", STORED_POINTER_SOURCE) else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    let worker = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "worker")
        .expect("worker function");
    let spawn = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Spawn {
                runtime,
                target: SpawnTarget::Context { entry, .. },
                ..
            } if runtime.as_str() == "pthread" => Some(entry),
            _ => None,
        })
        .expect("pthread spawn from stored pointer");
    assert_eq!(spawn, &worker.id);

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
