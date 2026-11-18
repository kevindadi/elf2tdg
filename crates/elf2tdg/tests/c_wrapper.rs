//! C helper-wrapper parameter forwarding.
//!
//! GCC at `-O0` spills `pthread_create`'s function-pointer argument to the
//! stack before reloading it into the ABI register. This test checks that the
//! analyzer follows the spill/reload pair, resolves the caller's argument, and
//! links the join back to the forwarded thread context.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::cfg::{CfgConcurrencyKind, CfgRootKind};
use elf2tdg::loader;

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
    let program = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    let worker = program
        .functions
        .iter()
        .find(|function| function.primary_name == "worker")
        .expect("worker function");
    let spawn = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Spawn {
                runtime,
                entry: Some(entry),
                ..
            } if runtime.as_str() == "pthread" => Some(entry),
            _ => None,
        })
        .expect("forwarded pthread spawn");
    assert_eq!(spawn, &worker.id);
    assert!(
        program
            .roots
            .iter()
            .any(|root| { root.kind == CfgRootKind::Task && root.function == worker.id })
    );

    let join = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Join { entry, .. } => entry.as_ref(),
            _ => None,
        })
        .expect("join edge");
    assert_eq!(join, &worker.id);
    assert!(
        program
            .diagnostics
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
    let program = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    let target = program
        .functions
        .iter()
        .find(|function| function.primary_name == "target")
        .expect("target function");
    let call = program
        .calls
        .iter()
        .find(|call| call.callee.as_ref() == Some(&target.id))
        .expect("resolved indirect call edge");
    assert!(!call.direct, "indirect call must not be marked direct");
    assert!(
        program
            .diagnostics
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
    let program = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    let worker = program
        .functions
        .iter()
        .find(|function| function.primary_name == "worker")
        .expect("worker function");
    let spawn = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Spawn {
                runtime,
                entry: Some(entry),
                ..
            } if runtime.as_str() == "pthread" => Some(entry),
            _ => None,
        })
        .expect("pthread spawn from stored pointer");
    assert_eq!(spawn, &worker.id);

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
