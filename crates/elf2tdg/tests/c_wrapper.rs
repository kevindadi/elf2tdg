//! C helper-wrapper parameter forwarding.
//!
//! GCC at `-O0` spills the task entry passed to a `FreeRTOS` `xTaskCreate`
//! wrapper to the stack before reloading it into the ABI register. This test
//! checks that the analyzer follows the spill/reload pair and resolves the
//! caller's argument.

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
        .args(["-O0", "-g", "-fno-pie", "-no-pie", "-o"])
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

const WRAPPER_SOURCE: &str = r#"
typedef void (*task_fn)(void *);

__attribute__((noinline)) int xTaskCreate(task_fn entry, const char *name,
                                             unsigned long stack, void *arg,
                                             unsigned long priority, void *handle) {
    (void)entry;
    (void)name;
    (void)stack;
    (void)arg;
    (void)priority;
    (void)handle;
    return 0;
}

void worker(void *arg) {
    (void)arg;
}

__attribute__((noinline)) static void start_worker(task_fn entry, void *arg) {
    xTaskCreate(entry, "worker", 128, arg, 1, 0);
}

int main(void) {
    start_worker(worker, (void *)0);
    return 0;
}
"#;

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

const STORED_POINTER_SOURCE: &str = r#"
typedef void (*task_fn)(void *);

__attribute__((noinline)) int xTaskCreate(task_fn entry, const char *name,
                                             unsigned long stack, void *arg,
                                             unsigned long priority, void *handle) {
    (void)entry;
    (void)name;
    (void)stack;
    (void)arg;
    (void)priority;
    (void)handle;
    return 0;
}

void worker(void *arg) {
    (void)arg;
}

task_fn stored_entry = worker;

int main(void) {
    xTaskCreate(stored_entry, "worker", 128, 0, 1, 0);
    return 0;
}
"#;

#[test]
fn forwards_wrapper_entry() {
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
            } if runtime.as_str() == "freertos" => Some(entry),
            _ => None,
        })
        .expect("forwarded FreeRTOS spawn");
    assert_eq!(spawn, &worker.id);
    assert!(
        program
            .roots
            .iter()
            .any(|root| { root.kind == CfgRootKind::Task && root.function == worker.id })
    );

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
            } if runtime.as_str() == "freertos" => Some(entry),
            _ => None,
        })
        .expect("FreeRTOS spawn from stored pointer");
    assert_eq!(spawn, &worker.id);

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
