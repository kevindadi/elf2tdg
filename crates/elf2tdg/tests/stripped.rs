//! Stripped-image prologue heuristics.
//!
//! A stripped dynamically linked C image has no local code symbols. The
//! analyzer still seeds from the ELF entry, PLT imports and common prologues,
//! then recovers wrapper forwardings and runtime edges without names.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::cfg::CfgConcurrencyKind;
use elf2tdg::loader;

const SOURCE: &str = r"
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

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn build_fixture() -> Option<(PathBuf, PathBuf)> {
    if !tool_available("gcc") || !tool_available("llvm-objcopy") {
        eprintln!("skipping stripped fixture: gcc or llvm-objcopy is unavailable");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-stripped-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("stripped.c");
    std::fs::write(&source, SOURCE).ok()?;
    let full = directory.join("full");
    let status = Command::new("gcc")
        .args(["-O0", "-g", "-pthread", "-o"])
        .arg(&full)
        .arg(&source)
        .status()
        .ok()?;
    if !status.success() || !full.exists() {
        eprintln!("skipping stripped fixture: compilation failed");
        return None;
    }
    let stripped = directory.join("stripped");
    let status = Command::new("llvm-objcopy")
        .arg("--strip-all")
        .arg(&full)
        .arg(&stripped)
        .status()
        .ok()?;
    if !status.success() || !stripped.exists() {
        eprintln!("skipping stripped fixture: llvm-objcopy failed");
        return None;
    }
    Some((full, stripped))
}

#[test]
fn recovers_prologues_and_wrapper_spawn_without_symbols() {
    let Some((full, stripped)) = build_fixture() else {
        return;
    };
    let full_image = loader::load(&full).expect("full fixture must load");
    let worker_address = full_image
        .symbols
        .iter()
        .find(|symbol| symbol.name == "worker")
        .expect("worker symbol")
        .canonical_address;
    let main_address = full_image
        .symbols
        .iter()
        .find(|symbol| symbol.name == "main")
        .expect("main symbol")
        .canonical_address;

    let stripped_image = loader::load(&stripped).expect("stripped fixture must load");
    assert!(
        !stripped_image
            .symbols
            .iter()
            .any(|symbol| { matches!(symbol.name.as_str(), "worker" | "main" | "start_worker") }),
        "fixture still has local function symbols"
    );
    let program = analyze(&stripped_image, &AnalysisOptions::default())
        .expect("stripped analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    assert!(
        program
            .functions
            .iter()
            .any(|function| function.address == worker_address),
        "worker prologue was not discovered"
    );
    assert!(
        program
            .functions
            .iter()
            .any(|function| function.address == main_address),
        "main prologue was not discovered"
    );
    assert!(
        program
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "stripped-heuristic-seeds"),
        "missing stripped-image heuristic diagnostic"
    );

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
        .expect("stripped pthread spawn");
    let worker = program
        .functions
        .iter()
        .find(|function| &function.id == spawn)
        .expect("spawn entry function");
    assert_eq!(worker.address, worker_address);

    let _ = std::fs::remove_dir_all(stripped.parent().expect("fixture directory"));
}
