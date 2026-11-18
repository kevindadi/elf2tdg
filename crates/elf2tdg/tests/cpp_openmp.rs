//! End-to-end C++ `std::thread` and OpenMP detection.
//!
//! These tests compile small host programs with `g++`/`gcc` and verify that
//! PLT resolution, C++ constructor matching and OpenMP entry-argument
//! recovery work on real dynamically linked ELFs. They skip when the compiler
//! is unavailable.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::cfg::{CfgConcurrencyKind, CfgRootKind};
use elf2tdg::loader;
use elf2tdg_schema::ScopeKind;

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn compile(compiler: &str, source_name: &str, args: &[&str], source: &str) -> Option<PathBuf> {
    if !tool_available(compiler) {
        eprintln!("skipping {source_name}: {compiler} is not available");
        return None;
    }
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-{}-{}", source_name, std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source_path = directory.join(source_name);
    std::fs::write(&source_path, source).ok()?;
    let binary = directory.join("fixture");
    let status = Command::new(compiler)
        .args(args)
        .arg("-o")
        .arg(&binary)
        .arg(&source_path)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping {source_name}: compilation failed");
        None
    }
}

#[test]
fn detects_cpp_std_thread_spawn_and_join() {
    let source = r#"
#include <thread>
#include <cstdio>

__attribute__((noinline)) void body() {
    std::printf("worker\n");
}

int main() {
    std::thread worker([]{ body(); });
    worker.join();
    return 0;
}
"#;
    let Some(binary) = compile("g++", "cpp_thread.cpp", &["-O0", "-g", "-pthread"], source) else {
        return;
    };
    let image = loader::load(&binary).expect("C++ fixture must load");
    let program = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    let spawn = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Spawn {
                runtime,
                api,
                entry: Some(entry),
                ..
            } if runtime.as_str() == "cpp-std" => Some((api.as_str(), entry)),
            _ => None,
        })
        .expect("C++ std::thread spawn edge");
    assert_eq!(spawn.0, "std::thread::thread");
    let function = program
        .functions
        .iter()
        .find(|function| &function.id == spawn.1)
        .expect("C++ thread entry function");
    assert!(
        function.primary_name.contains("_M_run"),
        "unexpected C++ thread entry: {}",
        function.primary_name
    );
    assert!(
        program
            .roots
            .iter()
            .any(|root| { root.kind == CfgRootKind::Task && &root.function == spawn.1 })
    );
    let join = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Join {
                entry: Some(entry), ..
            } => Some(entry),
            _ => None,
        })
        .expect("C++ std::thread join edge");
    assert_eq!(join, spawn.1);
    assert!(
        program
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "cpp-callable-entry"),
        "missing C++ callable-entry diagnostic"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn recovers_openmp_parallel_entry_and_timing() {
    let source = r#"
#include <stdio.h>

volatile int ticks;

__attribute__((noinline)) void work(void) {
    ticks++;
}

int main(void) {
#pragma omp parallel
    { work(); }
    printf("%d\n", ticks);
    return 0;
}
"#;
    let Some(binary) = compile("gcc", "openmp.c", &["-O0", "-g", "-fopenmp"], source) else {
        return;
    };
    let image = loader::load(&binary).expect("OpenMP fixture must load");
    let options = AnalysisOptions {
        cpu: Some("x86-64".to_owned()),
        ..AnalysisOptions::default()
    };
    let program = analyze(&image, &options).expect("analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    let spawn = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Spawn {
                runtime,
                api,
                entry: Some(entry),
                ..
            } if runtime.as_str() == "openmp" => Some((api.as_str(), entry)),
            _ => None,
        })
        .expect("OpenMP spawn edge");
    assert_eq!(spawn.0, "GOMP_parallel");
    let function = program
        .functions
        .iter()
        .find(|function| &function.id == spawn.1)
        .expect("OpenMP entry function");
    assert!(
        function.primary_name.contains("_omp_fn"),
        "unexpected OpenMP entry: {}",
        function.primary_name
    );
    let scope = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::ScopeEnter {
                scope_kind: ScopeKind::OpenMpParallel,
                implicit_join,
            } => Some(*implicit_join),
            _ => None,
        })
        .expect("OpenMP parallel scope");
    assert!(scope);

    assert!(
        program.timing.as_ref().is_some_and(|timing| timing
            .models
            .iter()
            .any(|model| model.id.as_str() == "x86-64-generic")),
        "x86-64 statistical timing model should be present"
    );
    assert!(
        !function.cfg.blocks_by_address.is_empty(),
        "OpenMP outlined function should have at least one block"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
