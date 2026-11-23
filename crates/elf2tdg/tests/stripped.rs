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

const SOURCE: &str = r#"
typedef void (*task_fn)(void *);

extern int xTaskCreate(task_fn entry, const char *name, unsigned long stack,
                       void *arg, unsigned long priority, void *handle);

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
    let stub_source = directory.join("stub.c");
    std::fs::write(
        &stub_source,
        r"
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
",
    )
    .ok()?;
    let stub_library = directory.join("libfreertosstub.so");
    let status = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&stub_library)
        .arg(&stub_source)
        .status()
        .ok()?;
    if !status.success() || !stub_library.exists() {
        eprintln!("skipping stripped fixture: stub library failed");
        return None;
    }
    let source = directory.join("stripped.c");
    std::fs::write(&source, SOURCE).ok()?;
    let full = directory.join("full");
    let status = Command::new("gcc")
        .args(["-O0", "-g", "-fno-pie", "-no-pie", "-L"])
        .arg(&directory)
        .arg(format!("-Wl,-rpath,{}", directory.display()))
        .args(["-lfreertosstub", "-o"])
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
            } if runtime.as_str() == "freertos" => Some(entry),
            _ => None,
        })
        .expect("stripped FreeRTOS spawn");
    let worker = program
        .functions
        .iter()
        .find(|function| &function.id == spawn)
        .expect("spawn entry function");
    assert_eq!(worker.address, worker_address);

    let _ = std::fs::remove_dir_all(stripped.parent().expect("fixture directory"));
}
