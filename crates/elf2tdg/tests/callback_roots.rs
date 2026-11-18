//! Callback registration edges and global function-pointer roots.
//!
//! The fixture registers qsort/atexit/signal callbacks from `main` and stores
//! two more functions only in a read-only callback table. The analyzer must
//! create `CallbackBind` edges for the registrations and treat the table
//! entries as system roots even though no code calls them directly.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{self, CfgConcurrencyKind};
use elf2tdg::loader;
use elf2tdg_schema::FunctionId;

const SOURCE: &str = r#"
#include <stddef.h>

static int compare_ints(const void *left, const void *right) {
    return *(const int *)left - *(const int *)right;
}

static void finalizer(void) {
}

static void signal_handler(int signal_number) {
    (void)signal_number;
}

__attribute__((noinline, used)) static void table_entry_a(void) {
}

__attribute__((noinline, used)) static void table_entry_b(void) {
}

__attribute__((used)) static void (*const callback_table[])(void) = {
    table_entry_a,
    table_entry_b,
    0,
};

__attribute__((noinline)) static void touch_callback_table(void) {
    const void *table = callback_table;
    __asm__ volatile("" : : "r"(table) : "memory");
}

extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
extern int atexit(void (*)(void));
extern void (*signal(int, void (*)(int)))(int);

int main(void) {
    int values[2] = {2, 1};
    touch_callback_table();
    qsort(values, 2, sizeof(int), compare_ints);
    atexit(finalizer);
    signal(2, signal_handler);
    return values[0];
}
"#;

fn compile_fixture() -> Option<PathBuf> {
    let available = Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        eprintln!("skipping callback/pointer fixture: gcc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-callback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("callbacks.c");
    std::fs::write(&source, SOURCE).ok()?;
    let binary = directory.join("callbacks");
    let status = Command::new("gcc")
        .args([
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-o",
        ])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping callback/pointer fixture: compilation failed");
        None
    }
}

fn function_id(program: &cfg::ProgramCfg, name: &str) -> FunctionId {
    program
        .functions
        .iter()
        .find(|function| function.primary_name == name)
        .unwrap_or_else(|| panic!("missing function {name}"))
        .id
        .clone()
}

#[test]
#[allow(clippy::too_many_lines)]
fn recovers_callback_edges_and_pointer_roots() {
    let Some(binary) = compile_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    analysis.cfg.ensure_valid().expect("CFG must validate");

    let main_id = function_id(&analysis.cfg, "main");
    for callback in ["compare_ints", "finalizer", "signal_handler"] {
        let callback_id = function_id(&analysis.cfg, callback);
        assert!(
            analysis.cfg.concurrency.iter().any(|site| {
                matches!(
                    &site.operation,
                    CfgConcurrencyKind::CallbackBind {
                        callback,
                        runtime,
                        ..
                    } if callback == &callback_id && runtime.as_str() == "libc"
                ) && site.function == main_id
            }),
            "missing callback annotation for {callback}"
        );
    }
    assert!(
        analysis
            .cfg
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "resolved-callback")
            .count()
            >= 3,
        "callback registrations should produce resolution diagnostics"
    );
    assert!(
        analysis
            .cfg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "pointer-roots"),
        "global pointer roots should be reported"
    );

    // Pointer roots come from the callback table, not from a direct call.
    let table_entries = ["table_entry_a", "table_entry_b"];
    for entry in table_entries {
        let function = analysis
            .cfg
            .functions
            .iter()
            .find(|function| function.primary_name == entry)
            .expect("table entry function");
        assert!(
            analysis.cfg.pointer_roots.contains(&function.address),
            "missing pointer root for {entry}"
        );
        assert!(
            !analysis.cfg.calls.iter().any(|call| {
                call.callee.as_ref() == Some(&function.id) || call.candidates.contains(&function.id)
            }),
            "{entry} must only be reachable through the pointer table"
        );
    }

    let roots = analysis.cfg.system_roots(&image);
    for name in [
        "compare_ints",
        "finalizer",
        "signal_handler",
        "table_entry_a",
        "table_entry_b",
    ] {
        let id = function_id(&analysis.cfg, name);
        assert!(roots.contains(&id), "missing system root for {name}");
    }
    let reachable = analysis.cfg.reachable_from_system(&image, false);
    for name in [
        "compare_ints",
        "finalizer",
        "signal_handler",
        "table_entry_a",
        "table_entry_b",
    ] {
        assert!(
            reachable
                .iter()
                .any(|function| function.primary_name == name),
            "default CFG should include {name}"
        );
    }

    let selected: Vec<&cfg::CfgFunction> = table_entries
        .iter()
        .map(|name| {
            analysis
                .cfg
                .select(Some(name))
                .expect("table entry selector")
                .into_iter()
                .next()
                .expect("table entry CFG")
        })
        .collect();
    let json = cfg::render_json_selected(&analysis.cfg, &selected, false).expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    let pointer_roots = value["pointer_roots"]
        .as_array()
        .expect("pointer_roots array");
    for entry in table_entries {
        let function = analysis
            .cfg
            .functions
            .iter()
            .find(|function| function.primary_name == entry)
            .expect("table entry function");
        let address = format!("0x{:x}", function.address);
        assert!(
            pointer_roots.iter().any(|root| root == &address),
            "CFG JSON should list pointer root {address}"
        );
    }

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
