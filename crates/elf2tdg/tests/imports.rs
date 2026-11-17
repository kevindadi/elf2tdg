//! Dynamic-import GOT calls without local PLT stubs.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::{Edge, FunctionKind};

fn compile_got_fixture() -> Option<PathBuf> {
    let available = Command::new("gcc")
        .arg("--version")
        .output()
        .ok()?
        .status
        .success();
    if !available {
        eprintln!("skipping GOT import fixture: gcc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-imports-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("imports.c");
    std::fs::write(
        &source,
        r"
#include <stdlib.h>

int main(void) {
    void *first = malloc(16);
    void *second = realloc(first, 32);
    free(second);
    return 0;
}
",
    )
    .ok()?;
    let binary = directory.join("imports");
    let status = Command::new("gcc")
        .args(["-O1", "-g", "-fno-plt", "-o"])
        .arg(&binary)
        .arg(source)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping GOT import fixture: compilation failed");
        None
    }
}

#[test]
fn resolves_got_imports_as_external_functions() {
    let Some(binary) = compile_got_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    assert!(
        image.imported_slots.values().any(|name| name == "malloc"),
        "malloc should have a GLOB_DAT slot"
    );
    assert!(
        image.imported_slots.values().any(|name| name == "free"),
        "free should have a GLOB_DAT slot"
    );

    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");
    let main = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "main")
        .expect("main function");

    for import in ["malloc", "realloc", "free"] {
        let external = tdg
            .functions
            .iter()
            .find(|function| {
                function.kind == FunctionKind::External && function.primary_name == import
            })
            .unwrap_or_else(|| panic!("missing external function for {import}"));
        let call = tdg.edges.iter().any(|edge| {
            matches!(
                edge,
                Edge::Call {
                    caller,
                    callee,
                    direct: false,
                    ..
                } if caller == &main.id && callee == &external.id
            )
        });
        assert!(call, "main should call external {import}");
    }
    assert!(
        !tdg.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unresolved-indirect-call"
                && diagnostic.function.as_ref() == Some(&main.id)
        }),
        "GOT import calls in main must be resolved"
    );

    for import in ["malloc", "realloc", "free"] {
        let selected = analysis
            .cfg
            .select(Some(import))
            .unwrap_or_else(|error| panic!("{import}: {error}"));
        assert_eq!(selected.len(), 1, "{import}");
        assert_eq!(selected[0].kind, FunctionKind::External);
        assert!(selected[0].cfg.blocks_by_address.is_empty());
        let json = cfg::render_json_selected(&analysis.cfg, tdg, &selected, false)
            .expect("external CFG JSON");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid CFG JSON");
        assert_eq!(value["functions"][0]["no_code"]["reason"], "external");
        assert_eq!(
            value["functions"][0]["blocks"].as_array().map(Vec::len),
            Some(0)
        );
        let dot = cfg::render_dot_selected(&analysis.cfg, &selected, false);
        assert!(dot.contains("external function"));
        assert!(dot.contains("no machine code"));
        let mermaid = cfg::render_mermaid_selected(&analysis.cfg, &selected, false);
        assert!(mermaid.contains("external function"));
    }

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
