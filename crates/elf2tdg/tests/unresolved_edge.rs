//! Explicit unresolved-call edges.
//!
//! A call through a non-code data value cannot be resolved. The CFG must keep
//! the call site as an explicit unknown edge so graph passes do not prune code
//! as if the caller had no outbound calls.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::Confidence;

const SOURCE: &str = r"
#include <stdint.h>

typedef void (*fn_t)(void);
static uintptr_t value = 0x1234;

int main(void) {
    fn_t f = (fn_t)value;
    f();
    return 0;
}
";

fn compile_fixture() -> Option<PathBuf> {
    if Command::new("gcc").arg("--version").output().is_err() {
        eprintln!("skipping unresolved-edge fixture: gcc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-unresolved-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("unresolved.c");
    std::fs::write(&source, SOURCE).ok()?;
    let binary = directory.join("unresolved");
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
    (status.success() && binary.exists()).then_some(binary)
}

#[test]
fn emits_explicit_unresolved_call_edges() {
    let Some(binary) = compile_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    analysis.cfg.ensure_valid().expect("CFG must validate");

    let diagnostic = analysis
        .cfg
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "unresolved-indirect-call")
        .expect("unresolved indirect call diagnostic");
    let site = diagnostic.site.expect("unresolved call site");
    let caller = diagnostic.function.clone().expect("unresolved caller");

    let unresolved: Vec<_> = analysis
        .cfg
        .calls
        .iter()
        .filter(|call| call.caller == caller && call.site == site && call.unresolved)
        .collect();
    assert_eq!(unresolved.len(), 1, "exactly one unresolved edge");
    let call = unresolved[0];
    assert_eq!(call.caller, caller);
    assert_eq!(call.site, site);
    assert!(!call.tail);
    assert_eq!(call.candidates.as_slice(), &[]);
    assert_eq!(call.confidence, Confidence::Unknown);
    assert_eq!(call.callee, None);
    assert!(
        !analysis
            .cfg
            .calls
            .iter()
            .any(|call| call.site == site && !call.unresolved),
        "unresolved site must not also have a resolved call edge"
    );

    let json = cfg::render_json(&analysis.cfg, None, false).expect("CFG JSON");
    assert!(json.contains("\"unresolved\": true"));

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
