//! Explicit unresolved-call edges.
//!
//! A call through a non-code data value cannot be resolved. The TDG must keep
//! the call site as an explicit unknown edge so graph passes do not prune code
//! as if the caller had no outbound calls.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;
use elf2tdg::output;
use elf2tdg_schema::{Confidence, Edge};

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
    let tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");

    let diagnostic = tdg
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "unresolved-indirect-call")
        .expect("unresolved indirect call diagnostic");
    let site = diagnostic.site.expect("unresolved call site");
    let caller = diagnostic.function.clone().expect("unresolved caller");

    let unresolved: Vec<&Edge> = tdg
        .edges
        .iter()
        .filter(|edge| {
            matches!(
                edge,
                Edge::UnresolvedCall {
                    caller: edge_caller,
                    site: edge_site,
                    ..
                } if edge_caller == &caller && edge_site == &site
            )
        })
        .collect();
    assert_eq!(unresolved.len(), 1, "exactly one unresolved edge");
    match unresolved[0] {
        Edge::UnresolvedCall {
            caller: edge_caller,
            site: edge_site,
            tail,
            candidates,
            confidence,
            ..
        } => {
            assert_eq!(edge_caller, &caller);
            assert_eq!(edge_site, &site);
            assert!(!tail);
            assert_eq!(candidates.as_slice(), []);
            assert_eq!(*confidence, Confidence::Unknown);
        }
        _ => unreachable!("filtered unresolved edge"),
    }
    assert!(
        !tdg.edges.iter().any(|edge| matches!(
            edge,
            Edge::Call { site: edge_site, .. } if edge_site == &site
        )),
        "unresolved site must not also have a resolved call edge"
    );

    let json = serde_json::to_string(tdg).expect("TDG JSON");
    assert!(json.contains("\"kind\":\"unresolved-call\""));
    let dot = output::render_dot(tdg);
    assert!(dot.contains("call?"));
    assert!(dot.contains("opaque:"));
    let mermaid = output::render_mermaid(tdg);
    assert!(mermaid.contains("call?"));
    let concurrency = output::render_dot_with(
        tdg,
        output::GraphOptions {
            projection: output::Projection::Concurrency,
            legend: false,
        },
    );
    assert!(!concurrency.contains("call?"));

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
