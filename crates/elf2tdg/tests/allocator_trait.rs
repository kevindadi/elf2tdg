//! Allocator and trait-object points-to in a no-std image.
//!
//! The fixture allocates a holder containing `Box<dyn Sensor>`. The global
//! allocator call must remain a direct edge; the trait method is reached
//! through a vtable loaded from the heap-held fat pointer and is recovered as
//! bounded candidate call edges.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;
use elf2tdg_schema::{Confidence, Edge};

fn fixture_elf() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_alloc_trait/firmware.elf");
    path.exists().then_some(path)
}

#[test]
fn resolves_allocator_and_trait_object_calls() {
    let Some(path) = fixture_elf() else {
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");

    let allocator = tdg
        .functions
        .iter()
        .find(|function| function.primary_name.contains("GlobalAlloc>::alloc"))
        .expect("global allocator function");
    let allocator_call = tdg.edges.iter().any(|edge| {
        matches!(
            edge,
            Edge::Call {
                callee,
                direct: true,
                ..
            } if callee == &allocator.id
        )
    });
    assert!(allocator_call, "allocator call should be a direct edge");

    let trait_call = tdg
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "resolved-trait-object-candidates")
        .expect("trait-object candidate diagnostic");
    let site = trait_call.site.expect("trait call site");
    assert!(
        !tdg.diagnostics.iter().any(|diagnostic| {
            (diagnostic.code == "unresolved-indirect-call"
                || diagnostic.code == "unresolved-indirect-jump")
                && diagnostic.site == Some(site)
        }),
        "trait-object candidates should replace the unresolved diagnostic"
    );

    let candidates: Vec<_> = tdg
        .edges
        .iter()
        .filter_map(|edge| match edge {
            Edge::Call {
                site: edge_site,
                callee,
                direct: false,
                tail: true,
                confidence: Confidence::Low,
                ..
            } if *edge_site == site => Some(callee),
            _ => None,
        })
        .collect();
    assert_eq!(candidates.len(), 2, "two trait implementations");
    for callee in &candidates {
        let target = tdg
            .functions
            .iter()
            .find(|function| &function.id == *callee)
            .expect("candidate method");
        assert!(target.primary_name.contains("::Sensor>::read"));
    }

    let call_sensor = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name.contains("::call_sensor"))
        .expect("call_sensor CFG");
    let cfg_candidates: Vec<_> = call_sensor
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| call_sensor.cfg.graph[*node].calls.iter())
        .filter(|call| call.site == site.get())
        .collect();
    assert_eq!(cfg_candidates.len(), 2);
    assert!(cfg_candidates.iter().all(|call| {
        !call.unresolved && call.heuristic && call.tail && call.target_function.is_some()
    }));
}
