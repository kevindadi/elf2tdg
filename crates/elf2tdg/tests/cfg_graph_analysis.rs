//! Real-image coverage for CFG graph analysis and normalization.

use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;

#[test]
fn analyzes_and_normalizes_real_cfgs() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let mut checked = 0usize;
    for function in &analysis.cfg.functions {
        if function.cfg.blocks_by_address.is_empty() {
            continue;
        }
        let graph = function.cfg.analyze_graph();
        assert_eq!(
            graph.reachable.len() + graph.unreachable.len(),
            function.cfg.graph.node_count(),
            "all graph nodes must be classified for {}",
            function.primary_name
        );
        for block in &graph.reachable {
            assert!(
                graph.dominators.contains_key(block),
                "reachable block {block} must have a dominator set"
            );
        }
        let mut normalized = function.cfg.clone();
        let report = normalized.normalize();
        normalized
            .ensure_valid()
            .expect("normalized function CFG must validate");
        assert_eq!(
            normalized.blocks_by_address.len(),
            function.cfg.blocks_by_address.len()
                - report.removed_unreachable.len()
                - report.merged.len(),
            "normalization report must account for block changes in {}",
            function.primary_name
        );
        checked += 1;
    }
    assert!(checked > 0, "example should contain analyzable functions");
}
