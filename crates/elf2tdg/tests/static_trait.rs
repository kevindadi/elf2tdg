//! Rust trait-object points-to through static fat-pointer registries.
//!
//! The fixture stores `&'static dyn Handler` values in a static array. The
//! vtable pointers live inside the array's fat pointers, not as constants in
//! `dispatch`, so code-only vtable discovery must fail and the DWARF
//! trait-object layout must provide the vtable bases.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;
use elf2tdg_schema::{Confidence, Edge};

fn fixture_elf() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_static_trait/firmware.elf");
    path.exists().then_some(path)
}

fn dispatch_function(cfg: &elf2tdg::cfg::ProgramCfg) -> &elf2tdg::cfg::CfgFunction {
    cfg.functions
        .iter()
        .find(|function| function.primary_name.contains("::dispatch"))
        .expect("dispatch CFG")
}

#[test]
fn resolves_static_trait_object_registry() {
    let Some(path) = fixture_elf() else {
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");

    let dwarf = image.dwarf.as_ref().expect("fixture must retain DWARF");
    let layout = dwarf
        .trait_object_layouts
        .iter()
        .find(|layout| {
            layout
                .name
                .as_deref()
                .is_some_and(|name| name.contains("dyn rust_static_trait::Handler"))
        })
        .expect("Handler trait-object layout");
    let pointer = u64::try_from(image.pointer_size()).expect("pointer size");
    assert_eq!(layout.data_offset, 0);
    assert_eq!(layout.vtable_offset, pointer);
    assert_eq!(layout.byte_size, Some(2 * pointer));
    let handlers = dwarf
        .variables
        .iter()
        .find(|variable| variable.name.as_deref() == Some("HANDLERS"))
        .expect("HANDLERS variable");
    assert_eq!(
        handlers.element_aggregate_index,
        Some(layout.aggregate_index)
    );
    assert_eq!(handlers.array_count, Some(2));
    assert_eq!(
        handlers.byte_size,
        Some(2 * layout.byte_size.expect("layout size"))
    );

    let dispatch = dispatch_function(&analysis.cfg);
    let call = dispatch
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| dispatch.cfg.graph[*node].calls.iter())
        .find(|call| !call.direct)
        .expect("trait-object call in dispatch");
    assert!(!call.unresolved);
    assert!(call.tail);
    assert!(call.target.is_none());
    assert_eq!(call.candidates.len(), 2);
    let mut names = Vec::new();
    for candidate in &call.candidates {
        let target = candidate
            .target_function
            .as_ref()
            .and_then(|id| analysis.cfg.function(id))
            .expect("candidate function");
        assert!(target.primary_name.contains("Handler>::handle"));
        names.push(target.primary_name.clone());
        assert!(
            analysis.cfg.pointer_roots.contains(&target.address),
            "method 0x{:x} should be a pointer root",
            target.address
        );
    }
    assert!(names.iter().any(|name| name.contains("::A as")));
    assert!(names.iter().any(|name| name.contains("::B as")));

    let call_edges: Vec<_> = tdg
        .edges
        .iter()
        .filter_map(|edge| match edge {
            Edge::Call {
                caller,
                callee,
                direct: false,
                tail: true,
                confidence: Confidence::Low,
                ..
            } if caller == &dispatch.id => Some(callee),
            _ => None,
        })
        .collect();
    assert_eq!(call_edges.len(), 2);
    assert!(
        tdg.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-trait-object-candidates")
    );
    assert!(
        !tdg.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unresolved-indirect-call"
                || diagnostic.code == "unresolved-indirect-jump"
        }),
        "static trait-object call must not remain unresolved"
    );
}
