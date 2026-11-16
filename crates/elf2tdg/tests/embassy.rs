//! End-to-end Embassy task detection in a no-std Cortex-M image.
//!
//! The fixture is the checked-in `rust-concurrency` example ELF. It targets
//! `thumbv7em-none-eabi`, links `cortex-m-rt` and `embassy-executor`, and has
//! no `std` dependency.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::loader::{self, ArchKind};
use elf2tdg_schema::{ContextKind, Edge, FunctionKind, SpawnTarget};

fn example_elf() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    path.exists().then_some(path)
}

#[test]
#[allow(clippy::too_many_lines)]
fn recovers_embassy_task_contexts_and_spawns() {
    let Some(path) = example_elf() else {
        return;
    };
    let image = loader::load(&path).expect("example ELF must load");
    assert_eq!(image.arch, ArchKind::Thumb);
    assert!(!image.vector_table.is_empty(), "Cortex-M vector table");

    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    assert!(
        !tdg.functions
            .iter()
            .any(|function| function.primary_name.starts_with("std::")),
        "the fixture must not contain std runtime functions"
    );
    assert!(
        !tdg.contexts
            .iter()
            .any(|context| context.name.contains("std::thread")),
        "std::thread is outside the supported no_std profile"
    );
    assert!(
        tdg.locks.is_empty(),
        "the example has no locking dependency"
    );

    let async_tasks: Vec<_> = tdg
        .contexts
        .iter()
        .filter(|context| context.kind == ContextKind::AsyncTask)
        .collect();
    assert_eq!(async_tasks.len(), 3, "main plus sensor/monitor tasks");
    for task in ["app_main", "sensor_task", "monitor_task"] {
        assert!(
            async_tasks
                .iter()
                .any(|context| context.name.contains(task)),
            "missing async task context for {task}"
        );
    }

    let main = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::Main)
        .expect("main context");
    let app_main = async_tasks
        .iter()
        .find(|context| context.name.contains("app_main"))
        .expect("Embassy main task");
    assert_eq!(
        app_main
            .parent
            .as_ref()
            .map(elf2tdg_schema::ContextId::as_str),
        Some(main.id.as_str()),
        "the Embassy main task should be rooted in the Cortex-M main context"
    );
    for task in ["sensor_task", "monitor_task"] {
        let context = async_tasks
            .iter()
            .find(|context| context.name.contains(task))
            .expect("task context");
        assert_eq!(
            context
                .parent
                .as_ref()
                .map(elf2tdg_schema::ContextId::as_str),
            Some(app_main.id.as_str()),
            "{task} should be spawned from the Embassy main task"
        );
        let entry = tdg
            .functions
            .iter()
            .find(|function| function.id == context.entry)
            .expect("task entry function");
        assert!(entry.primary_name.contains("TaskStorage<"));
        assert!(entry.primary_name.ends_with("::poll"));
    }

    let spawns: Vec<&Edge> = tdg
        .edges
        .iter()
        .filter(|edge| matches!(edge, Edge::Spawn { .. }))
        .collect();
    assert_eq!(spawns.len(), 3, "Embassy main, sensor and monitor spawns");
    for edge in &spawns {
        let Edge::Spawn {
            runtime,
            api,
            name,
            target: SpawnTarget::Context { entry, .. },
            ..
        } = edge
        else {
            panic!("expected a resolved Embassy spawn, got {edge:?}");
        };
        assert_eq!(runtime.as_str(), "rust-embassy");
        assert_eq!(api.as_str(), "embassy::Spawner::spawn");
        assert!(name.as_deref().is_some_and(|name| !name.contains("std::")));
        let entry = tdg
            .functions
            .iter()
            .find(|function| &function.id == entry)
            .expect("spawn entry function");
        assert_eq!(entry.kind, FunctionKind::Normal);
        assert!(entry.primary_name.contains("TaskStorage<"));
    }

    let isr_contexts: Vec<_> = tdg
        .contexts
        .iter()
        .filter(|context| context.kind == ContextKind::Isr)
        .collect();
    assert_eq!(isr_contexts.len(), 1, "only HardFault is a real vector");
    assert_eq!(isr_contexts[0].name, "HardFault");
}
