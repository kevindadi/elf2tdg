//! End-to-end C/RTOS spawn-entry recovery on Cortex-M.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::loader;
use elf2tdg_schema::{ContextKind, Edge, SpawnTarget};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cortex_m_spawn")
}

fn fixture_elf() -> Option<PathBuf> {
    let directory = fixture_dir();
    let elf = directory.join("firmware.elf");
    if elf.exists() {
        return Some(elf);
    }
    let status = Command::new("make")
        .arg("-C")
        .arg(&directory)
        .status()
        .ok()?;
    if status.success() && elf.exists() {
        Some(elf)
    } else {
        eprintln!(
            "skipping Cortex-M spawn fixture: build {} with `make` (requires arm-none-eabi-gcc)",
            elf.display()
        );
        None
    }
}

#[test]
fn recovers_freertos_task_entry_from_literal_pool() {
    let Some(path) = fixture_elf() else {
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    let task_id = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "my_task")
        .expect("my_task function")
        .id
        .clone();

    let spawn = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Spawn {
                runtime,
                api,
                target,
                ..
            } if runtime.as_str() == "freertos" => Some((api, target)),
            _ => None,
        })
        .expect("FreeRTOS spawn edge");
    assert_eq!(spawn.0, "xTaskCreate");
    let SpawnTarget::Context { context, entry } = spawn.1 else {
        panic!("expected resolved xTaskCreate entry, got {:?}", spawn.1);
    };
    assert_eq!(entry, &task_id);

    let context = tdg
        .contexts
        .iter()
        .find(|candidate| &candidate.id == context)
        .expect("task context");
    assert_eq!(context.kind, ContextKind::Thread);
    assert_eq!(context.name, "my_task");
    assert_eq!(context.entry, task_id);
    assert_eq!(
        context
            .parent
            .as_ref()
            .map(elf2tdg_schema::ContextId::as_str),
        Some("ctx:startup")
    );
}
