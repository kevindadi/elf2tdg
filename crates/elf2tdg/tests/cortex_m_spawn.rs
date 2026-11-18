//! End-to-end C/RTOS spawn-entry recovery on Cortex-M.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::cfg::{CfgConcurrencyKind, CfgRootKind};
use elf2tdg::loader;

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
    let program = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    program.ensure_valid().expect("CFG must validate");

    let task_id = program
        .functions
        .iter()
        .find(|function| function.primary_name == "my_task")
        .expect("my_task function")
        .id
        .clone();

    let spawn = program
        .concurrency
        .iter()
        .find_map(|site| match &site.operation {
            CfgConcurrencyKind::Spawn {
                runtime,
                api,
                entry: Some(entry),
                ..
            } if runtime.as_str() == "freertos" => Some((api.as_str(), entry)),
            _ => None,
        })
        .expect("FreeRTOS spawn edge");
    assert_eq!(spawn.0, "xTaskCreate");
    assert_eq!(spawn.1, &task_id);

    let root = program
        .roots
        .iter()
        .find(|root| root.kind == CfgRootKind::Task && root.function == task_id)
        .expect("task context root");
    assert_eq!(root.name.as_deref(), Some("my_task"));
}
