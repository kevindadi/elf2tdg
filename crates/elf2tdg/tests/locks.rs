//! Direct lock/semaphore event recovery from embedded RTOS APIs.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;
use elf2tdg_schema::{LockKind, LockOperation};

fn compile_freertos_fixture() -> Option<PathBuf> {
    let available = Command::new("gcc")
        .arg("--version")
        .output()
        .ok()?
        .status
        .success();
    if !available {
        eprintln!("skipping FreeRTOS lock fixture: gcc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-locks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("locks.c");
    std::fs::write(
        &source,
        r"
static long semaphore;

__attribute__((noinline)) long xSemaphoreTake(void *semaphore, unsigned long ticks) {
    (void)semaphore;
    (void)ticks;
    return 1;
}

__attribute__((noinline)) long xSemaphoreGive(void *semaphore) {
    (void)semaphore;
    return 1;
}

int main(void) {
    xSemaphoreTake(&semaphore, 1);
    xSemaphoreGive(&semaphore);
    return 0;
}
",
    )
    .ok()?;
    let binary = directory.join("locks");
    let status = Command::new("gcc")
        .args(["-O0", "-g", "-fno-pie", "-no-pie", "-o"])
        .arg(&binary)
        .arg(source)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping FreeRTOS lock fixture: compilation failed");
        None
    }
}

#[test]
fn recovers_direct_freertos_lock_events() {
    let Some(binary) = compile_freertos_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    analysis.cfg.ensure_valid().expect("CFG must validate");
    for (api, operation) in [
        ("xSemaphoreTake", LockOperation::Acquire),
        ("xSemaphoreGive", LockOperation::Release),
    ] {
        let event = analysis
            .cfg
            .locks
            .iter()
            .find(|event| event.api == api)
            .unwrap_or_else(|| panic!("missing lock event for {api}"));
        assert_eq!(event.operation, operation, "{api}");
        assert_eq!(event.lock_kind, LockKind::Semaphore, "{api}");
        assert!(!event.inlined, "{api} is a direct call");
    }

    let json = elf2tdg::cfg::render_json(&analysis.cfg, None, false).expect("CFG JSON");
    assert!(json.contains("\"locks\""));
    assert!(json.contains("xSemaphoreTake"));

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
