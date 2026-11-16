//! DWARF inline-frame recovery in optimized Rust builds.
//!
//! The fixture deliberately uses `Mutex::lock`, which is commonly inlined into
//! the caller at `-O1`/`-O2`. The symbol disappears from the machine call
//! graph, but the concrete `DW_TAG_inlined_subroutine` range remains in DWARF.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::{LockKind, LockOperation};

fn compile_fixture() -> Option<PathBuf> {
    let rustc_available = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?
        .status
        .success();
    if !rustc_available {
        eprintln!("skipping DWARF inline fixture: rustc is not available");
        return None;
    }
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-inline-dwarf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("inline_mutex.rs");
    std::fs::write(
        &source,
        r#"
use std::sync::Mutex;

fn main() {
    let counter = Mutex::new(0u64);
    {
        let mut guard = counter.lock().expect("lock");
        *guard += 1;
        std::hint::black_box(*guard);
    }
}
"#,
    )
    .ok()?;
    let binary = directory.join("inline_mutex");
    let status = Command::new("rustc")
        .args(["--edition=2021", "-C", "opt-level=1", "-C", "debuginfo=2"])
        .arg("-o")
        .arg(&binary)
        .arg(source)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping DWARF inline fixture: compilation failed");
        None
    }
}

fn is_mutex_lock(name: &str) -> bool {
    name.contains("Mutex") && name.contains("::lock")
}

#[test]
#[allow(clippy::too_many_lines)]
fn cfg_instructions_carry_inlined_mutex_lock_ranges() {
    let Some(binary) = compile_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let main = analysis
        .cfg
        .functions
        .iter()
        .filter(|function| function.primary_name.ends_with("::main"))
        .max_by_key(|function| function.size)
        .expect("Rust main function");

    let acquire = analysis
        .tdg
        .locks
        .iter()
        .find(|event| {
            event.api == "Mutex::lock"
                && event.operation == LockOperation::Acquire
                && event
                    .call_site
                    .as_ref()
                    .is_some_and(|site| site.file.ends_with("inline_mutex.rs") && site.line > 0)
        })
        .expect("inlined Mutex::lock acquire event");
    assert_eq!(acquire.lock_kind, LockKind::Mutex);
    assert!(acquire.inlined);
    assert!(acquire.extent.is_some_and(|extent| extent > acquire.site));
    assert_eq!(
        acquire
            .context
            .as_ref()
            .map(elf2tdg_schema::ContextId::as_str),
        Some("ctx:main")
    );
    let release = analysis
        .tdg
        .locks
        .iter()
        .find(|event| event.api == "MutexGuard::drop" && event.operation == LockOperation::Release)
        .expect("guard drop should produce a release event");
    assert!(
        release
            .call_site
            .as_ref()
            .is_some_and(|site| { site.file.ends_with("inline_mutex.rs") && site.line > 0 }),
        "drop_glue inline range should retain the user call site"
    );

    let mut lock_frames = Vec::new();
    for frame in &main.inline_frames {
        assert!(
            frame.high_pc > frame.low_pc,
            "inline frames must retain concrete address ranges"
        );
        assert!(
            frame.low_pc >= main.address && frame.high_pc <= main.address.saturating_add(main.size),
            "inline frame must lie inside its containing function"
        );
        if is_mutex_lock(&frame.name) {
            let covered = main
                .cfg
                .blocks_by_address
                .values()
                .flat_map(|block| main.cfg.graph[*block].instructions.iter())
                .any(|instruction| {
                    frame.low_pc <= instruction.address && instruction.address < frame.high_pc
                });
            assert!(
                covered,
                "decoded instructions should fall inside the inline range"
            );
            lock_frames.push(frame);
        }
    }
    assert!(
        !lock_frames.is_empty(),
        "Mutex::lock should be present as an inline frame in main"
    );

    let json =
        cfg::render_json_selected(&analysis.cfg, &analysis.tdg, &[main], true).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("valid CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    let rendered_lock = document["functions"][0]["inline_frames"]
        .as_array()
        .expect("inline_frames")
        .iter()
        .any(|frame| {
            frame["name"].as_str().is_some_and(is_mutex_lock)
                && frame["low"].is_string()
                && frame["high"].is_string()
                && frame["depth"].is_u64()
        });
    assert!(
        rendered_lock,
        "CFG JSON must expose inline-frame names, ranges and depth"
    );

    let compact = cfg::render_json_selected(&analysis.cfg, &analysis.tdg, &[main], false)
        .expect("compact CFG JSON");
    let compact: serde_json::Value = serde_json::from_str(&compact).expect("valid compact JSON");
    assert!(
        compact["functions"][0]["inline_frames"]
            .as_array()
            .is_some_and(|frames| !frames.is_empty()),
        "inline ranges should survive --no-cfg-instructions"
    );
    assert!(
        compact["functions"][0]["blocks"][0]
            .get("instructions")
            .is_none(),
        "instruction arrays should be omitted"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn inline_index_returns_nested_frames_outermost_first() {
    let Some(binary) = compile_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let dwarf = image.dwarf.as_ref().expect("debug info");
    let frame = dwarf
        .inlined_calls
        .iter()
        .find(|call| {
            call.display_name
                .as_deref()
                .is_some_and(|name| name.contains("Mutex") && name.contains("::lock"))
        })
        .expect("Mutex::lock inline DIE");
    assert!(frame.high_pc > frame.low_pc);
    let frames = dwarf.inline_frames_at(frame.low_pc);
    assert!(
        frames
            .iter()
            .any(|candidate| candidate.low_pc <= frame.low_pc && frame.low_pc < candidate.high_pc),
        "inline index must report the frame covering its start"
    );
    let depths: Vec<u32> = frames.iter().map(|frame| frame.depth).collect();
    assert!(
        depths.windows(2).all(|pair| pair[0] <= pair[1]),
        "inline frames should be ordered outermost first: {depths:?}"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
