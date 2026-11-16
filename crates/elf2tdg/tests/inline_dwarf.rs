//! DWARF inline-frame recovery in optimized no-std Rust builds.
//!
//! Embassy's `Spawner::spawn` is inlined into the user `start_tasks` function
//! at the analysis profile. The symbol disappears from the machine call graph,
//! but the concrete `DW_TAG_inlined_subroutine` ranges remain in DWARF.

use std::path::PathBuf;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::Edge;

fn example_elf() -> Option<PathBuf> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    path.exists().then_some(path)
}

fn is_embassy_spawn(name: &str) -> bool {
    name.contains("Spawner>::spawn") || name.contains("_spawn_async_fn")
}

#[test]
#[allow(clippy::too_many_lines)]
fn cfg_instructions_carry_inlined_embassy_spawn_ranges() {
    let Some(binary) = example_elf() else {
        return;
    };
    let image = loader::load(&binary).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let start_tasks = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name.ends_with("::start_tasks"))
        .expect("start_tasks function");

    let spawn_frames: Vec<_> = start_tasks
        .inline_frames
        .iter()
        .filter(|frame| is_embassy_spawn(&frame.name))
        .collect();
    assert!(
        spawn_frames.len() >= 2,
        "sensor and monitor spawn sites should retain inline ranges"
    );
    let mut covered_frames = 0;
    for frame in &spawn_frames {
        assert!(
            frame.high_pc > frame.low_pc,
            "inline frames must retain concrete address ranges"
        );
        assert!(
            frame.low_pc >= start_tasks.address
                && frame.high_pc <= start_tasks.address.saturating_add(start_tasks.size),
            "inline frame must lie inside its containing function"
        );
        let covered = start_tasks
            .cfg
            .blocks_by_address
            .values()
            .flat_map(|block| start_tasks.cfg.graph[*block].instructions.iter())
            .any(|instruction| {
                frame.low_pc <= instruction.address && instruction.address < frame.high_pc
            });
        covered_frames += usize::from(covered);
    }
    assert!(
        covered_frames >= 2,
        "decoded instructions should fall inside the main inline ranges"
    );
    assert!(
        spawn_frames.iter().any(|frame| {
            frame
                .call_site
                .as_ref()
                .is_some_and(|site| site.file.ends_with("main.rs") && site.line > 0)
        }),
        "inline frames should retain the user source call site"
    );

    for task in ["sensor_task", "monitor_task"] {
        assert!(
            analysis.tdg.edges.iter().any(|edge| matches!(
                edge,
                Edge::Spawn { runtime, name: Some(name), .. }
                    if runtime.as_str() == "rust-embassy" && name.contains(task)
            )),
            "inlined Spawner::spawn should produce a {task} spawn edge"
        );
    }

    let json = cfg::render_json_selected(&analysis.cfg, &analysis.tdg, &[start_tasks], true)
        .expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("valid CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    let rendered_spawn = document["functions"][0]["inline_frames"]
        .as_array()
        .expect("inline_frames")
        .iter()
        .any(|frame| {
            frame["name"].as_str().is_some_and(is_embassy_spawn)
                && frame["low"].is_string()
                && frame["high"].is_string()
                && frame["depth"].is_u64()
                && frame["call_site"]["line"].is_u64()
        });
    assert!(
        rendered_spawn,
        "CFG JSON must expose inline-frame names, ranges, depth and call sites"
    );

    let compact = cfg::render_json_selected(&analysis.cfg, &analysis.tdg, &[start_tasks], false)
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
}

#[test]
fn inline_index_returns_nested_frames_outermost_first() {
    let Some(binary) = example_elf() else {
        return;
    };
    let image = loader::load(&binary).expect("example ELF must load");
    let dwarf = image.dwarf.as_ref().expect("debug info");
    let frame = dwarf
        .inlined_calls
        .iter()
        .find(|call| call.display_name.as_deref().is_some_and(is_embassy_spawn))
        .expect("Spawner::spawn inline DIE");
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
}
